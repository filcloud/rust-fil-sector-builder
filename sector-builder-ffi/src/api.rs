use std::mem;
use std::ptr;
use std::slice::from_raw_parts;
use std::collections::HashMap;

use ffi_toolkit::rust_str_to_c_str;
use ffi_toolkit::{c_str_to_rust_str, raw_ptr};
use libc;
use once_cell::sync::OnceCell;
use sector_builder::{GetSealedSectorResult, PieceMetadata, SealStatus, SecondsSinceEpoch, StagedSectorMetadata, UnpaddedBytesAmount, SealedSectorMetadata};
use storage_proofs::sector::SectorId;

use crate::responses::{
    self, err_code_and_msg, FCPResponseStatus, FFIPieceMetadata, FFISealStatus,
    FFISealedSectorHealth,
};
use storage_proofs::rational_post::Challenge;

#[repr(C)]
pub struct FFISectorClass {
    sector_size: u64,
    porep_proof_partitions: u8,
}

pub type SectorBuilder = sector_builder::SectorBuilder<FileDescriptorRef>;

/// Filedescriptor, that does not drop the file descriptor when dropped.
pub struct FileDescriptorRef(nodrop::NoDrop<std::fs::File>);

impl FileDescriptorRef {
    #[cfg(not(target_os = "windows"))]
    pub unsafe fn new(raw: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        FileDescriptorRef(nodrop::NoDrop::new(std::fs::File::from_raw_fd(raw)))
    }
}

impl std::io::Read for FileDescriptorRef {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// Writes user piece-bytes to a staged sector and returns the id of the sector
/// to which the bytes were written.
/// The caller is responsible for closing the file descriptor.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_add_piece(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
    piece_fd_raw: libc::c_int,
    piece_bytes_amount: u64,
    store_until_utc_secs: u64,
) -> *mut responses::AddPieceResponse {
    init_log();

    let piece_key = c_str_to_rust_str(piece_key);
    let piece_fd = FileDescriptorRef::new(piece_fd_raw);

    let mut response: responses::AddPieceResponse = Default::default();

    match (*ptr).add_piece(
        String::from(piece_key),
        piece_fd,
        piece_bytes_amount,
        SecondsSinceEpoch(store_until_utc_secs),
    ) {
        Ok(sector_id) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_id = u64::from(sector_id);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Returns the number of user bytes (before bit-padding has been added) which
/// will fit into a sector of the given size.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_max_user_bytes_per_staged_sector(
    sector_size: u64,
) -> u64 {
    init_log();

    filecoin_proofs_ffi::api::get_max_user_bytes_per_staged_sector(sector_size)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_verify_piece_inclusion_proof(
    comm_d: &[u8; 32],
    comm_p: &[u8; 32],
    piece_inclusion_proof_ptr: *const u8,
    piece_inclusion_proof_len: libc::size_t,
    padded_piece_size: u64,
    sector_size: u64,
) -> *mut filecoin_proofs_ffi::responses::VerifyPieceInclusionProofResponse {
    init_log();

    filecoin_proofs_ffi::api::verify_piece_inclusion_proof(
        comm_d,
        comm_p,
        piece_inclusion_proof_ptr,
        piece_inclusion_proof_len,
        padded_piece_size,
        sector_size,
    )
}

/// Returns the merkle root for a piece after piece padding and alignment.
/// The caller is responsible for closing the file descriptor.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_generate_piece_commitment(
    piece_fd_raw: libc::c_int,
    unpadded_piece_size: u64,
) -> *mut filecoin_proofs_ffi::responses::GeneratePieceCommitmentResponse {
    init_log();

    filecoin_proofs_ffi::api::generate_piece_commitment(piece_fd_raw, unpadded_piece_size)
}

/// Returns sector sealing status for the provided sector id if it exists. If
/// we don't know about the provided sector id, produce an error.
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_seal_status(
    ptr: *mut SectorBuilder,
    sector_id: u64,
) -> *mut responses::GetSealStatusResponse {
    init_log();

    let mut response: responses::GetSealStatusResponse = Default::default();

    match (*ptr).get_seal_status(SectorId::from(sector_id)) {
        Ok(seal_status) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            match seal_status {
                SealStatus::Sealed(meta) => {
                    let meta = *meta;

                    let pieces = meta
                        .pieces
                        .iter()
                        .map(into_ffi_piece_metadata)
                        .collect::<Vec<FFIPieceMetadata>>();

                    response.comm_d = meta.comm_d;
                    response.comm_r = meta.comm_r;
                    response.comm_r_star = meta.comm_r_star;
                    response.pieces_len = pieces.len();
                    response.pieces_ptr = pieces.as_ptr();
                    response.proof_len = meta.proof.len();
                    response.proof_ptr = meta.proof.as_ptr();
                    response.seal_status_code = FFISealStatus::Sealed;
                    response.sector_access = rust_str_to_c_str(meta.sector_access);
                    response.sector_id = u64::from(meta.sector_id);

                    mem::forget(meta.proof);
                    mem::forget(pieces);
                }
                SealStatus::Sealing => {
                    response.seal_status_code = FFISealStatus::Sealing;
                }
                SealStatus::Pending => {
                    response.seal_status_code = FFISealStatus::Pending;
                }
                SealStatus::Failed(err) => {
                    response.seal_status_code = FFISealStatus::Failed;
                    response.seal_error_msg = rust_str_to_c_str(err);
                }
            }
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_sealed_sectors(
    ptr: *mut SectorBuilder,
    check_health: bool,
) -> *mut responses::GetSealedSectorsResponse {
    init_log();
    let mut response: responses::GetSealedSectorsResponse = Default::default();

    match (*ptr).get_sealed_sectors(check_health) {
        Ok(sealed_sectors) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let sectors = sealed_sectors
                .iter()
                .map(|wrapped_meta| {
                    let (ffi_health, meta) = match wrapped_meta {
                        GetSealedSectorResult::WithHealth(h, m) => ((*h).into(), m),
                        GetSealedSectorResult::WithoutHealth(m) => {
                            (FFISealedSectorHealth::Unknown, m)
                        }
                    };

                    let pieces = meta
                        .pieces
                        .iter()
                        .map(into_ffi_piece_metadata)
                        .collect::<Vec<FFIPieceMetadata>>();

                    let snark_proof = meta.proof.clone();

                    let sector = responses::FFISealedSectorMetadata {
                        comm_d: meta.comm_d,
                        comm_r: meta.comm_r,
                        comm_r_star: meta.comm_r_star,
                        pieces_len: pieces.len(),
                        pieces_ptr: pieces.as_ptr(),
                        proofs_len: snark_proof.len(),
                        proofs_ptr: snark_proof.as_ptr(),
                        sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                        sector_id: u64::from(meta.sector_id),
                        health: ffi_health,
                    };

                    mem::forget(snark_proof);
                    mem::forget(pieces);

                    sector
                })
                .collect::<Vec<responses::FFISealedSectorMetadata>>();

            response.sectors_len = sectors.len();
            response.sectors_ptr = sectors.as_ptr();

            mem::forget(sectors);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_staged_sectors(
    ptr: *mut SectorBuilder,
) -> *mut responses::GetStagedSectorsResponse {
    init_log();
    let mut response: responses::GetStagedSectorsResponse = Default::default();

    match (*ptr).get_staged_sectors() {
        Ok(staged_sectors) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let sectors = staged_sectors
                .iter()
                .map(|meta| {
                    let pieces = meta
                        .pieces
                        .iter()
                        .map(into_ffi_piece_metadata)
                        .collect::<Vec<FFIPieceMetadata>>();

                    let mut sector = responses::FFIStagedSectorMetadata {
                        sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                        sector_id: u64::from(meta.sector_id),
                        pieces_len: pieces.len(),
                        pieces_ptr: pieces.as_ptr(),
                        seal_status_code: FFISealStatus::Pending,
                        seal_error_msg: ptr::null(),
                    };

                    match meta.seal_status {
                        SealStatus::Failed(ref s) => {
                            sector.seal_status_code = FFISealStatus::Failed;
                            sector.seal_error_msg = rust_str_to_c_str(s.clone());
                        }
                        SealStatus::Sealing => {
                            sector.seal_status_code = FFISealStatus::Sealing;
                        }
                        SealStatus::Pending => {
                            sector.seal_status_code = FFISealStatus::Pending;
                        }
                        SealStatus::Sealed(_) => {
                            sector.seal_status_code = FFISealStatus::Sealed;
                        }
                    };

                    mem::forget(pieces);

                    sector
                })
                .collect::<Vec<responses::FFIStagedSectorMetadata>>();

            response.sectors_len = sectors.len();
            response.sectors_ptr = sectors.as_ptr();

            mem::forget(sectors);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Generates a proof-of-spacetime for the given replica commitments.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_generate_post(
    ptr: *mut SectorBuilder,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
    faults_ptr: *const u64,
    faults_len: libc::size_t,
) -> *mut responses::GeneratePoStResponse {
    init_log();

    info!("generate_post: {}", "start");

    let comm_rs = into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len);
    let faults = from_raw_parts(faults_ptr, faults_len)
        .iter()
        .map(|x| SectorId::from(*x))
        .collect();

    let result = (*ptr).generate_post(&comm_rs, challenge_seed, faults);

    let mut response = responses::GeneratePoStResponse::default();

    match result {
        Ok(proof) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            response.proof_len = proof.len();
            response.proof_ptr = proof.as_ptr();

            // we'll free this stuff when we free the GeneratePoSTResponse
            mem::forget(proof);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    info!("generate_post: {}", "finish");

    raw_ptr(response)
}

/// Initializes and returns a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_init_sector_builder(
    sector_class: FFISectorClass,
    last_used_sector_id: u64,
    metadata_dir: *const libc::c_char,
    prover_id: &[u8; 31],
    sealed_sector_dir: *const libc::c_char,
    staged_sector_dir: *const libc::c_char,
    max_num_staged_sectors: u8,
) -> *mut responses::InitSectorBuilderResponse {
    init_log();

    let result = SectorBuilder::init_from_metadata(
        from_ffi_sector_class(sector_class),
        SectorId::from(last_used_sector_id),
        c_str_to_rust_str(metadata_dir).to_string(),
        *prover_id,
        c_str_to_rust_str(sealed_sector_dir).to_string(),
        c_str_to_rust_str(staged_sector_dir).to_string(),
        max_num_staged_sectors,
    );

    let mut response = responses::InitSectorBuilderResponse::default();

    match result {
        Ok(sb) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_builder = raw_ptr(sb);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Unseals and returns the bytes associated with the provided piece key.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_read_piece_from_sealed_sector(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
) -> *mut responses::ReadPieceFromSealedSectorResponse {
    init_log();

    let mut response: responses::ReadPieceFromSealedSectorResponse = Default::default();

    let piece_key = c_str_to_rust_str(piece_key);

    match (*ptr).read_piece_from_sealed_sector(String::from(piece_key)) {
        Ok(piece_bytes) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.data_ptr = piece_bytes.as_ptr();
            response.data_len = piece_bytes.len();
            mem::forget(piece_bytes);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// For demo purposes. Seals all staged sectors.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_seal_all_staged_sectors(
    ptr: *mut SectorBuilder,
) -> *mut responses::SealAllStagedSectorsResponse {
    init_log();

    let mut response: responses::SealAllStagedSectorsResponse = Default::default();

    match (*ptr).seal_all_staged_sectors() {
        Ok(_) => {
            response.status_code = FCPResponseStatus::FCPNoError;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_verify_seal(
    sector_size: u64,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    comm_r_star: &[u8; 32],
    prover_id: &[u8; 31],
    sector_id: u64,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::responses::VerifySealResponse {
    init_log();

    filecoin_proofs_ffi::api::verify_seal(
        sector_size,
        comm_r,
        comm_d,
        comm_r_star,
        prover_id,
        sector_id,
        proof_ptr,
        proof_len,
    )
}

/// Verifies that a proof-of-spacetime is valid.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_verify_post(
    sector_size: u64,
    challenge_seed: &[u8; 32],
    sector_ids_ptr: *const u64,
    sector_ids_len: libc::size_t,
    faulty_sector_ids_ptr: *const u64,
    faulty_sector_ids_len: libc::size_t,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut filecoin_proofs_ffi::responses::VerifyPoStResponse {
    init_log();

    filecoin_proofs_ffi::api::verify_post(
        sector_size,
        challenge_seed,
        sector_ids_ptr,
        sector_ids_len,
        faulty_sector_ids_ptr,
        faulty_sector_ids_len,
        flattened_comm_rs_ptr,
        flattened_comm_rs_len,
        proof_ptr,
        proof_len,
    )
}

pub type SimpleSectorBuilder = sector_builder::SimpleSectorBuilder;

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_init_simple_sector_builder(
    sector_class: FFISectorClass,
    sealed_sector_dir: *const libc::c_char,
    staged_sector_dir: *const libc::c_char,
    max_num_staged_sectors: u8,
) -> *mut responses::InitSimpleSectorBuilderResponse {
    init_log();

    let result = SimpleSectorBuilder::new(
        from_ffi_sector_class(sector_class),
        c_str_to_rust_str(sealed_sector_dir).to_string(),
        c_str_to_rust_str(staged_sector_dir).to_string(),
        max_num_staged_sectors,
    );

    let mut response = responses::InitSimpleSectorBuilderResponse::default();

    match result {
        Ok(sb) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_builder = raw_ptr(sb);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_init_simple_sector_builder_response(
    ptr: *mut responses::InitSimpleSectorBuilderResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_simple_sector_builder(ptr: *mut SimpleSectorBuilder) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_add_piece_first(
    ptr: *mut SimpleSectorBuilder,
    miner: *const libc::c_char,
    sectors_ptr: *const responses::FFIPendingStagedSectorMetadata,
    sectors_len: libc::size_t,
    piece_bytes_amount: u64,
    new_sector_id: u64,
) -> *mut responses::AddPieceResponse {
    init_log();

    let mut response: responses::AddPieceResponse = Default::default();

    let sectors: Vec<&responses::FFIPendingStagedSectorMetadata> = from_raw_parts(sectors_ptr, sectors_len).iter().collect();
    let mut staged_sectors: HashMap<SectorId, StagedSectorMetadata> = HashMap::new();
    for s in sectors {
        staged_sectors.insert(s.sector_id.into(), into_staged_sector_metadata(s));
    }

    match (*ptr).add_piece_first(
        c_str_to_rust_str(miner).into(),
        staged_sectors,
        piece_bytes_amount,
        new_sector_id.into(),
    ) {
        Ok(sector_id) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_id = u64::from(sector_id);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

////////////////////////////////////////////////////////////////////////////////
// DESTRUCTORS
//////////////

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_add_piece_response(
    ptr: *mut responses::AddPieceResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_add_piece_second(
    ptr: *mut SimpleSectorBuilder,
    miner: *const libc::c_char,
    sector_ptr: *const responses::FFIPendingStagedSectorMetadata,
    piece_key: *const libc::c_char,
    piece_fd_raw: libc::c_int,
    piece_bytes_amount: u64,
) -> *mut responses::AddPieceSecondResponse {
    init_log();

    let sector = into_staged_sector_metadata(sector_ptr);

    let mut response: responses::AddPieceSecondResponse = Default::default();

    match (*ptr).add_piece_second(
        c_str_to_rust_str(miner).into(),
        sector,
        c_str_to_rust_str(piece_key).into(),
        FileDescriptorRef::new(piece_fd_raw),
        piece_bytes_amount,
    ) {
        Ok(meta) => {
            let pieces = meta
                .pieces
                .iter()
                .map(into_ffi_piece_metadata)
                .collect::<Vec<FFIPieceMetadata>>();

            let sector = responses::FFIPendingStagedSectorMetadata {
                sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                sector_id: u64::from(meta.sector_id),
                pieces_len: pieces.len(),
                pieces_ptr: pieces.as_ptr(),
            };
            mem::forget(pieces);

            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_ptr = raw_ptr(sector);
            response.sector_len = 1;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_add_piece_second_response(
    ptr: *mut responses::AddPieceSecondResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_read_piece_from_specified_sealed_sector(
    ptr: *mut SimpleSectorBuilder,
    miner: *const libc::c_char,
    sector_ptr: *const responses::FFISealedSectorMetadata,
    piece_key: *const libc::c_char,
    prover_id: &[u8; 31],
) -> *mut responses::ReadPieceFromSealedSectorResponse {
    init_log();

    let mut response: responses::ReadPieceFromSealedSectorResponse = Default::default();

    let sector = into_sealed_sector_metadata(sector_ptr);

    match (*ptr).read_piece_from_sealed_sector(
        c_str_to_rust_str(miner).into(),
        &sector,
        c_str_to_rust_str(piece_key).into(),
        *prover_id,
    ) {
        Ok(piece_bytes) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.data_ptr = piece_bytes.as_ptr();
            response.data_len = piece_bytes.len();
            mem::forget(piece_bytes);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_read_piece_from_specified_sealed_sector_response(
    ptr: *mut responses::ReadPieceFromSealedSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_seal_staged_sector(
    ptr: *mut SimpleSectorBuilder,
    miner: *const libc::c_char,
    sector_ptr: *const responses::FFIPendingStagedSectorMetadata,
    prover_id: &[u8; 31],
) -> *mut responses::SealStagedSectorResponse {
    init_log();

    let mut response: responses::SealStagedSectorResponse = Default::default();

    match (*ptr).seal_staged_sector(
        c_str_to_rust_str(miner).into(),
        &mut into_staged_sector_metadata(sector_ptr),
        *prover_id,
    ) {
        Ok(meta) => {
            let pieces = meta
                .pieces
                .iter()
                .map(into_ffi_piece_metadata)
                .collect::<Vec<FFIPieceMetadata>>();

            let snark_proof = meta.proof.clone();

            let sector = responses::FFISealedSectorMetadata {
                comm_d: meta.comm_d,
                comm_r: meta.comm_r,
                comm_r_star: meta.comm_r_star,
                pieces_len: pieces.len(),
                pieces_ptr: pieces.as_ptr(),
                proofs_len: snark_proof.len(),
                proofs_ptr: snark_proof.as_ptr(),
                sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                sector_id: u64::from(meta.sector_id),
                health: FFISealedSectorHealth::Unknown, // not used
            };

            mem::forget(snark_proof);
            mem::forget(pieces);

            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_ptr = raw_ptr(sector);
            response.sector_len = 1;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_seal_staged_sector_response(
    ptr: *mut responses::SealStagedSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_generate_post_first(
    ptr: *mut SimpleSectorBuilder,
    challenge_seed: &[u8; 32],
    faults_ptr: *const u64,
    faults_len: libc::size_t,
    sectors_ptr: *const responses::FFISealedSectorMetadata,
    sectors_len: libc::size_t,
) -> *mut responses::GeneratePoStFirstResponse {
    init_log();

    info!("generate_post_first: {}", "start");

    let faults = from_raw_parts(faults_ptr, faults_len)
        .iter()
        .map(|x| SectorId::from(*x))
        .collect();

    let sectors: Vec<&responses::FFISealedSectorMetadata> = from_raw_parts(sectors_ptr, sectors_len).iter().collect();
    let mut sealed_sectors: HashMap<SectorId, SealedSectorMetadata> = HashMap::new();
    for s in sectors {
        let meta = into_sealed_sector_metadata(s);
        sealed_sectors.insert(meta.sector_id, meta);
    }

    let result = (*ptr).generate_post_first(
        challenge_seed,
        faults,
        &sealed_sectors,
    );

    let mut response = responses::GeneratePoStFirstResponse::default();

    match result {
        Ok(challenges) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let ffi_challenges: Vec<responses::FFIChallenge> = challenges.iter().map(|c| responses::FFIChallenge {
                sector: c.sector.into(),
                leaf: c.leaf,
            }
            ).collect();

            response.challenges_ptr = ffi_challenges.as_ptr();
            response.challenges_len = ffi_challenges.len();

            mem::forget(ffi_challenges);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    info!("generate_post_first: {}", "finish");

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_generate_post_first_response(
    ptr: *mut responses::GeneratePoStFirstResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_generate_post_second(
    ptr: *mut SimpleSectorBuilder,
    miner: *const libc::c_char,
    challenges_ptr: *const responses::FFIChallenge,
    challenges_len: libc::size_t,
    faults_ptr: *const u64,
    faults_len: libc::size_t,
    sectors_ptr: *const responses::FFISealedSectorMetadata,
    sectors_len: libc::size_t,
) -> *mut responses::GeneratePoStResponse {
    init_log();

    info!("generate_post_second: {}", "start");

    let faults = from_raw_parts(faults_ptr, faults_len)
        .iter()
        .map(|x| SectorId::from(*x))
        .collect();

    let challenges = from_raw_parts(challenges_ptr, challenges_len);

    let sectors: Vec<&responses::FFISealedSectorMetadata> = from_raw_parts(sectors_ptr, sectors_len).iter().collect();
    let mut sealed_sectors: HashMap<SectorId, SealedSectorMetadata> = HashMap::new();
    for s in sectors {
        let meta = into_sealed_sector_metadata(s);
        sealed_sectors.insert(meta.sector_id, meta);
    }

    let result = (*ptr).generate_post_second(
        c_str_to_rust_str(miner).into(),
        &challenges.iter().map(|c| Challenge {
            sector: c.sector.into(),
            leaf: c.leaf,
        }).collect(),
        faults,
        &sealed_sectors,
    );

    let mut response = responses::GeneratePoStResponse::default();

    match result {
        Ok(proof) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            response.proof_len = proof.len();
            response.proof_ptr = proof.as_ptr();

            // we'll free this stuff when we free the GeneratePoSTResponse
            mem::forget(proof);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    info!("generate_post_second: {}", "finish");

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_generate_post_second_response(
    ptr: *mut responses::GeneratePoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_get_sectors_ready_for_sealing(
    ptr: *mut SimpleSectorBuilder,
    sectors_ptr: *const responses::FFIPendingStagedSectorMetadata,
    sectors_len: libc::size_t,
    seal_all_staged_sectors: bool,
) -> *mut responses::GetSectorsReadyForSealingResponse {
    init_log();

    let mut response: responses::GetSectorsReadyForSealingResponse = Default::default();

    let sectors: Vec<&responses::FFIPendingStagedSectorMetadata> = from_raw_parts(sectors_ptr, sectors_len).iter().collect();
    let mut staged_sectors: HashMap<SectorId, StagedSectorMetadata> = HashMap::new();
    for s in sectors {
        staged_sectors.insert(s.sector_id.into(), into_staged_sector_metadata(s));
    }

    let sector_ids: Vec<u64> = (*ptr).get_sectors_ready_for_sealing(
        staged_sectors,
        seal_all_staged_sectors,
    ).iter().map(|s| u64::from(*s)).collect();
    response.status_code = FCPResponseStatus::FCPNoError;
    response.sector_ids_ptr = sector_ids.as_ptr();
    response.sector_ids_len = sector_ids.len();
    mem::forget(sector_ids);

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_sectors_ready_for_sealing_response(
    ptr: *mut responses::GetSectorsReadyForSealingResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn into_staged_sector_metadata(
    sector_ptr: *const responses::FFIPendingStagedSectorMetadata,
) -> StagedSectorMetadata {
    let pieces: Vec<&FFIPieceMetadata> = from_raw_parts((*sector_ptr).pieces_ptr, (*sector_ptr).pieces_len).iter().collect();
    StagedSectorMetadata {
        sector_id: (*sector_ptr).sector_id.into(),
        sector_access: c_str_to_rust_str((*sector_ptr).sector_access).into(),
        pieces: pieces.iter().map(|p| PieceMetadata {
            piece_key: String::from(c_str_to_rust_str(p.piece_key)),
            num_bytes: UnpaddedBytesAmount(p.num_bytes),
            comm_p: Some(p.comm_p),
            piece_inclusion_proof: Some(from_raw_parts(p.piece_inclusion_proof_ptr, p.piece_inclusion_proof_len).to_vec()),
        }).collect(),
        seal_status: SealStatus::Pending,
    }
}

#[no_mangle]
pub unsafe extern "C" fn into_sealed_sector_metadata(
    sector_ptr: *const responses::FFISealedSectorMetadata,
) -> SealedSectorMetadata {
    let pieces: Vec<&FFIPieceMetadata> = from_raw_parts((*sector_ptr).pieces_ptr, (*sector_ptr).pieces_len).iter().collect();
    SealedSectorMetadata {
        sector_id: (*sector_ptr).sector_id.into(),
        sector_access: c_str_to_rust_str((*sector_ptr).sector_access).into(),
        pieces: pieces.iter().map(|p| PieceMetadata {
            piece_key: String::from(c_str_to_rust_str(p.piece_key)),
            num_bytes: UnpaddedBytesAmount(p.num_bytes),
            comm_p: Some(p.comm_p),
            piece_inclusion_proof: Some(from_raw_parts(p.piece_inclusion_proof_ptr, p.piece_inclusion_proof_len).to_vec()),
        }).collect(),
        // The following fields are unused.
        comm_r_star: (*sector_ptr).comm_r_star,
        comm_r: (*sector_ptr).comm_r,
        comm_d: (*sector_ptr).comm_d,
        proof: from_raw_parts((*sector_ptr).proofs_ptr, (*sector_ptr).proofs_len).to_vec(),
        blake2b_checksum: Default::default(), // unset
        len: 0, // unset
    }
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_generate_post_response(
    ptr: *mut responses::GeneratePoStResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_seal_status_response(
    ptr: *mut responses::GetSealStatusResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_sealed_sectors_response(
    ptr: *mut responses::GetSealedSectorsResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_get_staged_sectors_response(
    ptr: *mut responses::GetStagedSectorsResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_init_sector_builder_response(
    ptr: *mut responses::InitSectorBuilderResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_read_piece_from_sealed_sector_response(
    ptr: *mut responses::ReadPieceFromSealedSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_seal_all_staged_sectors_response(
    ptr: *mut responses::SealAllStagedSectorsResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// Deallocates a VerifySealResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_verify_seal_response(
    ptr: *mut filecoin_proofs_ffi::responses::VerifySealResponse,
) {
    filecoin_proofs_ffi::api::destroy_verify_seal_response(ptr)
}

/// Deallocates a VerifyPoStResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_verify_post_response(
    ptr: *mut filecoin_proofs_ffi::responses::VerifyPoStResponse,
) {
    filecoin_proofs_ffi::api::destroy_verify_post_response(ptr)
}

/// Deallocates a VerifyPieceInclusionProofResponse.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_verify_piece_inclusion_proof_response(
    ptr: *mut filecoin_proofs_ffi::responses::VerifyPieceInclusionProofResponse,
) {
    filecoin_proofs_ffi::api::destroy_verify_piece_inclusion_proof_response(ptr)
}

/// Deallocates a GeneratePieceCommitmentResponse.
///
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn sector_builder_ffi_destroy_generate_piece_commitment_response(
    ptr: *mut filecoin_proofs_ffi::responses::GeneratePieceCommitmentResponse,
) {
    filecoin_proofs_ffi::api::destroy_generate_piece_commitment_response(ptr)
}

/// Destroys a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn sector_builder_ffi_destroy_sector_builder(ptr: *mut SectorBuilder) {
    let _ = Box::from_raw(ptr);
}

////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
///////////////////

unsafe fn into_commitments(
    flattened_comms_ptr: *const u8,
    flattened_comms_len: libc::size_t,
) -> Vec<[u8; 32]> {
    from_raw_parts(flattened_comms_ptr, flattened_comms_len)
        .iter()
        .step_by(32)
        .fold(Default::default(), |mut acc: Vec<[u8; 32]>, item| {
            let sliced = from_raw_parts(item, 32);
            let mut x: [u8; 32] = Default::default();
            x.copy_from_slice(&sliced[..32]);
            acc.push(x);
            acc
        })
}

pub fn from_ffi_sector_class(fsc: FFISectorClass) -> filecoin_proofs::SectorClass {
    match fsc {
        FFISectorClass {
            sector_size,
            porep_proof_partitions,
        } => filecoin_proofs::SectorClass(
            filecoin_proofs::SectorSize(sector_size),
            filecoin_proofs::PoRepProofPartitions(porep_proof_partitions),
        ),
    }
}

fn into_ffi_piece_metadata(piece_metadata: &PieceMetadata) -> FFIPieceMetadata {
    let (len, ptr) = match &piece_metadata.piece_inclusion_proof {
        Some(proof) => {
            let buf = proof.clone();

            let len = buf.len();
            let ptr = buf.as_ptr();

            mem::forget(buf);

            (len, ptr)
        }
        None => (0, ptr::null()),
    };

    FFIPieceMetadata {
        piece_key: rust_str_to_c_str(piece_metadata.piece_key.to_string()),
        num_bytes: piece_metadata.num_bytes.into(),
        comm_p: piece_metadata.comm_p.unwrap_or([0; 32]),
        piece_inclusion_proof_len: len,
        piece_inclusion_proof_ptr: ptr,
    }
}

/// Protects the init off the logger.
static LOG_INIT: OnceCell<bool> = OnceCell::new();

/// Ensures the logger is initialized.
fn init_log() {
    LOG_INIT.get_or_init(|| {
        let _ = pretty_env_logger::try_init_timed();
        true
    });
}
