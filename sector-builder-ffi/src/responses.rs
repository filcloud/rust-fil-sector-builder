use std::ffi::CString;
use std::mem;
use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use failure::Error;
use ffi_toolkit::free_c_str;
use libc;
use sector_builder::{SealedSectorHealth, SectorBuilderErr, SectorManagerErr};

use crate::api::{SectorBuilder, SimpleSectorBuilder};

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FFISealedSectorHealth {
    Unknown = 0,
    Ok = 1,
    ErrorInvalidChecksum = 2,
    ErrorInvalidLength = 3,
    ErrorMissing = 4,
}

impl From<SealedSectorHealth> for FFISealedSectorHealth {
    fn from(status: SealedSectorHealth) -> Self {
        match status {
            SealedSectorHealth::Ok => FFISealedSectorHealth::Ok,
            SealedSectorHealth::ErrorInvalidChecksum => FFISealedSectorHealth::ErrorInvalidChecksum,
            SealedSectorHealth::ErrorInvalidLength => FFISealedSectorHealth::ErrorInvalidLength,
            SealedSectorHealth::ErrorMissing => FFISealedSectorHealth::ErrorMissing,
        }
    }
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FCPResponseStatus {
    // Don't use FCPSuccess, since that complicates description of 'successful' verification.
    FCPNoError = 0,
    FCPUnclassifiedError = 1,
    FCPCallerError = 2,
    FCPReceiverError = 3,
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FFISealStatus {
    Sealed = 0,
    Pending = 1,
    Failed = 2,
    Sealing = 3,
}

///////////////////////////////////////////////////////////////////////////////
/// GeneratePoSTResult
//////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePoStResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub proof_len: libc::size_t,
    pub proof_ptr: *const u8,
}

impl Default for GeneratePoStResponse {
    fn default() -> GeneratePoStResponse {
        GeneratePoStResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            proof_len: 0,
            proof_ptr: ptr::null(),
        }
    }
}

// err_code_and_msg accepts an Error struct and produces a tuple of response
// status code and a pointer to a C string, both of which can be used to set
// fields in a response struct to be returned from an FFI call.
pub fn err_code_and_msg(err: &Error) -> (FCPResponseStatus, *const libc::c_char) {
    use crate::responses::FCPResponseStatus::*;

    let msg = CString::new(format!("{}", err)).unwrap();
    let ptr = msg.as_ptr();
    mem::forget(msg);

    match err.downcast_ref() {
        Some(SectorBuilderErr::OverflowError { .. }) => return (FCPCallerError, ptr),
        Some(SectorBuilderErr::IncompleteWriteError { .. }) => return (FCPReceiverError, ptr),
        Some(SectorBuilderErr::Unrecoverable(_, _)) => return (FCPReceiverError, ptr),
        Some(SectorBuilderErr::PieceNotFound(_)) => return (FCPCallerError, ptr),
        None => (),
    }

    match err.downcast_ref() {
        Some(SectorManagerErr::UnclassifiedError(_)) => return (FCPUnclassifiedError, ptr),
        Some(SectorManagerErr::CallerError(_)) => return (FCPCallerError, ptr),
        Some(SectorManagerErr::ReceiverError(_)) => return (FCPReceiverError, ptr),
        None => (),
    }

    (FCPUnclassifiedError, ptr)
}

///////////////////////////////////////////////////////////////////////////////
/// InitSectorBuilderResponse
/////////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct InitSectorBuilderResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_builder: *mut SectorBuilder,
}

impl Default for InitSectorBuilderResponse {
    fn default() -> InitSectorBuilderResponse {
        InitSectorBuilderResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_builder: ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct InitSimpleSectorBuilderResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_builder: *mut SimpleSectorBuilder,
}

impl Default for InitSimpleSectorBuilderResponse {
    fn default() -> InitSimpleSectorBuilderResponse {
        InitSimpleSectorBuilderResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_builder: ptr::null_mut(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// AddPieceResponse
////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct AddPieceResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_id: u64,
}

impl Default for AddPieceResponse {
    fn default() -> AddPieceResponse {
        AddPieceResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_id: 0,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct AddPieceFirstResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_id: u64,
}

impl Default for AddPieceFirstResponse {
    fn default() -> AddPieceFirstResponse {
        AddPieceFirstResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_id: 0,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct AddPieceSecondResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_ptr: *const FFIPendingStagedSectorMetadata,
    pub sector_len: libc::size_t,
}

impl Default for AddPieceSecondResponse {
    fn default() -> AddPieceSecondResponse {
        AddPieceSecondResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_ptr: ptr::null(),
            sector_len: 0,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIPendingStagedSectorMetadata {
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealStagedSectorResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_ptr: *const FFISealedSectorMetadata,
    pub sector_len: libc::size_t,
}

impl Default for SealStagedSectorResponse {
    fn default() -> SealStagedSectorResponse {
        SealStagedSectorResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_ptr: ptr::null(),
            sector_len: 0,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePoStFirstResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub challenges_ptr: *const FFIChallenge,
    pub challenges_len: libc::size_t,
}

impl Default for GeneratePoStFirstResponse {
    fn default() -> GeneratePoStFirstResponse {
        GeneratePoStFirstResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            challenges_ptr: ptr::null(),
            challenges_len: 0,
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIChallenge {
    pub sector: u64,
    pub leaf: u64,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetSectorsReadyForSealingResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sector_ids_ptr: *const u64,
    pub sector_ids_len: libc::size_t,
}

impl Default for GetSectorsReadyForSealingResponse {
    fn default() -> GetSectorsReadyForSealingResponse {
        GetSectorsReadyForSealingResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_ids_ptr: ptr::null(),
            sector_ids_len: 0,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
/// ReadPieceFromSealedSectorResponse
/////////////////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct ReadPieceFromSealedSectorResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub data_len: libc::size_t,
    pub data_ptr: *const u8,
}

impl Default for ReadPieceFromSealedSectorResponse {
    fn default() -> ReadPieceFromSealedSectorResponse {
        ReadPieceFromSealedSectorResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            data_len: 0,
            data_ptr: ptr::null(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// SealAllStagedSectorsResponse
////////////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealAllStagedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for SealAllStagedSectorsResponse {
    fn default() -> SealAllStagedSectorsResponse {
        SealAllStagedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// GetSealStatusResponse
/////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetSealStatusResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub seal_status_code: FFISealStatus,

    // sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,

    // sealed sector metadata
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_r_star: [u8; 32],
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub proof_len: libc::size_t,
    pub proof_ptr: *const u8,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIPieceMetadata {
    pub piece_key: *const libc::c_char,
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
    pub piece_inclusion_proof_ptr: *const u8,
    pub piece_inclusion_proof_len: libc::size_t,
}

impl Default for GetSealStatusResponse {
    fn default() -> GetSealStatusResponse {
        GetSealStatusResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            comm_d: Default::default(),
            comm_r: Default::default(),
            comm_r_star: Default::default(),
            pieces_len: 0,
            pieces_ptr: ptr::null(),
            proof_len: 0,
            proof_ptr: ptr::null(),
            seal_error_msg: ptr::null(),
            seal_status_code: FFISealStatus::Failed,
            sector_access: ptr::null(),
            sector_id: 0,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// FFIStagedSectorMetadata
///////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIStagedSectorMetadata {
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,

    // must be one of: Pending, Failed, Sealing
    pub seal_status_code: FFISealStatus,

    // if sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,
}

///////////////////////////////////////////////////////////////////////////////
/// FFISealedSectorMetadata
///////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFISealedSectorMetadata {
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_r_star: [u8; 32],
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
    pub proofs_len: libc::size_t,
    pub proofs_ptr: *const u8,
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub health: FFISealedSectorHealth,
}

///////////////////////////////////////////////////////////////////////////////
/// GetSealedSectorsResponse
////////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetSealedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sectors_len: libc::size_t,
    pub sectors_ptr: *const FFISealedSectorMetadata,
}

impl Default for GetSealedSectorsResponse {
    fn default() -> GetSealedSectorsResponse {
        GetSealedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sectors_len: 0,
            sectors_ptr: ptr::null(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// GetStagedSectorsResponse
////////////////////////////
#[repr(C)]
#[derive(DropStructMacro)]
pub struct GetStagedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sectors_len: libc::size_t,
    pub sectors_ptr: *const FFIStagedSectorMetadata,
}

impl Default for GetStagedSectorsResponse {
    fn default() -> GetStagedSectorsResponse {
        GetStagedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sectors_len: 0,
            sectors_ptr: ptr::null(),
        }
    }
}
