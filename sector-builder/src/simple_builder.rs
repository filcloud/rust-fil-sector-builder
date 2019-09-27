use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet, BTreeMap};

use filecoin_proofs::{SectorClass, UnpaddedBytesAmount, SealOutput, PrivateReplicaInfo};
use filecoin_proofs::pieces::get_piece_start_byte;
use storage_proofs::sector::SectorId;
use storage_proofs::rational_post;

use crate::builder::*;
use crate::error::{Result, err_unrecov, err_piecenotfound};
use crate::{StagedSectorMetadata, SimpleSectorStore, SealedSectorMetadata, SealStatus, PieceMetadata, SealTicket};
use crate::helpers;
use crate::state::StagedState;
use crate::worker::{UnsealTaskPrototype, SealTaskPrototype};
use crate::disk_backed_storage::{new_simple_sector_store, SimpleConcreteSectorStore};

pub struct SimpleSectorBuilder {
    pub sector_store: SimpleConcreteSectorStore,
    pub max_num_staged_sectors: u8,
}

impl SimpleSectorBuilder {
    pub fn new(
        sector_class: SectorClass,
        sealed_sector_dir: impl AsRef<Path>,
        staged_sector_dir: impl AsRef<Path>,
        max_num_staged_sectors: u8,
    ) -> Result<SimpleSectorBuilder> {
        ensure_parameter_cache_hydrated(sector_class)?;

        let sector_store = new_simple_sector_store(sector_class, sealed_sector_dir, staged_sector_dir);

        Ok(SimpleSectorBuilder {
            sector_store,
            max_num_staged_sectors,
        })
    }

    pub fn add_piece_first(
        &self,
        miner: String,
        staged_sectors: HashMap<SectorId, StagedSectorMetadata>,
        piece_bytes_amount: u64,
        new_sector_id: SectorId,
    ) -> Result<SectorId> {
        let mut staged = StagedState {
            sectors: staged_sectors,
        };

        helpers::add_piece_first(
            &self.sector_store,
            &miner,
            &mut staged,
            piece_bytes_amount,
            new_sector_id,
        )
    }

    pub fn add_piece_second(
        &self,
        miner: String,
        staged_sector: StagedSectorMetadata,
        piece_key: String,
        piece_file: impl std::io::Read,
        piece_bytes_amount: u64,
    ) -> Result<StagedSectorMetadata> {
        helpers::add_piece_second(
            &self.sector_store,
            &miner,
            staged_sector,
            piece_bytes_amount,
            piece_key,
            piece_file,
        )
    }

    pub fn read_piece_from_sealed_sector(
        &self,
        miner: String,
        sealed_sector: &SealedSectorMetadata,
        piece_key: String,
        prover_id: [u8; 32],
    ) -> Result<Vec<u8>> {
        let proto = self.create_retrieve_piece_task_proto(&miner, sealed_sector, piece_key)?;
        let result = filecoin_proofs::get_unsealed_range(
            proto.porep_config,
            &proto.source_path,
            &proto.destination_path,
            prover_id,
            proto.sector_id,
            proto.comm_d,
            proto.seal_ticket.ticket_bytes,
            proto.piece_start_byte,
            proto.piece_len,
        )
            .map(|num_bytes_unsealed| (num_bytes_unsealed, proto.destination_path));

        self.read_unsealed_bytes_from(&miner, result)
    }

    pub fn seal_staged_sector(
        &self,
        miner: String,
        staged_sector: &mut StagedSectorMetadata,
        prover_id: [u8; 32],
        seal_ticket: SealTicket,
    ) -> Result<SealedSectorMetadata> {
        let proto = self.create_seal_task_proto(&miner, staged_sector, seal_ticket.clone())?;

        let result = filecoin_proofs::seal(
            proto.porep_config,
            &proto.staged_sector_path,
            &proto.sealed_sector_path,
            prover_id,
            proto.sector_id,
            seal_ticket.ticket_bytes,
            &proto.piece_lens,
        );

        result
            .and_then(|output| {
                let SealOutput {
                    comm_r,
                    comm_d,
                    p_aux,
                    proof,
                    comm_ps,
                    piece_inclusion_proofs,
                } = output;

                // generate checksum
                let blake2b_checksum =
                    helpers::calculate_checksum(&proto.sealed_sector_path)?.as_ref().to_vec();

                // get number of bytes in sealed sector-file
                let len = std::fs::metadata(&proto.sealed_sector_path)?.len();

                // combine the piece commitment, piece inclusion proof, and other piece
                // metadata into a single struct (to be persisted to metadata store)
                let pieces = staged_sector
                    .clone()
                    .pieces
                    .into_iter()
                    .zip(comm_ps.iter())
                    .zip(piece_inclusion_proofs.into_iter())
                    .map(|((piece, &comm_p), piece_inclusion_proof)| PieceMetadata {
                        piece_key: piece.piece_key,
                        num_bytes: piece.num_bytes,
                        comm_p: Some(comm_p),
                        piece_inclusion_proof: Some(piece_inclusion_proof.into()),
                    })
                    .collect();

                let meta = SealedSectorMetadata {
                    sector_id: staged_sector.sector_id,
                    sector_access: proto.sealed_sector_access,
                    pieces,
                    p_aux,
                    comm_r,
                    comm_d,
                    proof,
                    blake2b_checksum,
                    len,
                    seal_ticket,
                };

                Ok(meta)
            })
            .map_err(|err| {
                err_unrecov(err).into()
            })
    }

    pub fn generate_post_first(
        &self,
        challenge_seed: &[u8; 32],
        faults: Vec<SectorId>,
        sealed_sectors: &HashMap<SectorId, SealedSectorMetadata>, // sealed sectors that have been committed
    ) -> Result<Vec<rational_post::Challenge>> {
        let sectors = sealed_sectors.iter().map(|(sector_id, _)| *sector_id).collect();
        let faults = faults.iter().map(|sector_id| *sector_id).collect();

        filecoin_proofs::generate_post_first(
            self.sector_store.proofs_config().post_config(),
            challenge_seed,
            sectors,
            faults,
        )
    }

    pub fn generate_post_second(
        &self,
        miner: String,
        challenges: &Vec<rational_post::Challenge>,
        faults: Vec<SectorId>,
        sealed_sectors: &HashMap<SectorId, SealedSectorMetadata>, // sealed sectors that have been committed
    ) -> Result<Vec<u8>> {
        let fault_set: HashSet<SectorId> = faults.clone().into_iter().collect();

        let mut replicas: BTreeMap<SectorId, PrivateReplicaInfo> = Default::default();

        for sector in sealed_sectors.values() {
            let path_str = self
                .sector_store
                .manager()
                .sealed_sector_path(&miner, &sector.sector_access)
                .to_str()
                .map(str::to_string)
                .unwrap();

            let info = if fault_set.contains(&sector.sector_id) {
                PrivateReplicaInfo::new_faulty(path_str, sector.comm_r, sector.p_aux.clone())
            } else {
                PrivateReplicaInfo::new(path_str, sector.comm_r, sector.p_aux.clone())
            };

            replicas.insert(sector.sector_id, info);
        }

        filecoin_proofs::generate_post_second(
            self.sector_store.proofs_config().post_config(),
            challenges,
            &replicas,
            faults,
        )
    }

    pub fn get_sectors_ready_for_sealing(
        &self,
        staged_sectors: HashMap<SectorId, StagedSectorMetadata>,
        seal_all_staged_sectors: bool,
    ) -> Vec<SectorId> {
        let staged = StagedState {
            sectors: staged_sectors,
        };

        let max_user_bytes_per_staged_sector =
            self.sector_store.sector_config().max_unsealed_bytes_per_sector();

        helpers::get_sectors_ready_for_sealing(
            &staged,
            max_user_bytes_per_staged_sector,
            self.max_num_staged_sectors,
            seal_all_staged_sectors,
        )
    }

    fn create_retrieve_piece_task_proto(
        &self,
        miner: &str,
        sealed_sector: &SealedSectorMetadata,
        piece_key: String,
    ) -> Result<UnsealTaskPrototype> {
        let piece = sealed_sector
            .pieces
            .iter()
            .find(|p| p.piece_key == piece_key)
            .ok_or_else(|| err_piecenotfound(piece_key.clone()))?;

        let piece_lengths: Vec<_> = sealed_sector
            .pieces
            .iter()
            .take_while(|p| p.piece_key != piece_key)
            .map(|p| p.num_bytes)
            .collect();

        let staged_sector_access = self
            .sector_store
            .manager()
            .new_staging_sector_access(miner, sealed_sector.sector_id, true)
            .map_err(failure::Error::from)?;

        Ok(UnsealTaskPrototype {
            comm_d: sealed_sector.comm_d,
            porep_config: self.sector_store.proofs_config().porep_config(),
            source_path: self
                .sector_store
                .manager()
                .sealed_sector_path(miner, &sealed_sector.sector_access),
            destination_path: self
                .sector_store
                .manager()
                .staged_sector_path(miner, &staged_sector_access),
            sector_id: sealed_sector.sector_id,
            piece_start_byte: get_piece_start_byte(&piece_lengths, piece.num_bytes),
            piece_len: piece.num_bytes,
            seal_ticket: sealed_sector.seal_ticket.clone(),
        })
    }

    fn read_unsealed_bytes_from(
        &self,
        miner: &str,
        result: Result<(UnpaddedBytesAmount, PathBuf)>,
    ) -> Result<Vec<u8>> {
        result.and_then(|(n, pbuf)| {
            let buffer = self.sector_store.manager().read_raw(
                miner,
                pbuf.to_str()
                    .ok_or_else(|| format_err!("conversion failed"))?,
                0,
                n,
            )?;

            Ok(buffer)
        })
    }

    fn create_seal_task_proto(
        &self,
        miner: &str,
        staged_sector: &mut StagedSectorMetadata,
        seal_ticket: SealTicket,
    ) -> Result<SealTaskPrototype> {
        let sealed_sector_access = self
            .sector_store
            .manager()
            .new_sealed_sector_access(miner, staged_sector.sector_id)
            .map_err(failure::Error::from)?;

        let sealed_sector_path = self
            .sector_store
            .manager()
            .sealed_sector_path(miner, &sealed_sector_access);

        let staged_sector_path = self
            .sector_store
            .manager()
            .staged_sector_path(miner, &staged_sector.sector_access);

        let piece_lens = staged_sector
            .pieces
            .iter()
            .map(|p| p.num_bytes)
            .collect::<Vec<UnpaddedBytesAmount>>();

        // mutate staged sector state such that we don't try to write any
        // more pieces to it
        staged_sector.seal_status = SealStatus::Sealing(seal_ticket.clone());

        Ok(SealTaskPrototype {
            piece_lens,
            porep_config: self.sector_store.proofs_config().porep_config(),
            seal_ticket,
            sealed_sector_access,
            sealed_sector_path,
            sector_id: staged_sector.sector_id,
            staged_sector_path,
        })
    }
}
