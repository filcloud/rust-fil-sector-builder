#![deny(clippy::all, clippy::perf, clippy::correctness)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

pub use filecoin_proofs::types::*;

pub use crate::builder::*;
pub use crate::constants::*;
pub use crate::error::*;
// Exported for benchmarks
pub use crate::helpers::checksum::calculate_checksum;
pub use crate::metadata::*;
pub use crate::metadata_manager::*;
pub use crate::store::*;
pub use crate::simple_builder::*;

mod builder;
mod constants;
mod disk_backed_storage;
mod error;
mod helpers;
mod kv_store;
mod metadata;
mod metadata_manager;
mod scheduler;
mod state;
mod store;
mod worker;

mod simple_builder;
