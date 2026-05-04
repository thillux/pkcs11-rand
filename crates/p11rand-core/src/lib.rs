//! Core entropy backends and pool layer for mini-pkcs11-rand.
//!
//! The crate exposes two source backends — `iso7816` (PC/SC GET CHALLENGE) and
//! `infnoise` (`/dev/infnoiseN`) — plus a [`pool::Pool`] that combines N+M live
//! sources per output round via a SHA3-256 chain (or raw passthrough when the
//! pool holds exactly one source running at the 32-byte default).

pub mod debug;
pub mod infnoise;
pub mod iso7816;
pub mod pool;
