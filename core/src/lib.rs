//! Cœur de KittyPass : coffre KDBX, dérivation des clés de compte, générateur.
//!
//! Tout le chiffrement et le déchiffrement se font ici, côté client. Le serveur
//! ne reçoit que des fichiers KDBX chiffrés et une `AuthKey` à sens unique.
#![deny(unsafe_code)]

pub mod account;
pub mod autotype;
#[cfg(windows)]
pub mod winsec;
pub mod ssh;
pub mod browser;
pub mod error;
pub mod header;
pub mod hibp;
pub mod keyfile;
pub mod otp;
pub mod passgen;
pub mod sync;
#[cfg(feature = "client")]
pub mod client;
mod rng;
pub mod vault;

pub use error::{Error, Result};
