//! A Rust implementation of [CGGMP20](https://eprint.iacr.org/2021/060.pdf) with augmentations as described by the [Wamu protocol](https://wamu.tech/specification) for building threshold signature wallets controlled by multiple decentralized identities.

pub use self::{
    errors::Error, key_refresh::AugmentedKeyRefresh, keygen::AugmentedKeyGen,
    sign::AugmentedPreSigning, sign::AugmentedSigning,
};

#[macro_use]
pub mod asm;
mod errors;
mod key_refresh;
mod keygen;
mod sign;
