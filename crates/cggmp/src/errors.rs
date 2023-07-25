//! Types and abstractions for protocol errors.

use round_based::{IsCritical, StateMachine};

/// A protocol error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<T: IsCritical> {
    /// A wrapped error from `wamu-core`.
    Core(wamu_core::Error),
    /// A wrapped state machine error from `cggmp_threshold_ecdsa`.
    StateMachine(T),
    /// Missing augmentation parameters.
    MissingParams { bad_actors: Vec<usize> },
    /// An insecure FS-DKR threshold (i.e t > n/2, breaking the honest majority assumption).
    BadFSDKRThreshold,
}

impl<T: IsCritical> IsCritical for Error<T> {
    fn is_critical(&self) -> bool {
        match self {
            // All core errors are critical.
            Error::Core(_) => true,
            // Wrapped state machine errors call the wrapped implementation.
            Error::StateMachine(error) => error.is_critical(),
            // Augmentation parameters can't be skipped.
            Error::MissingParams { .. } => true,
            // FS-DKR assumptions can't be broken for key refresh.
            Error::BadFSDKRThreshold => true,
        }
    }
}

impl<T: IsCritical> From<wamu_core::Error> for Error<T> {
    fn from(error: wamu_core::Error) -> Self {
        Self::Core(error)
    }
}

impl<T: IsCritical> From<wamu_core::CryptoError> for Error<T> {
    fn from(error: wamu_core::CryptoError) -> Self {
        Self::Core(wamu_core::Error::Crypto(error))
    }
}

/// Implements `From` trait for `StateMachine` associated error types.
macro_rules! from_state_machine_error {
    ($($module_path:path => ($module_alias:ident, $state_machine_type:ident)),*$(,)?) => {
        $(
        use $module_path as $module_alias;
        impl From<$module_alias::Error> for Error<<$module_alias::$state_machine_type as StateMachine>::Err> {
            fn from(error: $module_alias::Error) -> Self {
                Self::StateMachine(error)
            }
        }
        )*
    }
}

// Implements `From` trait for all upstream `StateMachine` associated error types from `cggmp-threshold-ecdsa` and `multi-party-ecdsa`.
from_state_machine_error! {
    cggmp_threshold_ecdsa::presign::state_machine => (presign_state_machine, PreSigning),
    cggmp_threshold_ecdsa::sign::state_machine => (sign_state_machine, Signing),
    cggmp_threshold_ecdsa::refresh::state_machine => (key_refresh_state_machine, KeyRefresh),
    multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen => (key_gen_state_machine, Keygen),
}
