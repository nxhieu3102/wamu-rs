//! Utilities for Wamu.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the unix timestamp in seconds.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
