//! FFI bindings for nullifier PIR lookups.
//!
//! This module provides C-compatible FFI functions for performing
//! privacy-preserving nullifier lookups via PIR.

use std::ffi::{CStr, OsStr};
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::ptr;
use std::slice;

use anyhow::{anyhow, Context};
use ffi_helpers::panic::catch_panic;
use nullifier_common::{Nullifier, SpentInfo};
use nullifier_pir::BlockingNullifierPirClient;
use rand::rngs::OsRng;
use tracing::debug;
use zcash_client_backend::data_api::{NullifierQuery, WalletRead};
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_protocol::consensus::Network;

use crate::unwrap_exc_or_null;

// ============================================================================
// FFI Types
// ============================================================================

/// Information about a spent note (FFI-safe).
///
/// Returned when a nullifier is found in the PIR database.
#[repr(C)]
pub struct FfiSpentInfo {
    /// The block height where the nullifier was revealed.
    pub block_height: u32,
    /// The transaction index within the block.
    pub tx_index: u16,
    /// Padding for alignment (unused).
    pub _padding: u16,
}

impl From<SpentInfo> for FfiSpentInfo {
    fn from(info: SpentInfo) -> Self {
        Self {
            block_height: info.block_height,
            tx_index: info.tx_index,
            _padding: 0,
        }
    }
}

/// An array of SpentInfo results (FFI-safe).
///
/// Each element is either a pointer to FfiSpentInfo (if spent) or null (if unspent).
///
/// # Safety
///
/// - `items` must be non-null and valid for reads for `count * size_of::<*mut FfiSpentInfo>()`
/// - Each non-null item must point to a valid FfiSpentInfo
#[repr(C)]
pub struct FfiSpentInfoArray {
    /// Array of nullable pointers to SpentInfo
    pub items: *mut *mut FfiSpentInfo,
    /// Number of items in the array
    pub count: usize,
}

/// Opaque handle to a PIR client.
///
/// This wraps the Rust BlockingNullifierPirClient for FFI use.
pub struct PirClientHandle {
    client: BlockingNullifierPirClient,
}

// ============================================================================
// FFI Functions
// ============================================================================

/// Initialize PIR client and connect to server.
///
/// Returns opaque pointer to client state or null on error.
///
/// # Safety
///
/// - `server_url` must be a valid null-terminated UTF-8 string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_client_create(
    server_url: *const c_char,
) -> *mut PirClientHandle {
    let res = catch_panic(|| {
        if server_url.is_null() {
            return Err(anyhow!("server_url is null"));
        }

        let url_str = unsafe { CStr::from_ptr(server_url) }
            .to_str()
            .context("Invalid UTF-8 in server_url")?;

        debug!("Creating PIR client for server: {}", url_str);

        let client = BlockingNullifierPirClient::connect(url_str)
            .map_err(|e| anyhow!("Failed to connect to PIR server: {}", e))?;

        Ok(Box::into_raw(Box::new(PirClientHandle { client })))
    });

    unwrap_exc_or_null(res)
}

/// Precompute PIR keys (expensive operation).
///
/// Should be called once after client creation. This operation may take
/// several seconds (~5-20s depending on hardware).
///
/// Returns true on success, false on error.
///
/// # Safety
///
/// - `client` must be a valid pointer returned by `zcashlc_pir_client_create`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_precompute_keys(client: *mut PirClientHandle) -> bool {
    // Safety: We ensure PIR client state consistency by:
    // - Always checking for null before use
    // - Discarding the client if a panic occurs
    let client = AssertUnwindSafe(client);

    let res = catch_panic(|| {
        let client = *client;
        if client.is_null() {
            return Err(anyhow!("client is null"));
        }

        let handle = unsafe { &mut *client };
        handle
            .client
            .precompute_keys()
            .map_err(|e| anyhow!("Failed to precompute PIR keys: {}", e))?;

        Ok(true)
    });

    match res {
        Ok(v) => v,
        Err(_) => false,
    }
}

/// Check if keys have been precomputed.
///
/// Returns true if keys are ready for queries, false otherwise.
///
/// # Safety
///
/// - `client` must be a valid pointer returned by `zcashlc_pir_client_create`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_keys_ready(client: *const PirClientHandle) -> bool {
    if client.is_null() {
        return false;
    }

    let handle = unsafe { &*client };
    handle.client.keys_ready()
}

/// Check a single nullifier via PIR.
///
/// Returns pointer to SpentInfo if the nullifier is spent, null if unspent or on error.
/// Caller must free result with `zcashlc_pir_free_spent_info`.
///
/// # Safety
///
/// - `client` must be a valid pointer returned by `zcashlc_pir_client_create`
/// - `nullifier` must be non-null and point to exactly 32 bytes
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_check_nullifier(
    client: *mut PirClientHandle,
    nullifier: *const u8,
) -> *mut FfiSpentInfo {
    // Safety: We ensure PIR client state consistency by:
    // - Always checking for null before use
    // - Discarding the client if a panic occurs
    let client = AssertUnwindSafe(client);

    let res = catch_panic(|| {
        let client = *client;
        if client.is_null() || nullifier.is_null() {
            return Err(anyhow!("client or nullifier is null"));
        }

        let handle = unsafe { &mut *client };
        let nf_bytes: [u8; 32] = unsafe { slice::from_raw_parts(nullifier, 32) }
            .try_into()
            .context("Invalid nullifier length")?;

        let nf = Nullifier::from_bytes(nf_bytes);

        let result = handle
            .client
            .check_nullifier(&nf)
            .map_err(|e| anyhow!("PIR query failed: {}", e))?;

        match result {
            Some(info) => Ok(Box::into_raw(Box::new(FfiSpentInfo::from(info)))),
            None => Ok(ptr::null_mut()),
        }
    });

    unwrap_exc_or_null(res)
}

/// Check multiple nullifiers via PIR.
///
/// Returns array of SpentInfo (null entries mean unspent).
/// Caller must free result with `zcashlc_pir_free_spent_info_array`.
///
/// # Safety
///
/// - `client` must be a valid pointer returned by `zcashlc_pir_client_create`
/// - `nullifiers` must be non-null and point to `count * 32` bytes
/// - `count` must be the number of 32-byte nullifiers
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_check_nullifiers(
    client: *mut PirClientHandle,
    nullifiers: *const u8,
    count: usize,
) -> *mut FfiSpentInfoArray {
    // Safety: We ensure PIR client state consistency by:
    // - Always checking for null before use
    // - Discarding the client if a panic occurs
    let client = AssertUnwindSafe(client);

    let res = catch_panic(|| {
        let client = *client;
        if client.is_null() || nullifiers.is_null() {
            return Err(anyhow!("client or nullifiers is null"));
        }

        let handle = unsafe { &mut *client };
        let nf_data = unsafe { slice::from_raw_parts(nullifiers, count * 32) };

        // Parse nullifiers
        let mut nfs = Vec::with_capacity(count);
        for chunk in nf_data.chunks_exact(32) {
            let nf_bytes: [u8; 32] = chunk.try_into().context("Invalid nullifier chunk")?;
            nfs.push(Nullifier::from_bytes(nf_bytes));
        }

        // Check all nullifiers
        let results = handle
            .client
            .check_nullifiers(&nfs)
            .map_err(|e| anyhow!("PIR batch query failed: {}", e))?;

        // Convert to FFI array
        let mut items: Vec<*mut FfiSpentInfo> = Vec::with_capacity(count);
        for result in results {
            match result {
                Some(info) => items.push(Box::into_raw(Box::new(FfiSpentInfo::from(info)))),
                None => items.push(ptr::null_mut()),
            }
        }

        let items_ptr = items.as_mut_ptr();
        let items_len = items.len();
        std::mem::forget(items);

        Ok(Box::into_raw(Box::new(FfiSpentInfoArray {
            items: items_ptr,
            count: items_len,
        })))
    });

    unwrap_exc_or_null(res)
}

/// Free PIR client.
///
/// # Safety
///
/// - `client` must be a valid pointer returned by `zcashlc_pir_client_create`, or null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_client_free(client: *mut PirClientHandle) {
    if !client.is_null() {
        let _ = unsafe { Box::from_raw(client) };
    }
}

/// Free SpentInfo.
///
/// # Safety
///
/// - `info` must be a valid pointer returned by `zcashlc_pir_check_nullifier`, or null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_free_spent_info(info: *mut FfiSpentInfo) {
    if !info.is_null() {
        let _ = unsafe { Box::from_raw(info) };
    }
}

/// Free SpentInfoArray.
///
/// # Safety
///
/// - `array` must be a valid pointer returned by `zcashlc_pir_check_nullifiers`, or null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_free_spent_info_array(array: *mut FfiSpentInfoArray) {
    if !array.is_null() {
        let arr = unsafe { Box::from_raw(array) };

        // Free each non-null SpentInfo
        if !arr.items.is_null() {
            let items = unsafe { Vec::from_raw_parts(arr.items, arr.count, arr.count) };
            for item in items {
                if !item.is_null() {
                    let _ = unsafe { Box::from_raw(item) };
                }
            }
        }
    }
}

// ============================================================================
// Wallet Nullifier Retrieval
// ============================================================================

/// An array of 32-byte nullifiers (FFI-safe).
///
/// Each nullifier is 32 bytes. The array contains `count` nullifiers,
/// stored contiguously as `count * 32` bytes.
#[repr(C)]
pub struct FfiNullifierArray {
    /// Contiguous array of 32-byte nullifiers
    pub data: *mut u8,
    /// Number of nullifiers in the array
    pub count: usize,
}

/// Get unspent nullifiers from the wallet database.
///
/// Returns an array of 32-byte nullifiers for all unspent shielded notes
/// (both Sapling and Orchard) that the wallet is tracking.
///
/// These can be passed to PIR to verify none have been double-spent.
///
/// # Safety
///
/// - `db_data` must be non-null and valid for reads for `db_data_len` bytes.
///   Its contents must be a string representing a valid system path.
/// - `network_id` must be a valid network identifier (0 = testnet, 1 = mainnet).
/// - Caller must free result with `zcashlc_pir_free_nullifier_array`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_get_unspent_nullifiers(
    db_data: *const u8,
    db_data_len: usize,
    network_id: u32,
) -> *mut FfiNullifierArray {
    let res = catch_panic(|| {
        if db_data.is_null() {
            return Err(anyhow!("db_data is null"));
        }

        // Parse network
        let network = match network_id {
            0 => Network::TestNetwork,
            1 => Network::MainNetwork,
            _ => return Err(anyhow!("Invalid network_id: {}", network_id)),
        };

        // Open wallet database
        let db_path = Path::new(OsStr::from_bytes(unsafe {
            slice::from_raw_parts(db_data, db_data_len)
        }));
        let db = WalletDb::for_path(db_path, network, SystemClock, OsRng)
            .map_err(|e| anyhow!("Failed to open wallet database: {}", e))?;

        // Collect all unspent nullifiers
        let mut nullifiers: Vec<[u8; 32]> = Vec::new();

        // Get Sapling nullifiers
        let sapling_nfs = db
            .get_sapling_nullifiers(NullifierQuery::Unspent)
            .map_err(|e| anyhow!("Failed to get Sapling nullifiers: {}", e))?;
        let sapling_count = sapling_nfs.len();
        for (_, nf) in sapling_nfs {
            // Sapling Nullifier is a newtype around [u8; 32]
            nullifiers.push(nf.0);
        }

        // Get Orchard nullifiers
        let orchard_nfs = db
            .get_orchard_nullifiers(NullifierQuery::Unspent)
            .map_err(|e| anyhow!("Failed to get Orchard nullifiers: {}", e))?;
        let orchard_count = orchard_nfs.len();
        for (_, nf) in orchard_nfs {
            nullifiers.push(nf.to_bytes());
        }

        debug!(
            "Retrieved {} unspent nullifiers ({} sapling, {} orchard)",
            nullifiers.len(),
            sapling_count,
            orchard_count
        );

        // Flatten to contiguous byte array
        let count = nullifiers.len();
        let mut data: Vec<u8> = Vec::with_capacity(count * 32);
        for nf in nullifiers {
            data.extend_from_slice(&nf);
        }

        let data_ptr = data.as_mut_ptr();
        std::mem::forget(data);

        Ok(Box::into_raw(Box::new(FfiNullifierArray {
            data: data_ptr,
            count,
        })))
    });

    unwrap_exc_or_null(res)
}

/// Free a nullifier array.
///
/// # Safety
///
/// - `array` must be a valid pointer returned by `zcashlc_pir_get_unspent_nullifiers`, or null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_pir_free_nullifier_array(array: *mut FfiNullifierArray) {
    if !array.is_null() {
        let arr = unsafe { Box::from_raw(array) };

        if !arr.data.is_null() && arr.count > 0 {
            // Reconstruct and drop the Vec to free memory
            let _ = unsafe { Vec::from_raw_parts(arr.data, arr.count * 32, arr.count * 32) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_spent_info_conversion() {
        let info = SpentInfo {
            block_height: 1_000_000,
            tx_index: 42,
        };
        let ffi_info = FfiSpentInfo::from(info);
        assert_eq!(ffi_info.block_height, 1_000_000);
        assert_eq!(ffi_info.tx_index, 42);
        assert_eq!(ffi_info._padding, 0);
    }

    #[test]
    fn test_null_client_handling() {
        // These should not panic, just return false/null
        unsafe {
            assert!(!zcashlc_pir_keys_ready(ptr::null()));
            assert!(zcashlc_pir_check_nullifier(ptr::null_mut(), ptr::null()).is_null());
            // Free functions should handle null gracefully
            zcashlc_pir_client_free(ptr::null_mut());
            zcashlc_pir_free_spent_info(ptr::null_mut());
            zcashlc_pir_free_spent_info_array(ptr::null_mut());
        }
    }
}
