#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Specifies how a "spend max" request should be evaluated.
 */
typedef enum FfiMaxSpendMode {
  /**
   * `MaxSpendable` will target to spend all _currently_ spendable funds where it
   * could be the case that the wallet has received other funds that are not
   * confirmed and therefore not spendable yet and the caller evaluates that as
   * an acceptable scenario.
   */
  MaxSpendable,
  /**
   * `Everything` will target to spend **all funds** and will fail if there are
   * unspendable funds in the wallet or if the wallet is not yet synced.
   */
  Everything,
} FfiMaxSpendMode;

/**
 * A type describing the mined-ness of transactions that should be returned in response to a
 * [`TransactionDataRequest`].
 *
 */
typedef enum TransactionStatusFilter {
  /**
   * Only mined transactions should be returned.
   */
  TransactionStatusFilter_Mined,
  /**
   * Only mempool transactions should be returned.
   */
  TransactionStatusFilter_Mempool,
  /**
   * Both mined transactions and transactions in the mempool should be returned.
   */
  TransactionStatusFilter_All,
} TransactionStatusFilter;

/**
 * A type used to filter transactions to be returned in response to a [`TransactionDataRequest`],
 * in terms of the spentness of the transaction's transparent outputs.
 *
 */
typedef enum OutputStatusFilter {
  /**
   * Only transactions that have currently-unspent transparent outputs should be returned.
   */
  OutputStatusFilter_Unspent,
  /**
   * All transactions corresponding to the data request should be returned, irrespective of
   * whether or not those transactions produce transparent outputs that are currently unspent.
   */
  OutputStatusFilter_All,
} OutputStatusFilter;

/**
 * What level of sleep to put a Tor client into.
 */
typedef enum TorDormantMode {
  /**
   * The client functions as normal, and background tasks run periodically.
   */
  Normal,
  /**
   * Background tasks are suspended, conserving CPU usage. Attempts to use the client will
   * wake it back up again.
   */
  Soft,
} TorDormantMode;

/**
 * An exchange for which we know how to query the ZEC-USD exchange rate.
 */
typedef enum FfiZecUsdExchange {
  Binance,
  CoinEx,
  Coinbase,
  DigiFinex,
  Gemini,
  Kraken,
  KuCoin,
  Mexc,
  Xt,
} FfiZecUsdExchange;

/**
 * A struct that contains a ZIP 325 Account Metadata Key.
 */
typedef struct FfiAccountMetadataKey FfiAccountMetadataKey;

typedef struct LwdConn LwdConn;

typedef struct TorRuntime TorRuntime;

/**
 * A struct that contains a 16-byte account uuid.
 */
typedef struct FfiUuid {
  uint8_t uuid_bytes[16];
} FfiUuid;

/**
 * A struct that contains a pointer to, and length information for, a heap-allocated
 * slice of [`Uuid`] values.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<Uuid>()`
 *   many bytes, and it must be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `ptr` must be contained within a single allocated
 *     object. Slices can never span across multiple allocated objects.
 *   - `ptr` must be non-null and aligned even for zero-length slices.
 *   - `ptr` must point to `len` consecutive properly initialized values of type
 *     [`Uuid`].
 * - The total size `len * mem::size_of::<Uuid>()` of the slice pointed to
 *   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
 */
typedef struct FfiAccounts {
  struct FfiUuid *ptr;
  uintptr_t len;
} FfiAccounts;

/**
 * A struct that contains a 16-byte account uuid along with key derivation metadata for that
 * account.
 *
 * A returned value containing the all-zeros seed fingerprint and/or u32::MAX for the
 * hd_account_index indicates that no derivation metadata is available.
 */
typedef struct FfiAccount {
  uint8_t uuid_bytes[16];
  char *account_name;
  char *key_source;
  uint8_t seed_fingerprint[32];
  uint32_t hd_account_index;
  char *ufvk;
} FfiAccount;

/**
 * A struct that contains an account identifier along with a pointer to the binary encoding
 * of an associated key.
 *
 * # Safety
 *
 * - `encoding` must be non-null and must point to an array of `encoding_len` bytes.
 */
typedef struct FFIBinaryKey {
  uint8_t account_uuid[16];
  uint8_t *encoding;
  uintptr_t encoding_len;
} FFIBinaryKey;

/**
 * A single-use transparent address, along with metadata about the address's use within the
 * wallet's ephemeral gap limit.
 */
typedef struct FfiSingleUseTaddr {
  char *address;
  uint32_t gap_position;
  uint32_t gap_limit;
} FfiSingleUseTaddr;

/**
 * A struct that contains an account identifier along with a pointer to the string encoding
 * of an associated key.
 *
 * # Safety
 *
 * - `encoding` must be non-null and must point to a null-terminated UTF-8 string.
 */
typedef struct FFIEncodedKey {
  uint8_t account_uuid[16];
  char *encoding;
} FFIEncodedKey;

/**
 * A struct that contains a pointer to, and length information for, a heap-allocated
 * slice of [`EncodedKey`] values.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<EncodedKey>()`
 *   many bytes, and it must be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `ptr` must be contained within a single allocated
 *     object. Slices can never span across multiple allocated objects.
 *   - `ptr` must be non-null and aligned even for zero-length slices.
 *   - `ptr` must point to `len` consecutive properly initialized values of type
 *     [`EncodedKey`].
 * - The total size `len * mem::size_of::<EncodedKey>()` of the slice pointed to
 *   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
 * - See the safety documentation of [`EncodedKey`]
 */
typedef struct FFIEncodedKeys {
  struct FFIEncodedKey *ptr;
  uintptr_t len;
} FFIEncodedKeys;

/**
 * A description of the policy that is used to determine what notes are available for spending,
 * based upon the number of confirmations (the number of blocks in the chain since and including
 * the block in which a note was produced.)
 *
 * See [`ZIP 315`] for details including the definitions of "trusted" and "untrusted" notes.
 *
 * # Note
 *
 * `trusted` and `untrusted` are both meant to be non-zero values.
 * `0` will be treated as a request for a default value.
 *
 * [`ZIP 315`]: https://zips.z.cash/zip-0315
 */
typedef struct ConfirmationsPolicy {
  /**
   * The number of confirmations required before trusted notes may be spent. NonZero, set this
   * and `untrusted` to zero to accept the default value for each.
   */
  uint32_t trusted;
  /**
   * The number of confirmations required before untrusted notes may be spent. NonZero, set this
   * and `trusted` both to zero to accept the default value for each.
   */
  uint32_t untrusted;
  /**
   * A flag that enables selection of zero-conf transparent UTXOs for spends in shielding
   * transactions.
   */
  bool allow_zero_conf_shielding;
} ConfirmationsPolicy;

/**
 * A struct that contains a subtree root.
 *
 * # Safety
 *
 * - `root_hash_ptr` must be non-null and must be valid for reads for `root_hash_ptr_len`
 *   bytes, and it must have an alignment of `1`.
 * - The total size `root_hash_ptr_len` of the slice pointed to by `root_hash_ptr` must
 *   be no larger than `isize::MAX`. See the safety documentation of `pointer::offset`.
 */
typedef struct FfiSubtreeRoot {
  uint8_t *root_hash_ptr;
  uintptr_t root_hash_ptr_len;
  uint32_t completing_block_height;
} FfiSubtreeRoot;

/**
 * A struct that contains a pointer to, and length information for, a heap-allocated
 * slice of [`SubtreeRoot`] values.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<SubtreeRoot>()`
 *   many bytes, and it must be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `ptr` must be contained within a single
 *     allocated object. Slices can never span across multiple allocated objects.
 *   - `ptr` must be non-null and aligned even for zero-length slices.
 *   - `ptr` must point to `len` consecutive properly initialized values of type
 *     [`SubtreeRoot`].
 * - The total size `len * mem::size_of::<SubtreeRoot>()` of the slice pointed to
 *   by `ptr` must be no larger than isize::MAX. See the safety documentation of
 *   `pointer::offset`.
 * - See the safety documentation of [`SubtreeRoot`]
 */
typedef struct FfiSubtreeRoots {
  struct FfiSubtreeRoot *ptr;
  uintptr_t len;
} FfiSubtreeRoots;

/**
 * Balance information for a value within a single pool in an account.
 */
typedef struct FfiBalance {
  /**
   * The value in the account that may currently be spent; it is possible to compute witnesses
   * for all the notes that comprise this value, and all of this value is confirmed to the
   * required confirmation depth.
   */
  int64_t spendable_value;
  /**
   * The value in the account of shielded change notes that do not yet have sufficient
   * confirmations to be spendable.
   */
  int64_t change_pending_confirmation;
  /**
   * The value in the account of all remaining received notes that either do not have sufficient
   * confirmations to be spendable, or for which witnesses cannot yet be constructed without
   * additional scanning.
   */
  int64_t value_pending_spendability;
} FfiBalance;

/**
 * Balance information for a single account.
 *
 * The sum of this struct's fields is the total balance of the account.
 */
typedef struct FfiAccountBalance {
  uint8_t account_uuid[16];
  /**
   * The value of unspent Sapling outputs belonging to the account.
   */
  struct FfiBalance sapling_balance;
  /**
   * The value of unspent Orchard outputs belonging to the account.
   */
  struct FfiBalance orchard_balance;
  /**
   * The value of all unspent transparent outputs belonging to the account,
   * irrespective of confirmation depth.
   *
   * Unshielded balances are not subject to confirmation-depth constraints, because the
   * only possible operation on a transparent balance is to shield it, it is possible
   * to create a zero-conf transaction to perform that shielding, and the resulting
   * shielded notes will be subject to normal confirmation rules.
   */
  int64_t unshielded;
} FfiAccountBalance;

/**
 * A struct that contains details about scan progress.
 *
 * When `denominator` is zero, the numerator encodes a non-progress indicator:
 * - 0: progress is unknown.
 * - 1: an error occurred.
 */
typedef struct FfiScanProgress {
  uint64_t numerator;
  uint64_t denominator;
} FfiScanProgress;

/**
 * A type representing the potentially-spendable value of unspent outputs in the wallet.
 *
 * The balances reported using this data structure may overestimate the total spendable
 * value of the wallet, in the case that the spend of a previously received shielded note
 * has not yet been detected by the process of scanning the chain. The balances reported
 * using this data structure can only be certain to be unspent in the case that
 * [`Self::is_synced`] is true, and even in this circumstance it is possible that a newly
 * created transaction could conflict with a not-yet-mined transaction in the mempool.
 *
 * # Safety
 *
 * - `account_balances` must be non-null and must be valid for reads for
 *   `account_balances_len * mem::size_of::<AccountBalance>()` many bytes, and it must
 *   be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `account_balances` must be contained within
 *     a single allocated object. Slices can never span across multiple allocated objects.
 *   - `account_balances` must be non-null and aligned even for zero-length slices.
 *   - `account_balances` must point to `len` consecutive properly initialized values of
 *     type [`AccountBalance`].
 * - The total size `account_balances_len * mem::size_of::<AccountBalance>()` of the
 *   slice pointed to by `account_balances` must be no larger than `isize::MAX`. See the
 *   safety documentation of `pointer::offset`.
 * - `scan_progress` must, if non-null, point to a struct having the layout of
 *   [`ScanProgress`].
 * - `recovery_progress` must, if non-null, point to a struct having the layout of
 *   [`ScanProgress`].
 */
typedef struct FfiWalletSummary {
  struct FfiAccountBalance *account_balances;
  uintptr_t account_balances_len;
  int32_t chain_tip_height;
  int32_t fully_scanned_height;
  struct FfiScanProgress *scan_progress;
  struct FfiScanProgress *recovery_progress;
  uint64_t next_sapling_subtree_index;
  uint64_t next_orchard_subtree_index;
} FfiWalletSummary;

/**
 * A struct that contains the start (inclusive) and end (exclusive) of a range of blocks
 * to scan.
 */
typedef struct FfiScanRange {
  int32_t start;
  int32_t end;
  uint8_t priority;
} FfiScanRange;

/**
 * A struct that contains a pointer to, and length information for, a heap-allocated
 * slice of [`ScanRange`] values.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<ScanRange>()`
 *   many bytes, and it must be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `ptr` must be contained within a single
 *     allocated object. Slices can never span across multiple allocated objects.
 *   - `ptr` must be non-null and aligned even for zero-length slices.
 *   - `ptr` must point to `len` consecutive properly initialized values of type
 *     [`ScanRange`].
 * - The total size `len * mem::size_of::<ScanRange>()` of the slice pointed to
 *   by `ptr` must be no larger than isize::MAX. See the safety documentation of
 *   `pointer::offset`.
 */
typedef struct FfiScanRanges {
  struct FfiScanRange *ptr;
  uintptr_t len;
} FfiScanRanges;

/**
 * Metadata about modifications to the wallet state made in the course of scanning a set
 * of blocks.
 */
typedef struct FfiScanSummary {
  int32_t scanned_start;
  int32_t scanned_end;
  uint64_t spent_sapling_note_count;
  uint64_t received_sapling_note_count;
} FfiScanSummary;

typedef struct FFIBlockMeta {
  uint32_t height;
  uint8_t *block_hash_ptr;
  uintptr_t block_hash_ptr_len;
  uint32_t block_time;
  uint32_t sapling_outputs_count;
  uint32_t orchard_actions_count;
} FFIBlockMeta;

typedef struct FFIBlocksMeta {
  struct FFIBlockMeta *ptr;
  uintptr_t len;
} FFIBlocksMeta;

/**
 * A struct that optionally contains a pointer to, and length information for, a
 * heap-allocated boxed slice.
 *
 * This is an FFI representation of `Option<Box<[u8]>>`.
 *
 * # Safety
 *
 * - If `ptr` is non-null, it must be valid for reads for `len` bytes, and it must have
 *   an alignment of `1`.
 * - The memory referenced by `ptr` must not be mutated for the lifetime of the struct
 *   (up until [`zcashlc_free_boxed_slice`] is called with it).
 * - The total size `len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 *   - When `ptr` is null, `len` should be zero.
 */
typedef struct FfiBoxedSlice {
  uint8_t *ptr;
  uintptr_t len;
} FfiBoxedSlice;

/**
 * A struct that contains a pointer to, and length information for, a heap-allocated
 * slice of `[u8; 32]` arrays.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<[u8; 32]>()`
 *   many bytes, and it must be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `ptr` must be contained within a single
 *     allocated object. Slices can never span across multiple allocated objects.
 *   - `ptr` must be non-null and aligned even for zero-length slices.
 *   - `ptr` must point to `len` consecutive properly initialized values of type
 *     `[u8; 32]`.
 * - The total size `len * mem::size_of::<[u8; 32]>()` of the slice pointed to
 *   by `ptr` must be no larger than isize::MAX. See the safety documentation of
 *   `pointer::offset`.
 */
typedef struct FfiSymmetricKeys {
  uint8_t (*ptr)[32];
  uintptr_t len;
} FfiSymmetricKeys;

typedef struct FfiSymmetricKeys FfiTxIds;

/**
 * Metadata about the status of a transaction obtained by inspecting the chain state.
 */
enum FfiTransactionStatus_Tag {
  /**
   * The requested transaction ID was not recognized by the node.
   */
  TxidNotRecognized,
  /**
   * The requested transaction ID corresponds to a transaction that is recognized by the node,
   * but is in the mempool or is otherwise not mined in the main chain (but may have been mined
   * on a fork that was reorged away).
   */
  NotInMainChain,
  /**
   * The requested transaction ID corresponds to a transaction that has been included in the
   * block at the provided height.
   */
  Mined,
};
typedef uint8_t FfiTransactionStatus_Tag;

typedef struct FfiTransactionStatus {
  FfiTransactionStatus_Tag tag;
  union {
    struct {
      uint32_t mined;
    };
  };
} FfiTransactionStatus;

/**
 * A request for transaction data enhancement, spentness check, or discovery
 * of spends from a given transparent address within a specific block range.
 */
enum FfiTransactionDataRequest_Tag {
  /**
   * Information about the chain's view of a transaction is requested.
   *
   * The caller evaluating this request on behalf of the wallet backend should respond to this
   * request by determining the status of the specified transaction with respect to the main
   * chain; if using `lightwalletd` for access to chain data, this may be obtained by
   * interpreting the results of the [`GetTransaction`] RPC method. It should then call
   * [`WalletWrite::set_transaction_status`] to provide the resulting transaction status
   * information to the wallet backend.
   *
   * [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
   */
  GetStatus,
  /**
   * Transaction enhancement (download of complete raw transaction data) is requested.
   *
   * The caller evaluating this request on behalf of the wallet backend should respond to this
   * request by providing complete data for the specified transaction to
   * [`wallet::decrypt_and_store_transaction`]; if using `lightwalletd` for access to chain
   * state, this may be obtained via the [`GetTransaction`] RPC method. If no data is available
   * for the specified transaction, this should be reported to the backend using
   * [`WalletWrite::set_transaction_status`]. A [`TransactionDataRequest::Enhancement`] request
   * subsumes any previously existing [`TransactionDataRequest::GetStatus`] request.
   *
   * [`GetTransaction`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_transaction
   */
  Enhancement,
  /**
   * Information about transactions that receive or spend funds belonging to the specified
   * transparent address is requested.
   *
   * Fully transparent transactions, and transactions that do not contain either shielded inputs
   * or shielded outputs belonging to the wallet, may not be discovered by the process of chain
   * scanning; as a consequence, the wallet must actively query to find transactions that spend
   * such funds. Ideally we'd be able to query by [`OutPoint`] but this is not currently
   * functionality that is supported by the light wallet server.
   *
   * The caller evaluating this request on behalf of the wallet backend should respond to this
   * request by detecting transactions involving the specified address within the provided block
   * range; if using `lightwalletd` for access to chain data, this may be performed using the
   * [`GetTaddressTxids`] RPC method. It should then call [`wallet::decrypt_and_store_transaction`]
   * for each transaction so detected.
   *
   * [`GetTaddressTxids`]: crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::get_taddress_txids
   */
  TransactionsInvolvingAddress,
};
typedef uint8_t FfiTransactionDataRequest_Tag;

typedef struct TransactionsInvolvingAddress_Body {
  /**
   * The address to request transactions and/or UTXOs for.
   */
  char *address;
  /**
   * Only transactions mined at heights greater than or equal to this height should be
   * returned.
   */
  uint32_t block_range_start;
  /**
   * Only transactions mined at heights less than this height should be returned.
   *
   * Either a `u32` value, or `-1` representing no end height.
   */
  int64_t block_range_end;
  /**
   * If `request_at` is non-negative, the caller evaluating this request should attempt to
   * retrieve transaction data related to the specified address at a time that is as close
   * as practical to the specified instant, and in a fashion that decorrelates this request
   * to a light wallet server from other requests made by the same caller.
   *
   * `-1` is the only negative value, meaning "unset".
   *
   * This may be ignored by callers that are able to satisfy the request without exposing
   * correlations between addresses to untrusted parties; for example, a wallet application
   * that uses a private, trusted-for-privacy supplier of chain data can safely ignore this
   * field.
   */
  int64_t request_at;
  /**
   * The caller should respond to this request only with transactions that conform to the
   * specified transaction status filter.
   */
  enum TransactionStatusFilter tx_status_filter;
  /**
   * The caller should respond to this request only with transactions containing outputs
   * that conform to the specified output status filter.
   */
  enum OutputStatusFilter output_status_filter;
} TransactionsInvolvingAddress_Body;

typedef struct FfiTransactionDataRequest {
  FfiTransactionDataRequest_Tag tag;
  union {
    struct {
      uint8_t get_status[32];
    };
    struct {
      uint8_t enhancement[32];
    };
    TransactionsInvolvingAddress_Body transactions_involving_address;
  };
} FfiTransactionDataRequest;

/**
 * A struct that contains a pointer to, and length information for, a heap-allocated
 * slice of [`TransactionDataRequest`] values.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must be valid for reads for `len * mem::size_of::<TransactionDataRequest>()`
 *   many bytes, and it must be properly aligned. This means in particular:
 *   - The entire memory range pointed to by `ptr` must be contained within a single allocated
 *     object. Slices can never span across multiple allocated objects.
 *   - `ptr` must be non-null and aligned even for zero-length slices.
 *   - `ptr` must point to `len` consecutive properly initialized values of type
 *     [`TransactionDataRequest`].
 * - The total size `len * mem::size_of::<TransactionDataRequest>()` of the slice pointed to
 *   by `ptr` must be no larger than isize::MAX. See the safety documentation of pointer::offset.
 * - See the safety documentation of [`TransactionDataRequest`]
 */
typedef struct FfiTransactionDataRequests {
  struct FfiTransactionDataRequest *ptr;
  uintptr_t len;
} FfiTransactionDataRequests;

/**
 * An HTTP header from a response.
 *
 * Memory is managed by Rust.
 */
typedef struct FfiHttpResponseHeader {
  /**
   * The header name as a C string.
   */
  char *name;
  /**
   * The header value as a C string.
   */
  char *value;
} FfiHttpResponseHeader;

/**
 * A struct that contains an HTTP response.
 */
typedef struct FfiHttpResponseBytes {
  /**
   * The response's status.
   */
  uint16_t status;
  /**
   * The response's version.
   */
  char *version;
  /**
   * A pointer to a list of the response's headers.
   */
  struct FfiHttpResponseHeader *headers_ptr;
  /**
   * The length of the data in `headers_ptr`.
   */
  uintptr_t headers_len;
  /**
   * A pointer to the HTTP body bytes.
   */
  uint8_t *body_ptr;
  /**
   * The length of the data in `body_ptr`.
   */
  uintptr_t body_len;
} FfiHttpResponseBytes;

/**
 * An HTTP header for a request.
 *
 * Memory is managed by Swift.
 */
typedef struct FfiHttpRequestHeader {
  /**
   * The header name as a C string.
   */
  const char *name;
  /**
   * The header value as a C string.
   */
  const char *value;
} FfiHttpRequestHeader;

/**
 * A decimal suitable for converting into an `NSDecimalNumber`.
 */
typedef struct Decimal {
  uint64_t mantissa;
  int16_t exponent;
  bool is_sign_negative;
} Decimal;

/**
 * The result of checking for UTXOs received by an ephemeral address.
 *
 */
enum FfiAddressCheckResult_Tag {
  /**
   * No UTXOs were found as a result of the check.
   */
  FfiAddressCheckResult_NotFound,
  /**
   * UTXOs were found for the given address.
   */
  FfiAddressCheckResult_Found,
};
typedef uint8_t FfiAddressCheckResult_Tag;

typedef struct FfiAddressCheckResult_Found_Body {
  char *address;
} FfiAddressCheckResult_Found_Body;

typedef struct FfiAddressCheckResult {
  FfiAddressCheckResult_Tag tag;
  union {
    FfiAddressCheckResult_Found_Body found;
  };
} FfiAddressCheckResult;

/**
 * A struct that contains a Zcash unified address, along with the diversifier index used to
 * generate that address.
 */
typedef struct FfiAddress {
  char *address;
  uint8_t diversifier_index_bytes[11];
} FfiAddress;

/**
 * Initializes global Rust state, such as the logging infrastructure and threadpools.
 *
 * `log_level` defines how the Rust layer logs its events. These values are supported,
 * each level logging more information in addition to the earlier levels:
 * - `off`: The logs are completely disabled.
 * - `error`: Logs very serious errors.
 * - `warn`: Logs hazardous situations.
 * - `info`: Logs useful information.
 * - `debug`: Logs lower priority information.
 * - `trace`: Logs very low priority, often extremely verbose, information.
 *
 * # Safety
 *
 * - The memory pointed to by `log_level` must contain a valid nul terminator at the end
 *   of the string.
 * - `log_level` must be valid for reads of bytes up to and including the nul terminator.
 *   This means in particular:
 *   - The entire memory range of this `CStr` must be contained within a single allocated
 *     object!
 * - The memory referenced by the returned `CStr` must not be mutated for the duration of
 *   the function call.
 * - The nul terminator must be within `isize::MAX` from `log_level`.
 *
 * # Panics
 *
 * This method panics if called more than once.
 */
void zcashlc_init_on_load(const char *log_level);

/**
 * Returns the length of the last error message to be logged.
 */
int32_t zcashlc_last_error_length(void);

/**
 * Copies the last error message into the provided allocated buffer.
 *
 * # Safety
 *
 * - `buf` must be non-null and valid for reads for `length` bytes, and it must have an alignment
 *   of `1`.
 * - The memory referenced by `buf` must not be mutated for the duration of the function call.
 * - The total size `length` must be no larger than `isize::MAX`. See the safety documentation of
 *   pointer::offset.
 */
int32_t zcashlc_error_message_utf8(char *buf, int32_t length);

/**
 * Clears the record of the last error message.
 */
void zcashlc_clear_last_error(void);

/**
 * Sets up the internal structure of the data database.  The value for `seed` may be provided as a
 * null pointer if the caller wishes to attempt migrations without providing the wallet's seed
 * value.
 *
 * Returns:
 * - 0 if successful.
 * - 1 if the seed must be provided in order to execute the requested migrations
 * - 2 if the provided seed is not relevant to any of the derived accounts in the wallet.
 * - -1 on error.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of pointer::offset.
 */
int32_t zcashlc_init_data_database(const uint8_t *db_data,
                                   uintptr_t db_data_len,
                                   const uint8_t *seed,
                                   uintptr_t seed_len,
                                   uint32_t network_id);

/**
 * Returns a list of the accounts in the wallet.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_accounts`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FfiAccounts *zcashlc_list_accounts(const uint8_t *db_data,
                                          uintptr_t db_data_len,
                                          uint32_t network_id);

/**
 * Returns the account data for the specified account identifier, or the [`ffi::Account::NOT_FOUND`]
 * sentinel value if the account id does not correspond to an account in the wallet.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - Call [`zcashlc_free_account`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FfiAccount *zcashlc_get_account(const uint8_t *db_data,
                                       uintptr_t db_data_len,
                                       uint32_t network_id,
                                       const uint8_t *account_uuid_bytes);

/**
 * Adds the next available account-level spend authority, given the current set of [ZIP 316]
 * account identifiers known, to the wallet database.
 *
 * Returns the newly created [ZIP 316] account identifier, along with the binary encoding of the
 * [`UnifiedSpendingKey`] for the newly created account.  The caller should manage the memory of
 * (and store) the returned spending keys in a secure fashion.
 *
 * If `seed` was imported from a backup and this method is being used to restore a
 * previous wallet state, you should use this method to add all of the desired
 * accounts before scanning the chain from the seed's birthday height.
 *
 * By convention, wallets should only allow a new account to be generated after funds
 * have been received by the currently available account (in order to enable
 * automated account recovery).
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of pointer::offset.
 * - `treestate` must be non-null and valid for reads for `treestate_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `treestate` must not be mutated for the duration of the function call.
 * - The total size `treestate_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_binary_key`] to free the memory associated with the returned pointer when
 *   you are finished using it.
 *
 * [ZIP 316]: https://zips.z.cash/zip-0316
 */
struct FFIBinaryKey *zcashlc_create_account(const uint8_t *db_data,
                                            uintptr_t db_data_len,
                                            const uint8_t *seed,
                                            uintptr_t seed_len,
                                            const uint8_t *treestate,
                                            uintptr_t treestate_len,
                                            int64_t recover_until,
                                            uint32_t network_id,
                                            const char *account_name,
                                            const char *key_source);

/**
 * Adds a new account to the wallet by importing the UFVK that will be used to detect incoming
 * payments.
 *
 * Derivation metadata may optionally be included. To indicate that no derivation metadata is
 * available, the `seed_fingerprint` argument should be set to the null pointer and
 * `hd_account_index` should be set to the value `u32::MAX`. Derivation metadata will not be
 * stored unless both the seed fingerprint and the HD account index are provided.
 *
 * Returns the globally unique identifier for the account.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.
 * - `treestate` must be non-null and valid for reads for `treestate_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `treestate` must not be mutated for the duration of the function call.
 * - The total size `treestate_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `seed_fingerprint` must either be either null or valid for reads for 32 bytes, and it must
 *   have an alignment of `1`.
 *
 * - Call [`zcashlc_free_ffi_uuid`] to free the memory associated with the returned pointer when
 *   you are finished using it.
 */
struct FfiUuid *zcashlc_import_account_ufvk(const uint8_t *db_data,
                                            uintptr_t db_data_len,
                                            const char *ufvk,
                                            const uint8_t *treestate,
                                            uintptr_t treestate_len,
                                            int64_t recover_until,
                                            uint32_t network_id,
                                            uint32_t purpose,
                                            const char *account_name,
                                            const char *key_source,
                                            const uint8_t *seed_fingerprint,
                                            uint32_t hd_account_index_raw);

/**
 * Checks whether the given seed is relevant to any of the accounts in the wallet.
 *
 * Returns:
 * - `1` for `Ok(true)`.
 * - `0` for `Ok(false)`.
 * - `-1` for `Err(_)`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of pointer::offset.
 */
int8_t zcashlc_is_seed_relevant_to_any_derived_account(const uint8_t *db_data,
                                                       uintptr_t db_data_len,
                                                       const uint8_t *seed,
                                                       uintptr_t seed_len,
                                                       uint32_t network_id);

/**
 * Deletes the specified account, and all transactions that exclusively involve it, from the
 * wallet database.
 *
 * WARNING: This is a destructive operation and may result in the permanent loss of
 * potentially important information that is not recoverable from chain data, including:
 * * Data about transactions sent by the account for which [`OvkPolicy::Discard`] (or
 *   [`OvkPolicy::Custom`] with random OVKs) was used;
 * * Data related to transactions that the account attempted to send that expired or were
 *   otherwise invalidated without having been mined in the main chain;
 * * Data related to transactions that were observed in the mempool as having inputs or
 *   outputs that involved the account, but that were never mined in the main chain;
 * * Data related to transactions that were received by the wallet in a mined block, where
 *   that block was later un-mined in a chain reorg and the transaction was either invalidated
 *   or was never re-mined.
 *
 * Returns `true` on success, or `false` if an error is raised.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
 *   alignment of `1`.
 *
 * [`OvkPolicy::Discard`]: zcash_client_backend::wallet::OvkPolicy::Discard
 * [`OvkPolicy::Custom`]: zcash_client_backend::wallet::OvkPolicy::Custom
 */
bool zcashlc_delete_account(const uint8_t *db_data,
                            uintptr_t db_data_len,
                            uint32_t network_id,
                            const uint8_t *account_uuid_bytes);

/**
 * Returns the most-recently-generated unified payment address for the specified account.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
 *   when done using it.
 */
char *zcashlc_get_current_address(const uint8_t *db_data,
                                  uintptr_t db_data_len,
                                  const uint8_t *account_uuid_bytes,
                                  uint32_t network_id);

/**
 * Generates and returns an ephemeral address for one-time use, such as when receiving a swap from
 * a decentralized exchange.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - Call [`zcashlc_free_single_use_address`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FfiSingleUseTaddr *zcashlc_get_single_use_taddr(const uint8_t *db_data,
                                                       uintptr_t db_data_len,
                                                       uint32_t network_id,
                                                       const uint8_t *account_uuid_bytes);

/**
 * Returns a newly-generated unified payment address for the specified account, with the next
 * available diversifier and the specified set of receivers.
 *
 * The set of receivers to include in the generated address is specified by a byte which may have
 * any of the following bits set:
 * * P2PKH = 0b00000001
 * * SAPLING = 0b00000100
 * * ORCHARD = 0b00001000
 *
 * For each bit set, a corresponding receiver will be required to be generated. If no
 * corresponding viewing key exists in the wallet for a required receiver, this will return an
 * error. At present, p2pkh-only unified addresses are not supported.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
 *   when done using it.
 */
char *zcashlc_get_next_available_address(const uint8_t *db_data,
                                         uintptr_t db_data_len,
                                         const uint8_t *account_uuid_bytes,
                                         uint32_t network_id,
                                         uint32_t receiver_flags);

/**
 * Returns a list of the transparent addresses that have been allocated for the provided account,
 * including potentially-unrevealed public-scope and private-scope (change) addresses within the
 * gap limit, which is currently set to 10 for public-scope addresses and 5 for change addresses.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - Call [`zcashlc_free_keys`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FFIEncodedKeys *zcashlc_list_transparent_receivers(const uint8_t *db_data,
                                                          uintptr_t db_data_len,
                                                          const uint8_t *account_uuid_bytes,
                                                          uint32_t network_id);

/**
 * Returns the verified transparent balance for `address`, which ignores utxos that have been
 * received too recently and are not yet deemed spendable according to `confirmations_policy`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `address` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `address` must not be mutated for the duration of the function call.
 */
int64_t zcashlc_get_verified_transparent_balance(const uint8_t *db_data,
                                                 uintptr_t db_data_len,
                                                 const char *address,
                                                 uint32_t network_id,
                                                 struct ConfirmationsPolicy confirmations_policy);

/**
 * Returns the verified transparent balance for `account`, which ignores utxos that have been
 * received too recently and are not yet deemed spendable according to `confirmations_policy`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 */
int64_t zcashlc_get_verified_transparent_balance_for_account(const uint8_t *db_data,
                                                             uintptr_t db_data_len,
                                                             uint32_t network_id,
                                                             const uint8_t *account_uuid_bytes,
                                                             struct ConfirmationsPolicy confirmations_policy);

/**
 * Returns the balance for `address`, including all UTXOs that we know about.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `address` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `address` must not be mutated for the duration of the function call.
 */
int64_t zcashlc_get_total_transparent_balance(const uint8_t *db_data,
                                              uintptr_t db_data_len,
                                              const char *address,
                                              uint32_t network_id);

/**
 * Returns the balance for `account`, including all UTXOs that we know about.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 */
int64_t zcashlc_get_total_transparent_balance_for_account(const uint8_t *db_data,
                                                          uintptr_t db_data_len,
                                                          uint32_t network_id,
                                                          const uint8_t *account_uuid_bytes);

/**
 * Returns the memo for a note by copying the corresponding bytes to the received
 * pointer in `memo_bytes_ret`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `txid_bytes` must be non-null and valid for reads for 32 bytes, and it must have an alignment
 *   of `1`.
 * - `memo_bytes_ret` must be non-null and must point to an allocated 512-byte region of memory.
 */
bool zcashlc_get_memo(const uint8_t *db_data,
                      uintptr_t db_data_len,
                      const uint8_t *txid_bytes,
                      uint32_t output_pool,
                      uint16_t output_index,
                      uint8_t *memo_bytes_ret,
                      uint32_t network_id);

/**
 * Returns a ZIP-32 signature of the given seed bytes.
 *
 * # Safety
 * - `seed` must be non-null and valid for reads for `seed_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be at least 32 no larger than `252`. See the safety documentation
 *   of pointer::offset.
 */
bool zcashlc_seed_fingerprint(const uint8_t *seed,
                              uintptr_t seed_len,
                              uint8_t *signature_bytes_ret);

/**
 * Rewinds the data database to at most the given height.
 *
 * If the requested height is greater than or equal to the height of the last scanned block, this
 * function sets the `safe_rewind_ret` output parameter to `-1` and does nothing else.
 *
 * This procedure returns the height to which the database was actually rewound, or `-1` if no
 * rewind was performed.
 *
 * If the requested rewind could not be performed, but a rewind to a different (greater) height
 * would be valid, the `safe_rewind_ret` output parameter will be set to that value on completion;
 * otherwise, it will be set to `-1`.
 *
 * # Safety
 *
 * - `safe_rewind_ret` must be non-null, aligned, and valid for writing an `int64_t`.
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
int64_t zcashlc_rewind_to_height(const uint8_t *db_data,
                                 uintptr_t db_data_len,
                                 uint32_t height,
                                 uint32_t network_id,
                                 int64_t *safe_rewind_ret);

/**
 * Adds a sequence of Sapling subtree roots to the data store.
 *
 * Returns true if the subtrees could be stored, false otherwise. When false is returned,
 * caller should check for errors.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `roots` must be non-null and initialized.
 * - The memory referenced by `roots` must not be mutated for the duration of the function call.
 */
bool zcashlc_put_sapling_subtree_roots(const uint8_t *db_data,
                                       uintptr_t db_data_len,
                                       uint64_t start_index,
                                       const struct FfiSubtreeRoots *roots,
                                       uint32_t network_id);

/**
 * Adds a sequence of Orchard subtree roots to the data store.
 *
 * Returns true if the subtrees could be stored, false otherwise. When false is returned,
 * caller should check for errors.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `roots` must be non-null and initialized.
 * - The memory referenced by `roots` must not be mutated for the duration of the function call.
 */
bool zcashlc_put_orchard_subtree_roots(const uint8_t *db_data,
                                       uintptr_t db_data_len,
                                       uint64_t start_index,
                                       const struct FfiSubtreeRoots *roots,
                                       uint32_t network_id);

/**
 * Updates the wallet's view of the blockchain.
 *
 * This method is used to provide the wallet with information about the state of the blockchain,
 * and detect any previously scanned data that needs to be re-validated before proceeding with
 * scanning. It should be called at wallet startup prior to calling `zcashlc_suggest_scan_ranges`
 * in order to provide the wallet with the information it needs to correctly prioritize scanning
 * operations.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 */
bool zcashlc_update_chain_tip(const uint8_t *db_data,
                              uintptr_t db_data_len,
                              int32_t height,
                              uint32_t network_id);

/**
 * Returns the height to which the wallet has been fully scanned.
 *
 * This is the height for which the wallet has fully trial-decrypted this and all
 * preceding blocks above the wallet's birthday height.
 *
 * Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 */
int64_t zcashlc_fully_scanned_height(const uint8_t *db_data,
                                     uintptr_t db_data_len,
                                     uint32_t network_id);

/**
 * Returns the maximum height that the wallet has scanned.
 *
 * If the wallet is fully synced, this will be equivalent to `zcashlc_block_fully_scanned`;
 * otherwise the maximal scanned height is likely to be greater than the fully scanned
 * height due to the fact that out-of-order scanning can leave gaps.
 *
 * Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 */
int64_t zcashlc_max_scanned_height(const uint8_t *db_data,
                                   uintptr_t db_data_len,
                                   uint32_t network_id);

/**
 * Returns the account balances and sync status given the specified minimum number of
 * confirmations.
 *
 * Returns `fully_scanned_height = -1` if the wallet has no balance data available.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
 *   have an alignment of `1`. Its contents must be a string representing a valid system
 *   path in the operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the
 *   function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_wallet_summary`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiWalletSummary *zcashlc_get_wallet_summary(const uint8_t *db_data,
                                                    uintptr_t db_data_len,
                                                    uint32_t network_id,
                                                    struct ConfirmationsPolicy confirmations_policy);

/**
 * Returns a list of suggested scan ranges based upon the current wallet state.
 *
 * This method should only be used in cases where the `CompactBlock` data that will be
 * made available to `zcashlc_scan_blocks` for the requested block ranges includes note
 * commitment tree size information for each block; or else the scan is likely to fail if
 * notes belonging to the wallet are detected.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
 *   have an alignment of `1`. Its contents must be a string representing a valid system
 *   path in the operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the
 *   function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_scan_ranges`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiScanRanges *zcashlc_suggest_scan_ranges(const uint8_t *db_data,
                                                  uintptr_t db_data_len,
                                                  uint32_t network_id);

/**
 * Scans new blocks added to the cache for any transactions received by the tracked
 * accounts, while checking that they form a valid chan.
 *
 * This function is built on the core assumption that the information provided in the
 * block cache is more likely to be accurate than the previously-scanned information.
 * This follows from the design (and trust) assumption that the `lightwalletd` server
 * provides accurate block information as of the time it was requested.
 *
 * This function **assumes** that the caller is handling rollbacks.
 *
 * For brand-new light client databases, this function starts scanning from the Sapling
 * activation height. This height can be fast-forwarded to a more recent block by calling
 * [`zcashlc_init_blocks_table`] before this function.
 *
 * Scanned blocks are required to be height-sequential. If a block is missing from the
 * cache, an error will be signalled.
 *
 * # Safety
 *
 * - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
 * - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
struct FfiScanSummary *zcashlc_scan_blocks(const uint8_t *fs_block_cache_root,
                                           uintptr_t fs_block_cache_root_len,
                                           const uint8_t *db_data,
                                           uintptr_t db_data_len,
                                           int32_t from_height,
                                           const uint8_t *from_state,
                                           uintptr_t from_state_len,
                                           uint32_t scan_limit,
                                           uint32_t network_id);

/**
 * Inserts a UTXO into the wallet database.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `txid_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `txid_bytes_len` must not be mutated for the duration of the function call.
 * - The total size `txid_bytes_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `script_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `script_bytes_len` must not be mutated for the duration of the function call.
 * - The total size `script_bytes_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
bool zcashlc_put_utxo(const uint8_t *db_data,
                      uintptr_t db_data_len,
                      const uint8_t *txid_bytes,
                      uintptr_t txid_bytes_len,
                      int32_t index,
                      const uint8_t *script_bytes,
                      uintptr_t script_bytes_len,
                      int64_t value,
                      int32_t height,
                      uint32_t network_id);

/**
 * # Safety
 * Initializes the `FsBlockDb` sqlite database. Does nothing if already created
 *
 * Returns true when successful, false otherwise. When false is returned caller
 * should check for errors.
 * - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
 * - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
bool zcashlc_init_block_metadata_db(const uint8_t *fs_block_db_root,
                                    uintptr_t fs_block_db_root_len);

/**
 * Writes the blocks provided in `blocks_meta` into the `BlockMeta` database
 *
 * Returns true if the `blocks_meta` could be stored into the `FsBlockDb`. False
 * otherwise.
 *
 * When false is returned caller should check for errors.
 *
 * # Safety
 *
 * - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
 * - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Block metadata represented in `blocks_meta` must be non-null. Caller must guarantee that the
 *   memory reference by this pointer is not freed up, dereferenced or invalidated while this
 *   function is invoked.
 */
bool zcashlc_write_block_metadata(const uint8_t *fs_block_db_root,
                                  uintptr_t fs_block_db_root_len,
                                  struct FFIBlocksMeta *blocks_meta);

/**
 * Rewinds the data database to the given height.
 *
 * If the requested height is greater than or equal to the height of the last scanned
 * block, this function does nothing.
 *
 * # Safety
 *
 * - `fs_block_db_root` must be non-null and valid for reads for `fs_block_db_root_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `fs_block_db_root` must not be mutated for the duration of the function call.
 * - The total size `fs_block_db_root_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
bool zcashlc_rewind_fs_block_cache_to_height(const uint8_t *fs_block_db_root,
                                             uintptr_t fs_block_db_root_len,
                                             int32_t height);

/**
 * Get the latest cached block height in the filesystem block cache
 *
 * Returns a non-negative block height, -1 if empty, or -2 if an error occurred.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `tx` must not be mutated for the duration of the function call.
 * - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
int32_t zcashlc_latest_cached_block_height(const uint8_t *fs_block_db_root,
                                           uintptr_t fs_block_db_root_len);

/**
 * Decrypts whatever parts of the specified transaction it can and stores them in db_data.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `tx` must not be mutated for the duration of the function call.
 * - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `txid_ret` must be non-null and valid for writes of 32 bytes with an alignment of 1.
 *   On successful execution this will contain the txid of the decrypted transaction.
 */
int32_t zcashlc_decrypt_and_store_transaction(const uint8_t *db_data,
                                              uintptr_t db_data_len,
                                              const uint8_t *tx,
                                              uintptr_t tx_len,
                                              int64_t mined_height,
                                              uint32_t network_id,
                                              uint8_t *txid_ret);

/**
 * Select transaction inputs, compute fees, and construct a proposal for a transaction
 * that can then be authorized and made ready for submission to the network with
 * `zcashlc_create_proposed_transaction`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
 *   of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - `to` must be non-null and must point to a null-terminated UTF-8 string.
 * - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
 *   512-byte array.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_propose_transfer(const uint8_t *db_data,
                                               uintptr_t db_data_len,
                                               const uint8_t *account_uuid_bytes,
                                               const char *to,
                                               int64_t value,
                                               const uint8_t *memo,
                                               uint32_t network_id,
                                               struct ConfirmationsPolicy confirmations_policy);

/**
 * Selects all spendable transaction inputs, computes fees, and constructs a proposal for a transaction
 * that can then be authorized and made ready for submission to the network with
 * `zcashlc_create_proposed_transaction`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
 *   of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - `to` must be non-null and must point to a null-terminated UTF-8 string.
 * - `memo` must either be null (indicating an empty memo or a transparent recipient) or point to a
 *   512-byte array.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_propose_send_max_transfer(const uint8_t *db_data,
                                                        uintptr_t db_data_len,
                                                        uint32_t network_id,
                                                        const uint8_t *account_uuid_bytes,
                                                        const char *to,
                                                        const uint8_t *memo,
                                                        enum FfiMaxSpendMode mode,
                                                        struct ConfirmationsPolicy confirmations_policy);

/**
 * Select transaction inputs, compute fees, and construct a proposal for a transaction
 * from a ZIP-321 payment URI that can then be authorized and made ready for submission to the
 * network with `zcashlc_create_proposed_transaction`.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
 *   of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - `payment_uri` must be non-null and must point to a null-terminated UTF-8 string.
 * - `network_id` a u32. 0 for Testnet and 1 for Mainnet
 * - `confirmations_policy` number of trusted/untrusted confirmations of the funds to spend
 * - `use_zip317_fees` `true` to use ZIP-317 fees.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_propose_transfer_from_uri(const uint8_t *db_data,
                                                        uintptr_t db_data_len,
                                                        const uint8_t *account_uuid_bytes,
                                                        const char *payment_uri,
                                                        uint32_t network_id,
                                                        struct ConfirmationsPolicy confirmations_policy);

int32_t zcashlc_branch_id_for_height(int32_t height, uint32_t network_id);

/**
 * Frees strings returned by other zcashlc functions.
 *
 * # Safety
 *
 * - `s` should be a non-null pointer returned as a string by another zcashlc function.
 */
void zcashlc_string_free(char *s);

/**
 * Select transaction inputs, compute fees, and construct a proposal for a shielding
 * transaction that can then be authorized and made ready for submission to the network
 * with `zcashlc_create_proposed_transaction`. If there are no receivers (as selected
 * by `transparent_receiver`) for which at least `shielding_threshold` of value is
 * available to shield, fail with an error.
 *
 * # Parameters
 *
 * - db_data: A string represented as a sequence of UTF-8 bytes.
 * - db_data_len: The length of `db_data`, in bytes.
 * - account_uuid_bytes: a 16-byte array representing the UUID for an account
 * - memo: `null` to represent "no memo", or a pointer to an array containing exactly 512 bytes.
 * - shielding_threshold: the minimum value to be shielded for each receiver.
 * - transparent_receiver: `null` to represent "all receivers with shieldable funds", or a single
 *   transparent address for which to shield funds. WARNING: Note that calling this with `null`
 *   will leak the fact that all the addresses from which funds are drawn in the shielding
 *   transaction belong to the same wallet *ON CHAIN*. This immutably reveals the shared ownership
 *   of these addresses to all blockchain observers. If a caller wishes to avoid such linkability,
 *   they should not pass `null` for this parameter; however, note that temporal correlations can
 *   also heuristically be used to link addresses on-chain if funds from multiple addresses are
 *   individually shielded in transactions that may be temporally clustered. Keeping transparent
 *   activity private is very difficult; caveat emptor.
 * - network_id: The identifier for the network in use: 0 for testnet, 1 for mainnet.
 * - confirmations_policy: The minimum number of confirmations that are required for a UTXO to be considered
 *   for shielding.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an alignment
 *   of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - `shielding_threshold` a non-negative shielding threshold amount in zatoshi
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_propose_shielding(const uint8_t *db_data,
                                                uintptr_t db_data_len,
                                                const uint8_t *account_uuid_bytes,
                                                const uint8_t *memo,
                                                uint64_t shielding_threshold,
                                                const char *transparent_receiver,
                                                uint32_t network_id,
                                                struct ConfirmationsPolicy confirmations_policy);

/**
 * Creates a transaction from the given proposal.
 *
 * Returns the row index of the newly-created transaction in the `transactions` table
 * within the data database. The caller can read the raw transaction bytes from the `raw`
 * column in order to broadcast the transaction to the network.
 *
 * Do not call this multiple times in parallel, or you will generate transactions that
 * double-spend the same notes.
 *
 * # Parameters
 * - `spend_params`: A pointer to a buffer containing the operating system path of the Sapling
 *   spend proving parameters, in the operating system's preferred path representation.
 * - `spend_params_len`: the length of the `spend_params` buffer.
 * - `output_params`: A pointer to a buffer containing the operating system path of the Sapling
 *   output proving parameters, in the operating system's preferred path representation.
 * - `output_params_len`: the length of the `output_params` buffer.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
 *   have an alignment of `1`. Its contents must be a string representing a valid system
 *   path in the operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the
 *   function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `proposal_ptr` must be non-null and valid for reads for `proposal_len` bytes, and it
 *   must have an alignment of `1`. Its contents must be an encoded Proposal protobuf.
 * - The memory referenced by `proposal_ptr` must not be mutated for the duration of the
 *   function call.
 * - The total size `proposal_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes containing
 *   a unified spending key encoded as returned from the `zcashlc_create_account` or
 *   `zcashlc_derive_spending_key` functions.
 * - The memory referenced by `usk_ptr` must not be mutated for the duration of the
 *   function call.
 * - The total size `usk_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes,
 *   and it must have an alignment of `1`.
 * - The memory referenced by `spend_params` must not be mutated for the duration of the
 *   function call.
 * - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `output_params` must be non-null and valid for reads for `output_params_len` bytes,
 *   and it must have an alignment of `1`.
 * - The memory referenced by `output_params` must not be mutated for the duration of the
 *   function call.
 * - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
FfiTxIds *zcashlc_create_proposed_transactions(const uint8_t *db_data,
                                               uintptr_t db_data_len,
                                               const uint8_t *proposal_ptr,
                                               uintptr_t proposal_len,
                                               const uint8_t *usk_ptr,
                                               uintptr_t usk_len,
                                               const uint8_t *spend_params,
                                               uintptr_t spend_params_len,
                                               const uint8_t *output_params,
                                               uintptr_t output_params_len,
                                               uint32_t network_id);

/**
 * Creates a partially-constructed (unsigned without proofs) transaction from the given proposal.
 *
 * Returns the partially constructed transaction in the `postcard` format generated by the `pczt`
 * crate.
 *
 * Do not call this multiple times in parallel, or you will generate pczt instances that, if
 * finalized, would double-spend the same notes.
 *
 * # Parameters
 * - `db_data`: A pointer to a buffer containing the operating system path of the wallet database,
 *   in the operating system's preferred path representation.
 * - `db_data_len`: The length of the `db_data` buffer.
 * - `proposal_ptr`: A pointer to a buffer containing an encoded `Proposal` protobuf.
 * - `proposal_len`: The length of the `proposal_ptr` buffer.
 * - `account_uuid_bytes`: A pointer to the 16-byte representaion of the account UUID.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `proposal_ptr` must be non-null and valid for reads for `proposal_len` bytes, and it
 *   must have an alignment of `1`.
 * - The memory referenced by `proposal_ptr` must not be mutated for the duration of the
 *   function call.
 * - The total size `proposal_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `account_uuid_bytes` must be non-null and valid for reads for 16 bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `account_uuid_bytes` must not be mutated for the duration of the
 *   function call.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_create_pczt_from_proposal(const uint8_t *db_data,
                                                        uintptr_t db_data_len,
                                                        uint32_t network_id,
                                                        const uint8_t *proposal_ptr,
                                                        uintptr_t proposal_len,
                                                        const uint8_t *account_uuid_bytes);

/**
 * Redacts information from the given PCZT that is unnecessary for the Signer role.
 *
 * Returns the updated PCZT in its serialized format.
 *
 * # Parameters
 * - `pczt_ptr`: A pointer to a byte array containing the encoded partially-constructed
 *   transaction to be redacted.
 * - `pczt_len`: The length of the `pczt_ptr` buffer.
 *
 * # Safety
 *
 * - `pczt_ptr` must be non-null and valid for reads for `pczt_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `pczt_ptr` must not be mutated for the duration of the function
 *   call.
 * - The total size `pczt_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_redact_pczt_for_signer(const uint8_t *pczt_ptr, uintptr_t pczt_len);

/**
 * Returns `true` if this PCZT requires Sapling proofs (and thus the caller needs to have
 * downloaded them). If the PCZT is invalid, `false` will be returned.
 *
 * # Parameters
 * - `pczt_ptr`: A pointer to a byte array containing the encoded partially-constructed
 *   transaction to be redacted.
 * - `pczt_len`: The length of the `pczt_ptr` buffer.
 *
 * # Safety
 *
 * - `pczt_ptr` must be non-null and valid for reads for `pczt_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `pczt_ptr` must not be mutated for the duration of the function
 *   call.
 * - The total size `pczt_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 */
bool zcashlc_pczt_requires_sapling_proofs(const uint8_t *pczt_ptr, uintptr_t pczt_len);

/**
 * Adds proofs to the given PCZT.
 *
 * Returns the updated PCZT in its serialized format.
 *
 * # Parameters
 * - `pczt_ptr`: A pointer to a byte array containing the encoded partially-constructed
 *   transaction for which proofs will be computed.
 * - `pczt_len`: The length of the `pczt_ptr` buffer.
 * - `spend_params`: A pointer to a buffer containing the operating system path of the Sapling
 *   spend proving parameters, in the operating system's preferred path representation.
 * - `spend_params_len`: the length of the `spend_params` buffer.
 * - `output_params`: A pointer to a buffer containing the operating system path of the Sapling
 *   output proving parameters, in the operating system's preferred path representation.
 * - `output_params_len`: the length of the `output_params` buffer.
 *
 * # Safety
 *
 * - `pczt_ptr` must be non-null and valid for reads for `pczt_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `pczt_ptr` must not be mutated for the duration of the function
 *   call.
 * - The total size `pczt_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - `spend_params` must be non-null and valid for reads for `spend_params_len` bytes, and it must
 *   have an alignment of `1`.
 * - The memory referenced by `spend_params` must not be mutated for the duration of the function
 *   call.
 * - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `output_params` must be non-null and valid for reads for `output_params_len` bytes, and it
 *   must have an alignment of `1`.
 * - The memory referenced by `output_params` must not be mutated for the duration of the function
 *   call.
 * - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_add_proofs_to_pczt(const uint8_t *pczt_ptr,
                                                 uintptr_t pczt_len,
                                                 const uint8_t *spend_params,
                                                 uintptr_t spend_params_len,
                                                 const uint8_t *output_params,
                                                 uintptr_t output_params_len);

/**
 * Takes a PCZT that has been separately proven and signed, finalizes it, and stores it
 * in the wallet.
 *
 * Returns the txid of the completed transaction as a byte array.
 *
 * # Parameters
 * - `db_data`: A pointer to a buffer containing the operating system path of the wallet database,
 *   in the operating system's preferred path representation.
 * - `db_data_len`: The length of the `db_data` buffer.
 * - `pczt_with_proofs`: A pointer to a byte array containing the encoded partially-constructed
 *   transaction to which proofs have been added.
 * - `pczt_with_proofs_len`: The length of the `pczt_with_proofs` buffer.
 * - `pczt_with_sigs_ptr`: A pointer to a byte array containing the encoded partially-constructed
 *   transaction to which signatures have been added.
 * - `pczt_with_sigs_len`: The length of the `pczt_with_sigs` buffer.
 * - `spend_params`: A pointer to a buffer containing the operating system path of the Sapling
 *   spend proving parameters, in the operating system's preferred path representation.
 * - `spend_params_len`: the length of the `spend_params` buffer.
 * - `output_params`: A pointer to a buffer containing the operating system path of the Sapling
 *   output proving parameters, in the operating system's preferred path representation.
 * - `output_params_len`: the length of the `output_params` buffer.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `pczt_with_proofs_ptr` must be non-null and valid for reads for `pczt_with_proofs_len` bytes,
 *   and it must have an alignment of `1`.
 * - The memory referenced by `pczt_with_proofs_ptr` must not be mutated for the duration of the
 *   function call.
 * - The total size `pczt_with_proofs_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `pczt_with_sigs_ptr` must be non-null and valid for reads for `pczt_with_sigs_len` bytes, and
 *   it must have an alignment of `1`.
 * - The memory referenced by `pczt_with_sigs_ptr` must not be mutated for the duration of the
 *   function call.
 * - The total size `pczt_with_sigs_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `spend_params` must either be null, or it must be valid for reads for `spend_params_len` bytes
 *   and have an alignment of `1`.
 * - The memory referenced by `spend_params` must not be mutated for the duration of the function
 *   call.
 * - The total size `spend_params_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `output_params` must either be null, or it must be valid for reads for `output_params_len`
 *   bytes and have an alignment of `1`.
 * - The memory referenced by `output_params` must not be mutated for the duration of the function
 *   call.
 * - The total size `output_params_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FfiBoxedSlice *zcashlc_extract_and_store_from_pczt(const uint8_t *db_data,
                                                          uintptr_t db_data_len,
                                                          uint32_t network_id,
                                                          const uint8_t *pczt_with_proofs_ptr,
                                                          uintptr_t pczt_with_proofs_len,
                                                          const uint8_t *pczt_with_sigs_ptr,
                                                          uintptr_t pczt_with_sigs_len,
                                                          const uint8_t *spend_params,
                                                          uintptr_t spend_params_len,
                                                          const uint8_t *output_params,
                                                          uintptr_t output_params_len);

/**
 * Sets the transaction status to the provided value.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must
 *   have an alignment of `1`. Its contents must be a string representing a valid system
 *   path in the operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the
 *   function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - `txid_bytes` must be non-null and valid for reads for `db_data_len` bytes, and it must have
 *   an alignment of `1`.
 * - The memory referenced by `txid_bytes_len` must not be mutated for the duration of the
 *   function call.
 * - The total size `txid_bytes_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
void zcashlc_set_transaction_status(const uint8_t *db_data,
                                    uintptr_t db_data_len,
                                    uint32_t network_id,
                                    const uint8_t *txid_bytes,
                                    uintptr_t txid_bytes_len,
                                    struct FfiTransactionStatus status);

/**
 * Returns a list of transaction data requests that the network client should satisfy.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_transaction_data_requests`] to free the memory associated with the
 *   returned pointer when done using it.
 */
struct FfiTransactionDataRequests *zcashlc_transaction_data_requests(const uint8_t *db_data,
                                                                     uintptr_t db_data_len,
                                                                     uint32_t network_id);

/**
 * Detects notes with corrupt witnesses, and adds the block ranges corresponding to the corrupt
 * ranges to the scan queue so that the ordinary scanning process will re-scan these ranges to fix
 * the corruption in question.
 *
 * # Safety
 *
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
void zcashlc_fix_witnesses(const uint8_t *db_data, uintptr_t db_data_len, uint32_t network_id);

/**
 * Creates a Tor runtime.
 *
 * # Safety
 *
 * - `tor_dir` must be non-null and valid for reads for `tor_dir_len` bytes, and it must
 *   have an alignment of `1`. Its contents must be a string representing a valid system
 *   path in the operating system's preferred representation.
 * - The memory referenced by `tor_dir` must not be mutated for the duration of the
 *   function call.
 * - The total size `tor_dir_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_tor_runtime`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct TorRuntime *zcashlc_create_tor_runtime(const uint8_t *tor_dir, uintptr_t tor_dir_len);

/**
 * Frees a Tor runtime.
 *
 * # Safety
 *
 * - If `ptr` is non-null, it must be a pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 */
void zcashlc_free_tor_runtime(struct TorRuntime *ptr);

/**
 * Returns a new isolated `TorRuntime` handle.
 *
 * The two `TorRuntime`s will share internal state and configuration, but their streams
 * will never share circuits with one another.
 *
 * Use this method when you want separate parts of your program to each have a
 * `TorRuntime` handle, but where you don't want their activities to be linkable to one
 * another over the Tor network.
 *
 * Calling this method is usually preferable to creating a completely separate
 * `TorRuntime` instance, since it can share its internals with the existing `TorRuntime`.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 * - Call [`zcashlc_free_tor_runtime`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct TorRuntime *zcashlc_tor_isolated_client(struct TorRuntime *tor_runtime);

/**
 * Changes the client's current dormant mode, putting background tasks to sleep or waking
 * them up as appropriate.
 *
 * This can be used to conserve CPU usage if you aren’t planning on using the client for
 * a while, especially on mobile platforms.
 *
 * See the [`ffi::TorDormantMode`] documentation for more details.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 */
bool zcashlc_tor_set_dormant(struct TorRuntime *tor_runtime, enum TorDormantMode mode);

/**
 * Makes an HTTP GET request over Tor.
 *
 * `retry_limit` is the maximum number of times that a failed request should be retried.
 * You can disable retries by setting this to 0.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 * - `url` must be non-null and must point to a null-terminated UTF-8 string.
 * - `headers` must be non-null and valid for reads for
 *   `headers_len * size_of::<ffi::HttpRequestHeader>()` bytes, and it must be properly
 *   aligned. This means in particular:
 *   - The entire memory range of this slice must be contained within a single allocated
 *     object! Slices can never span across multiple allocated objects.
 *   - `headers` must be non-null and aligned even for zero-length slices.
 * - `headers` must point to `headers_len` consecutive properly initialized values of
 *   type `ffi::HttpRequestHeader`.
 * - The memory referenced by `headers` must not be mutated for the duration of the function
 *   call.
 * - The total size `headers_len * size_of::<ffi::HttpRequestHeader>()` of the slice must
 *   be no larger than `isize::MAX`, and adding that size to `headers` must not "wrap
 *   around" the address space.  See the safety documentation of pointer::offset.
 * - Call [`zcashlc_free_http_response_bytes`] to free the memory associated with the
 *   returned pointer when done using it.
 */
struct FfiHttpResponseBytes *zcashlc_tor_http_get(struct TorRuntime *tor_runtime,
                                                  const char *url,
                                                  const struct FfiHttpRequestHeader *headers,
                                                  uintptr_t headers_len,
                                                  uint8_t retry_limit);

/**
 * Makes an HTTP POST request over Tor.
 *
 * `retry_limit` is the maximum number of times that a failed request should be retried.
 * You can disable retries by setting this to 0.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 * - `url` must be non-null and must point to a null-terminated UTF-8 string.
 * - `headers` must be non-null and valid for reads for
 *   `headers_len * size_of::<ffi::HttpRequestHeader>()` bytes, and it must be properly
 *   aligned. This means in particular:
 *   - The entire memory range of this slice must be contained within a single allocated
 *     object! Slices can never span across multiple allocated objects.
 *   - `headers` must be non-null and aligned even for zero-length slices.
 * - `headers` must point to `headers_len` consecutive properly initialized values of
 *   type `ffi::HttpRequestHeader`.
 * - The memory referenced by `headers` must not be mutated for the duration of the function
 *   call.
 * - The total size `headers_len * size_of::<ffi::HttpRequestHeader>()` of the slice must
 *   be no larger than `isize::MAX`, and adding that size to `headers` must not "wrap
 *   around" the address space.  See the safety documentation of pointer::offset.
 * - `body` must be non-null and valid for reads for `body_len` bytes, and it must have
 *   an alignment of `1`.
 * - The memory referenced by `body` must not be mutated for the duration of the function
 *   call.
 * - The total size `body_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_http_response_bytes`] to free the memory associated with the
 *   returned pointer when done using it.
 */
struct FfiHttpResponseBytes *zcashlc_tor_http_post(struct TorRuntime *tor_runtime,
                                                   const char *url,
                                                   const struct FfiHttpRequestHeader *headers,
                                                   uintptr_t headers_len,
                                                   const uint8_t *body,
                                                   uintptr_t body_len,
                                                   uint8_t retry_limit);

/**
 * Fetches the current ZEC-USD exchange rate over Tor.
 *
 * The result is a [`Decimal`] struct containing the fields necessary to construct an
 * [`NSDecimalNumber`](https://developer.apple.com/documentation/foundation/nsdecimalnumber/1416003-init).
 *
 * Returns a negative value on error.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 */
struct Decimal zcashlc_get_exchange_rate_usd(struct TorRuntime *tor_runtime);

/**
 * Fetches the current ZEC-USD exchange rate over Tor from the specified exchanges.
 *
 * The result is a [`Decimal`] struct containing the fields necessary to construct an
 * [`NSDecimalNumber`](https://developer.apple.com/documentation/foundation/nsdecimalnumber/1416003-init).
 *
 * Returns a negative value on error.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 * - `exchanges` must be non-null and valid for reads for
 *   `exchanges_len * size_of::<ffi::ZecUsdExchange>()` bytes, and it must be properly
 *   aligned. This means in particular:
 *   - The entire memory range of this slice must be contained within a single allocated
 *     object! Slices can never span across multiple allocated objects.
 *   - `exchanges` must be non-null and aligned even for zero-length slices.
 * - `exchanges` must point to `exchanges_len` consecutive properly initialized values of
 *   type `ffi::ZecUsdExchange`.
 * - The memory referenced by `exchanges` must not be mutated for the duration of the function
 *   call.
 * - The total size `exchanges_len * size_of::<ffi::ZecUsdExchange>()` of the slice must
 *   be no larger than `isize::MAX`, and adding that size to `exchanges` must not "wrap
 *   around" the address space.  See the safety documentation of `pointer::offset`.
 */
struct Decimal zcashlc_get_exchange_rate_usd_from(struct TorRuntime *tor_runtime,
                                                  enum FfiZecUsdExchange trusted_exchange,
                                                  const enum FfiZecUsdExchange *exchanges,
                                                  uintptr_t exchanges_len);

/**
 * Connects to the lightwalletd server at the given endpoint.
 *
 * Each connection returned by this method is isolated from any other Tor usage.
 *
 * # Safety
 *
 * - `tor_runtime` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut TorRuntime` that has not previously been freed.
 * - `tor_runtime` must not be passed to two FFI calls at the same time.
 * - `endpoint` must be non-null and must point to a null-terminated UTF-8 string.
 * - Call [`zcashlc_free_tor_lwd_conn`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct LwdConn *zcashlc_tor_connect_to_lightwalletd(struct TorRuntime *tor_runtime,
                                                    const char *endpoint);

/**
 * Frees a Tor lightwalletd connection.
 *
 * # Safety
 *
 * - If `ptr` is non-null, it must be a pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 */
void zcashlc_free_tor_lwd_conn(struct LwdConn *ptr);

/**
 * Returns information about this lightwalletd instance and the blockchain.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_tor_lwd_conn_get_info(struct LwdConn *lwd_conn);

/**
 * Fetches the height and hash of the block at the tip of the best chain.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - `height_ret` must be non-null and valid for writes for 4 bytes, and it must have an
 *   alignment of `1`.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_tor_lwd_conn_latest_block(struct LwdConn *lwd_conn,
                                                        uint32_t *height_ret);

/**
 * Fetches the transaction with the given ID.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - `txid_bytes` must be non-null and valid for reads for 32 bytes, and it must have an
 *   alignment of `1`.
 * - `height_ret` must be non-null and valid for writes for 8 bytes, and it must have an
 *   alignment of `1`.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_tor_lwd_conn_fetch_transaction(struct LwdConn *lwd_conn,
                                                             const uint8_t *txid_bytes,
                                                             uint64_t *height_ret);

/**
 * Submits a transaction to the Zcash network via the given lightwalletd connection.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - `tx` must be non-null and valid for reads for `tx_len` bytes, and it must have an
 *   alignment of `1`.
 * - The memory referenced by `tx` must not be mutated for the duration of the function call.
 * - The total size `tx_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 */
bool zcashlc_tor_lwd_conn_submit_transaction(struct LwdConn *lwd_conn,
                                             const uint8_t *tx,
                                             uintptr_t tx_len);

/**
 * Fetches the note commitment tree state corresponding to the given block height.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - Call [`zcashlc_free_boxed_slice`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_tor_lwd_conn_get_tree_state(struct LwdConn *lwd_conn,
                                                          uint32_t height);

/**
 * Finds all transactions associated with the given transparent address within the given block
 * range, and calls [`decrypt_and_store_transaction`] with each such transaction.
 *
 * The query to the light wallet server will cover the provided block range. The end height is
 * optional; to omit the end height for the query range use the sentinel value `-1`. If any other
 * value is specified, it must be in the range of a valid u32. Note that older versions of
 * `lightwalletd` will return an error if the end height is not specified.
 *
 * Returns an [`ffi::AddressCheckResult`] if successful, or a null pointer in the case of an
 * error.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_address_check_result`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiAddressCheckResult *zcashlc_tor_lwd_conn_update_transparent_address_transactions(struct LwdConn *lwd_conn,
                                                                                           const uint8_t *db_data,
                                                                                           uintptr_t db_data_len,
                                                                                           uint32_t network_id,
                                                                                           const char *address,
                                                                                           uint32_t start,
                                                                                           int64_t end);

/**
 * Checks to find any UTXOs associated with the given transparent address.
 *
 * This check will cover the block range starting at the exposure height for that address, if
 * known, or otherwise at the birthday height of the specified account.
 *
 * Returns an [`ffi::AddressCheckResult`] if successful, or a null pointer in the case of an
 * error.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_address_check_result`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiAddressCheckResult *zcashlc_tor_lwd_conn_fetch_utxos_by_address(struct LwdConn *lwd_conn,
                                                                          const uint8_t *db_data,
                                                                          uintptr_t db_data_len,
                                                                          uint32_t network_id,
                                                                          const uint8_t *account_uuid_bytes,
                                                                          const char *address);

/**
 * Checks to find any single-use ephemeral addresses exposed in the past day that have not yet
 * received funds, excluding any whose next check time is in the future. This will then choose the
 * address that is most overdue for checking, retrieve any UTXOs for that address over Tor, and
 * add them to the wallet database. If no such UTXOs are found, the check will be rescheduled
 * following an expoential-backoff-with-jitter algorithm.
 *
 * Returns an [`ffi::AddressCheckResult`] if successful, or a null pointer in the case of an
 * error.
 *
 * # Safety
 *
 * - `lwd_conn` must be a non-null pointer returned by a `zcashlc_*` method with
 *   return type `*mut tor::LwdConn` that has not previously been freed.
 * - `lwd_conn` must not be passed to two FFI calls at the same time.
 * - `db_data` must be non-null and valid for reads for `db_data_len` bytes, and it must have an
 *   alignment of `1`. Its contents must be a string representing a valid system path in the
 *   operating system's preferred representation.
 * - The memory referenced by `db_data` must not be mutated for the duration of the function call.
 * - The total size `db_data_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of pointer::offset.
 * - Call [`zcashlc_free_address_check_result`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiAddressCheckResult *zcashlc_tor_lwd_conn_check_single_use_taddr(struct LwdConn *lwd_conn,
                                                                          const uint8_t *db_data,
                                                                          uintptr_t db_data_len,
                                                                          uint32_t network_id,
                                                                          const uint8_t *account_uuid_bytes);

/**
 * Returns the network type and address kind for the given address string,
 * if the address is a valid Zcash address.
 *
 * Address kind codes are as follows:
 * * p2pkh: 0
 * * p2sh: 1
 * * sapling: 2
 * * unified: 3
 * * tex: 4
 *
 * # Safety
 *
 * - `address` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `address` must not be mutated for the duration of the function call.
 */
bool zcashlc_get_address_metadata(const char *address,
                                  uint32_t *network_id_ret,
                                  uint32_t *addr_kind_ret);

/**
 * Extracts the typecodes of the receivers within the given Unified Address.
 *
 * Returns a pointer to a slice of typecodes. `len_ret` is set to the length of the
 * slice.
 *
 * See the following sections of ZIP 316 for details on how to interpret typecodes:
 * - [List of known typecodes](https://zips.z.cash/zip-0316#encoding-of-unified-addresses)
 * - [Adding new types](https://zips.z.cash/zip-0316#adding-new-types)
 * - [Metadata Items](https://zips.z.cash/zip-0316#metadata-items)
 *
 * # Safety
 *
 * - `ua` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `ua` must not be mutated for the duration of the function call.
 * - Call [`zcashlc_free_typecodes`] to free the memory associated with the returned
 *   pointer when done using it.
 */
uint32_t *zcashlc_get_typecodes_for_unified_address_receivers(const char *ua, uintptr_t *len_ret);

/**
 * Frees a list of typecodes previously obtained from the FFI.
 *
 * # Safety
 *
 * - `data` and `len` must have been obtained from
 *   [`zcashlc_get_typecodes_for_unified_address_receivers`].
 */
void zcashlc_free_typecodes(uint32_t *data, uintptr_t len);

/**
 * Returns true when the provided key decodes to a valid Sapling extended spending key for the
 * specified network, false in any other case.
 *
 * # Safety
 *
 * - `extsk` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `extsk` must not be mutated for the duration of the function call.
 */
bool zcashlc_is_valid_sapling_extended_spending_key(const char *extsk, uint32_t network_id);

/**
 * Returns true when the provided key decodes to a valid Sapling extended full viewing key for the
 * specified network, false in any other case.
 *
 * # Safety
 *
 * - `key` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `key` must not be mutated for the duration of the function call.
 */
bool zcashlc_is_valid_viewing_key(const char *key, uint32_t network_id);

/**
 * Returns true when the provided key decodes to a valid unified full viewing key for the
 * specified network, false in any other case.
 *
 * # Safety
 *
 * - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `ufvk` must not be mutated for the duration of the
 *   function call.
 */
bool zcashlc_is_valid_unified_full_viewing_key(const char *ufvk, uint32_t network_id);

/**
 * Derives and returns a unified spending key from the given seed for the given account ID.
 *
 * Returns the binary encoding of the spending key. The caller should manage the memory of (and
 * store, if necessary) the returned spending key in a secure fashion.
 *
 * # Safety
 *
 * - `seed` must be non-null and valid for reads for `seed_len` bytes.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - Call `zcashlc_free_binary_key` to free the memory associated with the returned pointer when
 *   you are finished using it.
 */
struct FfiBoxedSlice *zcashlc_derive_spending_key(const uint8_t *seed,
                                                  uintptr_t seed_len,
                                                  int32_t hd_account_index,
                                                  uint32_t network_id);

/**
 * Obtains the unified full viewing key for the given binary-encoded unified spending key
 * and returns the resulting encoded UFVK string. `usk_ptr` should point to an array of `usk_len`
 * bytes containing a unified spending key encoded as returned from the `zcashlc_create_account`
 * or `zcashlc_derive_spending_key` functions.
 *
 * # Safety
 *
 * - `usk_ptr` must be non-null and must point to an array of `usk_len` bytes.
 * - The memory referenced by `usk_ptr` must not be mutated for the duration of the function call.
 * - The total size `usk_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
 *   when you are done using it.
 */
char *zcashlc_spending_key_to_full_viewing_key(const uint8_t *usk_ptr,
                                               uintptr_t usk_len,
                                               uint32_t network_id);

/**
 * Derives a unified address address for the provided UFVK, along with the diversifier at which it
 * was derived; this may not be equal to the provided diversifier index if no valid Sapling
 * address could be derived at that index. If the `diversifier_index_bytes` parameter is null, the
 * default address for the UFVK is returned.
 *
 * # Safety
 *
 * - `ufvk` must be non-null and must point to a null-terminated UTF-8 string.
 * - `diversifier_index_bytes must either be null or be valid for reads for 11 bytes and have an
 *   alignment of `1`.
 * - Call [`zcashlc_free_ffi_address`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FfiAddress *zcashlc_derive_address_from_ufvk(uint32_t network_id,
                                                    const char *ufvk,
                                                    const uint8_t *diversifier_index_bytes);

/**
 * Derives a unified address address for the provided UIVK, along with the diversifier at which it
 * was derived; this may not be equal to the provided diversifier index if no valid Sapling
 * address could be derived at that index. If the `diversifier_index_bytes` parameter is null, the
 * default address for the UIVK is returned.
 *
 * # Safety
 *
 * - `uivk` must be non-null and must point to a null-terminated UTF-8 string.
 * - `diversifier_index_bytes must either be null or be valid for reads for 11 bytes and have an
 *   alignment of `1`.
 * - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
 *   when done using it.
 */
struct FfiAddress *zcashlc_derive_address_from_uivk(uint32_t network_id,
                                                    const char *uivk,
                                                    const uint8_t *diversifier_index_bytes);

/**
 * Returns the transparent receiver within the given Unified Address, if any.
 *
 * # Safety
 *
 * - `ua` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `ua` must not be mutated for the duration of the function call.
 * - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
 *   when done using it.
 */
char *zcashlc_get_transparent_receiver_for_unified_address(const char *ua);

/**
 * Returns the Sapling receiver within the given Unified Address, if any.
 *
 * # Safety
 *
 * - `ua` must be non-null and must point to a null-terminated UTF-8 string.
 * - The memory referenced by `ua` must not be mutated for the duration of the function call.
 * - Call [`zcashlc_string_free`] to free the memory associated with the returned pointer
 *   when done using it.
 */
char *zcashlc_get_sapling_receiver_for_unified_address(const char *ua);

/**
 * Constructs an ffi::AccountMetadataKey from its parts.
 *
 * # Safety
 *
 * - `sk` must be non-null and valid for reads for 32 bytes, and it must have an alignment of `1`.
 * - The memory referenced by `sk` must not be mutated for the duration of the function call.
 * - `chain_code` must be non-null and valid for reads for 32 bytes, and it must have an alignment
 *   of `1`.
 * - The memory referenced by `chain_code` must not be mutated for the duration of the function
 *   call.
 * - Call [`zcashlc_free_account_metadata_key`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiAccountMetadataKey *zcashlc_account_metadata_key_from_parts(const uint8_t *sk,
                                                                      const uint8_t *chain_code);

/**
 * Derives a ZIP 325 Account Metadata Key from the given seed.
 *
 * # Safety
 *
 * - `seed` must be non-null and valid for reads for `seed_len` bytes.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - Call [`zcashlc_free_account_metadata_key`] to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiAccountMetadataKey *zcashlc_derive_account_metadata_key(const uint8_t *seed,
                                                                  uintptr_t seed_len,
                                                                  int32_t account,
                                                                  uint32_t network_id);

/**
 * Derives a metadata key for private use from a ZIP 325 Account Metadata Key.
 *
 * - `ufvk` is the external UFVK for which a metadata key is required, or `null` if the
 *   metadata key is "inherent" (for the same account as the Account Metadata Key).
 * - `private_use_subject` is a globally unique non-empty sequence of at most 252 bytes
 *   that identifies the desired private-use context.
 *
 * If `ufvk` is null, this function will return a single 32-byte metadata key.
 *
 * If `ufvk` is non-null, this function will return one metadata key for every FVK item
 * contained within the UFVK, in preference order. As UFVKs may in general change over
 * time (due to the inclusion of new higher-preference FVK items, or removal of older
 * deprecated FVK items), private usage of these keys should always follow preference
 * order:
 * - For encryption-like private usage, the first key in the array should always be
 *   used, and all other keys ignored.
 * - For decryption-like private usage, each key in the array should be tried in turn
 *   until metadata can be recovered, and then the metadata should be re-encrypted
 *   under the first key.
 *
 * # Safety
 *
 * - `account_metadata_key` must be non-null and must point to a struct having the layout
 *   of [`ffi::AccountMetadataKey`].
 * - The memory referenced by `account_metadata_key` must not be mutated for the duration
 *   of the function call.
 * - If `ufvk` is non-null, it must point to a null-terminated UTF-8 string.
 * - `private_use_subject` must be non-null and valid for reads for `private_use_subject_len`
 *   bytes.
 * - The memory referenced by `private_use_subject` must not be mutated for the duration
 *   of the function call.
 * - The total size `private_use_subject_len` must be no larger than `isize::MAX`. See
 *   the safety documentation of `pointer::offset`.
 * - Call `zcashlc_free_symmetric_keys` to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiSymmetricKeys *zcashlc_derive_private_use_metadata_key(const struct FfiAccountMetadataKey *account_metadata_key,
                                                                 const char *ufvk,
                                                                 const uint8_t *private_use_subject,
                                                                 uintptr_t private_use_subject_len,
                                                                 uint32_t network_id);

/**
 * Derives and returns a ZIP 32 Arbitrary Key from the given seed at the "wallet level", i.e.
 * directly from the seed with no ZIP 32 path applied.
 *
 * The resulting key will be the same across all networks (Zcash mainnet, Zcash testnet, OtherCoin
 * mainnet, and so on). You can think of it as a context-specific seed fingerprint that can be used
 * as (static) key material.
 *
 * `context_string` is a globally-unique non-empty sequence of at most 252 bytes that identifies
 * the desired context.
 *
 * # Safety
 *
 * - `context_string` must be non-null and valid for reads for `context_string_len` bytes.
 * - The memory referenced by `context_string` must not be mutated for the duration of the function
 *   call.
 * - The total size `context_string_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `seed` must be non-null and valid for reads for `seed_len` bytes.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - Call `zcashlc_free_boxed_slice` to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_derive_arbitrary_wallet_key(const uint8_t *context_string,
                                                          uintptr_t context_string_len,
                                                          const uint8_t *seed,
                                                          uintptr_t seed_len);

/**
 * Derives and returns a ZIP 32 Arbitrary Key from the given seed at the account level.
 *
 * `context_string` is a globally-unique non-empty sequence of at most 252 bytes that identifies
 * the desired context.
 *
 * # Safety
 *
 * - `context_string` must be non-null and valid for reads for `context_string_len` bytes.
 * - The memory referenced by `context_string` must not be mutated for the duration of the function
 *   call.
 * - The total size `context_string_len` must be no larger than `isize::MAX`. See the safety
 *   documentation of `pointer::offset`.
 * - `seed` must be non-null and valid for reads for `seed_len` bytes`.
 * - The memory referenced by `seed` must not be mutated for the duration of the function call.
 * - The total size `seed_len` must be no larger than `isize::MAX`. See the safety documentation
 *   of `pointer::offset`.
 * - Call `zcashlc_free_boxed_slice` to free the memory associated with the returned
 *   pointer when done using it.
 */
struct FfiBoxedSlice *zcashlc_derive_arbitrary_account_key(const uint8_t *context_string,
                                                           uintptr_t context_string_len,
                                                           const uint8_t *seed,
                                                           uintptr_t seed_len,
                                                           int32_t account,
                                                           uint32_t network_id);

/**
 * Frees an [`Account`] value
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`Account`].
 */
void zcashlc_free_account(struct FfiAccount *ptr);

/**
 * Frees a [`Uuid`] value
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`Uuid`].
 */
void zcashlc_free_ffi_uuid(struct FfiUuid *ptr);

/**
 * Frees an array of [`Uuid`] values as allocated by `zcashlc_list_accounts`.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`Accounts`].
 *   See the safety documentation of [`Accounts`].
 */
void zcashlc_free_accounts(struct FfiAccounts *ptr);

/**
 * Frees a [`BinaryKey`] value
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`BinaryKey`].
 *   See the safety documentation of [`BinaryKey`].
 */
void zcashlc_free_binary_key(struct FFIBinaryKey *ptr);

/**
 * Frees an array of [`EncodedKey`] values as allocated by `zcashlc_list_transparent_receivers`.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`EncodedKeys`].
 *   See the safety documentation of [`EncodedKeys`].
 */
void zcashlc_free_keys(struct FFIEncodedKeys *ptr);

/**
 * Frees an [`WalletSummary`] value.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`WalletSummary`].
 *   See the safety documentation of [`WalletSummary`].
 */
void zcashlc_free_wallet_summary(struct FfiWalletSummary *ptr);

/**
 * Frees an array of [`ScanRange`] values as allocated by `zcashlc_suggest_scan_ranges`.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`ScanRanges`].
 *   See the safety documentation of [`ScanRanges`].
 */
void zcashlc_free_scan_ranges(struct FfiScanRanges *ptr);

/**
 * Frees a [`ScanSummary`] value.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`ScanSummary`].
 */
void zcashlc_free_scan_summary(struct FfiScanSummary *ptr);

/**
 * Frees a [`BoxedSlice`].
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of
 *   [`BoxedSlice`]. See the safety documentation of [`BoxedSlice`].
 */
void zcashlc_free_boxed_slice(struct FfiBoxedSlice *ptr);

/**
 * Frees an array of `[u8; 32]` values.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of
 *   [`SymmetricKeys`]. See the safety documentation of [`SymmetricKeys`].
 */
void zcashlc_free_symmetric_keys(struct FfiSymmetricKeys *ptr);

/**
 * Frees an array of `[u8; 32]` values as allocated by `zcashlc_create_proposed_transactions`.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`TxIds`].
 *   See the safety documentation of [`TxIds`].
 */
void zcashlc_free_txids(FfiTxIds *ptr);

/**
 * Frees an array of [`TransactionDataRequest`] values as allocated by `zcashlc_transaction_data_requests`.
 *
 * # Safety
 *
 * - `ptr` if `ptr` is non-null it must point to a struct having the layout of [`TransactionDataRequests`].
 *   See the safety documentation of [`TransactionDataRequests`].
 */
void zcashlc_free_transaction_data_requests(struct FfiTransactionDataRequests *ptr);

/**
 * Frees an [`Address`] value
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`Address`].
 */
void zcashlc_free_ffi_address(struct FfiAddress *ptr);

/**
 * Frees an AccountMetadataKey value
 *
 * # Safety
 *
 * - `ptr` must either be null or point to a struct having the layout of [`AccountMetadataKey`].
 */
void zcashlc_free_account_metadata_key(struct FfiAccountMetadataKey *ptr);

/**
 * Frees an HttpResponseBytes value
 *
 * # Safety
 *
 * - `ptr` must either be null or point to a struct having the layout of [`HttpResponseBytes`].
 */
void zcashlc_free_http_response_bytes(struct FfiHttpResponseBytes *ptr);

/**
 * Frees an [`SingleUseTaddr`] value.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`SingleUseTaddr`].
 */
void zcashlc_free_single_use_taddr(struct FfiSingleUseTaddr *ptr);

/**
 * Frees an [`AddressCheckResult`] value.
 *
 * # Safety
 *
 * - `ptr` must be non-null and must point to a struct having the layout of [`AddressCheckResult`].
 */
void zcashlc_free_address_check_result(struct FfiAddressCheckResult *ptr);
