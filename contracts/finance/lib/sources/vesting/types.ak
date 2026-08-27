use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{Lovelace}

/// Datum and redeemer types for the vesting wallet.
/// POSIX time in milliseconds since epoch.
pub type PosixTime =
  Int

/// The state of a single vesting wallet UTxO.
pub type VestingDatum {
  /// Key hash allowed to release vested funds.
  beneficiary: VerificationKeyHash,
  /// Vesting start timestamp.
  start: PosixTime,
  /// Duration before anything can be released.
  cliff: Int,
  /// Total vesting duration.
  duration: Int,
  /// Lovelace cumulatively released from this wallet.
  released: Lovelace,
}

/// Actions supported by the vesting wallet.
pub type VestingRedeemer {
  Release
}
