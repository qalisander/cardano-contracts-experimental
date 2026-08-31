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
  /// Key hash allowed to reclaim this wallet, and ONLY when its schedule is
  /// ill-formed. A well-formed grant is never revocable.
  grantor: VerificationKeyHash,
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
  /// Escape hatch for a wallet funded with a schedule `is_valid` rejects, which
  /// `Release` can never spend. Guarded so it cannot touch a valid grant.
  ReclaimInvalid
}
