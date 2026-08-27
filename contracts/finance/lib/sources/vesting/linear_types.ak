use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{Lovelace}

/// Datum and redeemer types for stepped linear vesting.
pub type PosixTime =
  Int

/// The state of a single linear vesting wallet UTxO.
pub type LinearVestingDatum {
  /// Key hash allowed to release vested funds.
  beneficiary: VerificationKeyHash,
  /// Vesting start timestamp.
  start: PosixTime,
  /// Duration after start before any step can be released.
  cliff: Int,
  /// Milliseconds per vesting step.
  period: Int,
  /// Number of equal linear steps.
  steps: Int,
  /// Lovelace cumulatively released from this wallet.
  released: Lovelace,
}

/// Actions supported by the linear vesting wallet.
pub type LinearVestingRedeemer {
  Release
}
