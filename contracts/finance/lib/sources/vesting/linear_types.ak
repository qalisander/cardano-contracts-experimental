use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{AssetName, Lovelace, PolicyId}

/// Datum and redeemer types for stepped linear vesting.
pub type PosixTime =
  Int

/// The state of a single linear vesting wallet UTxO.
pub type LinearVestingDatum {
  /// Key hash allowed to release vested funds.
  beneficiary: VerificationKeyHash,
  /// Key hash allowed to reclaim this wallet, and ONLY when its schedule is
  /// ill-formed. A well-formed grant is never revocable.
  grantor: VerificationKeyHash,
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
  /// The single native asset vested alongside lovelace, if any. A wallet may hold
  /// lovelace and this asset and nothing else.
  asset: Option<(PolicyId, AssetName)>,
  /// Units of `asset` cumulatively released from this wallet.
  released_units: Int,
}

/// Actions supported by the linear vesting wallet.
pub type LinearVestingRedeemer {
  Release
  /// Escape hatch for a wallet funded with a schedule `is_valid` rejects, which
  /// `Release` can never spend. Guarded so it cannot touch a valid grant.
  ReclaimInvalid
}
