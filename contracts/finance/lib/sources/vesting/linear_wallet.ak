use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Credential, VerificationKey}
use cardano/assets.{Value}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, find_input,
}
use sources/vesting/linear_schedule
use sources/vesting/linear_types.{LinearVestingDatum}

/// Core spending rules for a vesting wallet.
/// Validate a release spend.
pub fn release(
  datum: LinearVestingDatum,
  own_ref: OutputReference,
  self: Transaction,
) -> Bool {
  expect linear_schedule.is_valid(datum)

  expect Some(own_input) = self.inputs |> find_input(own_ref)
  let own_address = own_input.output.address
  let own_credential = own_address.payment_credential

  expect [_] = self.inputs |> list.filter(paid_from(own_credential))

  expect Some(now) = linear_schedule.now_at_least(self.validity_range)
  expect list.has(self.extra_signatories, datum.beneficiary)

  let locked = assets.lovelace_of(own_input.output.value)
  let locked_units = units_of(datum, own_input.output.value)

  // The wallet may hold lovelace and the one asset its datum names, nothing else.
  // A wallet holding anything it cannot vest is unspendable here and recoverable
  // only through `reclaim_invalid`.
  expect holds_only_vested_assets(datum, own_input.output.value, locked_units)

  let releasable = linear_schedule.releasable(datum, locked, now)
  let releasable_units = linear_schedule.releasable_units(
    datum,
    locked_units,
    now,
  )

  when self.outputs |> list.filter(paid_to(own_credential)) is {
    // Full exit is allowed only once everything remaining is releasable, and the
    // whole balance must reach the beneficiary.
    [] -> and {
        releasable >= locked,
        releasable_units >= locked_units,
        net_lovelace_to(datum.beneficiary, self) >= locked,
        net_units_to(datum, datum.beneficiary, self) >= locked_units,
      }
    [continuing] -> {
      expect InlineDatum(raw_datum) = continuing.datum
      expect next: LinearVestingDatum = raw_datum
      let claimed = locked - assets.lovelace_of(continuing.value)
      let claimed_units = locked_units - units_of(datum, continuing.value)

      and {
        // Lovelace and units are each bounded by their own vested share. At least
        // one of them must actually move, or this is a no-op that only rewrites
        // the datum.
        claimed >= 0,
        claimed_units >= 0,
        claimed + claimed_units > 0,
        claimed <= releasable,
        claimed_units <= releasable_units,
        // Preserve full address so staking rights stay unchanged.
        continuing.address == own_address,
        // A10: an attached reference script inflates size and min-ADA.
        continuing.reference_script == None,
        // Pins the vested asset to exactly what is left, and forbids any other
        // asset being added along the way.
        assets.without_lovelace(continuing.value) == expected_assets(
          datum,
          locked_units - claimed_units,
        ),
        next == LinearVestingDatum {
          ..datum,
          released: datum.released + claimed,
          released_units: datum.released_units + claimed_units,
        },
        // What was released must actually reach the beneficiary.
        net_lovelace_to(datum.beneficiary, self) >= claimed,
        net_units_to(datum, datum.beneficiary, self) >= claimed_units,
      }
    }
    // Multiple continuing outputs are rejected to prevent schedule splitting.
    _ -> False
  }
}

/// Validate a grantor reclaim of a wallet that `release` can never spend.
///
/// Two states are unreachable by `release` and would otherwise be terminal, since
/// nothing validates a datum at creation — creating an output runs no script:
///
/// 1. an ill-formed schedule, which `linear_schedule.is_valid` rejects; and
/// 2. a wallet holding an asset its datum does not name, which
///    `holds_only_vested_assets` rejects.
///
/// This arm is mutually exclusive with `release` by construction: it fires only
/// where one of those two guards provably fails, so a well-formed grant holding
/// only its vested assets stays non-revocable. It is not an admin backdoor.
pub fn reclaim_invalid(
  datum: LinearVestingDatum,
  own_ref: OutputReference,
  self: Transaction,
) -> Bool {
  expect Some(own_input) = self.inputs |> find_input(own_ref)
  let own_credential = own_input.output.address.payment_credential

  let locked = assets.lovelace_of(own_input.output.value)
  let locked_units = units_of(datum, own_input.output.value)

  expect or {
      !linear_schedule.is_valid(datum),
      !holds_only_vested_assets(datum, own_input.output.value, locked_units),
    }

  expect [_] = self.inputs |> list.filter(paid_from(own_credential))

  and {
    // A full unwind: nothing may remain at the script address.
    !list.any(self.outputs, paid_to(own_credential)),
    list.has(self.extra_signatories, datum.grantor),
    net_lovelace_to(datum.grantor, self) >= locked,
  }
}

/// Units of the asset this datum vests that are present in `value`.
///
/// Zero when the datum vests no asset, so every unit computation collapses to the
/// lovelace-only case without a special branch at each site.
fn units_of(datum: LinearVestingDatum, value: Value) -> Int {
  when datum.asset is {
    None -> 0
    Some((policy_id, asset_name)) ->
      assets.quantity_of(value, policy_id, asset_name)
  }
}

/// The exact non-ADA value a wallet with this datum may hold at `units`.
fn expected_assets(datum: LinearVestingDatum, units: Int) -> Value {
  when datum.asset is {
    None -> assets.zero
    Some((policy_id, asset_name)) ->
      assets.from_asset(policy_id, asset_name, units)
  }
}

/// True when `value` carries nothing beyond lovelace and the vested asset.
///
/// Checked by equality rather than per-asset quantity, so a junk asset cannot be
/// smuggled in alongside a correct balance of the vested one.
fn holds_only_vested_assets(
  datum: LinearVestingDatum,
  value: Value,
  units: Int,
) -> Bool {
  assets.without_lovelace(value) == expected_assets(datum, units)
}

/// Net lovelace `key` gains from this transaction, counting the fee it covered.
///
/// Inputs contributed by `key` are subtracted, so its own change cannot be counted
/// as a payout: a builder who spends a 100 ADA beneficiary UTxO for fees would
/// otherwise satisfy a naive "outputs to beneficiary >= claimed" check while
/// sending the released lovelace elsewhere. `self.fee` is added back because the
/// recipient legitimately pays it out of the same pocket.
fn net_lovelace_to(key: VerificationKeyHash, self: Transaction) -> Int {
  net_to(key, self, fn(value) { assets.lovelace_of(value) }) + self.fee
}

/// Net units of the vested asset `key` gains from this transaction.
///
/// No fee term: fees are paid in lovelace, never in native assets.
fn net_units_to(
  datum: LinearVestingDatum,
  key: VerificationKeyHash,
  self: Transaction,
) -> Int {
  net_to(key, self, fn(value) { units_of(datum, value) })
}

/// Outputs to `key` minus inputs from `key`, measured by `quantity`.
fn net_to(
  key: VerificationKeyHash,
  self: Transaction,
  quantity: fn(Value) -> Int,
) -> Int {
  let credential = VerificationKey(key)

  let received = self.outputs
    |> list.foldl(
        0,
        fn(output, total) {
          if output.address.payment_credential == credential {
            total + quantity(output.value)
          } else {
            total
          }
        },
      )

  let contributed = self.inputs
    |> list.foldl(
        0,
        fn(input, total) {
          if input.output.address.payment_credential == credential {
            total + quantity(input.output.value)
          } else {
            total
          }
        },
      )

  received - contributed
}

fn paid_from(credential: Credential) -> fn(Input) -> Bool {
  fn(input: Input) { input.output.address.payment_credential == credential }
}

fn paid_to(credential: Credential) -> fn(Output) -> Bool {
  fn(output: Output) { output.address.payment_credential == credential }
}
