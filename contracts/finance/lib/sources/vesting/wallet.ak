use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Credential, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, find_input,
}
use sources/vesting/schedule
use sources/vesting/types.{VestingDatum}

/// Core spending rules for a vesting wallet.
/// Validate a release spend.
pub fn release(
  datum: VestingDatum,
  own_ref: OutputReference,
  self: Transaction,
) -> Bool {
  expect schedule.is_valid(datum)

  expect Some(own_input) = self.inputs |> find_input(own_ref)
  let own_address = own_input.output.address
  let own_credential = own_address.payment_credential

  expect [_] = self.inputs |> list.filter(paid_from(own_credential))

  expect Some(now) = schedule.now_at_least(self.validity_range)
  expect list.has(self.extra_signatories, datum.beneficiary)

  let locked = assets.lovelace_of(own_input.output.value)
  let releasable = schedule.releasable(datum, locked, now)

  when self.outputs |> list.filter(paid_to(own_credential)) is {
    // Full exit is allowed only once everything remaining is releasable, and the
    // whole balance must reach the beneficiary.
    [] -> and {
        releasable >= locked,
        net_lovelace_to(datum.beneficiary, self) >= locked,
      }
    [continuing] -> {
      expect InlineDatum(raw_datum) = continuing.datum
      expect next: VestingDatum = raw_datum
      let claimed = locked - assets.lovelace_of(continuing.value)

      and {
        claimed > 0,
        claimed <= releasable,
        // Preserve full address so staking rights stay unchanged.
        continuing.address == own_address,
        // A10: an attached reference script inflates size and min-ADA.
        continuing.reference_script == None,
        assets.without_lovelace(continuing.value) == assets.without_lovelace(
          own_input.output.value,
        ),
        next == VestingDatum { ..datum, released: datum.released + claimed },
        // The released lovelace must actually reach the beneficiary.
        net_lovelace_to(datum.beneficiary, self) >= claimed,
      }
    }
    // Multiple continuing outputs are rejected to prevent schedule splitting.
    _ -> False
  }
}

/// Net lovelace `key` gains from this transaction, counting the fee it covered.
///
/// Inputs contributed by `key` are subtracted, so its own change cannot be counted
/// as a payout: a builder who spends a 100 ADA beneficiary UTxO for fees would
/// otherwise satisfy a naive "outputs to beneficiary >= claimed" check while
/// sending the released lovelace elsewhere. `self.fee` is added back because the
/// recipient legitimately pays it out of the same pocket.
/// Validate a grantor reclaim of a wallet whose schedule is unusable.
///
/// `schedule.is_valid` guards `release`, so a wallet funded with (for example)
/// `duration: 0` can never be spent by the beneficiary — and nothing validates a
/// datum at creation, because creating an output runs no script. This arm is the
/// only path out of that state.
///
/// Mutually exclusive with `release` by construction: the negated `is_valid` below
/// holds only where `release` provably fails, so a well-formed grant stays
/// non-revocable and this is not an admin backdoor.
pub fn reclaim_invalid(
  datum: VestingDatum,
  own_ref: OutputReference,
  self: Transaction,
) -> Bool {
  expect !schedule.is_valid(datum)

  expect Some(own_input) = self.inputs |> find_input(own_ref)
  let own_credential = own_input.output.address.payment_credential

  expect [_] = self.inputs |> list.filter(paid_from(own_credential))

  let locked = assets.lovelace_of(own_input.output.value)

  and {
    // A full unwind: nothing may remain at the script address.
    !list.any(self.outputs, paid_to(own_credential)),
    list.has(self.extra_signatories, datum.grantor),
    net_lovelace_to(datum.grantor, self) >= locked,
  }
}

fn net_lovelace_to(key: VerificationKeyHash, self: Transaction) -> Int {
  let credential = VerificationKey(key)

  let received = self.outputs
    |> list.foldl(
        0,
        fn(output, total) {
          if output.address.payment_credential == credential {
            total + assets.lovelace_of(output.value)
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
            total + assets.lovelace_of(input.output.value)
          } else {
            total
          }
        },
      )

  received + self.fee - contributed
}

fn paid_from(credential: Credential) -> fn(Input) -> Bool {
  fn(input: Input) { input.output.address.payment_credential == credential }
}

fn paid_to(credential: Credential) -> fn(Output) -> Bool {
  fn(output: Output) { output.address.payment_credential == credential }
}
