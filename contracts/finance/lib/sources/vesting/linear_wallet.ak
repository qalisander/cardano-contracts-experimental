use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Credential, VerificationKey}
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, find_input,
}
use sources/vesting/linear_schedule
use sources/vesting/linear_types.{LinearVestingDatum}

/// Core spending rules for a linear vesting wallet.
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
  let releasable = linear_schedule.releasable(datum, locked, now)

  when self.outputs |> list.filter(paid_to(own_credential)) is {
    [] -> and {
        releasable >= locked,
        net_to_beneficiary(datum.beneficiary, self) >= locked,
      }
    [continuing] -> {
      expect InlineDatum(raw_datum) = continuing.datum
      expect next: LinearVestingDatum = raw_datum
      let claimed = locked - assets.lovelace_of(continuing.value)

      and {
        claimed > 0,
        claimed <= releasable,
        continuing.address == own_address,
        // A10: an attached reference script inflates size and min-ADA.
        continuing.reference_script == None,
        assets.without_lovelace(continuing.value) == assets.without_lovelace(
          own_input.output.value,
        ),
        next == LinearVestingDatum {
          ..datum,
          released: datum.released + claimed,
        },
        // The released lovelace must actually reach the beneficiary.
        net_to_beneficiary(datum.beneficiary, self) >= claimed,
      }
    }
    _ -> False
  }
}

/// Net lovelace the beneficiary gains from this transaction, counting the fee they
/// covered.
///
/// Inputs the beneficiary contributes are subtracted, so their own change cannot
/// be counted as a vesting payout: a builder who spends a 100 ADA beneficiary UTxO
/// for fees would otherwise satisfy a naive "outputs to beneficiary >= claimed"
/// check while sending the released lovelace elsewhere. `self.fee` is added back
/// because the beneficiary legitimately pays it out of the same pocket.
fn net_to_beneficiary(
  beneficiary: VerificationKeyHash,
  self: Transaction,
) -> Int {
  let credential = VerificationKey(beneficiary)

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
