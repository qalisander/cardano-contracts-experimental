use aiken/collection/list
use cardano/address.{Credential}
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
    [] -> releasable >= locked
    [continuing] -> {
      expect InlineDatum(raw_datum) = continuing.datum
      expect next: LinearVestingDatum = raw_datum
      let claimed = locked - assets.lovelace_of(continuing.value)

      and {
        claimed > 0,
        claimed <= releasable,
        continuing.address == own_address,
        assets.without_lovelace(continuing.value) == assets.without_lovelace(
          own_input.output.value,
        ),
        next == LinearVestingDatum {
          ..datum,
          released: datum.released + claimed,
        },
      }
    }
    _ -> False
  }
}

fn paid_from(credential: Credential) -> fn(Input) -> Bool {
  fn(input: Input) { input.output.address.payment_credential == credential }
}

fn paid_to(credential: Credential) -> fn(Output) -> Bool {
  fn(output: Output) { output.address.payment_credential == credential }
}
