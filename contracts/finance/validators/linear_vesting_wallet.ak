use aiken/interval
use cardano/address
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use sources/vesting/linear_types.{
  LinearVestingDatum, LinearVestingRedeemer, ReclaimInvalid, Release,
}
use sources/vesting/linear_wallet

/// A stepped linear vesting wallet validator.
validator linear_vesting_wallet {
  spend(
    datum: Option<LinearVestingDatum>,
    redeemer: LinearVestingRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum
    when redeemer is {
      Release -> linear_wallet.release(datum, own_ref, self)
      ReclaimInvalid -> linear_wallet.reclaim_invalid(datum, own_ref, self)
    }
  }

  else(_) {
    fail
  }
}

const beneficiary = #"bebebebebebebebebebebebebebebebebebebebebebebebebebebebe"

const grantor = #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a"

const script = #"6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d"

fn schedule() -> LinearVestingDatum {
  LinearVestingDatum {
    beneficiary,
    grantor,
    start: 1000,
    cliff: 0,
    period: 10,
    steps: 10,
    released: 0,
    asset: None,
    released_units: 0,
  }
}

fn wallet_at(lovelace: Int, datum: LinearVestingDatum) -> Output {
  Output {
    address: address.from_script(script),
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn midpoint_release() -> (OutputReference, Transaction) {
  let own_ref = OutputReference {
    transaction_id: #"0303030303030303030303030303030303030303030303030303030303030303",
    output_index: 0,
  }

  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [
      Input {
        output_reference: own_ref,
        output: wallet_at(100_000_000, schedule()),
      },
    ],
    outputs: [
      wallet_at(
        50_000_000,
        LinearVestingDatum { ..schedule(), released: 50_000_000 },
      ),
      Output {
        address: address.from_verification_key(beneficiary),
        value: assets.from_lovelace(50_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    validity_range: interval.after(1050),
    extra_signatories: [beneficiary],
  }

  (own_ref, tx)
}

test spend_releases_the_vested_amount() {
  let (own_ref, tx) = midpoint_release()
  linear_vesting_wallet.spend(Some(schedule()), Release, own_ref, tx)
}

test spend_rejects_missing_datum() fail {
  let (own_ref, tx) = midpoint_release()
  linear_vesting_wallet.spend(None, Release, own_ref, tx)
}
