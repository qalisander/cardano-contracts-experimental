use aiken/interval
use cardano/address
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use sources/vesting/types.{ReclaimInvalid, Release, VestingDatum, VestingRedeemer}
use sources/vesting/wallet

/// A linear vesting wallet validator.
validator vesting_wallet {
  spend(
    datum: Option<VestingDatum>,
    redeemer: VestingRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum
    when redeemer is {
      Release -> wallet.release(datum, own_ref, self)
      ReclaimInvalid -> wallet.reclaim_invalid(datum, own_ref, self)
    }
  }

  else(_) {
    fail
  }
}

// Minimal handler tests; release semantics live in wallet tests.
const beneficiary = #"bebebebebebebebebebebebebebebebebebebebebebebebebebebebe"

const grantor = #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a"

const script = #"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

fn schedule() -> VestingDatum {
  VestingDatum {
    beneficiary,
    grantor,
    start: 1000,
    cliff: 0,
    duration: 100,
    released: 0,
  }
}

fn wallet_at(lovelace: Int, datum: VestingDatum) -> Output {
  Output {
    address: address.from_script(script),
    value: assets.from_lovelace(lovelace),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn midpoint_release() -> (OutputReference, Transaction) {
  let own_ref = OutputReference {
    transaction_id: #"0101010101010101010101010101010101010101010101010101010101010101",
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
      wallet_at(50_000_000, VestingDatum { ..schedule(), released: 50_000_000 }),
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
  vesting_wallet.spend(Some(schedule()), Release, own_ref, tx)
}

test spend_rejects_missing_datum() fail {
  let (own_ref, tx) = midpoint_release()
  vesting_wallet.spend(None, Release, own_ref, tx)
}
