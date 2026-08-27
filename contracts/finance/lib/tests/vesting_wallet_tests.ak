use aiken/interval
use cardano/address.{Address}
use cardano/assets.{Value}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use sources/vesting/schedule
use sources/vesting/types.{PosixTime, VestingDatum}
use sources/vesting/wallet

const beneficiary = #"bebebebebebebebebebebebebebebebebebebebebebebebebebebebe"

const stranger = #"babababababababababababababababababababababababababababa"

const own_script = #"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

const other_script = #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

const policy = #"70707070707070707070707070707070707070707070707070707070"

const start = 1000

const duration = 100

const total = 100_000_000

const half = 50_000_000

fn own_address() -> Address {
  address.from_script(own_script)
}

fn own_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"0101010101010101010101010101010101010101010101010101010101010101",
    output_index: 0,
  }
}

fn sibling_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"0202020202020202020202020202020202020202020202020202020202020202",
    output_index: 1,
  }
}

fn linear() -> VestingDatum {
  VestingDatum { beneficiary, start, cliff: 0, duration, released: 0 }
}

fn released(datum: VestingDatum, amount: Int) -> VestingDatum {
  VestingDatum { ..datum, released: amount }
}

fn ada(quantity: Int) -> Value {
  assets.from_lovelace(quantity)
}

fn with_token(value: Value, quantity: Int) -> Value {
  assets.merge(value, assets.from_asset(policy, "VEST", quantity))
}

fn wallet_input_at(
  ref: OutputReference,
  wallet_address: Address,
  datum: VestingDatum,
  value: Value,
) -> Input {
  Input {
    output_reference: ref,
    output: Output {
      address: wallet_address,
      value,
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn wallet_input(datum: VestingDatum, value: Value) -> Input {
  wallet_input_at(own_ref(), own_address(), datum, value)
}

fn continuing_output(datum: VestingDatum, value: Value) -> Output {
  Output {
    address: own_address(),
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn payout(value: Value) -> Output {
  Output {
    address: address.from_verification_key(beneficiary),
    value,
    datum: NoDatum,
    reference_script: None,
  }
}

fn tx(
  inputs: List<Input>,
  outputs: List<Output>,
  now: PosixTime,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs,
    outputs,
    validity_range: interval.after(now),
    extra_signatories: signatories,
  }
}

fn release_tx(
  datum: VestingDatum,
  locked: Int,
  next: VestingDatum,
  left: Int,
  now: PosixTime,
) -> Transaction {
  tx(
    [wallet_input(datum, ada(locked))],
    [continuing_output(next, ada(left)), payout(ada(locked - left))],
    now,
    [beneficiary],
  )
}

test schedule_vesting_math_with_cliff() {
  let datum = VestingDatum { ..linear(), cliff: 25 }

  and {
    schedule.is_valid(datum)?,
    schedule.vested(datum, total, start + 24) == 0,
    schedule.vested(datum, total, start + 50) == half,
    schedule.vested(datum, total, start + duration) == total,
  }
}

test release_partial_at_midpoint() {
  let datum = linear()

  wallet.release(
    datum,
    own_ref(),
    release_tx(datum, total, released(datum, half), half, start + 50),
  )
}

test release_full_exit_at_end() {
  let datum = linear()

  wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [payout(ada(total))],
      schedule.end(datum),
      [beneficiary],
    ),
  )
}

test cannot_full_exit_before_end() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [payout(ada(total))],
      schedule.end(datum) - 1,
      [beneficiary],
    ),
  )
}

test cannot_release_before_start() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    release_tx(datum, total, released(datum, 1), total - 1, start - 1),
  )
}

test cannot_release_without_advancing_counter() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    release_tx(datum, total, datum, half, start + 50),
  )
}

test cannot_split_wallet_across_two_outputs() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        continuing_output(released(datum, 25_000_000), ada(75_000_000)),
        continuing_output(released(datum, half), ada(half)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test cannot_skim_native_assets_on_partial_release() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 42))],
      [
        continuing_output(released(datum, half), with_token(ada(half), 1)),
        payout(with_token(ada(half), 41)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test cannot_release_without_beneficiary_signature() fail {
  let datum = linear()
  let base = release_tx(datum, total, released(datum, half), half, start + 50)

  wallet.release(
    datum,
    own_ref(),
    Transaction { ..base, extra_signatories: [stranger] },
  )
}

test cannot_release_without_validity_lower_bound() fail {
  let datum = linear()
  let base = release_tx(datum, total, released(datum, half), half, start + 50)

  wallet.release(
    datum,
    own_ref(),
    Transaction { ..base, validity_range: interval.everything },
  )
}

test cannot_release_with_two_wallet_inputs() fail {
  let datum = linear()

  wallet.release(
    datum,
    own_ref(),
    tx(
      [
        wallet_input(datum, ada(total)),
        wallet_input_at(sibling_ref(), own_address(), datum, ada(total)),
      ],
      [continuing_output(released(datum, half), ada(half)), payout(ada(half))],
      start + 50,
      [beneficiary],
    ),
  )
}

test cannot_change_script_address_on_partial_release() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        Output {
          address: address.from_script(other_script),
          value: ada(half),
          datum: InlineDatum(released(datum, half)),
          reference_script: None,
        },
        payout(ada(half)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}
