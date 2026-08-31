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

const grantor = #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a"

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
  VestingDatum {
    beneficiary,
    grantor,
    start,
    cliff: 0,
    duration,
    released: 0,
    asset: None,
    released_units: 0,
  }
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

// M-04: the vested asset has its own ledger, on the same schedule as lovelace.
fn vests_token(datum: VestingDatum) -> VestingDatum {
  VestingDatum { ..datum, asset: Some((policy, "VEST")) }
}

fn released_both(datum: VestingDatum, amount: Int, units: Int) -> VestingDatum {
  VestingDatum { ..datum, released: amount, released_units: units }
}

test native_assets_vest_proportionally() {
  let datum = vests_token(linear())

  // 100 units locked, midpoint of the schedule, so 50 units are releasable.
  wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 100))],
      [
        continuing_output(
          released_both(datum, half, 50),
          with_token(ada(half), 50),
        ),
        payout(with_token(ada(half), 50)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test cannot_skim_native_assets_on_partial_release() {
  let datum = vests_token(linear())

  // 60 units claimed where only 50 have vested.
  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 100))],
      [
        continuing_output(
          released_both(datum, half, 60),
          with_token(ada(half), 40),
        ),
        payout(with_token(ada(half), 60)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test released_units_must_advance_with_the_claim() {
  let datum = vests_token(linear())

  // Units leave, but the counter is not advanced.
  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 100))],
      [
        continuing_output(
          released_both(datum, half, 0),
          with_token(ada(half), 50),
        ),
        payout(with_token(ada(half), 50)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test vested_units_must_reach_the_beneficiary() {
  let datum = vests_token(linear())

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 100))],
      [
        continuing_output(
          released_both(datum, half, 50),
          with_token(ada(half), 50),
        ),
        payout(ada(half)),
        to_stranger(assets.from_asset(policy, "VEST", 50)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test a_wallet_holding_an_unvested_asset_is_unspendable() fail {
  // `asset: None` but the UTxO carries tokens: nothing vests them, so `release`
  // refuses outright rather than letting them leave un-scheduled.
  let datum = linear()

  wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 42))],
      [
        continuing_output(released(datum, half), with_token(ada(half), 42)),
        payout(ada(half)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test grantor_can_reclaim_a_wallet_holding_an_unvested_asset() {
  let datum = linear()

  wallet.reclaim_invalid(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 42))],
      [to_grantor(with_token(ada(total), 42))],
      start,
      [grantor],
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

// M-03: released lovelace must reach the beneficiary, and the beneficiary's own
// change must not be counted as that payout.
fn to_stranger(value: Value) -> Output {
  Output {
    address: address.from_verification_key(stranger),
    value,
    datum: NoDatum,
    reference_script: None,
  }
}

fn beneficiary_input(ref: OutputReference, value: Value) -> Input {
  Input {
    output_reference: ref,
    output: Output {
      address: address.from_verification_key(beneficiary),
      value,
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn fee_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"0202020202020202020202020202020202020202020202020202020202020202",
    output_index: 7,
  }
}

test release_must_pay_the_beneficiary() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        continuing_output(released(datum, half), ada(half)),
        to_stranger(ada(half)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test full_exit_must_pay_the_beneficiary() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [to_stranger(ada(total))],
      schedule.end(datum),
      [beneficiary],
    ),
  )
}

test beneficiary_change_cannot_be_counted_as_payout() {
  // The subtle version: the builder spends a beneficiary-owned UTxO "for fees",
  // sends the released lovelace to a stranger, and returns change to the
  // beneficiary. Summing beneficiary outputs alone would accept this.
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [
        wallet_input(datum, ada(total)),
        beneficiary_input(fee_ref(), ada(total)),
      ],
      [
        continuing_output(released(datum, half), ada(half)),
        to_stranger(ada(half)),
        payout(ada(total)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test release_allows_the_beneficiary_to_pay_fees() {
  // Happy path with a real fee: the beneficiary funds the fee from their own UTxO
  // and receives the claim minus that fee.
  let datum = linear()
  let fee = 2_000_000
  let base = tx(
    [
      wallet_input(datum, ada(total)),
      beneficiary_input(fee_ref(), ada(10_000_000)),
    ],
    [
      continuing_output(released(datum, half), ada(half)),
      payout(ada(half + 10_000_000 - fee)),
    ],
    start + 50,
    [beneficiary],
  )

  wallet.release(datum, own_ref(), Transaction { ..base, fee })
}

test release_allows_the_payout_split_across_outputs() {
  let datum = linear()

  wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        continuing_output(released(datum, half), ada(half)),
        payout(ada(20_000_000)),
        payout(ada(30_000_000)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

// L-01: the continuing output must carry no reference script.
test continuing_output_must_carry_no_reference_script() {
  let datum = linear()

  !wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        Output {
          ..continuing_output(released(datum, half), ada(half)),
          reference_script: Some(other_script),
        },
        payout(ada(half)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

// M-05: an ill-formed schedule can never be spent via `Release`, so without a
// recovery arm the funds are lost. `reclaim_invalid` is the only path out, and it
// must be unreachable for a well-formed grant.
fn broken() -> VestingDatum {
  VestingDatum { ..linear(), duration: 0 }
}

fn to_grantor(value: Value) -> Output {
  Output {
    address: address.from_verification_key(grantor),
    value,
    datum: NoDatum,
    reference_script: None,
  }
}

test grantor_can_reclaim_an_invalid_schedule() {
  let datum = broken()

  wallet.reclaim_invalid(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [to_grantor(ada(total))],
      start,
      [grantor],
    ),
  )
}

// The guard aborts the script rather than returning False, hence `fail`.
test grantor_cannot_reclaim_a_valid_schedule() fail {
  let datum = linear()

  wallet.reclaim_invalid(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [to_grantor(ada(total))],
      start,
      [grantor],
    ),
  )
}

test stranger_cannot_reclaim_an_invalid_schedule() {
  let datum = broken()

  !wallet.reclaim_invalid(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [to_stranger(ada(total))],
      start,
      [stranger],
    ),
  )
}

test reclaim_must_pay_the_grantor() {
  let datum = broken()

  !wallet.reclaim_invalid(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [to_stranger(ada(total))],
      start,
      [grantor],
    ),
  )
}

test reclaim_cannot_leave_value_at_the_script() {
  let datum = broken()

  !wallet.reclaim_invalid(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [continuing_output(datum, ada(half)), to_grantor(ada(half))],
      start,
      [grantor],
    ),
  )
}

test release_still_rejects_an_invalid_schedule() fail {
  let datum = broken()

  wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [payout(ada(total))],
      start + 1_000_000,
      [beneficiary],
    ),
  )
}
