use aiken/interval
use cardano/address.{Address}
use cardano/assets.{Value}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use sources/vesting/linear_schedule
use sources/vesting/linear_types.{LinearVestingDatum, PosixTime}
use sources/vesting/linear_wallet

const beneficiary = #"bebebebebebebebebebebebebebebebebebebebebebebebebebebebe"

const grantor = #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a"

const own_script = #"6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d"

const policy = #"70707070707070707070707070707070707070707070707070707070"

const start = 1000

const total = 80_000_000

fn own_address() -> Address {
  address.from_script(own_script)
}

fn own_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"0303030303030303030303030303030303030303030303030303030303030303",
    output_index: 0,
  }
}

fn stepped() -> LinearVestingDatum {
  LinearVestingDatum {
    beneficiary,
    grantor,
    start,
    cliff: 0,
    period: 10,
    steps: 8,
    released: 0,
    asset: None,
    released_units: 0,
  }
}

fn stepped_with_cliff() -> LinearVestingDatum {
  LinearVestingDatum { ..stepped(), cliff: 30 }
}

fn released(datum: LinearVestingDatum, amount: Int) -> LinearVestingDatum {
  LinearVestingDatum { ..datum, released: amount }
}

fn ada(quantity: Int) -> Value {
  assets.from_lovelace(quantity)
}

fn with_token(value: Value, quantity: Int) -> Value {
  assets.merge(value, assets.from_asset(policy, "VEST", quantity))
}

fn wallet_input(datum: LinearVestingDatum, value: Value) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output {
      address: own_address(),
      value,
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn continuing_output(datum: LinearVestingDatum, value: Value) -> Output {
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
  datum: LinearVestingDatum,
  locked: Int,
  next: LinearVestingDatum,
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

test stepped_schedule_math() {
  let datum = stepped()

  and {
    linear_schedule.is_valid(datum)?,
    linear_schedule.vested(datum, total, start) == 0,
    linear_schedule.vested(datum, total, start + 10) == 10_000_000,
    linear_schedule.vested(datum, total, start + 19) == 10_000_000,
    linear_schedule.vested(datum, total, start + 30) == 30_000_000,
    linear_schedule.vested(datum, total, linear_schedule.end(datum)) == total,
  }
}

test cliff_catchup_unlocks_elapsed_steps() {
  let datum = stepped_with_cliff()

  and {
    linear_schedule.vested(datum, total, start + 29) == 0,
    linear_schedule.vested(datum, total, start + 30) == 30_000_000,
  }
}

test partial_release_on_step_boundary() {
  let datum = stepped()

  linear_wallet.release(
    datum,
    own_ref(),
    release_tx(
      datum,
      total,
      released(datum, 30_000_000),
      50_000_000,
      start + 30,
    ),
  )
}

test cannot_release_more_than_current_step_allows() {
  let datum = stepped()

  !linear_wallet.release(
    datum,
    own_ref(),
    release_tx(
      datum,
      total,
      released(datum, 40_000_000),
      40_000_000,
      start + 30,
    ),
  )
}

test cannot_release_again_within_same_period_without_new_step() {
  let datum = released(stepped(), 30_000_000)

  !linear_wallet.release(
    datum,
    own_ref(),
    release_tx(
      datum,
      50_000_000,
      released(datum, 30_000_001),
      49_999_999,
      start + 39,
    ),
  )
}

test full_exit_after_end() {
  let datum = stepped()

  linear_wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [payout(ada(total))],
      linear_schedule.end(datum),
      [beneficiary],
    ),
  )
}

fn vests_token(datum: LinearVestingDatum) -> LinearVestingDatum {
  LinearVestingDatum { ..datum, asset: Some((policy, "VEST")) }
}

fn released_both(
  datum: LinearVestingDatum,
  amount: Int,
  units: Int,
) -> LinearVestingDatum {
  LinearVestingDatum { ..datum, released: amount, released_units: units }
}

test stepped_native_assets_vest_proportionally() {
  let datum = vests_token(stepped())

  // One step of eight elapsed, so 100/8 = 12 units are releasable.
  linear_wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 100))],
      [
        continuing_output(
          released_both(datum, 10_000_000, 12),
          with_token(ada(70_000_000), 88),
        ),
        payout(with_token(ada(10_000_000), 12)),
      ],
      start + 10,
      [beneficiary],
    ),
  )
}

test cannot_skim_native_assets_on_partial_release() {
  let datum = vests_token(stepped())

  // 41 units claimed at the first step, where only 12 have vested.
  !linear_wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, with_token(ada(total), 100))],
      [
        continuing_output(
          released_both(datum, 10_000_000, 41),
          with_token(ada(70_000_000), 59),
        ),
        payout(with_token(ada(10_000_000), 41)),
      ],
      start + 10,
      [beneficiary],
    ),
  )
}

test invalid_linear_schedule_rejected() fail {
  let datum = LinearVestingDatum {
    beneficiary,
    grantor,
    start,
    cliff: 0,
    period: 0,
    steps: 8,
    released: 0,
    asset: None,
    released_units: 0,
  }

  linear_wallet.release(
    datum,
    own_ref(),
    release_tx(datum, total, released(datum, 1), total - 1, start + 10),
  )
}

// M-03 / L-01 mirrors. The stepped wallet shares `release`'s shape, so it needs
// the same guarantees asserted independently — the two modules are near-verbatim
// duplicates and will drift otherwise (report I-01d).
const stranger = #"babababababababababababababababababababababababababababa"

const spare_script = #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

fn to_stranger(value: Value) -> Output {
  Output {
    address: address.from_verification_key(stranger),
    value,
    datum: NoDatum,
    reference_script: None,
  }
}

fn beneficiary_input(value: Value) -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"0404040404040404040404040404040404040404040404040404040404040404",
      output_index: 3,
    },
    output: Output {
      address: address.from_verification_key(beneficiary),
      value,
      datum: NoDatum,
      reference_script: None,
    },
  }
}

test release_must_pay_the_beneficiary() {
  let datum = stepped()

  !linear_wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        continuing_output(released(datum, 40_000_000), ada(40_000_000)),
        to_stranger(ada(40_000_000)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test beneficiary_change_cannot_be_counted_as_payout() {
  let datum = stepped()

  !linear_wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total)), beneficiary_input(ada(total))],
      [
        continuing_output(released(datum, 40_000_000), ada(40_000_000)),
        to_stranger(ada(40_000_000)),
        payout(ada(total)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

test continuing_output_must_carry_no_reference_script() {
  let datum = stepped()

  !linear_wallet.release(
    datum,
    own_ref(),
    tx(
      [wallet_input(datum, ada(total))],
      [
        Output {
          ..continuing_output(released(datum, 40_000_000), ada(40_000_000)),
          reference_script: Some(spare_script),
        },
        payout(ada(40_000_000)),
      ],
      start + 50,
      [beneficiary],
    ),
  )
}

// M-05 mirrors for the stepped wallet.
fn broken_stepped() -> LinearVestingDatum {
  LinearVestingDatum { ..stepped(), period: 0 }
}

fn to_grantor(value: Value) -> Output {
  Output {
    address: address.from_verification_key(grantor),
    value,
    datum: NoDatum,
    reference_script: None,
  }
}

test grantor_can_reclaim_an_invalid_stepped_schedule() {
  let datum = broken_stepped()

  linear_wallet.reclaim_invalid(
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

test grantor_cannot_reclaim_a_valid_stepped_schedule() fail {
  let datum = stepped()

  linear_wallet.reclaim_invalid(
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

test stranger_cannot_reclaim_an_invalid_stepped_schedule() {
  let datum = broken_stepped()

  !linear_wallet.reclaim_invalid(
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

test stepped_reclaim_must_pay_the_grantor() {
  let datum = broken_stepped()

  !linear_wallet.reclaim_invalid(
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
