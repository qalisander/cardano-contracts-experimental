# Finance (Aiken)

This package introduces Cardano vesting wallets in the spirit of OpenZeppelin's
finance modules.

The implementation chooses a Cardano-first approach (datum-driven, unparameterized
validators) while borrowing the modular separation seen in Sui:

- `types`: datum and redeemer definitions.
- `schedule`: pure vesting math and time extraction.
- `wallet`: spending rules and value-conservation checks.
- `validator`: thin on-chain wrapper that dispatches `Release`.

The package now includes two schedule variants:

- time-linear vesting (`vesting_*` files)
- stepped-linear vesting (`linear_*` files)

## Layout

- `lib/sources/vesting/types.ak`: `VestingDatum`, `VestingRedeemer`
- `lib/sources/vesting/schedule.ak`: schedule math and helpers
- `lib/sources/vesting/wallet.ak`: release rules
- `lib/sources/vesting/linear_types.ak`: stepped datum and redeemer types
- `lib/sources/vesting/linear_schedule.ak`: stepped schedule math and helpers
- `lib/sources/vesting/linear_wallet.ak`: stepped release rules
- `lib/tests/vesting_wallet_tests.ak`: behavior tests (happy and failure paths)
- `lib/tests/linear_vesting_wallet_tests.ak`: stepped linear behavior tests
- `validators/vesting_wallet.ak`: spend handler + minimal plumbing tests
- `validators/linear_vesting_wallet.ak`: stepped spend handler + plumbing tests

## Semantics

- Schedule is linear with optional cliff.
- `total` is derived from live state as `locked + released`.
- Partial release keeps exactly one continuing output at the same script address.
- Partial release preserves non-ADA assets exactly.
- Full exit is allowed only when all remaining lovelace is releasable.
- Beneficiary signature and finite validity lower bound are required.

For stepped-linear schedules, vesting progresses in discrete steps controlled
by `period` and `steps`, with optional cliff gating.

## Run Tests

From repository root:

```sh
cd contracts/finance && aiken check
```

Run only the vesting test module:

```sh
cd contracts/finance && aiken check -m "tests/vesting_wallet_tests.{..}"
```

Run only the stepped-linear test module:

```sh
cd contracts/finance && aiken check -m "tests/linear_vesting_wallet_tests.{..}"
```
