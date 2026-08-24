# Access Control (Aiken)

This module is a Cardano/Aiken adaptation of OpenZeppelin's Sui `access_control.move` design:

- Root/default admin role controls role management by default.
- Each role has a configurable admin role.
- Grant/revoke/renounce operations are idempotent.
- Root role cannot be managed via generic role operations.

## Layout

- `contracts/access/sources/access_control.ak`: role registry data model + transition functions.
- `contracts/access/tests/access_control_tests.ak`: baseline behavior tests.
- `contracts/access/examples/root_admin_gate.ak`: minimal validator example that gates spending to root-admin signers.

## Run Tests

From the repository root:

```sh
aiken check
```

Run only the access-control test module:

```sh
aiken check -m "contracts/access/tests/access_control_tests.{..}"
```

From inside `contracts/access` (or any subdirectory):

```sh
cd /Users/qalisander/source/open-zeppelin/cardano-contracts && aiken check
```

Note: Aiken discovers sources/tests from standard project roots (`lib/` and
`validators/`). This repository keeps the OpenZeppelin-style layout under
`contracts/access/` and mirrors discoverable modules accordingly.

## Cardano-Specific Adaptation

Unlike Sui Move object entrypoints, this library models access control as pure state transitions over datum-like state:

- `AccessControl` is a plain data structure.
- Authorization is checked from transaction `extra_signatories`.
- Functions return either `Success(updated_state)` or `Failure(error)`.

## Current Scope

Implemented:

- `new`, `new_with_root`
- `has_role`, `get_role_admin`, `assert_has_role`
- `grant_role[_as]`, `revoke_role[_as]`, `renounce_role[_as]`
- `set_role_admin[_as]`
- `transfer_default_admin[_as]`, `renounce_default_admin[_as]`
- Timelocked root-admin flow: `begin_default_admin_transfer`, `accept_default_admin_transfer`, `begin_default_admin_renounce`, `accept_default_admin_renounce`, `cancel_default_admin_transfer`
- Delay configuration + getters: `set_default_admin_delay[_as]`, `default_admin_delay_ms`, `pending_default_admin_*`
- Delayed delay-change flow: `begin_default_admin_delay_change[_as]`, `cancel_default_admin_delay_change[_as]`, `pending_default_admin_delay_change_*`, `default_admin_delay_ms_at`

Not yet implemented (for full Sui parity):

- Typed `Auth<Role>` witness equivalent.
- Home-module role typing restriction (Move `TypeName`-based invariant).

These can be added incrementally in the next iteration.
