# Access Control (Aiken)

This module is a Cardano/Aiken adaptation of OpenZeppelin's Sui `access_control.move` design:

- Root/default admin role controls role management by default.
- Each role has a configurable admin role.
- Grant/revoke/renounce operations are idempotent.
- Root role cannot be managed via generic role operations.

## Layout

- `lib/sources/access_control.ak`: role registry data model + transition functions.
- `lib/tests/access_control_tests.ak`: baseline behavior tests.

This package ships **no validators**. It is a library of pure state transitions
that your own validator enforces — see [Integrating this library](#integrating-this-library),
which you must read before embedding `AccessControl` in a datum.

## Run Tests

From the repository root:

```sh
cd contracts/access && aiken check
```

Run only the access-control test module:

```sh
cd contracts/access && aiken check -m "tests/access_control_tests.{..}"
```

From inside `contracts/access` (or any subdirectory):

```sh
cd ./contracts/access && aiken check
```

This folder is now a standalone Aiken package, so sources are discovered from
its local `lib/` and `validators/` directories.

## Integrating this library

**This library computes state transitions. It does not enforce them.** Every
function here is a pure function over `AccessControl`; nothing stops a
transaction from writing whatever successor state it likes. The guarantees below
hold only if your validator establishes them.

If you take one thing from this section: the redeemer should *name* the intended
next state, and the validator should *recompute it from this library and demand
equality*. That is what binds these transitions to the chain.

### 1. Authenticate the registry UTxO

Anyone can create a UTxO at your script address carrying any `AccessControl`
datum, naming themselves `default_admin`. Address alone is not identity. Mint a
one-shot beacon NFT — one that consumes a specific `OutputReference`, or it can be
minted again — and require it on the input:

```aiken
expect quantity_of(own_input.output.value, beacon_policy, beacon_name) == 1
```

Take the policy id as a **validator parameter**, not from the datum: parameters
are trusted, datum fields are not.

### 2. Constrain the continuing output

Locate your own input by the `OutputReference` the ledger supplies, permit
exactly one input at your payment credential, and require exactly one continuing
output that preserves the **full address** (payment *and* stake credential — a
payment-credential-only match is a staking-rights hijack), the whole value, and
`reference_script == None`.

### 3. Recompute and compare

```aiken
expect InlineDatum(raw) = continuing.datum
expect written: YourDatum = raw
expect Finite(now) = tx.validity_range.lower_bound.bound_type

// The transition itself is the authorization.
access_control.accept_default_admin_transfer(state.ac, now, tx) == access_control.Success(
  written.ac,
)
```

One redeemer constructor and one recompute-and-compare arm per supported
operation. Do not hand-write the successor state — if you assemble it yourself,
you are re-implementing the library's authorization checks and will diverge.

To prove `now >= T`, always read the validity range's **lower** bound. Using the
upper bound lets a caller declare a range far in the future.

### 4. Keep `roles` canonical

`roles` is wire-form `Pairs`, and `roles_of` lifts it into a `Dict` while
checking the ascending-unique-key invariant that lookups depend on. A malformed
registry **fails the script** rather than silently reporting a member as absent,
so your off-chain builder must emit entries sorted by ascending `Role` with no
duplicates. `Role` is a `ByteArray` compared bytewise — do not assume a generic
"canonical CBOR" mode produces that ordering.

Transitions computed by this library stay canonical automatically.

### 5. Handle a renounced root

`accept_default_admin_renounce` sets `default_admin` to `None`, after which
`has_role` for the root role is **false for every account**. A validator whose
only authorization path is the root role will then reject every spend, locking
whatever it guards.

Either forbid the renounced state in your transition check:

```aiken
expect written.ac.default_admin != None
```

or parameterize a recovery credential so the state is survivable:

```aiken
validator your_gate(recovery: VerificationKeyHash) {
  // ... or { tx_has_role(...), list.has(tx.extra_signatories, recovery) }
}
```

### 6. Bound registry growth

`roles` and each role's `members` are unbounded lists, re-parsed and scanned on
every spend. A registry that grows past the per-transaction ExUnits budget
becomes permanently unspendable, and the operation needed to shrink it is itself
a spend. Cap members per role, or give each `(role, account)` pair its own UTxO
with a membership NFT so a role check is a reference-input lookup whose cost is
independent of registry size.

### 7. A script cannot sign

`extra_signatories` holds verification-key hashes only, so every account in this
registry must be a key. If you need script-based authority, the eUTxO patterns
are the withdraw-zero trick, spending an authority UTxO, or a minted authority
token — none of which this library provides.

## Cardano-Specific Adaptation

Unlike Sui Move object entrypoints, this library models access control as pure state transitions over datum-like state:

- `AccessControl` is a plain data structure.
- Authorization is checked from transaction `extra_signatories`.
- Functions return either `Success(updated_state)` or `Failure(error)`.

## Current Scope

Implemented:

- `new`, `new_with_root`
- `has_role`, `tx_has_role`, `get_role_admin`, `roles_of`, `protected_root`
- `grant_role[_as]`, `revoke_role[_as]`, `renounce_role`
- `set_role_admin[_as]`
- Timelocked root-admin flow: `begin_default_admin_transfer`, `accept_default_admin_transfer`, `begin_default_admin_renounce`, `accept_default_admin_renounce`, `cancel_default_admin_transfer`
- Delay configuration + getters: `set_default_admin_delay[_as]`, `default_admin_delay_ms`, `pending_default_admin_*`
- Delayed delay-change flow: `begin_default_admin_delay_change[_as]`, `cancel_default_admin_delay_change[_as]`, `pending_default_admin_delay_change_*`, `default_admin_delay_ms_at`

Not yet implemented (for full Sui parity):

- Typed `Auth<Role>` witness equivalent.
- Home-module role typing restriction (Move `TypeName`-based invariant).

These can be added incrementally in the next iteration.
