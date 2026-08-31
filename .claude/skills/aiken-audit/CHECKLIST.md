# eUTxO / Aiken Vulnerability Checklist

Phase 2 sweep. Walk **every** item. For each, emit exactly one of:

- `APPLIES → <finding ID>` — becomes a finding; IDs are `<severity-letter>-<NN>`
  (`C`/`H`/`M`/`L`/`I`), numbered from `01` within each severity class, e.g. `H-01`, `M-02`
- `MITIGATED → file.ak:line` — cite the specific line that blocks it
- `N/A → <one-line reason>`

No item may be skipped, and no item may be left blank.

---

## A. eUTxO structural (highest yield — start here)

**A1. Double satisfaction.** One output satisfying two validators, two script inputs, or a validator
*and* a minting policy in the same transaction. Test each variant explicitly:
(a) two UTxOs at the same script address spent together, both "paid" by one output;
(b) this script spent alongside a *different* protocol's script that pays the same beneficiary;
(c) the spend handler and the mint handler of the same validator satisfied by one output;
(d) the beneficiary's own wallet output double-counted.
Mitigations to look for: restricting to exactly one script input (`expect [_] = filter …` — check it
filters on the right thing: payment credential vs. full address vs. own `OutputReference`), output
tagging by datum, beacon/state tokens, or explicit output indexing via the redeemer (**and** then
validating that index).

**A2. Multiple satisfaction / batching.** If N script inputs are permitted, does each get its own
distinct output? Sum-based checks (`total_out >= total_in`) are frequently exploitable when
schedules or beneficiaries differ per UTxO.

**A3. Trust No UTxO.** *Anyone can create a UTxO at the script address with any datum.* Which checks
break if a forged UTxO with a hand-crafted datum is spent, used as a reference input, or placed as a
decoy that the validator's `filter`/`find` picks up? Is there a beacon/state NFT authenticating
genuine UTxOs?

**A4. Own-input identification.** Does `spend` locate its own input via the supplied
`OutputReference` (not `list.head(inputs)`, not "the first script input", not by address)? Is the
*actual* input's value used for accounting, rather than a value inferred from the datum?

**A5. Continuing-output authentication.** Is the continuing output matched by **full address**
(payment *and* stake credential) or just payment credential? Payment-credential-only matching is a
**staking-rights hijack**: the attacker redirects the stake part to their own credential and farms
the rewards. Also: is exactly one continuing output enforced, or can state be *split* into many
(schedule splitting / accounting duplication) or *merged*?

**A6. Datum hijacking.** Can the next datum be crafted so a legitimate-looking transition steals
value or resets state? Is the next datum checked **field by field** (or by full structural equality
against `Datum { ..old, changed_field: new }`) so unmentioned fields provably cannot move? Any field
left unconstrained is a finding.

**A7. Value preservation.** Lovelace *and* every native asset. `assets.lovelace_of` alone leaks
tokens; `without_lovelace(a) == without_lovelace(b)` alone leaks ADA. Check both directions, and
check assets cannot be *added* either (see A9).

**A8. Output ordering / count assumptions.** Any reliance on `outputs` order, on `list.head`,
`list.at(i)`, or on there being exactly N outputs, without validating it.

**A9. Unbounded value & dust-token DoS.** Can an attacker add junk native assets to a script UTxO
(or to the continuing output) so it approaches the 5000-byte value limit, or so min-ADA makes the
remaining lovelace unspendable? Same for **unbounded datum size** (`List`/`ByteArray`/`Dict` fields)
and **unbounded list iteration** over `inputs`/`outputs`/`mint` → ExUnits exhaustion. Result:
permanent lock or protocol stall.

**A10. Reference-script injection.** Is `reference_script` on the continuing output constrained to
`None`? If not, an attacker inflates the UTxO (min-ADA, fees, size) — griefing or lock.

**A11. Locked value.** Is there always a path out for every reachable state? Check terminal states,
the rounding remainder, and states reachable only via an attacker-crafted datum.

**A12. UTxO contention.** A single global/config UTxO that every interaction must consume → cheap
DoS by an adversary who repeatedly spends it. Also cheap-spam: can an attacker create UTxOs the
protocol must later iterate over?

**A13. Min-ADA.** Can a legitimate transition produce an output below min-ADA (transaction
unbuildable) — effectively locking the tail of a schedule?

## B. Authorisation

**B14. Signature checks.** Is `extra_signatories` actually checked, against the right key, from a
*trusted* source? A `beneficiary`/`owner`/`admin` field read out of an unauthenticated datum
authorises nothing. Note: **a script cannot appear in `extra_signatories`** — if script-based
authority is intended, the only correct patterns are the withdraw-0 trick, spending an authority
UTxO, or a minted authority token. Flag any design that expects a script to "sign".

**B15. Withdraw-zero / staking-validator forwarding.** If used as an authorisation mechanism, is the
withdraw handler itself authorised, and is the *right* credential's presence in `tx.withdrawals`
checked (not just non-emptiness)? If a `withdraw` handler exists, can it be invoked with zero
rewards to bypass a check elsewhere?

**B16. Redeemer soundness.** Is the redeemer match exhaustive? Is there a branch that trivially
returns `True`? Can a UTxO be spent under a *different* redeemer than the design assumes (the "other
redeemer" attack) — including via a second script input with a permissive redeemer? Is redeemer data
trusted anywhere without validation?

**B17. Handler coordination.** For multi-purpose validators (`spend` + `mint` + `withdraw` + …), can
one handler satisfy the intent of another? Is the `else(_)` fallback `fail`? A fallback that does
anything other than `fail` needs a written justification.

**B18. Validator parameters vs. datum.** Values baked in as parameters are trusted; values in the
datum are not. Flag every place the code treats a datum field with parameter-level trust.

**B19. Reference-input / oracle authentication.** Is every reference input authenticated by an NFT or
a parameterised script hash? Is oracle data checked for **freshness** against the validity range?
Can the price/rate be manipulated within a single transaction?

## C. Tokens & minting

**C20. Unrestricted minting**; missing authorisation on the mint path.

**C21. Token name not validated** — policy authorises *a* mint and the attacker mints a *different*
asset name under the same policy ("other-token minting"). Check the mint field is validated
*exhaustively*, not just "contains the expected asset".

**C22. Quantity sign and burn path.** Are negative quantities handled? Is burning permitted where it
should not be, or impossible where it must be? Is `quantity_of` reading the mint field vs. an
output's value confused anywhere (double counting)?

**C23. One-shot NFT policies** that don't actually consume a specific `OutputReference` → infinite
mint of a "unique" beacon, which collapses every beacon-based mitigation above.

**C24. Asset-name construction / hash collisions.** Names built by concatenating attacker-influenced
byte strings can collide (self-collision). CIP-68 reference/user token pairing consistency.

## D. Time

**D25. Wrong bound.** Deadline enforcement must use the bound that is conservative *against* the
attacker: to prove "now ≥ T" use the **lower** bound; to prove "now ≤ T" use the **upper** bound.
Using the wrong one lets an attacker declare a validity range far in the future/past.

**D26. Unbounded or absent range.** Is a range with `NegativeInfinity`/`PositiveInfinity` rejected
where a concrete bound is required? Is `is_inclusive` on the bound respected (off-by-one at the
exact boundary)?

**D27. Range width.** Is an absurdly wide validity range accepted where it shouldn't be?

**D28. POSIX-time vs. slot** conversion assumptions; `PosixTime` in milliseconds vs. seconds
mismatches between datum, tests, and off-chain code.

## E. Arithmetic & logic

**E29. Integer division rounding direction.** Verify Aiken's `/` semantics (truncation toward
negative infinity for negative operands). Does rounding favour the protocol or the claimant? Compute
the exact dust per operation and whether repeated claims accumulate a leak or a lock.

**E30. Repeated-claim / salami attack.** Can the schedule be advanced in many tiny steps to extract
more (or strand more) than one big step? Compare `sum of many claims` vs `one claim` explicitly.

**E31. Division by zero** on any denominator sourced from datum or redeemer (e.g. `duration = 0`).

**E32. Negatives.** Aiken `Int` is arbitrary-precision (no overflow), so the real risk is **negative**
values from datum/redeemer flowing into value or time arithmetic, and subtraction producing a
negative that then passes a `<=` check.

**E33. Boundary conditions.** Exactly at cliff, exactly at end, `released == total`, `locked == 0`,
first step, last step, single-step schedule.

**E34. Monotonicity.** Can accumulated state (e.g. `released`) go *down*, or stay flat while value
leaves?

**E35. Partial patterns.** Every `expect` on attacker-controlled data is a **DoS surface**: if an
adversary can force it to fail, they lock the UTxO. Enumerate each `expect`, `list.head`, `list.at`,
and non-exhaustive `when`, and ask who controls the failure.

## F. Aiken / Plutus V3 language specifics

**F36. `expect x: T = data` is a structural coercion, not a validation.** Any `Data` matching the
shape is accepted, including one with extra/absurd field values. Every field still needs semantic
validation afterwards.

**F37. Datum form.** Does the code handle only `InlineDatum`? Then a `DatumHash` or `NoDatum` UTxO at
the address may be unspendable (lock) — or, if the code *accepts* `NoDatum`, unauthenticated.

**F38. `Pairs` are association lists, not maps.** `tx.redeemers`, `tx.mint`, `tx.withdrawals`,
`tx.datums` — duplicate keys are representable and ordering assumptions may not hold. Flag any
`list.find`/index-based access over these that assumes uniqueness or canonical order.

**F39. Traces are stripped in release builds** — no logic may depend on them. `?` operators left in
hot paths inflate ExUnits.

**F40. `aiken.toml` hygiene:** correct `plutusVersion`, pinned stdlib, no dependency on an unaudited
third-party package.

**F41. Dead / unreachable branches, unused validator parameters** (a parameter that never affects
behaviour signals a missing check), redundant always-true conditions.

## G. Protocol & economic

**G42. Front-running / tx-ordering.** The eUTxO analogue: an adversary observes your intended
transaction and spends one of its inputs first (griefing), or races to consume a shared UTxO on
better terms. Which flows are vulnerable, and is there first-come advantage worth money?

**G43. Replay & instance separation.** Nothing binds a script to a network or deployment unless
parameterised. Can a datum/signature/authorisation from one instance be replayed against another? Is
there a nonce or unique identifier where one is needed?

**G44. Upgrade & recovery.** Is there an admin path? If yes, audit it as the most dangerous code in
the repo (unilateral fund extraction, silent parameter change). If no, is that intentional given
A11?

**G45. Incentive check.** For each finding, state attacker cost (fees, capital) vs. gain. A
profitable attack outranks a merely possible one.

## H. Web3-general classes, translated

Access control, oracle manipulation, price manipulation, signature replay, integer edge cases, DoS,
griefing, upgrade risk, economic design — all covered above in eUTxO form. Confirm each was
considered.

Explicitly mark **reentrancy**, **`msg.sender`-style caller identity**, **`delegatecall`**, and
**storage collisions** as *not applicable to eUTxO*, so the reader knows they were ruled out rather
than forgotten.
