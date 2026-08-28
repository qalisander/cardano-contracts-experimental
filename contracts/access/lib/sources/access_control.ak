use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{Transaction}

/// Role-based access control primitives for Cardano contracts in Aiken.
///
/// This module adapts OpenZeppelin-style AccessControl semantics to the eUTxO
/// model by storing authorization state in plain data and checking transaction
/// signers when mutating state.
///
/// Structural invariants:
/// 1. Root role membership is stored only in `default_admin`.
/// 2. Non-root roles are stored in `roles` and are root-administered by default.
/// 3. Root role transfer and renounce are timelocked through pending actions.
/// 4. `DEFAULT_ADMIN_ROLE` is reserved: it can never be held as a non-root role,
///    even when the registry uses a custom root role.
/// Role identifier.
pub type Role =
  ByteArray

/// Default root role key, equivalent to OpenZeppelin's default admin role.
pub const default_admin_role = "DEFAULT_ADMIN_ROLE"

/// Upper bound for default admin delay in milliseconds (60 days).
pub const max_default_admin_delay_ms_value = 60 * 24 * 60 * 60 * 1000

/// Cap for how long a delay increase must wait before taking effect (48 hours).
pub const max_delay_increase_wait_ms_value = 48 * 60 * 60 * 1000

/// Access control state, intended to be embedded in contract datum/state.
pub type AccessControl {
  AccessControl {
    /// Canonical identifier of the root role.
    root_role: Role,
    /// Non-root role map. Root role membership is stored in `default_admin`.
    roles: Dict<Role, RoleData>,
    /// Current root role holder.
    default_admin: Option<VerificationKeyHash>,
    /// Pending root transfer (`Some(new_admin)`) or renounce (`None`).
    pending_default_admin: Option<PendingAdminTransfer>,
    /// Pending change to `default_admin_delay_ms`.
    pending_default_admin_delay_change: Option<PendingDelayChange>,
    /// Active timelock in milliseconds for root transfer and renounce.
    default_admin_delay_ms: Int,
  }
}

/// Per-role membership and admin role pointer.
pub type RoleData {
  RoleData {
    /// Accounts currently holding the role.
    members: List<VerificationKeyHash>,
    /// Role required to grant/revoke this role.
    admin_role: Role,
  }
}

/// Pending root transfer or renounce action.
pub type PendingAdminTransfer {
  PendingAdminTransfer {
    /// Pending transfer target. `None` means pending renounce.
    new_admin: Option<VerificationKeyHash>,
    /// Millisecond timestamp after which accept is allowed.
    execute_after_ms: Int,
  }
}

/// Pending change to the default admin delay.
pub type PendingDelayChange {
  PendingDelayChange {
    /// Proposed `default_admin_delay_ms`.
    new_delay_ms: Int,
    /// Millisecond timestamp when `new_delay_ms` becomes active.
    schedule_after_ms: Int,
  }
}

/// Errors returned by access control state transitions.
pub type AccessControlError {
  /// Caller or signer set does not satisfy authorization requirements.
  Unauthorized
  /// Role is reserved and cannot be managed with generic role operations:
  /// either the registry's root role, or the `DEFAULT_ADMIN_ROLE` identifier.
  CannotManageRootRole
  /// Operation expected a signer, but none matched the constraints.
  MissingSigner
  /// No pending root transfer/renounce exists.
  NoPendingAdminTransfer
  /// Caller is not the pending new admin.
  NotPendingAdmin
  /// Pending action timelock has not elapsed yet.
  DelayNotElapsed
  /// Pending action is renounce, not transfer.
  NotPendingTransfer
  /// Pending action is transfer, not renounce.
  NotPendingRenounce
  /// Delay value exceeds allowed bounds.
  DelayTooLarge
  /// Transfer target equals the current default admin.
  DefaultAdminTransferToSelf
  /// No active pending delay change exists.
  NoPendingDelayChange
}

/// Result type for all state-mutating operations.
pub type AccessControlResult {
  Success(AccessControl)
  Failure(AccessControlError)
}

/// Create a registry with DEFAULT_ADMIN_ROLE as root role.
///
/// Parameters:
/// - `initial_admin`: account that receives the root role.
/// Returns:
/// - A new `AccessControl` using `DEFAULT_ADMIN_ROLE` as root role.
/// Errors:
/// - None.
pub fn new(initial_admin: VerificationKeyHash) -> AccessControl {
  new_with_root(default_admin_role, initial_admin)
}

/// Create a registry with a custom root role identifier.
///
/// Parameters:
/// - `root_role`: custom identifier to treat as root role.
/// - `initial_admin`: account that receives the root role.
/// Returns:
/// - A new `AccessControl` initialized with the provided root role.
/// Errors:
/// - None.
pub fn new_with_root(
  root_role: Role,
  initial_admin: VerificationKeyHash,
) -> AccessControl {
  AccessControl {
    root_role,
    roles: dict.empty,
    default_admin: Some(initial_admin),
    pending_default_admin: None,
    pending_default_admin_delay_change: None,
    default_admin_delay_ms: 0,
  }
}

/// Return the root role identifier guarded by this registry.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - The root role identifier protected by this registry.
/// Errors:
/// - None.
pub fn protected_root(ac: AccessControl) -> Role {
  ac.root_role
}

/// Return the current default admin, if one exists.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - `Some(account)` when a default admin exists, otherwise `None`.
/// Errors:
/// - None.
pub fn default_admin(ac: AccessControl) -> Option<VerificationKeyHash> {
  ac.default_admin
}

/// Return the maximum allowed root-admin delay in milliseconds.
///
/// Parameters:
/// - None.
/// Returns:
/// - Maximum allowed root-admin delay in milliseconds.
/// Errors:
/// - None.
pub fn max_default_admin_delay_ms() -> Int {
  max_default_admin_delay_ms_value
}

/// Return the maximum wait applied to delay increases.
///
/// Parameters:
/// - None.
/// Returns:
/// - Maximum wait applied before a delay increase becomes active.
/// Errors:
/// - None.
pub fn max_delay_increase_wait_ms() -> Int {
  max_delay_increase_wait_ms_value
}

/// Return the currently stored root-admin delay in milliseconds.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - Stored `default_admin_delay_ms` value.
/// Errors:
/// - None.
pub fn default_admin_delay_ms(ac: AccessControl) -> Int {
  ac.default_admin_delay_ms
}

/// Return the effective root-admin delay at a given timestamp.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// - `now_ms`: current timestamp in milliseconds.
/// Returns:
/// - Effective delay at `now_ms`, including elapsed pending delay changes.
/// Errors:
/// - None.
pub fn default_admin_delay_ms_at(ac: AccessControl, now_ms: Int) -> Int {
  effective_default_admin_delay_ms(ac, now_ms)
}

/// Return true when any pending root transfer or renounce exists.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - `True` when a pending root transfer or renounce exists.
/// Errors:
/// - None.
pub fn has_pending_default_admin_transfer(ac: AccessControl) -> Bool {
  ac.pending_default_admin != None
}

/// Return true only when the pending root action is a renounce.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - `True` only when the pending root action is a renounce.
/// Errors:
/// - None.
pub fn is_pending_default_admin_renounce(ac: AccessControl) -> Bool {
  when ac.pending_default_admin is {
    Some(pending) -> pending.new_admin == None
    None -> False
  }
}

/// Return the pending root transfer target, if one exists.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - `Some(account)` when a transfer is pending; `None` otherwise.
/// Errors:
/// - None.
pub fn pending_default_admin_new_admin(
  ac: AccessControl,
) -> Option<VerificationKeyHash> {
  when ac.pending_default_admin is {
    Some(pending) -> pending.new_admin
    None -> None
  }
}

/// Return when the pending root action becomes executable.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// Returns:
/// - `Some(timestamp_ms)` when a root action is pending; `None` otherwise.
/// Errors:
/// - None.
pub fn pending_default_admin_execute_after_ms(ac: AccessControl) -> Option<Int> {
  when ac.pending_default_admin is {
    Some(pending) -> Some(pending.execute_after_ms)
    None -> None
  }
}

/// Return true when an active pending delay change exists.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// - `now_ms`: current timestamp in milliseconds.
/// Returns:
/// - `True` while a pending delay change exists and is still active.
/// Errors:
/// - None.
pub fn has_pending_default_admin_delay_change(
  ac: AccessControl,
  now_ms: Int,
) -> Bool {
  has_active_pending_default_admin_delay_change(ac, now_ms)
}

/// Return the proposed new delay for an active pending change.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// - `now_ms`: current timestamp in milliseconds.
/// Returns:
/// - `Some(new_delay_ms)` for an active pending delay change, otherwise `None`.
/// Errors:
/// - None.
pub fn pending_default_admin_delay_change_new_delay_ms(
  ac: AccessControl,
  now_ms: Int,
) -> Option<Int> {
  when ac.pending_default_admin_delay_change is {
    None -> None
    Some(pending) ->
      if now_ms >= pending.schedule_after_ms {
        None
      } else {
        Some(pending.new_delay_ms)
      }
  }
}

/// Return when the active pending delay change takes effect.
///
/// Parameters:
/// - `ac`: registry to inspect.
/// - `now_ms`: current timestamp in milliseconds.
/// Returns:
/// - `Some(timestamp_ms)` when a pending delay change is still active, otherwise `None`.
/// Errors:
/// - None.
pub fn pending_default_admin_delay_change_schedule_after_ms(
  ac: AccessControl,
  now_ms: Int,
) -> Option<Int> {
  when ac.pending_default_admin_delay_change is {
    None -> None
    Some(pending) ->
      if now_ms >= pending.schedule_after_ms {
        None
      } else {
        Some(pending.schedule_after_ms)
      }
  }
}

/// Set the root-admin delay immediately, using an explicit actor account.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `new_delay_ms`: new root-admin delay in milliseconds.
/// - `actor`: account attempting the update.
/// Returns:
/// - `Success(updated)` when actor is root role holder and delay is in range.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `DelayTooLarge` when delay is negative or above the configured maximum.
/// - `Unauthorized` when actor does not hold the root role.
pub fn set_default_admin_delay_as(
  ac: AccessControl,
  new_delay_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if new_delay_ms < 0 || new_delay_ms > max_default_admin_delay_ms_value {
    Failure(DelayTooLarge)
  } else {
    if has_role(ac, ac.root_role, actor) {
      Success(
        AccessControl {
          root_role: ac.root_role,
          roles: ac.roles,
          default_admin: ac.default_admin,
          pending_default_admin: ac.pending_default_admin,
          pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
          default_admin_delay_ms: new_delay_ms,
        },
      )
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Set the root-admin delay immediately, deriving actor from transaction signers.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `new_delay_ms`: new root-admin delay in milliseconds.
/// - `tx`: transaction whose signers authorize the action.
/// Returns:
/// - `Success(updated)` when an authorized root signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when no signer with root role is present.
/// - `DelayTooLarge` propagated from `set_default_admin_delay_as`.
pub fn set_default_admin_delay(
  ac: AccessControl,
  new_delay_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when role_signer(ac, tx, ac.root_role) is {
    Some(actor) -> set_default_admin_delay_as(ac, new_delay_ms, actor)
    None -> Failure(Unauthorized)
  }
}

/// Schedule a delayed change to default_admin_delay_ms using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `new_delay_ms`: proposed new root-admin delay.
/// - `now_ms`: current timestamp in milliseconds.
/// - `actor`: account attempting the update.
/// Returns:
/// - `Success(updated)` with a scheduled delay change when authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `DelayTooLarge` when delay is negative or above the configured maximum.
/// - `Unauthorized` when actor does not hold the root role.
pub fn begin_default_admin_delay_change_as(
  ac: AccessControl,
  new_delay_ms: Int,
  now_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if new_delay_ms < 0 || new_delay_ms > max_default_admin_delay_ms_value {
    Failure(DelayTooLarge)
  } else {
    if has_role(ac, ac.root_role, actor) {
      let ac0 = refresh_default_admin_delay(ac, now_ms)
      let current = ac0.default_admin_delay_ms
      let wait = if new_delay_ms > current {
        min_int(new_delay_ms, max_delay_increase_wait_ms_value)
      } else {
        current - new_delay_ms
      }

      Success(
        AccessControl {
          root_role: ac0.root_role,
          roles: ac0.roles,
          default_admin: ac0.default_admin,
          pending_default_admin: ac0.pending_default_admin,
          pending_default_admin_delay_change: Some(
            PendingDelayChange {
              new_delay_ms,
              schedule_after_ms: now_ms + wait,
            },
          ),
          default_admin_delay_ms: ac0.default_admin_delay_ms,
        },
      )
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Schedule a delayed change to default_admin_delay_ms using transaction signers.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `new_delay_ms`: proposed new root-admin delay.
/// - `now_ms`: current timestamp in milliseconds.
/// - `tx`: transaction whose signers authorize the action.
/// Returns:
/// - `Success(updated)` when an authorized root signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when no signer with root role is present.
/// - `DelayTooLarge` propagated from `begin_default_admin_delay_change_as`.
pub fn begin_default_admin_delay_change(
  ac: AccessControl,
  new_delay_ms: Int,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when role_signer(ac, tx, ac.root_role) is {
    Some(actor) ->
      begin_default_admin_delay_change_as(ac, new_delay_ms, now_ms, actor)
    None -> Failure(Unauthorized)
  }
}

/// Cancel an active pending delay change using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `actor`: account attempting cancellation.
/// Returns:
/// - `Success(updated)` when cancellation is allowed.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `NoPendingDelayChange` when no active pending change exists.
/// - `Unauthorized` when actor does not hold the root role.
pub fn cancel_default_admin_delay_change_as(
  ac: AccessControl,
  now_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if !has_active_pending_default_admin_delay_change(ac, now_ms) {
    Failure(NoPendingDelayChange)
  } else {
    if has_role(ac, ac.root_role, actor) {
      Success(
        AccessControl {
          root_role: ac.root_role,
          roles: ac.roles,
          default_admin: ac.default_admin,
          pending_default_admin: ac.pending_default_admin,
          pending_default_admin_delay_change: None,
          default_admin_delay_ms: ac.default_admin_delay_ms,
        },
      )
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Cancel an active pending delay change using transaction signers.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `tx`: transaction whose signers authorize cancellation.
/// Returns:
/// - `Success(updated)` when an authorized root signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when no signer with root role is present.
/// - `NoPendingDelayChange` propagated from `cancel_default_admin_delay_change_as`.
pub fn cancel_default_admin_delay_change(
  ac: AccessControl,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when role_signer(ac, tx, ac.root_role) is {
    Some(actor) -> cancel_default_admin_delay_change_as(ac, now_ms, actor)
    None -> Failure(Unauthorized)
  }
}

/// Return true when account currently holds role.
///
/// Parameters:
/// - `ac`: registry to query.
/// - `role`: role identifier to check.
/// - `account`: account to test membership for.
/// Returns:
/// - `True` when account currently holds role.
/// Errors:
/// - None.
pub fn has_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
) -> Bool {
  if role == ac.root_role {
    ac.default_admin == Some(account)
  } else {
    when dict.get(ac.roles, role) is {
      Some(role_data) -> list.has(role_data.members, account)
      None -> False
    }
  }
}

/// Return the role that administers role.
///
/// Parameters:
/// - `ac`: registry to query.
/// - `role`: role identifier to inspect.
/// Returns:
/// - Admin role for `role`, defaulting to root role when unconfigured.
/// Errors:
/// - None.
pub fn get_role_admin(ac: AccessControl, role: Role) -> Role {
  if role == ac.root_role {
    ac.root_role
  } else {
    when dict.get(ac.roles, role) is {
      Some(role_data) -> role_data.admin_role
      None -> ac.root_role
    }
  }
}

/// Convenience predicate for role-gated call sites and validators.
///
/// Parameters:
/// - `ac`: registry to query.
/// - `role`: role identifier to check.
/// - `account`: account to test membership for.
/// Returns:
/// - Same boolean result as `has_role`.
/// Errors:
/// - None.
pub fn assert_has_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
) -> Bool {
  has_role(ac, role, account)
}

/// Return true when at least one transaction signer currently holds role.
///
/// Parameters:
/// - `ac`: registry to query.
/// - `tx`: transaction whose signers are checked.
/// - `role`: role identifier to check.
/// Returns:
/// - `True` when at least one signer currently holds `role`.
/// Errors:
/// - None.
pub fn tx_has_role(ac: AccessControl, tx: Transaction, role: Role) -> Bool {
  signer_has_role(ac, tx, role)
}

/// Grant role using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role to grant.
/// - `account`: target account to receive role.
/// - `actor`: account attempting the grant.
/// Returns:
/// - `Success(updated)` when grant is authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `Unauthorized` when actor lacks role admin rights.
pub fn grant_role_as(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    let admin_role = get_role_admin(ac, role)
    if has_role(ac, admin_role, actor) {
      Success(grant_role_unchecked(ac, role, account))
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Grant role when any signer holds the role admin.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role to grant.
/// - `account`: target account to receive role.
/// - `tx`: transaction whose signers authorize the grant.
/// Returns:
/// - `Success(updated)` when an authorized role-admin signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `Unauthorized` when no signer has role admin rights.
pub fn grant_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  tx: Transaction,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    let admin_role = get_role_admin(ac, role)
    if signer_has_role(ac, tx, admin_role) {
      Success(grant_role_unchecked(ac, role, account))
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Revoke role using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role to revoke.
/// - `account`: target account to lose role.
/// - `actor`: account attempting the revoke.
/// Returns:
/// - `Success(updated)` when revoke is authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `Unauthorized` when actor lacks role admin rights.
pub fn revoke_role_as(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    let admin_role = get_role_admin(ac, role)
    if has_role(ac, admin_role, actor) {
      Success(revoke_role_unchecked(ac, role, account))
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Revoke role when any signer holds the role admin.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role to revoke.
/// - `account`: target account to lose role.
/// - `tx`: transaction whose signers authorize the revoke.
/// Returns:
/// - `Success(updated)` when an authorized role-admin signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `Unauthorized` when no signer has role admin rights.
pub fn revoke_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  tx: Transaction,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    let admin_role = get_role_admin(ac, role)
    if signer_has_role(ac, tx, admin_role) {
      Success(revoke_role_unchecked(ac, role, account))
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Renounce role for an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role to renounce.
/// - `actor`: account that renounces membership.
/// Returns:
/// - `Success(updated)` when role is non-root.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
pub fn renounce_role_as(
  ac: AccessControl,
  role: Role,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    Success(revoke_role_unchecked(ac, role, actor))
  }
}

/// Renounce role with a single-signer transaction.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role to renounce.
/// - `tx`: transaction expected to contain exactly one signer.
/// Returns:
/// - `Success(updated)` when exactly one signer renounces a non-root role.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `MissingSigner` when signer count is not exactly one.
pub fn renounce_role(
  ac: AccessControl,
  role: Role,
  tx: Transaction,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    when only_signer(tx) is {
      Some(actor) -> Success(revoke_role_unchecked(ac, role, actor))
      None -> Failure(MissingSigner)
    }
  }
}

/// Set role admin using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role whose admin is being changed.
/// - `new_admin_role`: role that will administer `role`.
/// - `actor`: account attempting the admin update.
/// Returns:
/// - `Success(updated)` when update is authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `Unauthorized` when actor lacks current admin rights.
pub fn set_role_admin_as(
  ac: AccessControl,
  role: Role,
  new_admin_role: Role,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    let previous_admin_role = get_role_admin(ac, role)
    if has_role(ac, previous_admin_role, actor) {
      Success(set_role_admin_unchecked(ac, role, new_admin_role))
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Set role admin when any signer holds the current role admin.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `role`: role whose admin is being changed.
/// - `new_admin_role`: role that will administer `role`.
/// - `tx`: transaction whose signers authorize the update.
/// Returns:
/// - `Success(updated)` when an authorized current-admin signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `CannotManageRootRole` when `role` is the registry's root role, or the
///   reserved `DEFAULT_ADMIN_ROLE` identifier.
/// - `Unauthorized` when no signer has current admin rights.
pub fn set_role_admin(
  ac: AccessControl,
  role: Role,
  new_admin_role: Role,
  tx: Transaction,
) -> AccessControlResult {
  if is_reserved_role(ac, role) {
    Failure(CannotManageRootRole)
  } else {
    let previous_admin_role = get_role_admin(ac, role)
    if signer_has_role(ac, tx, previous_admin_role) {
      Success(set_role_admin_unchecked(ac, role, new_admin_role))
    } else {
      Failure(Unauthorized)
    }
  }
}

/// Schedule a root role transfer to new_admin using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `new_admin`: proposed new root admin account.
/// - `now_ms`: current timestamp in milliseconds.
/// - `actor`: account attempting to schedule transfer.
/// Returns:
/// - `Success(updated)` with pending transfer when authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when actor does not hold root role.
/// - `DefaultAdminTransferToSelf` when transfer target equals current admin.
pub fn begin_default_admin_transfer_as(
  ac: AccessControl,
  new_admin: VerificationKeyHash,
  now_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if has_role(ac, ac.root_role, actor) {
    let ac0 = refresh_default_admin_delay(ac, now_ms)
    if ac0.default_admin == Some(new_admin) {
      Failure(DefaultAdminTransferToSelf)
    } else {
      Success(
        AccessControl {
          root_role: ac0.root_role,
          roles: ac0.roles,
          default_admin: ac0.default_admin,
          pending_default_admin: Some(
            PendingAdminTransfer {
              new_admin: Some(new_admin),
              execute_after_ms: now_ms + ac0.default_admin_delay_ms,
            },
          ),
          pending_default_admin_delay_change: ac0.pending_default_admin_delay_change,
          default_admin_delay_ms: ac0.default_admin_delay_ms,
        },
      )
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Schedule a root role transfer when a root signer is present in the transaction.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `new_admin`: proposed new root admin account.
/// - `now_ms`: current timestamp in milliseconds.
/// - `tx`: transaction whose signers authorize scheduling.
/// Returns:
/// - `Success(updated)` when an authorized root signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when no signer with root role is present.
/// - `DefaultAdminTransferToSelf` propagated from `begin_default_admin_transfer_as`.
pub fn begin_default_admin_transfer(
  ac: AccessControl,
  new_admin: VerificationKeyHash,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when role_signer(ac, tx, ac.root_role) is {
    Some(actor) -> begin_default_admin_transfer_as(ac, new_admin, now_ms, actor)
    None -> Failure(Unauthorized)
  }
}

/// Schedule a root role renounce using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `actor`: account attempting to schedule renounce.
/// Returns:
/// - `Success(updated)` with pending renounce when authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when actor does not hold root role.
pub fn begin_default_admin_renounce_as(
  ac: AccessControl,
  now_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if has_role(ac, ac.root_role, actor) {
    let ac0 = refresh_default_admin_delay(ac, now_ms)
    Success(
      AccessControl {
        root_role: ac0.root_role,
        roles: ac0.roles,
        default_admin: ac0.default_admin,
        pending_default_admin: Some(
          PendingAdminTransfer {
            new_admin: None,
            execute_after_ms: now_ms + ac0.default_admin_delay_ms,
          },
        ),
        pending_default_admin_delay_change: ac0.pending_default_admin_delay_change,
        default_admin_delay_ms: ac0.default_admin_delay_ms,
      },
    )
  } else {
    Failure(Unauthorized)
  }
}

/// Schedule a root role renounce when a root signer is present in the transaction.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `tx`: transaction whose signers authorize scheduling.
/// Returns:
/// - `Success(updated)` when an authorized root signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when no signer with root role is present.
pub fn begin_default_admin_renounce(
  ac: AccessControl,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when role_signer(ac, tx, ac.root_role) is {
    Some(actor) -> begin_default_admin_renounce_as(ac, now_ms, actor)
    None -> Failure(Unauthorized)
  }
}

/// Accept a pending root role transfer using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `actor`: account attempting acceptance.
/// Returns:
/// - `Success(updated)` when pending transfer is valid and matured.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `NoPendingAdminTransfer` when no pending action exists.
/// - `NotPendingTransfer` when pending action is renounce.
/// - `NotPendingAdmin` when actor is not scheduled new admin.
/// - `DelayNotElapsed` when timelock has not elapsed.
pub fn accept_default_admin_transfer_as(
  ac: AccessControl,
  now_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  when ac.pending_default_admin is {
    None -> Failure(NoPendingAdminTransfer)
    Some(pending) ->
      when pending.new_admin is {
        None -> Failure(NotPendingTransfer)
        Some(new_admin) ->
          if actor != new_admin {
            Failure(NotPendingAdmin)
          } else {
            if now_ms < pending.execute_after_ms {
              Failure(DelayNotElapsed)
            } else {
              Success(
                AccessControl {
                  root_role: ac.root_role,
                  roles: ac.roles,
                  default_admin: Some(new_admin),
                  pending_default_admin: None,
                  pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
                  default_admin_delay_ms: ac.default_admin_delay_ms,
                },
              )
            }
          }
      }
  }
}

/// Accept a pending root role transfer with a single-signer transaction.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `tx`: transaction expected to contain exactly one signer.
/// Returns:
/// - `Success(updated)` when transfer can be accepted.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `MissingSigner` when signer count is not exactly one.
/// - Root transfer acceptance errors propagated from `accept_default_admin_transfer_as`.
pub fn accept_default_admin_transfer(
  ac: AccessControl,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when only_signer(tx) is {
    Some(actor) -> accept_default_admin_transfer_as(ac, now_ms, actor)
    None -> Failure(MissingSigner)
  }
}

/// Accept a pending root role renounce using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `actor`: account attempting acceptance.
/// Returns:
/// - `Success(updated)` when pending renounce is valid and matured.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `NoPendingAdminTransfer` when no pending action exists.
/// - `NotPendingRenounce` when pending action is transfer.
/// - `Unauthorized` when actor does not hold root role.
/// - `DelayNotElapsed` when timelock has not elapsed.
pub fn accept_default_admin_renounce_as(
  ac: AccessControl,
  now_ms: Int,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  when ac.pending_default_admin is {
    None -> Failure(NoPendingAdminTransfer)
    Some(pending) ->
      when pending.new_admin is {
        Some(_) -> Failure(NotPendingRenounce)
        None ->
          if !has_role(ac, ac.root_role, actor) {
            Failure(Unauthorized)
          } else {
            if now_ms < pending.execute_after_ms {
              Failure(DelayNotElapsed)
            } else {
              Success(
                AccessControl {
                  root_role: ac.root_role,
                  roles: ac.roles,
                  default_admin: None,
                  pending_default_admin: None,
                  pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
                  default_admin_delay_ms: ac.default_admin_delay_ms,
                },
              )
            }
          }
      }
  }
}

/// Accept a pending root role renounce with a single-signer transaction.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `now_ms`: current timestamp in milliseconds.
/// - `tx`: transaction expected to contain exactly one signer.
/// Returns:
/// - `Success(updated)` when renounce can be accepted.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `MissingSigner` when signer count is not exactly one.
/// - Root renounce acceptance errors propagated from `accept_default_admin_renounce_as`.
pub fn accept_default_admin_renounce(
  ac: AccessControl,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  when only_signer(tx) is {
    Some(actor) -> accept_default_admin_renounce_as(ac, now_ms, actor)
    None -> Failure(MissingSigner)
  }
}

/// Cancel a pending root transfer or renounce using an explicit actor.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `actor`: account attempting cancellation.
/// Returns:
/// - `Success(updated)` when cancellation is authorized.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `NoPendingAdminTransfer` when no pending action exists.
/// - `Unauthorized` when actor does not hold root role.
pub fn cancel_default_admin_transfer_as(
  ac: AccessControl,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  when ac.pending_default_admin is {
    None -> Failure(NoPendingAdminTransfer)
    Some(_) ->
      if has_role(ac, ac.root_role, actor) {
        Success(
          AccessControl {
            root_role: ac.root_role,
            roles: ac.roles,
            default_admin: ac.default_admin,
            pending_default_admin: None,
            pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
            default_admin_delay_ms: ac.default_admin_delay_ms,
          },
        )
      } else {
        Failure(Unauthorized)
      }
  }
}

/// Cancel a pending root transfer or renounce when a root signer is present.
///
/// Parameters:
/// - `ac`: registry state to update.
/// - `tx`: transaction whose signers authorize cancellation.
/// Returns:
/// - `Success(updated)` when an authorized root signer is present.
/// - `Failure(error)` otherwise.
/// Errors:
/// - `Unauthorized` when no signer with root role is present.
/// - `NoPendingAdminTransfer` propagated from `cancel_default_admin_transfer_as`.
pub fn cancel_default_admin_transfer(
  ac: AccessControl,
  tx: Transaction,
) -> AccessControlResult {
  when role_signer(ac, tx, ac.root_role) is {
    Some(actor) -> cancel_default_admin_transfer_as(ac, actor)
    None -> Failure(Unauthorized)
  }
}

/// Returns true when any transaction signer currently holds `role`.
fn signer_has_role(ac: AccessControl, tx: Transaction, role: Role) -> Bool {
  list.any(tx.extra_signatories, fn(signer) { has_role(ac, role, signer) })
}

/// Returns the first signer in the transaction that holds `role`.
fn role_signer(
  ac: AccessControl,
  tx: Transaction,
  role: Role,
) -> Option<VerificationKeyHash> {
  first_signer_with_role(ac, tx.extra_signatories, role)
}

/// Returns the signer only when the transaction contains exactly one signer.
fn only_signer(tx: Transaction) -> Option<VerificationKeyHash> {
  when tx.extra_signatories is {
    [signer] -> Some(signer)
    _ -> None
  }
}

/// Recursively scans signer list and returns the first signer holding `role`.
fn first_signer_with_role(
  ac: AccessControl,
  signers: List<VerificationKeyHash>,
  role: Role,
) -> Option<VerificationKeyHash> {
  when signers is {
    [head, ..tail] ->
      if has_role(ac, role, head) {
        Some(head)
      } else {
        first_signer_with_role(ac, tail, role)
      }
    [] -> None
  }
}

/// Returns true when `role` may not be managed through generic role operations.
///
/// Two identifiers are reserved. The registry's own `root_role`, because root
/// membership lives solely in `default_admin` (invariant 1). And the
/// `default_admin_role` literal, unconditionally — otherwise a registry built with
/// `new_with_root` could grant `DEFAULT_ADMIN_ROLE` as an ordinary role, and any
/// validator that checks that identifier rather than `protected_root` would honour
/// its members as root admins.
fn is_reserved_role(ac: AccessControl, role: Role) -> Bool {
  role == ac.root_role || role == default_admin_role
}

/// Returns current role data or a root-administered empty default entry.
fn role_data_or_default(ac: AccessControl, role: Role) -> RoleData {
  when dict.get(ac.roles, role) is {
    Some(role_data) -> role_data
    None -> RoleData { members: [], admin_role: ac.root_role }
  }
}

/// Replaces role data for `role`, preserving all other registry state.
fn with_role_data(
  ac: AccessControl,
  role: Role,
  role_data: RoleData,
) -> AccessControl {
  AccessControl {
    root_role: ac.root_role,
    roles: dict.insert(ac.roles, role, role_data),
    default_admin: ac.default_admin,
    pending_default_admin: ac.pending_default_admin,
    pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
    default_admin_delay_ms: ac.default_admin_delay_ms,
  }
}

/// Computes the effective delay at `now_ms`, including elapsed pending changes.
fn effective_default_admin_delay_ms(ac: AccessControl, now_ms: Int) -> Int {
  when ac.pending_default_admin_delay_change is {
    Some(pending) ->
      if now_ms >= pending.schedule_after_ms {
        pending.new_delay_ms
      } else {
        ac.default_admin_delay_ms
      }
    None -> ac.default_admin_delay_ms
  }
}

/// Returns true only while a pending delay change exists and is not yet elapsed.
fn has_active_pending_default_admin_delay_change(
  ac: AccessControl,
  now_ms: Int,
) -> Bool {
  when ac.pending_default_admin_delay_change is {
    Some(pending) -> now_ms < pending.schedule_after_ms
    None -> False
  }
}

/// Applies and clears an elapsed pending delay change; otherwise returns input state.
fn refresh_default_admin_delay(ac: AccessControl, now_ms: Int) -> AccessControl {
  when ac.pending_default_admin_delay_change is {
    None -> ac
    Some(pending) ->
      if now_ms < pending.schedule_after_ms {
        ac
      } else {
        AccessControl {
          root_role: ac.root_role,
          roles: ac.roles,
          default_admin: ac.default_admin,
          pending_default_admin: ac.pending_default_admin,
          pending_default_admin_delay_change: None,
          default_admin_delay_ms: pending.new_delay_ms,
        }
      }
  }
}

/// Returns the smaller of two integers.
fn min_int(left: Int, right: Int) -> Int {
  if left < right {
    left
  } else {
    right
  }
}

/// Grants `role` membership without authorization checks and keeps operation idempotent.
fn grant_role_unchecked(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
) -> AccessControl {
  let current = role_data_or_default(ac, role)
  if list.has(current.members, account) {
    ac
  } else {
    with_role_data(
      ac,
      role,
      RoleData {
        members: [account, ..current.members],
        admin_role: current.admin_role,
      },
    )
  }
}

/// Revokes `role` membership without authorization checks and keeps operation idempotent.
fn revoke_role_unchecked(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
) -> AccessControl {
  when dict.get(ac.roles, role) is {
    None -> ac
    Some(current) ->
      if list.has(current.members, account) {
        with_role_data(
          ac,
          role,
          RoleData {
            members: list.delete(current.members, account),
            admin_role: current.admin_role,
          },
        )
      } else {
        ac
      }
  }
}

/// Sets role admin pointer without authorization checks.
fn set_role_admin_unchecked(
  ac: AccessControl,
  role: Role,
  new_admin_role: Role,
) -> AccessControl {
  let current = role_data_or_default(ac, role)
  with_role_data(
    ac,
    role,
    RoleData { members: current.members, admin_role: new_admin_role },
  )
}
