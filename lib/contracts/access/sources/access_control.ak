use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{Transaction}

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
    root_role: Role,
    roles: Dict<Role, RoleData>,
    default_admin: Option<VerificationKeyHash>,
    pending_default_admin: Option<PendingAdminTransfer>,
    pending_default_admin_delay_change: Option<PendingDelayChange>,
    default_admin_delay_ms: Int,
  }
}

/// Per-role membership and admin role pointer.
pub type RoleData {
  RoleData { members: List<VerificationKeyHash>, admin_role: Role }
}

pub type PendingAdminTransfer {
  PendingAdminTransfer {
    new_admin: Option<VerificationKeyHash>,
    execute_after_ms: Int,
  }
}

pub type PendingDelayChange {
  PendingDelayChange { new_delay_ms: Int, schedule_after_ms: Int }
}

pub type AccessControlError {
  Unauthorized
  CannotManageRootRole
  MissingSigner
  NoPendingAdminTransfer
  NotPendingAdmin
  DelayNotElapsed
  NotPendingTransfer
  NotPendingRenounce
  DelayTooLarge
  DefaultAdminTransferToSelf
  NoPendingDelayChange
}

pub type AccessControlResult {
  Success(AccessControl)
  Failure(AccessControlError)
}

/// Create a registry with DEFAULT_ADMIN_ROLE as root role.
pub fn new(initial_admin: VerificationKeyHash) -> AccessControl {
  new_with_root(default_admin_role, initial_admin)
}

/// Create a registry with a custom root role identifier.
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

pub fn protected_root(ac: AccessControl) -> Role {
  ac.root_role
}

pub fn default_admin(ac: AccessControl) -> Option<VerificationKeyHash> {
  ac.default_admin
}

pub fn max_default_admin_delay_ms() -> Int {
  max_default_admin_delay_ms_value
}

pub fn max_delay_increase_wait_ms() -> Int {
  max_delay_increase_wait_ms_value
}

pub fn default_admin_delay_ms(ac: AccessControl) -> Int {
  ac.default_admin_delay_ms
}

/// Effective delay at a given time, including elapsed pending changes.
pub fn default_admin_delay_ms_at(ac: AccessControl, now_ms: Int) -> Int {
  effective_default_admin_delay_ms(ac, now_ms)
}

pub fn has_pending_default_admin_transfer(ac: AccessControl) -> Bool {
  ac.pending_default_admin != None
}

pub fn is_pending_default_admin_renounce(ac: AccessControl) -> Bool {
  when ac.pending_default_admin is {
    Some(pending) -> pending.new_admin == None
    None -> False
  }
}

pub fn pending_default_admin_new_admin(
  ac: AccessControl,
) -> Option<VerificationKeyHash> {
  when ac.pending_default_admin is {
    Some(pending) -> pending.new_admin
    None -> None
  }
}

pub fn pending_default_admin_execute_after_ms(ac: AccessControl) -> Option<Int> {
  when ac.pending_default_admin is {
    Some(pending) -> Some(pending.execute_after_ms)
    None -> None
  }
}

pub fn has_pending_default_admin_delay_change(
  ac: AccessControl,
  now_ms: Int,
) -> Bool {
  has_active_pending_default_admin_delay_change(ac, now_ms)
}

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

pub fn set_default_admin_delay(
  ac: AccessControl,
  new_delay_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    when first_signer(tx) is {
      Some(actor) -> set_default_admin_delay_as(ac, new_delay_ms, actor)
      None -> Failure(MissingSigner)
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Schedule a delayed change to `default_admin_delay_ms`.
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

/// Schedule a delayed change to `default_admin_delay_ms` using transaction signers.
pub fn begin_default_admin_delay_change(
  ac: AccessControl,
  new_delay_ms: Int,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    when first_signer(tx) is {
      Some(actor) ->
        begin_default_admin_delay_change_as(ac, new_delay_ms, now_ms, actor)
      None -> Failure(MissingSigner)
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Cancel an active pending delay change.
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
pub fn cancel_default_admin_delay_change(
  ac: AccessControl,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    when first_signer(tx) is {
      Some(actor) -> cancel_default_admin_delay_change_as(ac, now_ms, actor)
      None -> Failure(MissingSigner)
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Returns true when `account` currently holds `role`.
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

/// Returns the role that administers `role`.
/// Unconfigured roles default to root_role.
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

pub fn assert_has_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
) -> Bool {
  has_role(ac, role, account)
}

/// Returns true when at least one transaction signer currently holds `role`.
pub fn tx_has_role(ac: AccessControl, tx: Transaction, role: Role) -> Bool {
  signer_has_role(ac, tx, role)
}

/// Grant role using explicit actor.
pub fn grant_role_as(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if role == ac.root_role {
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

/// Grant role when any extra signer holds role admin.
pub fn grant_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  tx: Transaction,
) -> AccessControlResult {
  if role == ac.root_role {
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

/// Revoke role using explicit actor.
pub fn revoke_role_as(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if role == ac.root_role {
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

/// Revoke role when any extra signer holds role admin.
pub fn revoke_role(
  ac: AccessControl,
  role: Role,
  account: VerificationKeyHash,
  tx: Transaction,
) -> AccessControlResult {
  if role == ac.root_role {
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

/// Renounce role for explicit actor.
pub fn renounce_role_as(
  ac: AccessControl,
  role: Role,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if role == ac.root_role {
    Failure(CannotManageRootRole)
  } else {
    Success(revoke_role_unchecked(ac, role, actor))
  }
}

/// Renounce role with a single signer transaction.
/// We require exactly one signer to mirror Move's `ctx.sender()` semantics.
pub fn renounce_role(
  ac: AccessControl,
  role: Role,
  tx: Transaction,
) -> AccessControlResult {
  if role == ac.root_role {
    Failure(CannotManageRootRole)
  } else {
    when only_signer(tx) is {
      Some(actor) -> Success(revoke_role_unchecked(ac, role, actor))
      None -> Failure(MissingSigner)
    }
  }
}

/// Set role admin using explicit actor.
pub fn set_role_admin_as(
  ac: AccessControl,
  role: Role,
  new_admin_role: Role,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if role == ac.root_role {
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

/// Set role admin when any extra signer holds current role admin.
pub fn set_role_admin(
  ac: AccessControl,
  role: Role,
  new_admin_role: Role,
  tx: Transaction,
) -> AccessControlResult {
  if role == ac.root_role {
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

/// Schedule a root role transfer to `new_admin`.
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
pub fn begin_default_admin_transfer(
  ac: AccessControl,
  new_admin: VerificationKeyHash,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    when first_signer(tx) is {
      Some(actor) ->
        begin_default_admin_transfer_as(ac, new_admin, now_ms, actor)
      None -> Failure(MissingSigner)
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Schedule a root role renounce.
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
pub fn begin_default_admin_renounce(
  ac: AccessControl,
  now_ms: Int,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    when first_signer(tx) is {
      Some(actor) -> begin_default_admin_renounce_as(ac, now_ms, actor)
      None -> Failure(MissingSigner)
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Accept a pending root role transfer.
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

/// Accept a pending root role transfer. Requires exactly one signer.
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

/// Accept a pending root role renounce.
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

/// Accept a pending root role renounce. Requires exactly one signer.
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

/// Cancel a pending root transfer or renounce.
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
pub fn cancel_default_admin_transfer(
  ac: AccessControl,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    when first_signer(tx) is {
      Some(actor) -> cancel_default_admin_transfer_as(ac, actor)
      None -> Failure(MissingSigner)
    }
  } else {
    Failure(Unauthorized)
  }
}

/// Immediate root transfer helper.
/// Prefer the begin/accept delayed flow for production behavior parity.
pub fn transfer_default_admin_as(
  ac: AccessControl,
  new_admin: VerificationKeyHash,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if has_role(ac, ac.root_role, actor) {
    Success(
      AccessControl {
        root_role: ac.root_role,
        roles: ac.roles,
        default_admin: Some(new_admin),
        pending_default_admin: ac.pending_default_admin,
        pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
        default_admin_delay_ms: ac.default_admin_delay_ms,
      },
    )
  } else {
    Failure(Unauthorized)
  }
}

pub fn transfer_default_admin(
  ac: AccessControl,
  new_admin: VerificationKeyHash,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    Success(
      AccessControl {
        root_role: ac.root_role,
        roles: ac.roles,
        default_admin: Some(new_admin),
        pending_default_admin: ac.pending_default_admin,
        pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
        default_admin_delay_ms: ac.default_admin_delay_ms,
      },
    )
  } else {
    Failure(Unauthorized)
  }
}

pub fn renounce_default_admin_as(
  ac: AccessControl,
  actor: VerificationKeyHash,
) -> AccessControlResult {
  if has_role(ac, ac.root_role, actor) {
    Success(
      AccessControl {
        root_role: ac.root_role,
        roles: ac.roles,
        default_admin: None,
        pending_default_admin: ac.pending_default_admin,
        pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
        default_admin_delay_ms: ac.default_admin_delay_ms,
      },
    )
  } else {
    Failure(Unauthorized)
  }
}

pub fn renounce_default_admin(
  ac: AccessControl,
  tx: Transaction,
) -> AccessControlResult {
  if signer_has_role(ac, tx, ac.root_role) {
    Success(
      AccessControl {
        root_role: ac.root_role,
        roles: ac.roles,
        default_admin: None,
        pending_default_admin: ac.pending_default_admin,
        pending_default_admin_delay_change: ac.pending_default_admin_delay_change,
        default_admin_delay_ms: ac.default_admin_delay_ms,
      },
    )
  } else {
    Failure(Unauthorized)
  }
}

fn signer_has_role(ac: AccessControl, tx: Transaction, role: Role) -> Bool {
  list.any(tx.extra_signatories, fn(signer) { has_role(ac, role, signer) })
}

fn only_signer(tx: Transaction) -> Option<VerificationKeyHash> {
  when tx.extra_signatories is {
    [signer] -> Some(signer)
    _ -> None
  }
}

fn first_signer(tx: Transaction) -> Option<VerificationKeyHash> {
  when tx.extra_signatories is {
    [head, ..] -> Some(head)
    [] -> None
  }
}

fn role_data_or_default(ac: AccessControl, role: Role) -> RoleData {
  when dict.get(ac.roles, role) is {
    Some(role_data) -> role_data
    None -> RoleData { members: [], admin_role: ac.root_role }
  }
}

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

fn has_active_pending_default_admin_delay_change(
  ac: AccessControl,
  now_ms: Int,
) -> Bool {
  when ac.pending_default_admin_delay_change is {
    Some(pending) -> now_ms < pending.schedule_after_ms
    None -> False
  }
}

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

fn min_int(left: Int, right: Int) -> Int {
  if left < right {
    left
  } else {
    right
  }
}

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
