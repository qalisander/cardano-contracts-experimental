use aiken/crypto.{VerificationKeyHash}
use cardano/transaction
use sources/access_control

const admin = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const alice = #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const bob = #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const carol = #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

const role_writer = "WRITER_ROLE"

const role_editor = "EDITOR_ROLE"

fn tx_with_signers(signers: List<VerificationKeyHash>) {
  transaction.Transaction {
    ..transaction.placeholder,
    extra_signatories: signers,
  }
}

test new_sets_default_admin() {
  let ac = access_control.new(admin)

  and {
    access_control.has_role(ac, access_control.default_admin_role, admin)?,
    access_control.default_admin(ac) == Some(admin),
  }
}

test grant_role_happy_path() {
  let ac = access_control.new(admin)
  let tx = tx_with_signers([admin])

  expect access_control.Success(next) = access_control.grant_role(
    ac,
    role_writer,
    alice,
    tx,
  )

  access_control.has_role(next, role_writer, alice)
}

test grant_role_rejects_non_admin() {
  let ac = access_control.new(admin)
  let tx = tx_with_signers([alice])

  access_control.grant_role(ac, role_writer, alice, tx) == access_control.Failure(
    access_control.Unauthorized,
  )
}

test set_role_admin_transfers_grant_authority() {
  let ac0 = access_control.new(admin)
  let tx_admin = tx_with_signers([admin])

  expect access_control.Success(ac1) = access_control.grant_role(
    ac0,
    role_editor,
    alice,
    tx_admin,
  )

  expect access_control.Success(ac2) = access_control.set_role_admin(
    ac1,
    role_writer,
    role_editor,
    tx_admin,
  )

  let tx_alice = tx_with_signers([alice])
  expect access_control.Success(ac3) = access_control.grant_role(
    ac2,
    role_writer,
    bob,
    tx_alice,
  )

  and {
    access_control.has_role(ac3, role_writer, bob)?,
    access_control.grant_role(ac3, role_writer, carol, tx_admin) == access_control.Failure(
      access_control.Unauthorized,
    ),
  }
}

test renounce_role_requires_single_signer() {
  let ac0 = access_control.new(admin)
  let tx_admin = tx_with_signers([admin])

  expect access_control.Success(ac1) = access_control.grant_role(
    ac0,
    role_writer,
    alice,
    tx_admin,
  )

  let tx_multi = tx_with_signers([alice, bob])

  access_control.renounce_role(ac1, role_writer, tx_multi) == access_control.Failure(
    access_control.MissingSigner,
  )
}

test renounce_role_happy_path() {
  let ac0 = access_control.new(admin)
  let tx_admin = tx_with_signers([admin])

  expect access_control.Success(ac1) = access_control.grant_role(
    ac0,
    role_writer,
    alice,
    tx_admin,
  )

  let tx_alice = tx_with_signers([alice])
  expect access_control.Success(ac2) = access_control.renounce_role(
    ac1,
    role_writer,
    tx_alice,
  )

  !access_control.has_role(ac2, role_writer, alice)
}

test root_admin_tx_ops_pick_authorized_signer_not_first_signer() {
  let ac = access_control.new(admin)
  let tx = tx_with_signers([alice, admin])

  expect access_control.Success(next) = access_control.set_default_admin_delay(
    ac,
    77,
    tx,
  )

  access_control.default_admin_delay_ms(next) == 77
}

test begin_and_accept_default_admin_transfer_with_delay() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    100,
    admin,
  )

  let tx_admin = tx_with_signers([admin])
  expect access_control.Success(ac2) = access_control.begin_default_admin_transfer(
    ac1,
    bob,
    0,
    tx_admin,
  )

  expect and {
      access_control.has_pending_default_admin_transfer(ac2)?,
      access_control.pending_default_admin_new_admin(ac2) == Some(bob),
      access_control.pending_default_admin_execute_after_ms(ac2) == Some(100),
    }

  let tx_bob = tx_with_signers([bob])
  expect
    access_control.accept_default_admin_transfer(ac2, 99, tx_bob) == access_control.Failure(
      access_control.DelayNotElapsed,
    )

  expect access_control.Success(ac3) = access_control.accept_default_admin_transfer(
    ac2,
    100,
    tx_bob,
  )

  and {
    access_control.default_admin(ac3) == Some(bob),
    !access_control.has_pending_default_admin_transfer(ac3),
  }
}

test begin_and_accept_default_admin_renounce_with_delay() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    50,
    admin,
  )

  let tx_admin = tx_with_signers([admin])
  expect access_control.Success(ac2) = access_control.begin_default_admin_renounce(
    ac1,
    0,
    tx_admin,
  )

  expect and {
      access_control.has_pending_default_admin_transfer(ac2)?,
      access_control.is_pending_default_admin_renounce(ac2)?,
      access_control.pending_default_admin_new_admin(ac2) == None,
      access_control.pending_default_admin_execute_after_ms(ac2) == Some(50),
    }

  expect
    access_control.accept_default_admin_renounce(ac2, 49, tx_admin) == access_control.Failure(
      access_control.DelayNotElapsed,
    )

  expect access_control.Success(ac3) = access_control.accept_default_admin_renounce(
    ac2,
    50,
    tx_admin,
  )

  and {
    access_control.default_admin(ac3) == None,
    !access_control.has_pending_default_admin_transfer(ac3),
  }
}

test cancel_pending_default_admin_transfer() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    10,
    admin,
  )

  let tx_admin = tx_with_signers([admin])
  expect access_control.Success(ac2) = access_control.begin_default_admin_transfer(
    ac1,
    bob,
    0,
    tx_admin,
  )

  expect access_control.Success(ac3) = access_control.cancel_default_admin_transfer(
    ac2,
    tx_admin,
  )

  and {
    !access_control.has_pending_default_admin_transfer(ac3),
    access_control.default_admin(ac3) == Some(admin),
  }
}

test set_default_admin_delay_rejects_out_of_bounds() {
  let ac = access_control.new(admin)

  access_control.set_default_admin_delay_as(
    ac,
    access_control.max_default_admin_delay_ms() + 1,
    admin,
  ) == access_control.Failure(access_control.DelayTooLarge)
}

test begin_default_admin_delay_change_increase_wait_is_capped() {
  let ac0 = access_control.new(admin)
  let new_delay = 200_000_000

  expect access_control.Success(ac1) = access_control.begin_default_admin_delay_change_as(
    ac0,
    new_delay,
    10,
    admin,
  )

  and {
    access_control.pending_default_admin_delay_change_new_delay_ms(ac1, 11) == Some(
      new_delay,
    ),
    access_control.pending_default_admin_delay_change_schedule_after_ms(ac1, 11) == Some(
      10 + access_control.max_delay_increase_wait_ms(),
    ),
  }
}

test begin_default_admin_delay_change_decrease_wait_matches_delta() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    100,
    admin,
  )

  expect access_control.Success(ac2) = access_control.begin_default_admin_delay_change_as(
    ac1,
    30,
    5,
    admin,
  )

  access_control.pending_default_admin_delay_change_schedule_after_ms(ac2, 6) == Some(
    75,
  )
}

test delay_change_elapsed_is_applied_before_transfer_scheduling() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    10,
    admin,
  )

  expect access_control.Success(ac2) = access_control.begin_default_admin_delay_change_as(
    ac1,
    100,
    0,
    admin,
  )

  let tx_admin = tx_with_signers([admin])
  expect access_control.Success(ac3) = access_control.begin_default_admin_transfer(
    ac2,
    bob,
    100,
    tx_admin,
  )

  and {
    access_control.default_admin_delay_ms(ac3) == 100,
    access_control.pending_default_admin_execute_after_ms(ac3) == Some(200),
    !access_control.has_pending_default_admin_delay_change(ac3, 100),
  }
}

test cancel_default_admin_delay_change_active() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    100,
    admin,
  )

  expect access_control.Success(ac2) = access_control.begin_default_admin_delay_change_as(
    ac1,
    20,
    0,
    admin,
  )

  expect access_control.Success(ac3) = access_control.cancel_default_admin_delay_change_as(
    ac2,
    10,
    admin,
  )

  and {
    !access_control.has_pending_default_admin_delay_change(ac3, 10),
    access_control.default_admin_delay_ms(ac3) == 100,
  }
}

test cancel_default_admin_delay_change_rejects_elapsed_pending() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    40,
    admin,
  )

  expect access_control.Success(ac2) = access_control.begin_default_admin_delay_change_as(
    ac1,
    10,
    0,
    admin,
  )

  access_control.cancel_default_admin_delay_change_as(ac2, 30, admin) == access_control.Failure(
    access_control.NoPendingDelayChange,
  )
}

test pending_default_admin_delay_change_getters_hide_elapsed_state() {
  let ac0 = access_control.new(admin)
  expect access_control.Success(ac1) = access_control.set_default_admin_delay_as(
    ac0,
    40,
    admin,
  )

  expect access_control.Success(ac2) = access_control.begin_default_admin_delay_change_as(
    ac1,
    10,
    0,
    admin,
  )

  and {
    access_control.pending_default_admin_delay_change_new_delay_ms(ac2, 10) == Some(
      10,
    ),
    access_control.pending_default_admin_delay_change_new_delay_ms(ac2, 30) == None,
    access_control.pending_default_admin_delay_change_schedule_after_ms(ac2, 30) == None,
    access_control.default_admin_delay_ms_at(ac2, 30) == 10,
  }
}

// H-01b: `DEFAULT_ADMIN_ROLE` is reserved even when the registry uses a custom
// root role, so no shadow admin role can be created for a validator to honour.
const custom_root = "ROOT_ROLE"

test default_admin_role_cannot_be_granted_under_a_custom_root() {
  let ac = access_control.new_with_root(custom_root, admin)

  and {
    access_control.grant_role_as(
      ac,
      access_control.default_admin_role,
      alice,
      admin,
    ) == access_control.Failure(access_control.CannotManageRootRole),
    access_control.grant_role(
      ac,
      access_control.default_admin_role,
      alice,
      tx_with_signers([admin]),
    ) == access_control.Failure(access_control.CannotManageRootRole),
  }
}

test default_admin_role_is_reserved_across_every_management_op() {
  let ac = access_control.new_with_root(custom_root, admin)
  let reserved = access_control.default_admin_role
  let expected = access_control.Failure(access_control.CannotManageRootRole)

  and {
    access_control.revoke_role_as(ac, reserved, alice, admin) == expected,
    access_control.revoke_role(ac, reserved, alice, tx_with_signers([admin])) == expected,
    access_control.renounce_role_as(ac, reserved, alice) == expected,
    access_control.renounce_role(ac, reserved, tx_with_signers([alice])) == expected,
    access_control.set_role_admin_as(ac, reserved, custom_root, admin) == expected,
    access_control.set_role_admin(
      ac,
      reserved,
      custom_root,
      tx_with_signers([admin]),
    ) == expected,
  }
}

test custom_root_role_is_still_reserved() {
  let ac = access_control.new_with_root(custom_root, admin)

  access_control.grant_role_as(ac, custom_root, alice, admin) == access_control.Failure(
    access_control.CannotManageRootRole,
  )
}

test reserving_default_admin_role_does_not_affect_ordinary_roles() {
  let ac = access_control.new_with_root(custom_root, admin)

  expect access_control.Success(granted) = access_control.grant_role_as(
    ac,
    role_writer,
    alice,
    admin,
  )

  and {
    access_control.has_role(granted, role_writer, alice),
    // the root holder is unchanged and still resolves through `protected_root`
    access_control.has_role(
      granted,
      access_control.protected_root(granted),
      admin,
    ),
  }
}
