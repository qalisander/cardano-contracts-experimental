use contracts/access/sources/access_control
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction

const ADMIN: VerificationKeyHash =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const ALICE: VerificationKeyHash =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const BOB: VerificationKeyHash =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const CAROL: VerificationKeyHash =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

const ROLE_WRITER =
  "WRITER_ROLE"

const ROLE_EDITOR =
  "EDITOR_ROLE"

fn tx_with_signers(signers: List<VerificationKeyHash>) {
  transaction.Transaction {
    ..transaction.placeholder,
    extra_signatories: signers,
  }
}

test new_sets_default_admin() {
  let ac = access_control.new(ADMIN)

  and {
    access_control.has_role(ac, access_control.DEFAULT_ADMIN_ROLE, ADMIN)?,
    access_control.default_admin(ac) == Some(ADMIN),
  }
}

test grant_role_happy_path() {
  let ac = access_control.new(ADMIN)
  let tx = tx_with_signers([ADMIN])

  expect access_control.Success(next) =
    access_control.grant_role(ac, ROLE_WRITER, ALICE, tx)

  access_control.has_role(next, ROLE_WRITER, ALICE)
}

test grant_role_rejects_non_admin() {
  let ac = access_control.new(ADMIN)
  let tx = tx_with_signers([ALICE])

  access_control.grant_role(ac, ROLE_WRITER, ALICE, tx)
    == access_control.Failure(access_control.Unauthorized)
}

test set_role_admin_transfers_grant_authority() {
  let ac0 = access_control.new(ADMIN)
  let tx_admin = tx_with_signers([ADMIN])

  expect access_control.Success(ac1) =
    access_control.grant_role(ac0, ROLE_EDITOR, ALICE, tx_admin)

  expect access_control.Success(ac2) =
    access_control.set_role_admin(ac1, ROLE_WRITER, ROLE_EDITOR, tx_admin)

  let tx_alice = tx_with_signers([ALICE])
  expect access_control.Success(ac3) =
    access_control.grant_role(ac2, ROLE_WRITER, BOB, tx_alice)

  and {
    access_control.has_role(ac3, ROLE_WRITER, BOB)?,
    access_control.grant_role(ac3, ROLE_WRITER, CAROL, tx_admin)
      == access_control.Failure(access_control.Unauthorized),
  }
}

test renounce_role_requires_single_signer() {
  let ac0 = access_control.new(ADMIN)
  let tx_admin = tx_with_signers([ADMIN])

  expect access_control.Success(ac1) =
    access_control.grant_role(ac0, ROLE_WRITER, ALICE, tx_admin)

  let tx_multi = tx_with_signers([ALICE, BOB])

  access_control.renounce_role(ac1, ROLE_WRITER, tx_multi)
    == access_control.Failure(access_control.MissingSigner)
}

test renounce_role_happy_path() {
  let ac0 = access_control.new(ADMIN)
  let tx_admin = tx_with_signers([ADMIN])

  expect access_control.Success(ac1) =
    access_control.grant_role(ac0, ROLE_WRITER, ALICE, tx_admin)

  let tx_alice = tx_with_signers([ALICE])
  expect access_control.Success(ac2) =
    access_control.renounce_role(ac1, ROLE_WRITER, tx_alice)

  !access_control.has_role(ac2, ROLE_WRITER, ALICE)
}

test transfer_default_admin_happy_path() {
  let ac = access_control.new(ADMIN)
  let tx = tx_with_signers([ADMIN])

  expect access_control.Success(next) =
    access_control.transfer_default_admin(ac, BOB, tx)

  and {
    access_control.has_role(next, access_control.DEFAULT_ADMIN_ROLE, BOB)?,
    !access_control.has_role(next, access_control.DEFAULT_ADMIN_ROLE, ADMIN),
  }
}

test begin_and_accept_default_admin_transfer_with_delay() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 100, ADMIN)

  let tx_admin = tx_with_signers([ADMIN])
  expect access_control.Success(ac2) =
    access_control.begin_default_admin_transfer(ac1, BOB, 0, tx_admin)

  and {
    access_control.has_pending_default_admin_transfer(ac2)?,
    access_control.pending_default_admin_new_admin(ac2) == Some(BOB),
    access_control.pending_default_admin_execute_after_ms(ac2) == Some(100),
  }

  let tx_bob = tx_with_signers([BOB])
  access_control.accept_default_admin_transfer(ac2, 99, tx_bob)
    == access_control.Failure(access_control.DelayNotElapsed)

  expect access_control.Success(ac3) =
    access_control.accept_default_admin_transfer(ac2, 100, tx_bob)

  and {
    access_control.default_admin(ac3) == Some(BOB),
    !access_control.has_pending_default_admin_transfer(ac3),
  }
}

test begin_and_accept_default_admin_renounce_with_delay() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 50, ADMIN)

  let tx_admin = tx_with_signers([ADMIN])
  expect access_control.Success(ac2) =
    access_control.begin_default_admin_renounce(ac1, 0, tx_admin)

  and {
    access_control.has_pending_default_admin_transfer(ac2)?,
    access_control.is_pending_default_admin_renounce(ac2)?,
    access_control.pending_default_admin_new_admin(ac2) == None,
    access_control.pending_default_admin_execute_after_ms(ac2) == Some(50),
  }

  access_control.accept_default_admin_renounce(ac2, 49, tx_admin)
    == access_control.Failure(access_control.DelayNotElapsed)

  expect access_control.Success(ac3) =
    access_control.accept_default_admin_renounce(ac2, 50, tx_admin)

  and {
    access_control.default_admin(ac3) == None,
    !access_control.has_pending_default_admin_transfer(ac3),
  }
}

test cancel_pending_default_admin_transfer() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 10, ADMIN)

  let tx_admin = tx_with_signers([ADMIN])
  expect access_control.Success(ac2) =
    access_control.begin_default_admin_transfer(ac1, BOB, 0, tx_admin)

  expect access_control.Success(ac3) =
    access_control.cancel_default_admin_transfer(ac2, tx_admin)

  and {
    !access_control.has_pending_default_admin_transfer(ac3),
    access_control.default_admin(ac3) == Some(ADMIN),
  }
}

test set_default_admin_delay_rejects_out_of_bounds() {
  let ac = access_control.new(ADMIN)

  access_control.set_default_admin_delay_as(
    ac,
    access_control.max_default_admin_delay_ms() + 1,
    ADMIN,
  )
    == access_control.Failure(access_control.DelayTooLarge)
}

test begin_default_admin_delay_change_increase_wait_is_capped() {
  let ac0 = access_control.new(ADMIN)
  let new_delay = 200_000_000

  expect access_control.Success(ac1) =
    access_control.begin_default_admin_delay_change_as(ac0, new_delay, 10, ADMIN)

  and {
    access_control.pending_default_admin_delay_change_new_delay_ms(ac1, 11)
      == Some(new_delay),
    access_control.pending_default_admin_delay_change_schedule_after_ms(ac1, 11)
      == Some(10 + access_control.max_delay_increase_wait_ms()),
  }
}

test begin_default_admin_delay_change_decrease_wait_matches_delta() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 100, ADMIN)

  expect access_control.Success(ac2) =
    access_control.begin_default_admin_delay_change_as(ac1, 30, 5, ADMIN)

  access_control.pending_default_admin_delay_change_schedule_after_ms(ac2, 6)
    == Some(75)
}

test delay_change_elapsed_is_applied_before_transfer_scheduling() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 10, ADMIN)

  expect access_control.Success(ac2) =
    access_control.begin_default_admin_delay_change_as(ac1, 100, 0, ADMIN)

  let tx_admin = tx_with_signers([ADMIN])
  expect access_control.Success(ac3) =
    access_control.begin_default_admin_transfer(ac2, BOB, 100, tx_admin)

  and {
    access_control.default_admin_delay_ms(ac3) == 100,
    access_control.pending_default_admin_execute_after_ms(ac3) == Some(200),
    !access_control.has_pending_default_admin_delay_change(ac3, 100),
  }
}

test cancel_default_admin_delay_change_active() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 100, ADMIN)

  expect access_control.Success(ac2) =
    access_control.begin_default_admin_delay_change_as(ac1, 20, 0, ADMIN)

  expect access_control.Success(ac3) =
    access_control.cancel_default_admin_delay_change_as(ac2, 10, ADMIN)

  and {
    !access_control.has_pending_default_admin_delay_change(ac3, 10),
    access_control.default_admin_delay_ms(ac3) == 100,
  }
}

test cancel_default_admin_delay_change_rejects_elapsed_pending() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 40, ADMIN)

  expect access_control.Success(ac2) =
    access_control.begin_default_admin_delay_change_as(ac1, 10, 0, ADMIN)

  access_control.cancel_default_admin_delay_change_as(ac2, 30, ADMIN)
    == access_control.Failure(access_control.NoPendingDelayChange)
}

test pending_default_admin_delay_change_getters_hide_elapsed_state() {
  let ac0 = access_control.new(ADMIN)
  expect access_control.Success(ac1) =
    access_control.set_default_admin_delay_as(ac0, 40, ADMIN)

  expect access_control.Success(ac2) =
    access_control.begin_default_admin_delay_change_as(ac1, 10, 0, ADMIN)

  and {
    access_control.pending_default_admin_delay_change_new_delay_ms(ac2, 10)
      == Some(10),
    access_control.pending_default_admin_delay_change_new_delay_ms(ac2, 30)
      == None,
    access_control.pending_default_admin_delay_change_schedule_after_ms(ac2, 30)
      == None,
    access_control.default_admin_delay_ms_at(ac2, 30) == 10,
  }
}
