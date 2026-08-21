use cardano/transaction.{Transaction}
use contracts/access/sources/access_control

pub type AccessControlled {
  AccessControlled { ac: access_control.AccessControl }
}

validator root_admin_gate {
  spend(datum: AccessControlled, _redeemer: Void, _own_ref, tx: Transaction) {
    access_control.tx_has_role(datum.ac, tx, access_control.DEFAULT_ADMIN_ROLE)
  }

  else(_) {
    fail
  }
}
