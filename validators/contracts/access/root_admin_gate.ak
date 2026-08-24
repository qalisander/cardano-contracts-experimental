use cardano/transaction.{Transaction}
use contracts/access/sources/access_control

pub type AccessControlled {
  AccessControlled { ac: access_control.AccessControl }
}

validator root_admin_gate {
  spend(datum: Option<AccessControlled>, _redeemer: Void, _own_ref, tx: Transaction) {
    expect Some(state) = datum
    access_control.tx_has_role(state.ac, tx, access_control.default_admin_role)
  }

  else(_) {
    fail
  }
}
