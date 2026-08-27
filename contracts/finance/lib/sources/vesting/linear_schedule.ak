use aiken/interval.{Finite, Interval}
use aiken/math
use cardano/assets.{Lovelace}
use sources/vesting/linear_types.{LinearVestingDatum, PosixTime}

/// Stepped-linear schedule helpers.
pub fn duration(self: LinearVestingDatum) -> Int {
  self.period * self.steps
}

/// The first timestamp at which funds can be released.
pub fn cliff_end(self: LinearVestingDatum) -> PosixTime {
  self.start + self.cliff
}

/// The timestamp at which the schedule is fully vested.
pub fn end(self: LinearVestingDatum) -> PosixTime {
  self.start + duration(self)
}

/// Check that the schedule is well formed.
pub fn is_valid(self: LinearVestingDatum) -> Bool {
  and {
    self.period > 0,
    self.steps > 0,
    self.cliff >= 0,
    self.cliff <= duration(self),
    self.released >= 0,
  }
}

/// Cumulative vested amount at `now`.
pub fn vested(
  self: LinearVestingDatum,
  total: Lovelace,
  now: PosixTime,
) -> Lovelace {
  if now < self.start {
    0
  } else if self.cliff > 0 && now < cliff_end(self) {
    0
  } else {
    if now >= end(self) {
      total
    } else {
      let elapsed_steps = ( now - self.start ) / self.period
      total * elapsed_steps / self.steps
    }
  }
}

/// Newly releasable amount at `now`, clamped to available locked lovelace.
pub fn releasable(
  self: LinearVestingDatum,
  locked: Lovelace,
  now: PosixTime,
) -> Lovelace {
  let total = locked + self.released
  math.clamp(vested(self, total, now) - self.released, min: 0, max: locked)
}

/// Conservative "now" extracted from the tx validity lower bound.
pub fn now_at_least(range: Interval<Int>) -> Option<PosixTime> {
  when range.lower_bound.bound_type is {
    Finite(t) -> Some(t)
    _ -> None
  }
}
