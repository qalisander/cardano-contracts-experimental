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
    self.released_units >= 0,
    // No unit accounting without an asset to account for.
    or {
      self.asset != None,
      self.released_units == 0,
    },
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

/// Newly releasable amount at `now`, clamped to what is still locked.
///
/// Shared by the lovelace and unit ledgers: both vest on the same schedule and
/// differ only in which balance and which counter they read.
pub fn releasable_from(
  self: LinearVestingDatum,
  locked: Int,
  released: Int,
  now: PosixTime,
) -> Int {
  let total = locked + released
  math.clamp(vested(self, total, now) - released, min: 0, max: locked)
}

/// Newly releasable lovelace at `now`.
pub fn releasable(
  self: LinearVestingDatum,
  locked: Lovelace,
  now: PosixTime,
) -> Lovelace {
  releasable_from(self, locked, self.released, now)
}

/// Newly releasable units of the vested asset at `now`.
pub fn releasable_units(
  self: LinearVestingDatum,
  locked_units: Int,
  now: PosixTime,
) -> Int {
  releasable_from(self, locked_units, self.released_units, now)
}

/// Conservative "now" extracted from the tx validity lower bound.
pub fn now_at_least(range: Interval<Int>) -> Option<PosixTime> {
  when range.lower_bound.bound_type is {
    Finite(t) -> Some(t)
    _ -> None
  }
}
