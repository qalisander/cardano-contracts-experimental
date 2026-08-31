use aiken/interval.{Finite, Interval}
use aiken/math
use cardano/assets.{Lovelace}
use sources/vesting/types.{PosixTime, VestingDatum}

/// Pure vesting schedule helpers.
/// The first timestamp at which funds can be released.
pub fn cliff_end(self: VestingDatum) -> PosixTime {
  self.start + self.cliff
}

/// The timestamp at which the schedule is fully vested.
pub fn end(self: VestingDatum) -> PosixTime {
  self.start + self.duration
}

/// Check that the schedule is well formed.
pub fn is_valid(self: VestingDatum) -> Bool {
  and {
    self.duration > 0,
    self.cliff >= 0,
    self.cliff <= self.duration,
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
pub fn vested(self: VestingDatum, total: Lovelace, now: PosixTime) -> Lovelace {
  if now < cliff_end(self) {
    0
  } else if now >= end(self) {
    total
  } else {
    total * ( now - self.start ) / self.duration
  }
}

/// Newly releasable amount at `now`, clamped to what is still locked.
///
/// Shared by the lovelace and unit ledgers: both vest on the same schedule and
/// differ only in which balance and which counter they read.
pub fn releasable_from(
  self: VestingDatum,
  locked: Int,
  released: Int,
  now: PosixTime,
) -> Int {
  let total = locked + released
  math.clamp(vested(self, total, now) - released, min: 0, max: locked)
}

/// Newly releasable lovelace at `now`.
pub fn releasable(
  self: VestingDatum,
  locked: Lovelace,
  now: PosixTime,
) -> Lovelace {
  releasable_from(self, locked, self.released, now)
}

/// Newly releasable units of the vested asset at `now`.
pub fn releasable_units(
  self: VestingDatum,
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
