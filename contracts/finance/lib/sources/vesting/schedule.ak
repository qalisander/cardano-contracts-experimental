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

/// Newly releasable amount at `now`, clamped to available locked lovelace.
pub fn releasable(
  self: VestingDatum,
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
