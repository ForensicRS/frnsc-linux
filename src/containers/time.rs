//! Hand-rolled RFC3339Nano parsing (`2023-11-15T12:34:56.123456789Z`, the format Docker's
//! `json-file` driver and containerd/CRI both stamp every log line with).
//!
//! No `chrono` dependency, matching the rest of the workspace's timestamp handling
//! ([`forensic_rs::utils::time`]). Bounds-checked throughout: a malformed or hostile timestamp
//! string returns `None`, never a panic and never a guessed value.

use forensic_rs::prelude::ForensicTimestamp;

/// Parses an RFC3339Nano timestamp (as emitted by Docker's `json-file` driver and CRI log
/// lines) into a [`ForensicTimestamp`]. The rules require these to be treated as already UTC:
/// an explicit numeric offset (`+02:00`) is honored and converted to UTC, never reinterpreted
/// against the host's timezone. Returns `None` on anything that doesn't parse, rather than
/// guessing.
pub(crate) fn parse_rfc3339_nano(s: &str) -> Option<ForensicTimestamp> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let digit = |i: usize| -> Option<i64> {
        let c = *b.get(i)?;
        c.is_ascii_digit().then_some((c - b'0') as i64)
    };
    let two = |i: usize| -> Option<i64> { Some(digit(i)? * 10 + digit(i + 1)?) };
    let four = |i: usize| -> Option<i64> {
        Some(digit(i)? * 1000 + digit(i + 1)? * 100 + digit(i + 2)? * 10 + digit(i + 3)?)
    };

    let year = four(0)?;
    if b[4] != b'-' {
        return None;
    }
    let month = two(5)?;
    if b[7] != b'-' {
        return None;
    }
    let day = two(8)?;
    if b[10] != b'T' && b[10] != b't' {
        return None;
    }
    let hour = two(11)?;
    if b[13] != b':' {
        return None;
    }
    let minute = two(14)?;
    if b[16] != b':' {
        return None;
    }
    let second = two(17)?;

    let mut idx = 19;
    let mut nanos: i64 = 0;
    if b.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while b.get(idx).is_some_and(u8::is_ascii_digit) {
            idx += 1;
        }
        let frac_len = idx - start;
        if frac_len == 0 || frac_len > 9 {
            return None;
        }
        for &c in &b[start..idx] {
            nanos = nanos * 10 + (c - b'0') as i64;
        }
        for _ in frac_len..9 {
            nanos *= 10;
        }
    }

    let offset_seconds: i64 = match b.get(idx) {
        Some(b'Z') | Some(b'z') => {
            idx += 1;
            0
        }
        Some(&sign @ (b'+' | b'-')) => {
            idx += 1;
            let offset_hour = two(idx)?;
            idx += 2;
            if b.get(idx) != Some(&b':') {
                return None;
            }
            idx += 1;
            let offset_minute = two(idx)?;
            idx += 2;
            let total = offset_hour * 3600 + offset_minute * 60;
            if sign == b'-' {
                -total
            } else {
                total
            }
        }
        _ => return None,
    };
    if idx != b.len() {
        return None;
    }

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    if !is_valid_day(year, month, day) {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600)?
        .checked_add(minute * 60)?
        .checked_add(second)?
        .checked_sub(offset_seconds)?;
    let micros = secs.checked_mul(1_000_000)?.checked_add(nanos / 1000)?;
    Some(ForensicTimestamp::from_unix_micros(micros))
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn is_valid_day(year: i64, month: i64, day: i64) -> bool {
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= days_in_month
}

/// Days since the Unix epoch (1970-01-01) for a proleptic-Gregorian `y-m-d`, per Howard
/// Hinnant's `days_from_civil` algorithm. `month`/`day` are assumed already range-checked by
/// [`is_valid_day`].
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_zulu_timestamp_with_nanoseconds() {
        let ts = parse_rfc3339_nano("2023-11-15T12:34:56.123456789Z").unwrap();
        // 2023-11-15T12:34:56Z is 1700051696 unix seconds; +123456 micros (truncated from nanos).
        assert_eq!(
            ts,
            ForensicTimestamp::from_unix_micros(1_700_051_696_123_456)
        );
    }

    #[test]
    fn parses_a_timestamp_with_no_fraction() {
        let ts = parse_rfc3339_nano("2023-11-15T12:34:56Z").unwrap();
        assert_eq!(
            ts,
            ForensicTimestamp::from_unix_micros(1_700_051_696_000_000)
        );
    }

    #[test]
    fn pads_a_short_fraction_instead_of_misreading_its_scale() {
        // ".5" means 500ms, not 5ns -- a short fraction must be treated as the *leading* digits.
        let ts = parse_rfc3339_nano("2023-11-15T12:34:56.5Z").unwrap();
        assert_eq!(
            ts,
            ForensicTimestamp::from_unix_micros(1_700_051_696_500_000)
        );
    }

    #[test]
    fn honors_an_explicit_positive_offset_by_converting_to_utc() {
        let with_offset = parse_rfc3339_nano("2023-11-15T14:34:56Z+02:00");
        // malformed (Z and offset both present) -- must not silently pick one.
        assert!(with_offset.is_none());
        let offset_only = parse_rfc3339_nano("2023-11-15T14:34:56+02:00").unwrap();
        let zulu_equivalent = parse_rfc3339_nano("2023-11-15T12:34:56Z").unwrap();
        assert_eq!(offset_only, zulu_equivalent);
    }

    #[test]
    fn honors_an_explicit_negative_offset() {
        let offset = parse_rfc3339_nano("2023-11-15T10:34:56-02:00").unwrap();
        let zulu_equivalent = parse_rfc3339_nano("2023-11-15T12:34:56Z").unwrap();
        assert_eq!(offset, zulu_equivalent);
    }

    #[test]
    fn rejects_an_invalid_calendar_date_instead_of_normalizing_it() {
        assert!(parse_rfc3339_nano("2023-02-30T00:00:00Z").is_none());
        assert!(parse_rfc3339_nano("2023-13-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_nano("2023-00-01T00:00:00Z").is_none());
    }

    #[test]
    fn accepts_february_29_on_a_leap_year_only() {
        assert!(parse_rfc3339_nano("2024-02-29T00:00:00Z").is_some());
        assert!(parse_rfc3339_nano("2023-02-29T00:00:00Z").is_none());
    }

    #[test]
    fn rejects_garbage_instead_of_panicking() {
        assert!(parse_rfc3339_nano("").is_none());
        assert!(parse_rfc3339_nano("not-a-timestamp").is_none());
        assert!(parse_rfc3339_nano("2023-11-15T12:34:56.").is_none());
        assert!(
            parse_rfc3339_nano("2023-11-15 12:34:56Z").is_none(),
            "only 'T'/'t' separates the date and time, not a space"
        );
    }
}
