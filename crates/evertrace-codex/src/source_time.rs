//! Timestamp normalization at the native session-record format boundary.

use evertrace_domain::evidence::EventTimeProvenance;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedSourceTimestamp {
    pub timestamp_us: i64,
    pub provenance: EventTimeProvenance,
}

pub fn source_timestamp_us(value: &str) -> Option<i64> {
    parse_source_timestamp(value).map(|value| value.timestamp_us)
}

/// The format supplies an offset and representation precision, not clock accuracy.
pub fn parse_source_timestamp(value: &str) -> Option<ParsedSourceTimestamp> {
    if !value.is_ascii() || !(20..=32).contains(&value.len()) {
        return None;
    }
    let (local, offset_seconds) = if let Some(local) = value.strip_suffix('Z') {
        (local, 0_i32)
    } else {
        let split = value.len().checked_sub(6)?;
        let offset = value.get(split..)?;
        let sign = match offset.get(..1)? {
            "+" => 1,
            "-" if offset != "-00:00" => -1,
            _ => return None,
        };
        if !offset
            .get(1..3)?
            .bytes()
            .chain(offset.get(4..6)?.bytes())
            .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let hour = offset.get(1..3)?.parse::<i32>().ok()?;
        let minute = offset.get(4..6)?.parse::<i32>().ok()?;
        if offset.get(3..4)? != ":" || !(0..24).contains(&hour) || !(0..60).contains(&minute) {
            return None;
        }
        (value.get(..split)?, sign * (hour * 3600 + minute * 60))
    };
    let (whole, fraction) = match local.split_once('.') {
        Some((_, "")) => return None,
        Some(parts) => parts,
        None => (local, ""),
    };
    if whole.len() != 19
        || whole.get(4..5)? != "-"
        || whole.get(7..8)? != "-"
        || whole.get(10..11)? != "T"
        || whole.get(13..14)? != ":"
        || whole.get(16..17)? != ":"
        || fraction.len() > 6
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let number = |start, end| {
        let text = whole.get(start..end)?;
        text.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then_some(())?;
        text.parse::<i64>().ok()
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > months[usize::try_from(month - 1).ok()?]
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let leap_days = |year: i64| year / 4 - year / 100 + year / 400;
    let days = 365 * (year - 1970) + leap_days(year - 1) - leap_days(1969)
        + months[..usize::try_from(month - 1).ok()?]
            .iter()
            .sum::<i64>()
        + day
        - 1;
    let precision_us = 10_u32.pow(u32::try_from(6 - fraction.len()).ok()?);
    let micros = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<i64>().ok()? * i64::from(precision_us)
    };
    let timestamp_us = ((days * 24 + hour) * 3600 + minute * 60 + second) * 1_000_000 + micros
        - i64::from(offset_seconds) * 1_000_000;
    (timestamp_us >= 0).then_some(ParsedSourceTimestamp {
        timestamp_us,
        provenance: EventTimeProvenance::SourceTimestamp {
            utc_offset_seconds: offset_seconds,
            precision_us,
            uncertainty_us: None,
        },
    })
}

/// Read only the fixed timestamp field, never an event time inferred from prose.
pub fn record_source_timestamp(bytes: &[u8]) -> Option<ParsedSourceTimestamp> {
    #[derive(serde::Deserialize)]
    struct Timestamp {
        timestamp: Option<String>,
    }
    let record: Timestamp = serde_json::from_slice(bytes).ok()?;
    parse_source_timestamp(record.timestamp.as_deref()?)
}
