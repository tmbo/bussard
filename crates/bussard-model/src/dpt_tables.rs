//! Label tables of the enumerated and bit-set DPTs: the 20.xxx enumerations
//! (N8) and the 21.xxx / 22.xxx bit sets (B8 / B16).
//!
//! The words are bussard's short English names for the values KNX 03_07_02
//! Datapoint Types v02.02.01 defines; the section of each table is cited at
//! its row. A code missing from an enumeration is reserved, a bit missing from
//! a bit set is reserved and specified as 0.

/// One enumeration value: the code on the wire and its label.
pub(crate) type EnumEntry = (u8, &'static str);

/// The value list of a DPT 20.xxx enumeration, `None` when bussard has no
/// table for the sub-type.
///
/// 20.001-20.022: 03_07_02 §3.21; 20.100-20.122: §4.3 (HVAC); 20.600-20.613:
/// §6.3 (lighting and DALI converters).
pub(crate) fn enum_table(sub: u16) -> Option<&'static [EnumEntry]> {
    let table: &'static [EnumEntry] = match sub {
        1 => &[(0, "autonomous"), (1, "slave"), (2, "master")],
        2 => &[
            (0, "Building in use"),
            (1, "Building not used"),
            (2, "Building protection"),
        ],
        3 => &[(0, "occupied"), (1, "standby"), (2, "not occupied")],
        4 => &[(0, "High"), (1, "Medium"), (2, "Low"), (3, "void")],
        5 => &[(0, "normal"), (1, "presence simulation"), (2, "night round")],
        7 => &[(1, "simple alarm"), (2, "basic alarm"), (3, "extended alarm")],
        8 => &[(0, "disabled"), (1, "enabled"), (2, "auto")],
        11 => &[
            (0, "no fault"),
            (1, "general device fault"),
            (2, "communication fault"),
            (3, "configuration fault"),
            (4, "hardware fault"),
            (5, "software fault"),
            (6, "insufficient non volatile memory"),
            (7, "insufficient volatile memory"),
            (8, "memory allocation command with size 0 received"),
            (9, "CRC error"),
            (10, "watchdog reset detected"),
            (11, "invalid opcode detected"),
            (12, "general protection fault"),
            (13, "maximal table length exceeded"),
            (14, "undefined load command received"),
            (15, "group address table is not sorted"),
            (16, "invalid connection number (TSAP)"),
            (17, "invalid group object number (ASAP)"),
            (18, "group object type exceeds max APDU length"),
        ],
        12 => &[
            (0, "no fault"),
            (1, "sensor fault"),
            (2, "process fault / controller fault"),
            (3, "actuator fault"),
            (4, "other fault"),
        ],
        13 => &[
            (0, "not active"),
            (1, "1 s"),
            (2, "2 s"),
            (3, "3 s"),
            (4, "5 s"),
            (5, "10 s"),
            (6, "15 s"),
            (7, "20 s"),
            (8, "30 s"),
            (9, "45 s"),
            (10, "1 min"),
            (11, "1.25 min"),
            (12, "1.5 min"),
            (13, "2 min"),
            (14, "2.5 min"),
            (15, "3 min"),
            (16, "5 min"),
            (17, "15 min"),
            (18, "20 min"),
            (19, "30 min"),
            (20, "1 h"),
            (21, "2 h"),
            (22, "3 h"),
            (23, "5 h"),
            (24, "12 h"),
            (25, "24 h"),
        ],
        14 => &[
            (0, "calm"),
            (1, "light air"),
            (2, "light breeze"),
            (3, "gentle breeze"),
            (4, "moderate breeze"),
            (5, "fresh breeze"),
            (6, "strong breeze"),
            (7, "near gale"),
            (8, "fresh gale"),
            (9, "strong gale"),
            (10, "whole gale"),
            (11, "violent storm"),
            (12, "hurricane"),
        ],
        17 => &[
            (0, "inactive"),
            (1, "digital input not inverted"),
            (2, "digital input inverted"),
            (3, "analog input"),
            (4, "temperature sensor input"),
        ],
        20 => &[(1, "SensorConnection"), (2, "ControllerConnection")],
        // 20.021 names okta 6 and 7 only in German; bussard uses the okta.
        21 => &[
            (0, "Cloudless"),
            (1, "Sunny"),
            (2, "Sunshiny"),
            (3, "Lightly cloudy"),
            (4, "Scattered clouds"),
            (5, "Cloudy"),
            (6, "6 okta"),
            (7, "7 okta"),
            (8, "Overcast"),
            (9, "Sky obstructed from view"),
        ],
        22 => &[
            (0, "do not send"),
            (1, "send always"),
            (2, "send if value changed during powerdown"),
        ],
        100 => &[(0, "auto"), (1, "oil"), (2, "gas"), (3, "solid state fuel")],
        101 => &[(1, "1 stage"), (2, "2 stage"), (3, "modulating")],
        102 => &[
            (0, "Auto"),
            (1, "Comfort"),
            (2, "Standby"),
            (3, "Economy"),
            (4, "Building Protection"),
        ],
        103 => &[
            (0, "Auto"),
            (1, "LegioProtect"),
            (2, "Normal"),
            (3, "Reduced"),
            (4, "Off/FrostProtect"),
        ],
        104 => &[
            (0, "None"),
            (1, "Shift load priority"),
            (2, "Absolute load priority"),
        ],
        105 => &[
            (0, "Auto"),
            (1, "Heat"),
            (2, "Morning Warmup"),
            (3, "Cool"),
            (4, "Night Purge"),
            (5, "Precool"),
            (6, "Off"),
            (7, "Test"),
            (8, "Emergency Heat"),
            (9, "Fan only"),
            (10, "Free Cool"),
            (11, "Ice"),
            (12, "Maximum Heating Mode"),
            (13, "Economic Heat/Cool Mode"),
            (14, "Dehumidification"),
            (15, "Calibration Mode"),
            (16, "Emergency Cool Mode"),
            (17, "Emergency Steam Mode"),
            (20, "NoDem"),
        ],
        106 => &[
            (0, "Normal"),
            (1, "EmergPressure"),
            (2, "EmergDepressure"),
            (3, "EmergPurge"),
            (4, "EmergShutdown"),
            (5, "EmergFire"),
        ],
        107 => &[(0, "Auto"), (1, "CoolingOnly"), (2, "HeatingOnly")],
        108 => &[
            (1, "Heat stage A"),
            (2, "Heat stage B"),
            (3, "Cool stage A"),
            (4, "Cool stage B"),
            (5, "Heat/Cool changeover"),
        ],
        109 => &[
            (1, "Fresh air"),
            (2, "Supply Air"),
            (3, "Discharge Air"),
            (4, "Extract Air"),
        ],
        110 => &[
            (1, "Heat Stage A On/Off"),
            (2, "Heat Stage A Proportional"),
            (3, "Heat Stage B Proportional"),
        ],
        111 => &[
            (0, "not running"),
            (1, "permanently running"),
            (2, "running in intervals"),
        ],
        112 => &[(0, "autonomous"), (1, "master"), (2, "slave")],
        113 => &[
            (0, "normal setpoint"),
            (1, "alternative setpoint"),
            (2, "building protection setpoint"),
        ],
        115 => &[(0, "inactive"), (1, "humidification"), (2, "dehumidification")],
        120 => &[(1, "Air Damper"), (2, "VAV")],
        121 => &[(0, "Backup Value"), (1, "Keep Last State")],
        122 => &[
            (0, "Position unchanged"),
            (1, "Single close"),
            (2, "Single open"),
        ],
        600 => &[
            (0, "off"),
            (1, "on"),
            (2, "no change"),
            (3, "value according to additional parameter"),
            (4, "memory function value"),
            (5, "updated value"),
            (6, "value before locking"),
        ],
        601 => &[
            (0, "off"),
            (1, "on"),
            (2, "no change"),
            (3, "value according to additional parameter"),
            (4, "last value before bus power down"),
        ],
        602 => &[
            (0, "0 s"),
            (1, "0.7 s"),
            (2, "1.0 s"),
            (3, "1.4 s"),
            (4, "2.0 s"),
            (5, "2.8 s"),
            (6, "4.0 s"),
            (7, "5.7 s"),
            (8, "8.0 s"),
            (9, "11.3 s"),
            (10, "16.0 s"),
            (11, "22.6 s"),
            (12, "32.0 s"),
            (13, "45.3 s"),
            (14, "64.0 s"),
            (15, "90.5 s"),
        ],
        603 => &[
            (0, "BlinkingDisabled"),
            (1, "WithoutAcknowledge"),
            (2, "BlinkingWithAcknowledge"),
        ],
        604 => &[
            (0, "automatic light control"),
            (1, "manual light control"),
        ],
        605 => &[(1, "one PB mode"), (2, "two PBs mode")],
        606 => &[
            (0, "inactive"),
            (1, "SwitchOff sent"),
            (2, "SwitchOn sent"),
            (3, "inverse of InfoOnOff sent"),
        ],
        607 => &[
            (1, "one PB, toggle"),
            (2, "one PB, On/DimUp"),
            (3, "one PB, Off/DimDown"),
            (4, "two PBs mode"),
        ],
        608 => &[
            (0, "last actual value"),
            (1, "value according to additional parameter"),
            (2, "last received absolute setvalue"),
        ],
        609 => &[
            (0, "automatic"),
            (1, "leading edge"),
            (2, "trailing edge"),
            (3, "switch mode only"),
            (4, "automatic once"),
            (5, "CFL, leading"),
            (6, "CFL, trailing"),
            (7, "LED, leading"),
            (8, "LED, trailing"),
        ],
        610 => &[
            (0, "undefined"),
            (1, "leading edge"),
            (2, "trailing edge"),
            (3, "detection not possible or error"),
            (4, "calibration pending"),
            (5, "CFL, leading"),
            (6, "CFL, trailing"),
            (7, "LED, leading"),
            (8, "LED, trailing"),
        ],
        611 => &[
            (1, "Start Function Test"),
            (2, "Start Duration Test"),
            (3, "Start Partial Duration Test"),
            (4, "Stop Test"),
            (5, "Reset Function Test Done Flag"),
            (6, "Reset Duration Test Done"),
        ],
        612 => &[
            (0, "Restore Factory Default Settings"),
            (1, "Goto Rest Mode"),
            (2, "Goto Inhibit Mode"),
            (3, "Re-Light / Reset Inhibit"),
            (4, "Reset Lamp Time"),
        ],
        613 => &[
            (1, "Request Converter Status"),
            (2, "Request Converter Test Result"),
            (3, "Request Battery Info"),
            (4, "Request Converter FT Info"),
            (5, "Request Converter DT Info"),
            (6, "Request Converter PDT Info"),
            (7, "Request Converter Info"),
            (8, "Request Converter Info Fix"),
        ],
        _ => return None,
    };
    Some(table)
}

/// The label of `code` in a 20.xxx enumeration, `None` for a reserved code.
pub(crate) fn enum_label(sub: u16, code: u8) -> Option<&'static str> {
    enum_table(sub)?
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, l)| *l)
}

/// Normalises a label or user word for comparison: lowercase, with `_`, `-`
/// and runs of spaces folded to one space.
pub(crate) fn fold_word(s: &str) -> String {
    s.to_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The code of the 20.xxx label `word` (compared with [`fold_word`]).
pub(crate) fn enum_code(sub: u16, word: &str) -> Option<u8> {
    let want = fold_word(word);
    enum_table(sub)?
        .iter()
        .find(|(_, l)| fold_word(l) == want)
        .map(|(c, _)| *c)
}

/// The bit names of a 21.xxx (B8) or 22.xxx (B16) bit set, indexed by bit
/// number; an empty name marks a reserved bit. `None` when bussard has no
/// table for the sub-type.
///
/// 21.001, 21.002: 03_07_02 §3.22; 21.100-21.106 and 22.100, 22.101: §4.4 and
/// §4.5 (HVAC); 21.601: §6.4.1 (lighting actuator error information).
pub(crate) fn flag_table(main: u16, sub: u16) -> Option<&'static [&'static str]> {
    let table: &'static [&'static str] = match (main, sub) {
        (21, 1) => &[
            "OutOfService",
            "Fault",
            "Overridden",
            "InAlarm",
            "AlarmUnAck",
        ],
        (21, 2) => &["UserStopped", "OwnIA", "VerifyMode"],
        (21, 100) => &[
            "ForceRequest",
            "Protection",
            "Oversupply",
            "Overrun",
            "DHWNorm",
            "DHWLegio",
            "RoomHComf",
            "RoomHMax",
        ],
        (21, 101) => &["ForceRequest"],
        (21, 102) => &[
            "Fault",
            "StatusECO",
            "TempFlowLimit",
            "TempReturnLimit",
            "StatusMorningBoost",
            "StatusStartOptim",
            "StatusStopOptim",
            "SummerMode",
        ],
        (21, 103) => &["Fault", "SDHWLoadActive", "SolarLoadSufficient"],
        (21, 104) => &["Oil", "Gas", "SolidState"],
        (21, 105) => &["Fault"],
        (21, 106) => &["Fault", "FanActive", "Heat", "Cool"],
        (21, 601) => &[
            "LoadDetectionError",
            "Undervoltage",
            "Overcurrent",
            "Underload",
            "DefectiveLoad",
            "LampFailure",
            "Overheat",
        ],
        (22, 100) => &[
            "Fault",
            "DHWLoadActive",
            "LegioProtActive",
            "DHWPushActive",
            "OtherEnergySourceActive",
            "SolarEnergyOnly",
            "SolarEnergySupport",
            "TempOptimShiftActive",
        ],
        // Bit 8 is HeatCoolMode, 0 = cooling, 1 = heating: the decoder names
        // it either way (see `codec::decode`).
        (22, 101) => &[
            "Fault",
            "StatusEcoH",
            "TempFlowLimit",
            "TempReturnLimit",
            "StatusMorningBoostH",
            "StatusStartOptim",
            "StatusStopOptim",
            "HeatingDisabled",
            "Heating",
            "StatusEcoC",
            "StatusPreCool",
            "CoolingDisabled",
            "DewPointStatus",
            "FrostAlarm",
            "OverheatAlarm",
        ],
        _ => return None,
    };
    Some(table)
}

/// The mask of the bits a known bit set reserves (specified as 0), `0` for an
/// unknown sub-type.
pub(crate) fn flag_reserved_mask(main: u16, sub: u16) -> u16 {
    let width = if main == 22 { 16 } else { 8 };
    let Some(names) = flag_table(main, sub) else {
        return 0;
    };
    (0..width)
        .filter(|bit| names.get(*bit).is_none_or(|n| n.is_empty()))
        .fold(0u16, |m, bit| m | (1 << bit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_tables_have_unique_codes_and_words() {
        for sub in (0..=999).filter_map(|s| enum_table(s).map(|t| (s, t))) {
            let (s, table) = sub;
            for (i, (code, label)) in table.iter().enumerate() {
                for (other_code, other_label) in &table[i + 1..] {
                    assert_ne!(code, other_code, "20.{s:03} code {code}");
                    assert_ne!(
                        fold_word(label),
                        fold_word(other_label),
                        "20.{s:03} label {label}"
                    );
                }
                assert_eq!(enum_code(s, label), Some(*code), "20.{s:03} {label}");
            }
        }
    }

    #[test]
    fn test_flag_reserved_mask_known_sets() {
        assert_eq!(flag_reserved_mask(21, 1), 0xE0);
        assert_eq!(flag_reserved_mask(21, 601), 0x80);
        assert_eq!(flag_reserved_mask(22, 101), 0x8000);
        assert_eq!(flag_reserved_mask(22, 100), 0xFF00);
        assert_eq!(flag_reserved_mask(21, 999), 0);
    }
}
