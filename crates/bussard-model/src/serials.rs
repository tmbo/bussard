//! Device serial numbers in `bussard.lock` (issue #752).
//!
//! A KNX device reports its serial number in PID 11 of its device object. The
//! commands that read it anyway (`adopt`, `assign`, `scan`, `describe`) record
//! it in the device's lock entry as `serial_number`, so a device certificate,
//! whose serial selects its device, finds a device ETS never saw.
//!
//! A serial number names one piece of hardware, and hardware has one address:
//! recording it on a device clears it from any other device of the model (the
//! hardware was re-addressed, or the entry is stale).

use crate::IndividualAddress;
use crate::loader::Model;

/// The length of a KNX serial number in octets.
pub const SERIAL_LEN: usize = 6;

/// A serial number as the lock spells it: twelve upper-case hex digits.
pub fn format_serial(serial: &[u8; SERIAL_LEN]) -> String {
    serial.iter().map(|b| format!("{b:02X}")).collect()
}

/// What [`Model::record_serial`] changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialRecord {
    /// The model holds no device at the address; nothing changed.
    NotModelled,
    /// The lock already held this serial number for the device.
    Unchanged,
    /// The serial number was recorded.
    Recorded {
        /// The serial number the lock held for the device before, if any
        /// (another one means the hardware was replaced).
        previous: Option<String>,
        /// The other devices whose entry held this serial number and no
        /// longer does.
        cleared: Vec<IndividualAddress>,
    },
}

impl SerialRecord {
    /// Whether the model changed (and needs a save).
    pub fn changed(&self) -> bool {
        matches!(self, SerialRecord::Recorded { .. })
    }
}

impl Model {
    /// Records `serial` as the serial number of the device at `ia` in its
    /// lock entry and clears it from every other device. Nothing is saved;
    /// the caller saves when [`SerialRecord::changed`].
    pub fn record_serial(
        &mut self,
        ia: IndividualAddress,
        serial: &[u8; SERIAL_LEN],
    ) -> SerialRecord {
        let text = format_serial(serial);
        let Some(loaded) = self.devices.get(&ia) else {
            return SerialRecord::NotModelled;
        };
        let previous = loaded.device.lock.serial_number.clone();
        let cleared: Vec<IndividualAddress> = self
            .devices
            .iter()
            .filter(|(other, d)| {
                **other != ia
                    && d.device
                        .lock
                        .serial_number
                        .as_deref()
                        .is_some_and(|s| s.eq_ignore_ascii_case(&text))
            })
            .map(|(other, _)| *other)
            .collect();
        if previous.as_deref() == Some(text.as_str()) && cleared.is_empty() {
            return SerialRecord::Unchanged;
        }
        for other in &cleared {
            if let Some(d) = self.devices.get_mut(other) {
                d.device.lock.serial_number = None;
            }
        }
        if let Some(d) = self.devices.get_mut(&ia) {
            d.device.lock.serial_number = Some(text);
        }
        SerialRecord::Recorded { previous, cleared }
    }

    /// The device whose lock entry records `serial`, if any.
    pub fn device_with_serial(&self, serial: &[u8; SERIAL_LEN]) -> Option<IndividualAddress> {
        let text = format_serial(serial);
        self.devices
            .iter()
            .find(|(_, d)| {
                d.device
                    .lock
                    .serial_number
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&text))
            })
            .map(|(ia, _)| *ia)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::LoadedDevice;
    use crate::schema::Device;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A synthetic serial number.
    const SERIAL: [u8; SERIAL_LEN] = [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04];

    fn model_with(addrs: &[&str]) -> Result<Model, Box<dyn std::error::Error>> {
        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        for a in addrs {
            let address: IndividualAddress = a.parse()?;
            let device: Device = toml::from_str(&format!("address = \"{a}\"\nname = \"d\"\n"))?;
            model.devices.insert(
                address,
                LoadedDevice {
                    device,
                    file_stem: a.to_string(),
                },
            );
        }
        Ok(model)
    }

    #[test]
    fn test_format_serial_upper_hex() {
        assert_eq!(format_serial(&SERIAL), "00FA01020304");
    }

    #[test]
    fn test_record_serial_moves_between_devices() -> TestResult {
        let mut model = model_with(&["1.1.1", "1.1.2"])?;
        let a: IndividualAddress = "1.1.1".parse()?;
        let b: IndividualAddress = "1.1.2".parse()?;
        assert_eq!(
            model.record_serial("1.1.9".parse()?, &SERIAL),
            SerialRecord::NotModelled
        );
        assert_eq!(
            model.record_serial(a, &SERIAL),
            SerialRecord::Recorded {
                previous: None,
                cleared: vec![]
            }
        );
        assert_eq!(model.record_serial(a, &SERIAL), SerialRecord::Unchanged);
        assert_eq!(model.device_with_serial(&SERIAL), Some(a));
        assert_eq!(
            model.record_serial(b, &SERIAL),
            SerialRecord::Recorded {
                previous: None,
                cleared: vec![a]
            }
        );
        assert_eq!(model.device_with_serial(&SERIAL), Some(b));
        let a_lock = &model.devices.get(&a).ok_or("no 1.1.1")?.device.lock;
        assert_eq!(a_lock.serial_number, None);
        Ok(())
    }

    #[test]
    fn test_record_serial_round_trips_through_the_lock() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "bussard-serials-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        let a: IndividualAddress = "1.1.1".parse()?;
        let mut model = model_with(&["1.1.1"])?;
        model.save(&dir)?;
        let lock = std::fs::read_to_string(dir.join("bussard.lock")).unwrap_or_default();
        assert!(!lock.contains("version = 4"), "{lock}");
        model.record_serial(a, &SERIAL);
        model.save(&dir)?;
        let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
        assert!(lock.contains("version = 4"), "{lock}");
        assert!(lock.contains("serial_number = \"00FA01020304\""), "{lock}");
        let back = Model::load(&dir)?;
        assert_eq!(back.device_with_serial(&SERIAL), Some(a));
        // A v3 lock may not carry the v4 key.
        std::fs::write(
            dir.join("bussard.lock"),
            lock.replace("version = 4", "version = 3"),
        )?;
        assert!(Model::load(&dir).is_err());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
