//! The observable event stream — the seam a future read-only HTML
//! visualization consumes.
//!
//! Every telegram crossing the bus and every device state change is published
//! through an [`EventSink`]. The bus only ever *emits* events; it never queries
//! a sink, so any observer (a logger today, an HTML view later) is strictly
//! read-only and cannot perturb the simulation.

use crate::wire::IndividualAddress;

/// Which way a telegram was travelling relative to the tunnelling frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the connected tool toward the bus/devices.
    ToBus,
    /// From a device toward the connected tool.
    ToTool,
}

/// A structured observation of something that happened in the simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A cEMI telegram crossed the bus.
    Telegram {
        /// Travel direction.
        direction: Direction,
        /// The raw cEMI bytes (independently decodable by an observer).
        cemi: Vec<u8>,
        /// A short human summary for logs.
        summary: String,
    },
    /// A device's load state changed for a given object (LSM index).
    LoadStateChanged {
        /// The device address.
        device: IndividualAddress,
        /// The object / LSM index.
        object: u8,
        /// The new load-state byte.
        state: u8,
    },
    /// A device accepted a memory write.
    MemoryWritten {
        /// The device address.
        device: IndividualAddress,
        /// The write base address (up to 24-bit).
        addr: u32,
        /// The number of bytes written.
        len: usize,
    },
    /// A device accepted a property write.
    PropertyWritten {
        /// The device address.
        device: IndividualAddress,
        /// The interface-object index.
        object: u8,
        /// The property id.
        pid: u8,
    },
    /// A device restarted (master reset or plain restart).
    Restarted {
        /// The device address.
        device: IndividualAddress,
        /// Whether this was a master reset (erase) vs a plain restart.
        master_reset: bool,
    },
    /// A device's authorization level changed.
    AuthChanged {
        /// The device address.
        device: IndividualAddress,
        /// The new access level (0 = highest).
        level: u8,
    },
    /// A device entered or left KNX programming mode (its `PID_PROGMODE` bit).
    /// While in programming mode the device answers the broadcast
    /// `A_IndividualAddress_Read`.
    ProgModeChanged {
        /// The device address.
        device: IndividualAddress,
        /// Whether programming mode is now on.
        on: bool,
    },
    /// A device updated a com-object's value from an inbound group write it
    /// listens to (the runtime group-communication path).
    GroupObjectUpdated {
        /// The device address.
        device: IndividualAddress,
        /// The com-object number (ASAP) that was updated.
        object: u16,
        /// The group address the write arrived on (raw 16-bit).
        ga: u16,
    },
}

/// A read-only observer of the simulation's [`Event`] stream.
pub trait EventSink: Send + Sync {
    /// Publish one event. Must not block for long; observers should offload.
    fn emit(&self, event: Event);
}

/// An [`EventSink`] that logs each event via `tracing` — the Phase 1 placeholder
/// for the eventual HTML visualization.
#[derive(Debug, Default)]
pub struct TracingSink;

impl EventSink for TracingSink {
    fn emit(&self, event: Event) {
        match &event {
            Event::Telegram {
                direction, summary, ..
            } => tracing::info!(?direction, "{summary}"),
            Event::LoadStateChanged {
                device,
                object,
                state,
            } => tracing::info!(%device, object, state, "load-state changed"),
            Event::MemoryWritten { device, addr, len } => {
                tracing::info!(%device, addr = format!("0x{addr:06x}"), len, "memory written")
            }
            Event::PropertyWritten {
                device,
                object,
                pid,
            } => tracing::info!(%device, object, pid, "property written"),
            Event::Restarted {
                device,
                master_reset,
            } => tracing::info!(%device, master_reset, "device restarted"),
            Event::AuthChanged { device, level } => {
                tracing::info!(%device, level, "authorization changed")
            }
            Event::ProgModeChanged { device, on } => {
                tracing::info!(%device, on, "programming mode changed")
            }
            Event::GroupObjectUpdated { device, object, ga } => {
                tracing::info!(%device, object, ga = format!("0x{ga:04x}"), "group object updated")
            }
        }
    }
}

/// An [`EventSink`] that records every event into a shared buffer — useful in
/// tests to assert on the observed stream, and a template for a real subscriber.
#[derive(Debug, Default, Clone)]
pub struct RecordingSink {
    events: std::sync::Arc<std::sync::Mutex<Vec<Event>>>,
}

impl RecordingSink {
    /// Create an empty recording sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded events so far.
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl EventSink for RecordingSink {
    fn emit(&self, event: Event) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }
}

/// An [`EventSink`] that fans one event out to several sinks.
pub struct FanoutSink {
    sinks: Vec<std::sync::Arc<dyn EventSink>>,
}

impl FanoutSink {
    /// Build a fan-out over the given sinks.
    pub fn new(sinks: Vec<std::sync::Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }
}

impl EventSink for FanoutSink {
    fn emit(&self, event: Event) {
        for s in &self.sinks {
            s.emit(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recording_sink_captures() {
        let sink = RecordingSink::new();
        sink.emit(Event::Restarted {
            device: IndividualAddress::new(1, 1, 2),
            master_reset: true,
        });
        assert_eq!(sink.events().len(), 1);
    }

    #[test]
    fn test_fanout_delivers_to_all() {
        let a = std::sync::Arc::new(RecordingSink::new());
        let b = std::sync::Arc::new(RecordingSink::new());
        let fan = FanoutSink::new(vec![a.clone(), b.clone()]);
        fan.emit(Event::AuthChanged {
            device: IndividualAddress::new(1, 1, 2),
            level: 0,
        });
        assert_eq!(a.events().len(), 1);
        assert_eq!(b.events().len(), 1);
    }
}
