//! The wire trace costs nothing while `BUSSARD_WIRE_TRACE` is off (issue
//! #215): `trace_frame` neither encodes nor formats, so it allocates nothing.
//! A counting global allocator proves it; the test binary runs in its own
//! process under nextest, so the allocator sees only this test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use bussard_transport::cemi::{
    Apdu, CemiFrame, Control1, Control2, Destination, MessageCode, Tpci,
};
use bussard_transport::wire_trace::{Direction, WIRE_TRACE_ENV, trace_frame};

/// Counts every allocation, then defers to the system allocator.
struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` unchanged; the counter is an
// atomic increment with no other effect.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn test_trace_frame_allocates_nothing_when_off() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: nextest runs this test in its own process and nothing else
    // reads the environment concurrently; the flag is read once, below.
    unsafe {
        std::env::remove_var(WIRE_TRACE_ENV);
    }
    let frame = CemiFrame {
        message_code: MessageCode::LDataReq,
        additional_info: Vec::new(),
        control1: Control1::default(),
        control2: Control2::default(),
        source: "1.0.255".parse()?,
        destination: Destination::Individual("1.0.30".parse()?),
        tpci: Tpci::Other(0x4b),
        apdu: Apdu::Other {
            apci: 0x03D5,
            data: vec![0x00, 0x0c, 0x10, 0x01],
        },
    };
    // The first call reads and caches the environment flag.
    trace_frame(Direction::Outbound, &frame);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let started = std::time::Instant::now();
    for _ in 0..100_000 {
        trace_frame(Direction::Outbound, std::hint::black_box(&frame));
        trace_frame(Direction::Inbound, std::hint::black_box(&frame));
    }
    let elapsed = started.elapsed();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
    println!(
        "trace off: 200000 calls, {allocations} allocations, {:.1} ns per call",
        elapsed.as_nanos() as f64 / 200_000.0
    );
    assert_eq!(allocations, 0);
    Ok(())
}
