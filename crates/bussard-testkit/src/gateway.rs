//! [`MockGateway`]: a configurable loopback KNXnet/IP tunnelling server.
//!
//! Build one with [`MockGateway::builder`], start it, and point the client
//! under test at [`MockGateway::addr`]. The gateway runs as a tokio task until
//! the client disconnects (unless [`GatewayBuilder::keep_serving`] is set), until
//! it has been idle for [`GatewayBuilder::idle_timeout`], or until it is dropped.
//!
//! ```no_run
//! # async fn demo() -> bussard_testkit::TestResult {
//! use bussard_testkit::{MockDevice, MockGateway, ia};
//! let gw = MockGateway::builder()
//!     .device(MockDevice::system_b(ia("1.1.4")?))
//!     .start()
//!     .await?;
//! // ... run the client against gw.addr() ...
//! assert!(gw.sent()?.len() > 0);
//! # Ok(()) }
//! ```

use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, MessageCode, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::MockError;
use crate::device::{MockDevice, Reaction, Step};
use crate::wire::{self, connect_refusal_body, connect_response_body};

/// How the gateway answers the client's TUNNELLING_REQUESTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPolicy {
    /// ACK every request with status 0 (a normal gateway).
    Ack,
    /// Never ACK, so the client's ACK timeout and retransmits run out.
    Never,
    /// ACK with this non-zero status (a refusal).
    Status(u8),
}

/// A gateway link outage (issue #177): models a pulled LAN cable on the IP
/// interface. Configure it with [`GatewayBuilder::outage`].
///
/// The `after_frame`-th TUNNELLING_REQUEST (1-based) is served normally. From
/// then on the gateway swallows **every** datagram (no ACK, no heartbeat
/// answer, no CONNECT_RESPONSE) until `duration` has passed since that frame.
/// When the outage ends the gateway has dropped the old channel: requests on it
/// stay unanswered, a DISCONNECT for it is answered (and does not stop the
/// gateway), and the next CONNECT is granted a new channel id (the old one plus
/// one). With [`Duration::MAX`] the link never comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outage {
    /// The last TUNNELLING_REQUEST served before the link goes down (1-based).
    pub after_frame: usize,
    /// How long the link stays down, measured from that frame.
    pub duration: Duration,
}

/// A scripted reaction to a client frame: returns the frames to push back.
type Responder = Box<dyn FnMut(&CemiFrame) -> Vec<CemiFrame> + Send>;

/// One datagram as an [`GatewayBuilder::intercept`] hook sees it, before the
/// gateway acts on it.
#[derive(Debug, Clone, Copy)]
pub struct Inbound<'a> {
    /// The KNXnet/IP service.
    pub service: ServiceType,
    /// The cEMI frame of a TUNNELLING_REQUEST, `None` for other services.
    pub cemi: Option<&'a CemiFrame>,
}

/// What the gateway does with one datagram, as decided by an
/// [`GatewayBuilder::intercept`] hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Handle it normally.
    Serve,
    /// Drop it silently: no answer, no ACK, no capture, not seen by the line.
    /// A hook that keeps its own "link down until" clock models a gateway
    /// outage that, unlike [`Outage`], keeps the channel id when it ends.
    Swallow,
}

/// A fault-injection hook; see [`GatewayBuilder::intercept`].
type Interceptor = Box<dyn FnMut(&Inbound<'_>) -> Verdict + Send>;

/// Decides the `L_Data.con` for one client frame; see
/// [`GatewayBuilder::confirm_with`]. `on_line` says whether a device of the
/// line sits at the frame's individual destination (always `false` for a group
/// frame). `Some(true)` is a positive con, `Some(false)` a negative one, `None`
/// sends none.
type ConfirmHook = Box<dyn FnMut(&CemiFrame, bool) -> Option<bool> + Send>;

/// The delay between a client request and its `L_Data.con` that
/// [`GatewayBuilder::confirmations`] uses. The live interface confirmed within
/// 20-45 ms (negative con 22-45 ms after the request, positive 20-30 ms; wire
/// log 1.1.5, 2026-09-24, issue #45); 30 ms sits inside both ranges.
pub const CONFIRMATION_DELAY: Duration = Duration::from_millis(30);

/// A snapshot of what the gateway has seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayStats {
    /// CONNECT_REQUESTs answered (granted or refused).
    pub connects: usize,
    /// DISCONNECT_REQUESTs answered.
    pub disconnects: usize,
    /// CONNECTIONSTATE_REQUESTs seen (answered or not).
    pub heartbeats: usize,
    /// TUNNELLING_REQUESTs received from the client.
    pub requests: usize,
    /// TUNNELLING_ACKs received from the client.
    pub client_acks: usize,
    /// Every KNXnet/IP service received, in order (including the datagrams an
    /// [`Outage`] swallowed).
    pub services: Vec<ServiceType>,
    /// Datagrams swallowed during an [`Outage`].
    pub outage_dropped: usize,
    /// Datagrams an [`GatewayBuilder::intercept`] hook swallowed.
    pub intercepted: usize,
    /// The channel ids granted by successful CONNECTs, in order.
    pub channels: Vec<u8>,
    /// Whether the gateway task has ended.
    pub finished: bool,
}

/// Configures a [`MockGateway`]. Create one with [`MockGateway::builder`].
pub struct GatewayBuilder {
    channel: u8,
    ack: AckPolicy,
    refuse: Option<u8>,
    answer_heartbeats: bool,
    keep_serving: bool,
    idle_timeout: Duration,
    description: Option<Vec<u8>>,
    after_connect: Vec<(Duration, CemiFrame)>,
    once_after_connect: Vec<(Duration, CemiFrame)>,
    responders: Vec<Responder>,
    devices: Vec<MockDevice>,
    outage: Option<Outage>,
    interceptors: Vec<Interceptor>,
    confirm: Option<(Duration, ConfirmHook)>,
}

impl Default for GatewayBuilder {
    fn default() -> Self {
        GatewayBuilder {
            channel: 0x21,
            ack: AckPolicy::Ack,
            refuse: None,
            answer_heartbeats: true,
            keep_serving: false,
            idle_timeout: Duration::from_secs(10),
            description: None,
            after_connect: Vec::new(),
            once_after_connect: Vec::new(),
            responders: Vec::new(),
            devices: Vec::new(),
            outage: None,
            interceptors: Vec::new(),
            confirm: None,
        }
    }
}

impl GatewayBuilder {
    /// The channel id CONNECT_RESPONSE grants (default `0x21`).
    pub fn channel(mut self, channel: u8) -> Self {
        self.channel = channel;
        self
    }

    /// How client requests are ACKed (default [`AckPolicy::Ack`]).
    pub fn ack_policy(mut self, policy: AckPolicy) -> Self {
        self.ack = policy;
        self
    }

    /// Refuse every CONNECT with `status`, e.g. `0x24` (no more connections).
    pub fn refuse_connect(mut self, status: u8) -> Self {
        self.refuse = Some(status);
        self
    }

    /// Leave CONNECTIONSTATE_REQUESTs unanswered (a dead gateway).
    pub fn ignore_heartbeats(mut self) -> Self {
        self.answer_heartbeats = false;
        self
    }

    /// Keep serving after a DISCONNECT, so a second client run finds the same
    /// line with the same state.
    pub fn keep_serving(mut self) -> Self {
        self.keep_serving = true;
        self
    }

    /// End the task after this long without a datagram (default 10 s).
    pub fn idle_timeout(mut self, idle: Duration) -> Self {
        self.idle_timeout = idle;
        self
    }

    /// Answer DESCRIPTION_REQUESTs with this body, e.g. from
    /// [`wire::description_response_body`].
    pub fn description(mut self, body: Vec<u8>) -> Self {
        self.description = Some(body);
        self
    }

    /// Push `frame` to the client `delay` after each successful CONNECT. Frames
    /// go out in delay order, and in configuration order for equal delays.
    pub fn push_after_connect(mut self, delay: Duration, frame: CemiFrame) -> Self {
        self.after_connect.push((delay, frame));
        self
    }

    /// Push `frame` to the client once, `delay` after the latest CONNECT the
    /// client keeps: a DISCONNECT or a newer CONNECT before the first of these
    /// frames goes out restarts the wait. Frames go out in delay order (and in
    /// configuration order for equal delays), all measured from that CONNECT;
    /// once the first has gone out the rest follow. Use it for traffic that a
    /// client's long-lived session should see exactly once, when the client
    /// opens a short probe connection first.
    pub fn push_once_after_connect(mut self, delay: Duration, frame: CemiFrame) -> Self {
        self.once_after_connect.push((delay, frame));
        self
    }

    /// Add a scripted responder. After the ACK, it sees every frame the client
    /// sends and returns the frames to push back, in order. Responders run
    /// before the device line.
    pub fn respond<F>(mut self, responder: F) -> Self
    where
        F: FnMut(&CemiFrame) -> Vec<CemiFrame> + Send + 'static,
    {
        self.responders.push(Box::new(responder));
        self
    }

    /// Take the link down after the `after_frame`-th TUNNELLING_REQUEST for
    /// `duration` (see [`Outage`]). Without this call the gateway behaves
    /// exactly as before.
    pub fn outage(mut self, after_frame: usize, duration: Duration) -> Self {
        self.outage = Some(Outage {
            after_frame,
            duration,
        });
        self
    }

    /// Add a fault-injection hook. It sees every parsed datagram first (after
    /// it is recorded in [`GatewayStats::services`]) and decides whether the
    /// gateway serves or swallows it. Use it for faults that depend on the
    /// traffic: drop the tunnel after the Nth memory frame, stop ACKing until
    /// the next CONNECT, or black out for a while after a restart. Hooks run in
    /// the order they were added; the first [`Verdict::Swallow`] wins.
    pub fn intercept<F>(mut self, hook: F) -> Self
    where
        F: FnMut(&Inbound<'_>) -> Verdict + Send + 'static,
    {
        self.interceptors.push(Box::new(hook));
        self
    }

    /// Report `L_Data.con`s the way a real interface does (issue #45): after
    /// [`CONFIRMATION_DELAY`], a **negative** con (error bit set) for a frame to
    /// an individual address no device of the line sits at, and a positive con
    /// for every other frame. Without this call (or [`confirm_with`]) the
    /// gateway sends no confirmations at all, which models an interface that
    /// does not report them.
    ///
    /// [`confirm_with`]: GatewayBuilder::confirm_with
    pub fn confirmations(self) -> Self {
        self.confirm_with(CONFIRMATION_DELAY, |frame, on_line| {
            match frame.individual_destination() {
                Some(_) => Some(on_line),
                None => Some(true),
            }
        })
    }

    /// Send an `L_Data.con` `delay` after each client frame, as `hook` decides.
    /// `hook` gets the frame and whether a device of the line sits at its
    /// individual destination (`false` for a group frame) and returns
    /// `Some(true)` for a positive con, `Some(false)` for a negative one and
    /// `None` for none. The con echoes the request with the message code
    /// `L_Data.con` and, for a negative one, the control field's error bit set.
    /// It is pushed asynchronously, so the device line's answers are not held
    /// back by the delay.
    pub fn confirm_with<F>(mut self, delay: Duration, hook: F) -> Self
    where
        F: FnMut(&CemiFrame, bool) -> Option<bool> + Send + 'static,
    {
        self.confirm = Some((delay, Box::new(hook)));
        self
    }

    /// Put a device on the line.
    pub fn device(mut self, device: MockDevice) -> Self {
        self.devices.push(device);
        self
    }

    /// Put several devices on the line.
    pub fn devices(mut self, devices: impl IntoIterator<Item = MockDevice>) -> Self {
        self.devices.extend(devices);
        self
    }

    /// Binds `127.0.0.1:0` and spawns the gateway task on the current runtime.
    ///
    /// # Errors
    /// Fails when the loopback socket cannot be bound.
    pub async fn start(self) -> Result<MockGateway, MockError> {
        let (addr, sock) = wire::bind().await?;
        let sent = Arc::new(Mutex::new(Vec::new()));
        let line = Arc::new(Mutex::new(self.devices));
        let (stats_tx, stats_rx) = watch::channel(GatewayStats::default());
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let server = Server {
            sock,
            port: addr.port(),
            channel: self.channel,
            ack: self.ack,
            refuse: self.refuse,
            answer_heartbeats: self.answer_heartbeats,
            keep_serving: self.keep_serving,
            idle_timeout: self.idle_timeout,
            description: self.description,
            after_connect: self.after_connect,
            once_after_connect: self.once_after_connect,
            connect_gen: Arc::new(AtomicU64::new(0)),
            once_done: Arc::new(AtomicBool::new(false)),
            responders: Mutex::new(self.responders),
            interceptors: Mutex::new(self.interceptors),
            confirm: Mutex::new(self.confirm),
            line: Arc::clone(&line),
            sent: Arc::clone(&sent),
            stats: stats_tx,
            cmd_tx: cmd_tx.clone(),
            peer: None,
            gw_seq: 0,
            pending: VecDeque::new(),
            outage: self.outage,
            served: 0,
            down_until: None,
            stale_channel: None,
        };
        let task = tokio::spawn(server.run(cmd_rx));
        Ok(MockGateway {
            addr,
            sent,
            line,
            stats: stats_rx,
            cmd_tx,
            task: Some(task),
        })
    }
}

/// Commands from the test to the running gateway.
enum Command {
    Push(CemiFrame),
}

/// A running mock gateway. Dropping it stops the task.
pub struct MockGateway {
    addr: SocketAddrV4,
    sent: Arc<Mutex<Vec<CemiFrame>>>,
    line: Arc<Mutex<Vec<MockDevice>>>,
    stats: watch::Receiver<GatewayStats>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for MockGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockGateway")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl MockGateway {
    /// A builder with the defaults: channel `0x21`, ACK everything, answer
    /// heartbeats, stop after DISCONNECT, 10 s idle timeout, empty line.
    pub fn builder() -> GatewayBuilder {
        GatewayBuilder::default()
    }

    /// The loopback address to give the client under test.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// The bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Every cEMI frame the client has sent in a TUNNELLING_REQUEST, in order.
    ///
    /// # Errors
    /// Fails when the capture lock is poisoned.
    pub fn sent(&self) -> Result<Vec<CemiFrame>, MockError> {
        Ok(self.sent.lock().map_err(|_| MockError::Poisoned)?.clone())
    }

    /// A snapshot of the gateway statistics.
    pub fn stats(&self) -> GatewayStats {
        self.stats.borrow().clone()
    }

    /// Waits until `pred` holds for the statistics, up to `within`. Returns
    /// whether it did.
    pub async fn wait_until<F>(&self, within: Duration, mut pred: F) -> bool
    where
        F: FnMut(&GatewayStats) -> bool,
    {
        let mut rx = self.stats.clone();
        tokio::time::timeout(within, async move {
            loop {
                if pred(&rx.borrow_and_update()) {
                    return true;
                }
                if rx.changed().await.is_err() {
                    return pred(&rx.borrow());
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Pushes `frame` to the client as an indication. Before the first CONNECT
    /// it is queued and sent once a client connects.
    ///
    /// # Errors
    /// Fails when the gateway task has already ended.
    pub fn push(&self, frame: CemiFrame) -> Result<(), MockError> {
        self.cmd_tx
            .send(Command::Push(frame))
            .map_err(|_| MockError::Timeout("a running gateway task (it has ended)"))
    }

    /// A clone of every device on the line, in their current state.
    ///
    /// # Errors
    /// Fails when the line lock is poisoned.
    pub fn devices(&self) -> Result<Vec<MockDevice>, MockError> {
        Ok(self.line.lock().map_err(|_| MockError::Poisoned)?.clone())
    }

    /// Runs `f` on the whole device line, e.g. to swap a dead device for a
    /// factory-fresh spare between two client runs.
    ///
    /// # Errors
    /// Fails when the line lock is poisoned.
    pub fn with_line<R>(&self, f: impl FnOnce(&mut Vec<MockDevice>) -> R) -> Result<R, MockError> {
        let mut line = self.line.lock().map_err(|_| MockError::Poisoned)?;
        Ok(f(&mut line))
    }

    /// Runs `f` on the device currently at `address`.
    ///
    /// # Errors
    /// Fails when no device has that address, or the line lock is poisoned.
    pub fn with_device<R>(
        &self,
        address: IndividualAddress,
        f: impl FnOnce(&mut MockDevice) -> R,
    ) -> Result<R, MockError> {
        let mut line = self.line.lock().map_err(|_| MockError::Poisoned)?;
        let dev = line
            .iter_mut()
            .find(|d| d.address == address)
            .ok_or(MockError::NoDevice(address))?;
        Ok(f(dev))
    }

    /// Waits up to `within` for the task to end on its own, then returns the
    /// final statistics. On timeout the task is stopped and
    /// [`MockError::Timeout`] is returned.
    ///
    /// # Errors
    /// Fails on a timeout or when the task panicked.
    pub async fn finish(mut self, within: Duration) -> Result<GatewayStats, MockError> {
        if let Some(task) = self.task.take() {
            let abort = task.abort_handle();
            match tokio::time::timeout(within, task).await {
                Ok(joined) => joined?,
                Err(_) => {
                    abort.abort();
                    return Err(MockError::Timeout("the mock gateway to finish"));
                }
            }
        }
        Ok(self.stats())
    }
}

impl Drop for MockGateway {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// The task side of a [`MockGateway`].
struct Server {
    sock: UdpSocket,
    port: u16,
    channel: u8,
    ack: AckPolicy,
    refuse: Option<u8>,
    answer_heartbeats: bool,
    keep_serving: bool,
    idle_timeout: Duration,
    description: Option<Vec<u8>>,
    after_connect: Vec<(Duration, CemiFrame)>,
    once_after_connect: Vec<(Duration, CemiFrame)>,
    /// Bumped on every CONNECT and DISCONNECT; a pending one-shot push
    /// schedule is dropped when it changes.
    connect_gen: Arc<AtomicU64>,
    /// Whether the one-shot push schedule has started sending.
    once_done: Arc<AtomicBool>,
    // A mutex only to make `Server` `Sync`; the task is its sole user.
    responders: Mutex<Vec<Responder>>,
    // Likewise.
    interceptors: Mutex<Vec<Interceptor>>,
    // Likewise.
    confirm: Mutex<Option<(Duration, ConfirmHook)>>,
    line: Arc<Mutex<Vec<MockDevice>>>,
    sent: Arc<Mutex<Vec<CemiFrame>>>,
    stats: watch::Sender<GatewayStats>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    peer: Option<SocketAddr>,
    gw_seq: u8,
    pending: VecDeque<CemiFrame>,
    /// The configured outage, taken (`None`) once it has started.
    outage: Option<Outage>,
    /// TUNNELLING_REQUESTs served so far, metered against the outage.
    served: usize,
    /// While the link is down: when it comes back (`None` = never).
    down_until: Option<Option<tokio::time::Instant>>,
    /// The channel the outage dropped, until the client disconnects it.
    stale_channel: Option<u8>,
}

/// Whether the gateway loop should keep going.
enum Flow {
    Continue,
    Stop,
}

impl Server {
    async fn run(mut self, mut cmd_rx: mpsc::UnboundedReceiver<Command>) {
        let mut buf = [0u8; 1024];
        loop {
            let flow = tokio::select! {
                received = tokio::time::timeout(self.idle_timeout, self.sock.recv_from(&mut buf)) => {
                    match received {
                        Ok(Ok((n, from))) => self.on_datagram(&buf[..n], from).await,
                        _ => Flow::Stop,
                    }
                }
                Some(Command::Push(frame)) = cmd_rx.recv() => {
                    match self.peer {
                        Some(peer) => self.push(peer, &frame).await,
                        None => {
                            self.pending.push_back(frame);
                            Flow::Continue
                        }
                    }
                }
            };
            if matches!(flow, Flow::Stop) {
                break;
            }
        }
        self.stats.send_modify(|s| s.finished = true);
    }

    async fn send(&self, bytes: &[u8], to: SocketAddr) -> Flow {
        match self.sock.send_to(bytes, to).await {
            Ok(_) => Flow::Continue,
            Err(_) => Flow::Stop,
        }
    }

    /// Pushes one indication and advances the gateway's sequence number.
    async fn push(&mut self, peer: SocketAddr, frame: &CemiFrame) -> Flow {
        let header = ConnectionHeader {
            channel_id: self.channel,
            seq: self.gw_seq,
        };
        self.gw_seq = self.gw_seq.wrapping_add(1);
        self.send(&knxnet::tunneling_request(header, frame), peer)
            .await
    }

    async fn push_all(&mut self, peer: SocketAddr, frames: Vec<CemiFrame>) -> Flow {
        for frame in frames {
            if matches!(self.push(peer, &frame).await, Flow::Stop) {
                return Flow::Stop;
            }
        }
        Flow::Continue
    }

    /// Pushes the line's output, sleeping through its pauses.
    async fn push_out(&mut self, peer: SocketAddr, out: Vec<Out>) -> Flow {
        for item in out {
            match item {
                Out::Frame(frame) => {
                    if matches!(self.push(peer, &frame).await, Flow::Stop) {
                        return Flow::Stop;
                    }
                }
                Out::Pause(pause) => tokio::time::sleep(pause).await,
                Out::Delayed(delay, frames) => {
                    let tx = self.cmd_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        for frame in frames {
                            let _ = tx.send(Command::Push(frame));
                        }
                    });
                }
            }
        }
        Flow::Continue
    }

    /// Whether the link is down right now; ends an outage whose time is up
    /// (dropping the old channel and moving to a new channel id).
    fn link_down(&mut self) -> bool {
        match self.down_until {
            None => false,
            Some(None) => true,
            Some(Some(until)) if tokio::time::Instant::now() < until => true,
            Some(Some(_)) => {
                self.down_until = None;
                self.stale_channel = Some(self.channel);
                self.channel = self.channel.wrapping_add(1);
                self.peer = None;
                self.gw_seq = 0;
                false
            }
        }
    }

    /// Whether an intercept hook swallows this datagram.
    fn intercepted(&self, service: ServiceType, body: &[u8]) -> bool {
        let Ok(mut hooks) = self.interceptors.lock() else {
            return false;
        };
        if hooks.is_empty() {
            return false;
        }
        let tunnelled = if service == ServiceType::TunnelingRequest {
            knxnet::parse_tunneling_request(body).ok()
        } else {
            None
        };
        let inbound = Inbound {
            service,
            cemi: tunnelled.as_ref().map(|tr| &tr.cemi),
        };
        hooks
            .iter_mut()
            .any(|hook| hook(&inbound) == Verdict::Swallow)
    }

    async fn on_datagram(&mut self, bytes: &[u8], from: SocketAddr) -> Flow {
        let Ok(parsed) = knxnet::parse(bytes) else {
            return Flow::Continue;
        };
        let service = parsed.service;
        let body = parsed.body.to_vec();
        self.stats.send_modify(|s| s.services.push(service));
        if self.intercepted(service, &body) {
            self.stats.send_modify(|s| s.intercepted += 1);
            return Flow::Continue;
        }
        if self.link_down() {
            self.stats.send_modify(|s| s.outage_dropped += 1);
            return Flow::Continue;
        }
        if let Some(stale) = self.stale_channel {
            // After an outage: the old channel is gone. Answer its DISCONNECT
            // without stopping, and leave its requests and heartbeats unanswered.
            let channel = body.first().copied();
            match service {
                ServiceType::DisconnectRequest if channel == Some(stale) => {
                    self.stale_channel = None;
                    self.stats.send_modify(|s| s.disconnects += 1);
                    let resp = knxnet::disconnect_response(stale, 0);
                    return self.send(&resp, from).await;
                }
                ServiceType::ConnectionstateRequest
                | ServiceType::TunnelingRequest
                | ServiceType::TunnelingAck
                    if channel == Some(stale) =>
                {
                    return Flow::Continue;
                }
                _ => {}
            }
        }
        match service {
            ServiceType::ConnectRequest => self.on_connect(from).await,
            ServiceType::ConnectionstateRequest => {
                self.stats.send_modify(|s| s.heartbeats += 1);
                if self.answer_heartbeats {
                    let resp = knxnet::connectionstate_response(self.channel, 0);
                    self.send(&resp, from).await
                } else {
                    Flow::Continue
                }
            }
            ServiceType::DisconnectRequest => {
                self.connect_gen.fetch_add(1, Ordering::SeqCst);
                let resp = knxnet::disconnect_response(self.channel, 0);
                let flow = self.send(&resp, from).await;
                self.stats.send_modify(|s| s.disconnects += 1);
                if self.keep_serving { flow } else { Flow::Stop }
            }
            ServiceType::DescriptionRequest => match &self.description {
                Some(desc) => {
                    let reply = wire::frame(ServiceType::DescriptionResponse, desc);
                    self.send(&reply, from).await
                }
                None => Flow::Continue,
            },
            ServiceType::TunnelingAck => {
                self.stats.send_modify(|s| s.client_acks += 1);
                Flow::Continue
            }
            ServiceType::TunnelingRequest => self.on_tunneling_request(&body, from).await,
            _ => Flow::Continue,
        }
    }

    async fn on_connect(&mut self, from: SocketAddr) -> Flow {
        self.stats.send_modify(|s| s.connects += 1);
        if let Some(status) = self.refuse {
            let reply = wire::frame(ServiceType::ConnectResponse, &connect_refusal_body(status));
            return self.send(&reply, from).await;
        }
        let reply = wire::frame(
            ServiceType::ConnectResponse,
            &connect_response_body(self.channel, self.port),
        );
        if matches!(self.send(&reply, from).await, Flow::Stop) {
            return Flow::Stop;
        }
        let channel = self.channel;
        self.stats.send_modify(|s| s.channels.push(channel));
        self.peer = Some(from);
        // A fresh tunnel connection: the gateway's send sequence starts at 0, as
        // on a real KNXnet/IP server.
        self.gw_seq = 0;
        if !self.after_connect.is_empty() {
            // One task for all scheduled pushes, sorted by delay, so frames with
            // equal delays still go out in the order they were configured.
            let mut schedule = self.after_connect.clone();
            schedule.sort_by_key(|(delay, _)| *delay);
            let tx = self.cmd_tx.clone();
            tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                for (delay, frame) in schedule {
                    tokio::time::sleep_until(start + delay).await;
                    if tx.send(Command::Push(frame)).is_err() {
                        return;
                    }
                }
            });
        }
        let generation = self.connect_gen.fetch_add(1, Ordering::SeqCst) + 1;
        if !self.once_after_connect.is_empty() && !self.once_done.load(Ordering::SeqCst) {
            let mut schedule = self.once_after_connect.clone();
            schedule.sort_by_key(|(delay, _)| *delay);
            let tx = self.cmd_tx.clone();
            let current = Arc::clone(&self.connect_gen);
            let done = Arc::clone(&self.once_done);
            tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                for (i, (delay, frame)) in schedule.into_iter().enumerate() {
                    tokio::time::sleep_until(start + delay).await;
                    if i == 0
                        && (current.load(Ordering::SeqCst) != generation
                            || done.swap(true, Ordering::SeqCst))
                    {
                        return;
                    }
                    if tx.send(Command::Push(frame)).is_err() {
                        return;
                    }
                }
            });
        }
        let pending: Vec<CemiFrame> = self.pending.drain(..).collect();
        self.push_all(from, pending).await
    }

    async fn on_tunneling_request(&mut self, body: &[u8], from: SocketAddr) -> Flow {
        let Ok(tr) = knxnet::parse_tunneling_request(body) else {
            return Flow::Continue;
        };
        self.peer = Some(from);
        self.stats.send_modify(|s| s.requests += 1);
        self.served += 1;
        if let Some(outage) = self.outage
            && self.served >= outage.after_frame
        {
            // This frame is served; the link goes down right after it.
            self.outage = None;
            self.down_until = Some(tokio::time::Instant::now().checked_add(outage.duration));
        }
        if let Ok(mut sent) = self.sent.lock() {
            sent.push(tr.cemi.clone());
        }
        let ack_status = match self.ack {
            AckPolicy::Ack => Some(0),
            AckPolicy::Status(status) => Some(status),
            AckPolicy::Never => None,
        };
        if let Some(status) = ack_status {
            let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, status);
            if matches!(self.send(&ack, from).await, Flow::Stop) {
                return Flow::Stop;
            }
        }

        self.schedule_confirmation(&tr.cemi);

        let mut replies = Vec::new();
        if let Ok(mut responders) = self.responders.lock() {
            for responder in responders.iter_mut() {
                replies.extend(responder(&tr.cemi));
            }
        }
        if matches!(self.push_all(from, replies).await, Flow::Stop) {
            return Flow::Stop;
        }
        let replies = self.line_output(&tr.cemi);
        self.push_out(from, replies).await
    }

    /// Schedules the `L_Data.con` of one client frame, if confirmations are
    /// configured: a task sleeps the delay and pushes it through the command
    /// channel, so the gateway keeps serving meanwhile.
    fn schedule_confirmation(&self, cemi: &CemiFrame) {
        let on_line = match cemi.individual_destination() {
            Some(dest) => self
                .line
                .lock()
                .map(|line| line.iter().any(|d| d.address == dest))
                .unwrap_or(false),
            None => false,
        };
        let Ok(mut confirm) = self.confirm.lock() else {
            return;
        };
        let Some((delay, hook)) = confirm.as_mut() else {
            return;
        };
        let Some(positive) = hook(cemi, on_line) else {
            return;
        };
        let mut con = cemi.clone();
        con.message_code = MessageCode::LDataCon;
        con.control1.error = !positive;
        let delay = *delay;
        let tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = tx.send(Command::Push(con));
        });
    }

    /// The device line's answers to one client frame.
    fn line_output(&self, cemi: &CemiFrame) -> Vec<Out> {
        let Ok(mut line) = self.line.lock() else {
            return Vec::new();
        };
        line_output(&mut line, cemi)
    }
}

/// One item of a line's output: a frame to push, a pause, or frames to push
/// later without holding up the gateway.
#[derive(Debug, Clone)]
pub(crate) enum Out {
    Frame(CemiFrame),
    Pause(Duration),
    Delayed(Duration, Vec<CemiFrame>),
}

/// The frames of a line's output, dropping pauses. For the secure gateway mock,
/// which sends its replies as one batch.
pub(crate) fn line_replies(line: &mut [MockDevice], cemi: &CemiFrame) -> Vec<CemiFrame> {
    line_output(line, cemi)
        .into_iter()
        .filter_map(|out| match out {
            Out::Frame(frame) => Some(vec![frame]),
            Out::Delayed(_, frames) => Some(frames),
            Out::Pause(_) => None,
        })
        .flatten()
        .collect()
}

/// The answers of a line of [`MockDevice`]s to one client frame: broadcast
/// management, connected-mode transport control and the devices' application
/// answers, each as an `L_Data.ind`. Shared by [`MockGateway`] and the secure
/// gateway mock.
pub(crate) fn line_output(line: &mut [MockDevice], cemi: &CemiFrame) -> Vec<Out> {
    let tool = cemi.source;
    let mut out = Vec::new();
    match cemi.destination {
        Destination::Group(group) if group.raw() == 0 => {
            let Apdu::Other { apci, data } = &cemi.apdu else {
                return out;
            };
            for dev in line.iter_mut() {
                if let Some((rapci, rdata)) = dev.handle_broadcast(*apci, data) {
                    out.push(Out::Frame(indication(CemiFrame::t_broadcast(
                        dev.address,
                        rapci,
                        &rdata,
                    ))));
                }
            }
        }
        Destination::Group(_) => {}
        Destination::Individual(dest) => {
            let Some(dev) = line.iter_mut().find(|d| d.address == dest) else {
                return out;
            };
            dev.tool = tool;
            let kind = tpci::classify(cemi.tpci_octet());
            match kind {
                TpciKind::Connect => {
                    dev.send_seq = Some(0);
                    dev.connects += 1;
                }
                TpciKind::Disconnect => dev.send_seq = None,
                TpciKind::NumberedData(client_seq) => {
                    let (Tpci::Other(_), Apdu::Other { apci, data }) = (&cemi.tpci, &cemi.apdu)
                    else {
                        return out;
                    };
                    dev.client_seq = client_seq;
                    dev.request_tpci = cemi.tpci_octet();
                    let steps = match dev.handle_request(*apci, data) {
                        Reaction::Silent => Vec::new(),
                        Reaction::Nak => vec![Step::Nak],
                        Reaction::Ack => vec![Step::Ack],
                        Reaction::Answer(rapci, rdata) => match dev.response_delay {
                            Some(delay) => {
                                vec![Step::Ack, Step::Pause(delay), Step::Data(rapci, rdata)]
                            }
                            None => vec![Step::Ack, Step::Data(rapci, rdata)],
                        },
                        Reaction::Script(steps) => steps,
                    };
                    emit(dev, tool, Some(client_seq), steps, &mut out);
                    return out;
                }
                _ => {}
            }
            let steps = dev.handle_control(kind);
            emit(dev, tool, None, steps, &mut out);
        }
    }
    out
}

/// Turns a device's steps into line output. `client_seq` is the request being
/// answered; without one, [`Step::Ack`] and [`Step::Nak`] are ignored.
fn emit(
    dev: &mut MockDevice,
    tool: IndividualAddress,
    client_seq: Option<u8>,
    steps: Vec<Step>,
    out: &mut Vec<Out>,
) {
    let me = dev.address;
    for step in steps {
        let frame = match step {
            Step::Ack => match client_seq {
                Some(seq) => CemiFrame::t_control(tool, me, tpci::t_ack(seq)),
                None => continue,
            },
            Step::Nak => match client_seq {
                Some(seq) => CemiFrame::t_control(tool, me, tpci::t_nak(seq)),
                None => continue,
            },
            Step::Data(apci, data) => {
                let seq = dev.send_seq.unwrap_or(0);
                dev.send_seq = Some((seq + 1) & 0x0f);
                CemiFrame::t_data_connected(tool, me, tpci::ndt(seq), apci, &data)
            }
            Step::DataAtSeq(seq, apci, data) => {
                CemiFrame::t_data_connected(tool, me, tpci::ndt(seq & 0x0f), apci, &data)
            }
            Step::Control(octet) => CemiFrame::t_control(tool, me, octet),
            Step::Frame(frame) => frame,
            Step::Pause(pause) => {
                out.push(Out::Pause(pause));
                continue;
            }
            Step::After(delay, steps) => {
                let steps = steps
                    .into_iter()
                    .filter(|s| !matches!(s, Step::Pause(_) | Step::After(..)))
                    .collect();
                let mut later = Vec::new();
                emit(dev, tool, client_seq, steps, &mut later);
                let frames = later
                    .into_iter()
                    .filter_map(|o| match o {
                        Out::Frame(frame) => Some(frame),
                        Out::Pause(_) | Out::Delayed(..) => None,
                    })
                    .collect();
                out.push(Out::Delayed(delay, frames));
                continue;
            }
        };
        out.push(Out::Frame(indication(frame)));
    }
}

/// Marks a device-originated frame as an `L_Data.ind`, as a real interface
/// delivers it.
fn indication(mut frame: CemiFrame) -> CemiFrame {
    frame.message_code = MessageCode::LDataInd;
    frame
}
