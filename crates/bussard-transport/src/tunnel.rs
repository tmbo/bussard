//! KNXnet/IP tunneling client.
//!
//! A [`Tunnel`] opens a unicast connection to a KNXnet/IP gateway and runs a
//! background task that owns the UDP socket. The task:
//!
//! - drives the CONNECT / CONNECT_RESPONSE handshake,
//! - sends CONNECTIONSTATE_REQUEST heartbeats every
//!   [`HEARTBEAT_INTERVAL`](crate::config::HEARTBEAT_INTERVAL) and reconnects the
//!   caller's error path if they fail,
//! - transmits our TUNNELING_REQUESTs with an incrementing sequence counter and
//!   awaits the matching TUNNELING_ACK (retransmitting once on timeout),
//! - ACKs inbound TUNNELING_REQUESTs, delivering their cEMI to the caller, and
//!   drops duplicate sequence numbers (ACKing them but not re-delivering),
//! - handles a server-initiated DISCONNECT_REQUEST.
//!
//! The public [`Tunnel`] handle talks to the task over channels.

use std::net::SocketAddrV4;
use std::time::SystemTime;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use crate::cemi::CemiFrame;
use crate::config::{
    CONNECT_TIMEOUT, ConnectionConfig, DISCONNECT_TIMEOUT, HEARTBEAT_INTERVAL, HEARTBEAT_RETRIES,
    HEARTBEAT_TIMEOUT, TUNNELING_ACK_TIMEOUT, TUNNELING_RETRANSMITS,
};
use crate::conn::{BusConnection, TimestampedFrame};
use crate::error::{Result, TransportError};
use crate::knxnet::{self, ConnectionHeader, Hpai, ServiceType};

/// How many sequence numbers *behind* the expected inbound sequence are still
/// treated as a retransmitted duplicate (ACK-and-drop) rather than silently
/// discarded. One frame is not enough: a gateway can retransmit a frame two or a
/// few behind after several of our ACKs were lost, and silently dropping those
/// leaves the gateway retransmitting forever with no chance to resync (issue
/// #58). The window is kept small so a genuinely fresh (ahead) sequence is never
/// mistaken for a duplicate.
const DUP_ACK_WINDOW: u8 = 8;

/// Command sent from a [`Tunnel`] handle to its background task.
enum Command {
    /// Send a cEMI frame; reply once ACKed (or on error).
    Send {
        frame: Box<CemiFrame>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Cleanly disconnect; reply when done.
    Close { reply: oneshot::Sender<Result<()>> },
}

/// A KNXnet/IP tunneling connection.
pub struct Tunnel {
    commands: mpsc::Sender<Command>,
    frames: mpsc::Receiver<Result<TimestampedFrame>>,
    task: Option<JoinHandle<()>>,
    /// The individual address the gateway assigned to this tunnel, if reported.
    assigned_ia: Option<u16>,
}

impl Tunnel {
    /// Opens a tunneling connection to the gateway named in `config`.
    ///
    /// Performs the CONNECT handshake and spawns the background task before
    /// returning. Errors if the gateway is unreachable or rejects the request.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self> {
        let gateway = config.gateway.ok_or(TransportError::InvalidField {
            field: "tunnel gateway (none configured)",
            value: 0,
        })?;

        // Bind an ephemeral local UDP port on the chosen interface.
        let local_bind = SocketAddrV4::new(config.local_interface, 0);
        let socket = UdpSocket::bind(local_bind).await?;
        socket.connect(gateway).await?;
        // Reject an IPv6 local socket up front: KNXnet/IP HPAIs are IPv4-only.
        if let std::net::SocketAddr::V6(_) = socket.local_addr()? {
            return Err(TransportError::InvalidField {
                field: "local socket is IPv6, KNXnet/IP requires IPv4",
                value: 0,
            });
        }

        // Handshake. Advertise the REAL local endpoint (classic mode). Wildcard
        // route-back HPAIs are NAT-friendly and real gateways (e.g. the Jung IP
        // interface) honor them, but simpler stacks take the HPAI literally and
        // reply to 0.0.0.0:0 — KNX Virtual does exactly that, so a wildcard
        // CONNECT never completes against it. On loopback and LAN/routed paths
        // (KNX's home reality) the real endpoint always works; NAT traversal
        // would need a wildcard opt-in, which nothing has required yet.
        let local = match socket.local_addr()? {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => unreachable!("rejected above"),
        };
        let control_hpai = Hpai::new(local);
        let data_hpai = Hpai::new(local);
        let (channel_id, assigned_ia) = Self::handshake(&socket, control_hpai, data_hpai).await?;

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (frame_tx, frame_rx) = mpsc::channel(256);

        let task_state = TaskState {
            socket,
            channel_id,
            local_hpai: control_hpai,
            outgoing_seq: 0,
            incoming_seq: 0,
            first_incoming: true,
            commands: cmd_rx,
            frames: frame_tx,
        };
        let task = tokio::spawn(task_state.run());

        Ok(Tunnel {
            commands: cmd_tx,
            frames: frame_rx,
            task: Some(task),
            assigned_ia,
        })
    }

    /// The individual address assigned to this tunnel by the gateway, if any.
    pub fn assigned_individual_address(&self) -> Option<u16> {
        self.assigned_ia
    }

    /// Runs the CONNECT / CONNECT_RESPONSE handshake, returning the channel id
    /// and any assigned individual address.
    async fn handshake(socket: &UdpSocket, control: Hpai, data: Hpai) -> Result<(u8, Option<u16>)> {
        let req = knxnet::connect_request(control, data);
        socket.send(&req).await?;

        let mut buf = [0u8; 512];
        let n = time::timeout(CONNECT_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| TransportError::Timeout("CONNECT_RESPONSE"))??;
        let parsed = knxnet::parse(&buf[..n])?;
        if parsed.service != ServiceType::ConnectResponse {
            return Err(TransportError::InvalidField {
                field: "expected CONNECT_RESPONSE",
                value: 0,
            });
        }
        let resp = knxnet::parse_connect_response(parsed.body)?;
        if resp.status != 0 {
            return Err(TransportError::GatewayStatus {
                status: resp.status,
                context: "CONNECT_RESPONSE",
            });
        }
        Ok((resp.channel_id, resp.assigned_ia))
    }
}

impl BusConnection for Tunnel {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Send {
                frame: Box::new(frame),
                reply,
            })
            .await
            .map_err(|_| TransportError::Closed)?;
        rx.await.map_err(|_| TransportError::Closed)?
    }

    async fn recv(&mut self) -> Result<TimestampedFrame> {
        match self.frames.recv().await {
            Some(result) => result,
            None => Err(TransportError::Closed),
        }
    }

    async fn close(mut self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        // If the task already exited, treat as already-closed (Ok).
        if self.commands.send(Command::Close { reply }).await.is_err() {
            return Ok(());
        }
        let result = rx.await.map_err(|_| TransportError::Closed)?;
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        result
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Do NOT abort the task. Dropping the `Tunnel` drops `self.commands`
        // (the only command sender), so the task's `commands.recv()` yields
        // `None` and its `None` branch runs `do_close`, which sends a
        // DISCONNECT_REQUEST and briefly awaits the response before exiting.
        // Aborting here would kill that graceful close and leak the gateway's
        // tunnel slot (~2 min hold) — see issue #31.
        //
        // The task is detached (its `JoinHandle` is simply dropped): it owns its
        // socket and channel and finishes on its own. Callers that need to *wait*
        // for the close to complete use `close().await` instead of dropping.
        self.task.take();
    }
}

/// State owned by the background task.
struct TaskState {
    socket: UdpSocket,
    channel_id: u8,
    /// Sequence counter for frames we send.
    outgoing_seq: u8,
    /// Next expected sequence counter for frames the gateway sends us.
    incoming_seq: u8,
    /// Whether we have yet to receive our first inbound request.
    first_incoming: bool,
    /// The real local endpoint advertised in every HPAI (see `connect`).
    local_hpai: Hpai,
    commands: mpsc::Receiver<Command>,
    frames: mpsc::Sender<Result<TimestampedFrame>>,
}

impl TaskState {
    async fn run(mut self) {
        let mut heartbeat =
            time::interval_at(Instant::now() + HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
        let mut buf = [0u8; 1024];

        loop {
            tokio::select! {
                // A command from the handle.
                cmd = self.commands.recv() => {
                    match cmd {
                        Some(Command::Send { frame, reply }) => {
                            let r = self.do_send(&frame, &mut buf).await;
                            let _ = reply.send(r);
                        }
                        Some(Command::Close { reply }) => {
                            let r = self.do_close(&mut buf).await;
                            let _ = reply.send(r);
                            return;
                        }
                        None => {
                            // Handle dropped; disconnect quietly and exit.
                            let _ = self.do_close(&mut buf).await;
                            return;
                        }
                    }
                }

                // Inbound datagram.
                res = self.socket.recv(&mut buf) => {
                    match res {
                        Ok(n) => {
                            if !self.handle_inbound(&buf[..n]).await {
                                return; // disconnected
                            }
                        }
                        Err(e) => {
                            let _ = self.frames.send(Err(TransportError::from(e))).await;
                            return;
                        }
                    }
                }

                // Heartbeat tick.
                _ = heartbeat.tick() => {
                    if let Err(e) = self.do_heartbeat(&mut buf).await {
                        let _ = self.frames.send(Err(e)).await;
                        return;
                    }
                }
            }
        }
    }

    /// Sends a TUNNELING_REQUEST and awaits its ACK, retransmitting once.
    async fn do_send(&mut self, frame: &CemiFrame, buf: &mut [u8]) -> Result<()> {
        crate::wire_trace::trace_frame(crate::wire_trace::Direction::Outbound, frame);
        let seq = self.outgoing_seq;
        let header = ConnectionHeader {
            channel_id: self.channel_id,
            seq,
        };
        let datagram = knxnet::tunneling_request(header, frame);

        let mut attempt = 0;
        loop {
            self.socket.send(&datagram).await?;
            match self.await_ack(seq, buf).await {
                Ok(()) => {
                    self.outgoing_seq = self.outgoing_seq.wrapping_add(1);
                    return Ok(());
                }
                Err(TransportError::Timeout(_)) if attempt < TUNNELING_RETRANSMITS => {
                    attempt += 1;
                    tracing::warn!(seq, attempt, "tunneling ACK timeout; retransmitting");
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Waits for the TUNNELING_ACK matching `seq`, servicing other inbound
    /// datagrams (indications, heartbeats-from-us are not expected here, server
    /// requests) meanwhile so nothing is lost.
    async fn await_ack(&mut self, seq: u8, buf: &mut [u8]) -> Result<()> {
        let deadline = Instant::now() + TUNNELING_ACK_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout("TUNNELING_ACK"));
            }
            let n = match time::timeout(remaining, self.socket.recv(buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(TransportError::from(e)),
                Err(_) => return Err(TransportError::Timeout("TUNNELING_ACK")),
            };
            let datagram = buf[..n].to_vec();
            let parsed = match knxnet::parse(&datagram) {
                Ok(p) => p,
                Err(_) => continue, // ignore garbage while waiting
            };
            match parsed.service {
                ServiceType::TunnelingAck => {
                    if let Ok((hdr, status)) = knxnet::parse_tunneling_ack(parsed.body) {
                        if hdr.seq == seq {
                            if status != 0 {
                                return Err(TransportError::GatewayStatus {
                                    status,
                                    context: "TUNNELING_ACK",
                                });
                            }
                            return Ok(());
                        }
                    }
                }
                // Server can interleave requests / disconnects while we await.
                _ => {
                    if !self.handle_inbound(&datagram).await {
                        return Err(TransportError::Disconnected(self.channel_id));
                    }
                }
            }
        }
    }

    /// Processes an inbound datagram that is not an awaited ACK. Returns `false`
    /// if the connection has been disconnected and the task should exit.
    async fn handle_inbound(&mut self, datagram: &[u8]) -> bool {
        let parsed = match knxnet::parse(datagram) {
            Ok(p) => p,
            Err(_) => return true, // ignore malformed
        };
        match parsed.service {
            ServiceType::TunnelingRequest => {
                self.handle_tunneling_request(parsed.body).await;
                true
            }
            ServiceType::DisconnectRequest => {
                // Acknowledge and tear down.
                if let Ok(channel) = knxnet::parse_disconnect_request(parsed.body) {
                    let resp = knxnet::disconnect_response(channel, 0);
                    let _ = self.socket.send(&resp).await;
                }
                let _ = self
                    .frames
                    .send(Err(TransportError::Disconnected(self.channel_id)))
                    .await;
                false
            }
            ServiceType::ConnectionstateResponse => true, // handled inline elsewhere
            // A late/duplicate ACK with no waiter, or other services: ignore.
            _ => true,
        }
    }

    /// Handles an inbound TUNNELING_REQUEST per the KNXnet/IP tunnelling ACK rules
    /// (issue #60).
    ///
    /// The sequence number decides the ACK, and it is read *before* the cEMI is
    /// decoded so an un-decodable-but-in-sequence frame is still ACKed:
    ///
    /// * **Expected seq** — ACK, advance the window, and deliver the cEMI. If the
    ///   cEMI carries an unknown message code (fails to decode) the frame is still
    ///   ACKed and the window still advances (C3): otherwise the gateway would
    ///   retransmit forever and stall the tunnel. The undecodable payload is
    ///   simply not delivered.
    /// * **Exact previous seq (seq-1)** — a retransmitted duplicate: ACK it (so
    ///   the gateway stops resending) but drop it without advancing.
    /// * **Any other out-of-window seq** — SILENTLY DISCARD, no ACK (C2). ACKing
    ///   a frame we then drop would wrongly tell the gateway we accepted it.
    async fn handle_tunneling_request(&mut self, body: &[u8]) {
        // Read the connection header (sequence) without committing to a cEMI
        // decode, so an unknown-message-code frame can still be ACKed.
        let (header, cemi_bytes) = match knxnet::parse_tunneling_header(body) {
            Ok(parts) => parts,
            Err(_) => return, // a body too short even for the header: nothing to ACK
        };
        let seq = header.seq;

        if self.first_incoming {
            // Accept whatever the gateway starts at as the expected sequence.
            self.incoming_seq = seq;
            self.first_incoming = false;
        }

        // How far `seq` is *behind* the expected sequence, modulo the 8-bit space
        // (0 means it is the expected frame). A small window of behind values are
        // treated as retransmitted duplicates.
        let behind = self.incoming_seq.wrapping_sub(seq);

        if seq == self.incoming_seq {
            // Expected frame: ACK and advance the window regardless of whether the
            // cEMI decodes (C3 — an unknown message code must not stall the tunnel).
            let ack = knxnet::tunneling_ack(self.channel_id, seq, 0);
            let _ = self.socket.send(&ack).await;
            self.incoming_seq = self.incoming_seq.wrapping_add(1);

            match CemiFrame::decode(cemi_bytes) {
                Ok(cemi) => {
                    crate::wire_trace::trace_frame(crate::wire_trace::Direction::Inbound, &cemi);
                    let stamped = TimestampedFrame {
                        received_at: SystemTime::now(),
                        frame: cemi,
                    };
                    let _ = self.frames.send(Ok(stamped)).await;
                }
                Err(err) => {
                    // ACKed above; ignore the payload we cannot parse.
                    tracing::debug!(
                        seq,
                        ?err,
                        "ACKed in-sequence tunneling request with an undecodable cEMI; ignoring payload"
                    );
                }
            }
        } else if (1..=DUP_ACK_WINDOW).contains(&behind) {
            // A recently-seen sequence, up to `DUP_ACK_WINDOW` frames behind the
            // one we expect next: a retransmitted duplicate we already accepted.
            // ACK it with its OWN sequence (so the gateway stops resending) but do
            // NOT advance and do NOT re-deliver. The window is wider than one frame
            // because a gateway can retransmit a frame two (or a few) behind after
            // several of our ACKs were lost; the old one-frame window silently
            // discarded those, so the gateway retransmitted forever and its next
            // in-order frame — which we would have accepted — never got a chance to
            // resync `incoming_seq` (issue #58).
            let ack = knxnet::tunneling_ack(self.channel_id, seq, 0);
            let _ = self.socket.send(&ack).await;
            tracing::debug!(
                seq,
                behind,
                "ACK-and-drop duplicate (behind) tunneling request"
            );
        } else {
            // Ahead of the window, or too far behind to be a plausible retransmit:
            // silently discard, NO ACK (C2). ACKing a frame we then drop would
            // wrongly tell the gateway we accepted it.
            tracing::warn!(
                seq,
                expected = self.incoming_seq,
                "out-of-window tunneling sequence; silently discarding (no ACK)"
            );
        }
    }

    /// Sends a heartbeat and awaits its response, retrying per the spec.
    async fn do_heartbeat(&mut self, buf: &mut [u8]) -> Result<()> {
        // The same real control HPAI the CONNECT used (see `connect` for why
        // wildcard route-back breaks literal-minded gateways like KNX Virtual).
        let control = self.local_hpai;
        let req = knxnet::connectionstate_request(self.channel_id, control);

        for attempt in 0..HEARTBEAT_RETRIES {
            self.socket.send(&req).await?;
            let deadline = Instant::now() + HEARTBEAT_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break; // retry
                }
                match time::timeout(remaining, self.socket.recv(buf)).await {
                    Ok(Ok(n)) => {
                        let datagram = buf[..n].to_vec();
                        if let Ok(parsed) = knxnet::parse(&datagram) {
                            if parsed.service == ServiceType::ConnectionstateResponse {
                                if let Ok(cs) = knxnet::parse_channel_status(parsed.body) {
                                    if cs.channel_id == self.channel_id {
                                        if cs.status == 0 {
                                            return Ok(());
                                        }
                                        // Non-zero status: retry.
                                        break;
                                    }
                                }
                            } else {
                                // Interleaved traffic during heartbeat wait.
                                if !self.handle_inbound(&datagram).await {
                                    return Err(TransportError::Disconnected(self.channel_id));
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => return Err(TransportError::from(e)),
                    Err(_) => break, // timed out; retry
                }
            }
            tracing::warn!(attempt = attempt + 1, "heartbeat attempt failed");
        }
        Err(TransportError::HeartbeatLost)
    }

    /// Sends a DISCONNECT_REQUEST and waits briefly for the response.
    async fn do_close(&mut self, buf: &mut [u8]) -> Result<()> {
        // The same real control HPAI as CONNECT and the heartbeat, for the same
        // interop reason. The DISCONNECT_RESPONSE is best-effort.
        let control = self.local_hpai;
        let req = knxnet::disconnect_request(self.channel_id, control);
        self.socket.send(&req).await?;

        let deadline = Instant::now() + DISCONNECT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Best-effort close: not receiving the response is not fatal.
                return Ok(());
            }
            match time::timeout(remaining, self.socket.recv(buf)).await {
                Ok(Ok(n)) => {
                    if let Ok(parsed) = knxnet::parse(&buf[..n]) {
                        if parsed.service == ServiceType::DisconnectResponse {
                            return Ok(());
                        }
                    }
                }
                Ok(Err(_)) | Err(_) => return Ok(()),
            }
        }
    }
}
