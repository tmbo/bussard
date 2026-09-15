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

        // Handshake. We use route-back (wildcard) HPAIs so the gateway replies on
        // the same socket — NAT-friendly and works when we don't know our own
        // routable address.
        let control_hpai = Hpai::wildcard();
        let data_hpai = Hpai::wildcard();
        let (channel_id, assigned_ia) = Self::handshake(&socket, control_hpai, data_hpai).await?;

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (frame_tx, frame_rx) = mpsc::channel(256);

        let task_state = TaskState {
            socket,
            channel_id,
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

    /// Handles an inbound TUNNELING_REQUEST: ACK it, and deliver the cEMI unless
    /// it is a duplicate of the previous sequence number.
    async fn handle_tunneling_request(&mut self, body: &[u8]) {
        let req = match knxnet::parse_tunneling_request(body) {
            Ok(r) => r,
            Err(_) => return,
        };
        let seq = req.header.seq;

        // Always ACK with the received sequence number.
        let ack = knxnet::tunneling_ack(self.channel_id, seq, 0);
        let _ = self.socket.send(&ack).await;

        if self.first_incoming {
            // Accept whatever the gateway starts at.
            self.incoming_seq = seq;
            self.first_incoming = false;
        }

        if seq == self.incoming_seq {
            // Expected frame: deliver and advance.
            self.incoming_seq = self.incoming_seq.wrapping_add(1);
            let stamped = TimestampedFrame {
                received_at: SystemTime::now(),
                frame: req.cemi,
            };
            let _ = self.frames.send(Ok(stamped)).await;
        } else if seq == self.incoming_seq.wrapping_sub(1) {
            // Duplicate of the last frame: ACK (already done) but drop.
            tracing::debug!(seq, "dropping duplicate tunneling request");
        } else {
            // Out-of-window sequence: ACK done; drop without advancing.
            tracing::warn!(
                seq,
                expected = self.incoming_seq,
                "unexpected tunneling sequence; dropping"
            );
        }
    }

    /// Sends a heartbeat and awaits its response, retrying per the spec.
    async fn do_heartbeat(&mut self, buf: &mut [u8]) -> Result<()> {
        // Advertise the same wildcard (route-back) control HPAI the CONNECT used.
        // A strict/NAT gateway replies to the HPAI it is given; if we advertised
        // our real local address here (unreachable behind NAT) the gateway would
        // send CONNECTIONSTATE_RESPONSEs somewhere we never receive them, the
        // heartbeat would time out, and the tunnel would die after a few
        // intervals (~2.5 min). Wildcard makes it reply on the source socket.
        let control = Hpai::wildcard();
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
        // Use the same wildcard (route-back) control HPAI as CONNECT and the
        // heartbeat, so a NAT/strict gateway replies on the source socket. The
        // DISCONNECT_RESPONSE is best-effort, but staying consistent avoids the
        // gateway routing it to an unreachable advertised address.
        let control = Hpai::wildcard();
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
