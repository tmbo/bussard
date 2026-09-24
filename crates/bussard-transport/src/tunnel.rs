//! KNXnet/IP tunneling client.
//!
//! A [`Tunnel`] opens a unicast connection to a KNXnet/IP gateway and runs a
//! background task that owns the UDP socket. The task:
//!
//! - drives the CONNECT / CONNECT_RESPONSE handshake,
//! - sends CONNECTIONSTATE_REQUEST heartbeats every
//!   [`HEARTBEAT_INTERVAL`](crate::config::HEARTBEAT_INTERVAL),
//! - transmits our TUNNELING_REQUESTs with an incrementing sequence counter and
//!   awaits the matching TUNNELING_ACK (retransmitting once on timeout),
//! - re-establishes the tunnel when the gateway link is lost (see below),
//! - ACKs inbound TUNNELING_REQUESTs, delivering their cEMI to the caller, and
//!   drops duplicate sequence numbers (ACKing them but not re-delivering),
//! - handles a server-initiated DISCONNECT_REQUEST.
//!
//! The public [`Tunnel`] handle talks to the task over channels.
//!
//! # KNXnet/IP Secure (issue #71 Phase B)
//!
//! With [`SecureTunnelConfig`](crate::SecureTunnelConfig) credentials the same
//! state machine runs over a TCP connection carrying an authenticated
//! KNXnet/IP Secure session: every frame is wrapped in a SECURE_WRAPPER, no
//! TUNNELING_ACK is exchanged (TCP is reliable; the ETS capture of the Jung
//! interface shows none), every HPAI is the TCP route-back HPAI, and a wrapped
//! SESSION_STATUS keepalive goes out every
//! [`SECURE_KEEPALIVE_INTERVAL`](crate::config::SECURE_KEEPALIVE_INTERVAL). A
//! lost link re-establishes a new TCP connection and a new session before the
//! CONNECT. [`Tunnel::connect`] picks the user: explicitly given, or from a
//! keyring by matching the gateway's individual address (read with a
//! SEARCH_REQUEST_EXTENDED) and preferring a free tunnel slot. A plain CONNECT
//! refused by a secure-only interface becomes
//! [`TransportError::SecureRequired`] (issue #182).
//!
//! # Re-establishing a lost tunnel (issue #177)
//!
//! A pulled LAN cable on the IP interface, a switch reboot or a Wi-Fi hiccup
//! leaves the gateway unreachable for a few seconds. The tunnel treats three
//! signals as a lost link: a TUNNELING_REQUEST still unacknowledged after its
//! retransmit, a failed CONNECTIONSTATE heartbeat, and a socket error. On any
//! of them it runs the [`TunnelReconnect`] policy from the
//! [`ConnectionConfig`]:
//!
//! 1. publish [`LinkState::Reconnecting`] and log `gateway connection lost`,
//! 2. send a best-effort DISCONNECT_REQUEST for the old channel (repeated per
//!    attempt until the gateway answers it, so a gateway that still holds the
//!    old channel frees the slot before the new CONNECT),
//! 3. send CONNECT_REQUEST and wait for the CONNECT_RESPONSE; on success adopt
//!    the new channel id and reset both sequence counters,
//! 4. otherwise back off (1, 2, 4, 8, 8 ... s by default) and try again until
//!    the budget (60 s by default) has passed since the loss.
//!
//! On success the task publishes [`LinkState::Up`], logs `gateway connection
//! re-established` and re-sends the frame whose ACK it was waiting for, so the
//! caller's `send` simply takes longer. When the budget runs out the pending
//! send (or, for a heartbeat loss, the inbound stream) fails with
//! [`TransportError::TunnelLost`], which names the gateway.
//!
//! Frames the gateway sent while the link was down are gone; the layers above
//! (the Layer-4 session of a flash) detect that as a connection death and
//! resume. With [`TunnelReconnect::disabled`] the first loss fails the send, as
//! before issue #177.
//!
//! # Inbound buffering policy (issue #82)
//!
//! The task hands decoded frames to the handle over an **unbounded** channel and
//! never awaits that handover. This is a deadlock-avoidance requirement, not a
//! performance choice:
//!
//! * The task delivers inbound frames from inside its `await_ack` and
//!   `do_heartbeat` loops, i.e. while it still owes the caller the reply to an
//!   in-flight `send`.
//! * The only consumer, `bussard-bus`'s actor, awaits that `send` reply *inline*
//!   (spawning it reorders L4 request/response under a flash lease — see the
//!   `Actor::consume` docs and issue #57), so it is not calling
//!   [`recv`](BusConnection::recv) meanwhile.
//! * With a *bounded* channel, a burst that filled it during one ACK window left
//!   the task awaiting capacity that only the blocked actor could free: both
//!   waited forever. Delivery must therefore never block the task.
//!
//! Dropping frames instead is not an option here: a connection-oriented
//! management response (a device's `T_ACK` or `A_*_Response`) is indistinguishable
//! from monitor traffic at this layer without policy the transport should not
//! own, and losing one desynchronises an L4 session mid-flash.
//!
//! The bound was never back-pressure anyway: an inbound TUNNELING_REQUEST is
//! ACKed *before* it is queued, so the gateway is already committed to it and
//! blocking here cannot slow the source — it can only stall the ACK loop.
//!
//! Memory stays bounded by the arithmetic of the stall: the consumer is blocked
//! only for one send's ACK budget
//! ([`TUNNELING_ACK_TIMEOUT`](crate::config::TUNNELING_ACK_TIMEOUT) x
//! 1+[`TUNNELING_RETRANSMITS`](crate::config::TUNNELING_RETRANSMITS), ~2 s) and a
//! TP1 bus carries ~50 frames/s, so the queue holds ~100 frames at worst. The
//! depth is metered and `INBOUND_WARN_DEPTH` logs a warning if it ever runs
//! deeper, which is the signal that a consumer is wedged for some other reason.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use crate::cemi::CemiFrame;
use crate::config::{
    CONNECT_TIMEOUT, ConnectionConfig, DISCONNECT_TIMEOUT, HEARTBEAT_INTERVAL, HEARTBEAT_RETRIES,
    HEARTBEAT_TIMEOUT, SECURE_KEEPALIVE_INTERVAL, SECURE_PROBE_TIMEOUT, SecureSource, SecureUser,
    TUNNELING_ACK_TIMEOUT, TUNNELING_RETRANSMITS, TunnelReconnect,
};
use crate::conn::{BusConnection, TimestampedFrame};
use crate::error::{Result, TransportError};
use crate::knxnet::{self, ConnectionHeader, GatewayDescription, Hpai, ServiceType};
use crate::secure::{SecureLink, UserKeys};

/// How many sequence numbers *behind* the expected inbound sequence are still
/// treated as a retransmitted duplicate (ACK-and-drop) rather than silently
/// discarded. One frame is not enough: a gateway can retransmit a frame two or a
/// few behind after several of our ACKs were lost, and silently dropping those
/// leaves the gateway retransmitting forever with no chance to resync (issue
/// #58). The window is kept small so a genuinely fresh (ahead) sequence is never
/// mistaken for a duplicate.
const DUP_ACK_WINDOW: u8 = 8;

/// Inbound queue depth at which the tunnel starts warning that its consumer is
/// falling behind.
///
/// Reaching this means the handle has not called
/// [`recv`](BusConnection::recv) for far longer than one send's ACK budget (see
/// the inbound buffering policy in the module docs); the frames are still
/// delivered, in order, but something upstream is wedged. The warning repeats
/// every further `INBOUND_WARN_DEPTH` frames rather than once per frame.
const INBOUND_WARN_DEPTH: usize = 512;

/// The state of a tunnel's link to its gateway, as published by
/// [`Tunnel::link_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// The tunnel is connected. `assigned_ia` is the individual address the
    /// gateway assigned on the latest CONNECT (it can change after a
    /// re-establish when the gateway hands out a different slot).
    Up {
        /// The raw assigned individual address, if the gateway reported one.
        assigned_ia: Option<u16>,
    },
    /// The link was lost and the tunnel is re-establishing itself.
    Reconnecting,
}

/// The socket under a tunnel: plain UDP, or a KNXnet/IP Secure session over
/// TCP (issue #71 Phase B). The tunnel state machine talks plain KNXnet/IP
/// frames to either.
enum Link {
    /// A connected UDP socket (the classic tunnel).
    Udp(UdpSocket),
    /// An authenticated secure session over TCP.
    Secure(Box<SecureLink>),
}

impl Link {
    /// Sends one plain KNXnet/IP frame (wrapped on a secure link).
    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        match self {
            Link::Udp(socket) => {
                socket.send(frame).await?;
                Ok(())
            }
            Link::Secure(link) => link.send(frame).await,
        }
    }

    /// Receives the next plain KNXnet/IP frame into `buf`. Cancel-safe.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Link::Udp(socket) => Ok(socket.recv(buf).await?),
            Link::Secure(link) => link.recv(buf).await,
        }
    }

    /// Whether the tunnelling layer uses TUNNELING_ACK. Over TCP it does not
    /// (CONFIRMED against the ETS capture: no ACKs on a TCP tunnel).
    fn acks(&self) -> bool {
        matches!(self, Link::Udp(_))
    }

    /// Sends the secure session keepalive; a no-op on UDP.
    async fn keepalive(&mut self) -> Result<()> {
        match self {
            Link::Udp(_) => Ok(()),
            Link::Secure(link) => link.keepalive().await,
        }
    }

    /// Ends a secure session (best effort); a no-op on UDP.
    async fn close(&mut self) {
        if let Link::Secure(link) = self {
            link.close().await;
        }
    }
}

/// What [`Tunnel::connect`] decided to open.
enum Plan {
    /// The plain UDP tunnel.
    Plain {
        /// What a secure probe already learned, so a refused CONNECT does not
        /// probe twice.
        probed: Option<GatewayDescription>,
        /// Why a keyring did not lead to a secure session, for the refusal.
        keyring_note: Option<String>,
    },
    /// A secure tunnel with this user.
    Secure(Box<SecureUser>),
}

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
    frames: mpsc::UnboundedReceiver<Result<TimestampedFrame>>,
    /// How many items sit undelivered in `frames`; the task meters the depth of
    /// its own unbounded queue through this (see the module docs).
    queued: Arc<AtomicUsize>,
    task: Option<JoinHandle<()>>,
    /// The individual address the gateway assigned to this tunnel, if reported.
    assigned_ia: Option<u16>,
    /// The link state the task publishes (up / re-establishing).
    link: watch::Receiver<LinkState>,
}

impl Tunnel {
    /// Opens a tunneling connection to the gateway named in `config`.
    ///
    /// Performs the CONNECT handshake and spawns the background task before
    /// returning. Errors if the gateway is unreachable or rejects the request.
    ///
    /// With KNXnet/IP Secure credentials in `config.secure` the tunnel runs
    /// over an authenticated secure session on TCP (see the module docs);
    /// with none it is the plain UDP tunnel, and an interface that refuses it
    /// because it is secure-only fails fast with
    /// [`TransportError::SecureRequired`] (issue #182).
    pub async fn connect(config: &ConnectionConfig) -> Result<Self> {
        let gateway = config.gateway.ok_or(TransportError::InvalidField {
            field: "tunnel gateway (none configured)",
            value: 0,
        })?;

        let plan = plan_connection(config, gateway).await?;
        let secure_user = match &plan {
            Plan::Secure(user) => Some(UserKeys::derive(user)),
            Plan::Plain { .. } => None,
        };
        let (mut link, local_hpai) = match &secure_user {
            Some(user) => {
                let link = SecureLink::open(gateway, config.local_interface, user, CONNECT_TIMEOUT)
                    .await?;
                (Link::Secure(Box::new(link)), Hpai::tcp_route_back())
            }
            None => {
                let (socket, hpai) = udp_socket(gateway, config.local_interface).await?;
                (Link::Udp(socket), hpai)
            }
        };

        let handshake = Self::handshake(&mut link, local_hpai).await;
        let (channel_id, assigned_ia) = match (handshake, plan) {
            (Ok(ok), _) => ok,
            (
                Err(TransportError::GatewayStatus { status, context }),
                Plan::Plain {
                    probed,
                    keyring_note,
                },
            ) => {
                return Err(refusal(gateway, status, context, probed, keyring_note).await);
            }
            (Err(err), _) => {
                link.close().await;
                return Err(err);
            }
        };
        let (link_tx, link_rx) = watch::channel(LinkState::Up { assigned_ia });
        if secure_user.is_some() {
            tracing::info!(
                "KNXnet/IP Secure tunnel to {gateway} established (channel {channel_id})"
            );
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        // Unbounded and never awaited: the task must not be able to block on
        // delivery while a send's ACK is outstanding (see the module docs).
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));

        let task_state = TaskState {
            link,
            channel_id,
            local_hpai,
            outgoing_seq: 0,
            incoming_seq: 0,
            first_incoming: true,
            commands: cmd_rx,
            frames: frame_tx,
            queued: queued.clone(),
            warned_depth: 0,
            gateway,
            local_interface: config.local_interface,
            secure_user,
            reconnect: config.reconnect,
            link_state: link_tx,
        };
        let task = tokio::spawn(task_state.run());

        Ok(Tunnel {
            commands: cmd_tx,
            frames: frame_rx,
            queued,
            task: Some(task),
            assigned_ia,
            link: link_rx,
        })
    }

    /// A receiver that observes the tunnel's [`LinkState`]: `Up` after the
    /// handshake, `Reconnecting` while a lost link is being re-established,
    /// `Up` again once it is back. The sender is dropped when the task ends.
    pub fn link_state(&self) -> watch::Receiver<LinkState> {
        self.link.clone()
    }

    /// The individual address assigned to this tunnel by the gateway, if any.
    pub fn assigned_individual_address(&self) -> Option<u16> {
        self.assigned_ia
    }

    /// Runs the CONNECT / CONNECT_RESPONSE handshake, returning the channel id
    /// and any assigned individual address.
    async fn handshake(link: &mut Link, hpai: Hpai) -> Result<(u8, Option<u16>)> {
        let req = knxnet::connect_request(hpai, hpai);
        link.send(&req).await?;

        let mut buf = [0u8; 512];
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let n = time::timeout(remaining, link.recv(&mut buf))
                .await
                .map_err(|_| TransportError::Timeout("CONNECT_RESPONSE"))??;
            let parsed = knxnet::parse(&buf[..n])?;
            if parsed.service == ServiceType::ConnectResponse {
                return accept_connect_response(parsed.body);
            }
            if link.acks() {
                return Err(TransportError::InvalidField {
                    field: "expected CONNECT_RESPONSE",
                    value: 0,
                });
            }
            // Over a secure session other frames can precede the answer
            // (a TUNNELLING_FEATURE_INFO, say): skip them.
        }
    }
}

/// Binds the UDP socket of a plain tunnel and returns it with the HPAI it
/// advertises.
async fn udp_socket(gateway: SocketAddrV4, local_interface: Ipv4Addr) -> Result<(UdpSocket, Hpai)> {
    // Bind an ephemeral local UDP port on the chosen interface.
    let local_bind = SocketAddrV4::new(local_interface, 0);
    let socket = UdpSocket::bind(local_bind).await?;
    socket.connect(gateway).await?;
    // Advertise the REAL local endpoint (classic mode). Wildcard route-back
    // HPAIs are NAT-friendly and real gateways (e.g. the Jung IP interface)
    // honor them, but simpler stacks take the HPAI literally and reply to
    // 0.0.0.0:0 — KNX Virtual does exactly that, so a wildcard CONNECT never
    // completes against it. On loopback and LAN/routed paths (KNX's home
    // reality) the real endpoint always works; NAT traversal would need a
    // wildcard opt-in, which nothing has required yet.
    match socket.local_addr()? {
        std::net::SocketAddr::V4(v4) => Ok((socket, Hpai::new(v4))),
        // Reject an IPv6 local socket: KNXnet/IP HPAIs are IPv4-only.
        std::net::SocketAddr::V6(_) => Err(TransportError::InvalidField {
            field: "local socket is IPv6, KNXnet/IP requires IPv4",
            value: 0,
        }),
    }
}

/// Decides between a plain and a secure tunnel (issue #71 Phase B, #182).
///
/// * No credentials: plain.
/// * Explicit credentials (`--secure-user`): secure with that user.
/// * Keyring credentials: probe the gateway (SEARCH_REQUEST_EXTENDED). Secure
///   when a keyring interface names this gateway's individual address as its
///   host and the gateway advertises KNXnet/IP Secure; the user whose tunnel
///   address is a free slot is preferred. Otherwise plain.
async fn plan_connection(config: &ConnectionConfig, gateway: SocketAddrV4) -> Result<Plan> {
    let Some(secure) = &config.secure else {
        return Ok(Plan::Plain {
            probed: None,
            keyring_note: None,
        });
    };
    if secure.source == SecureSource::Explicit {
        return match secure.users.first() {
            Some(user) => Ok(Plan::Secure(Box::new(user.clone()))),
            None => Ok(Plan::Plain {
                probed: None,
                keyring_note: None,
            }),
        };
    }
    let probed =
        match crate::discovery::describe_gateway_extended(gateway, SECURE_PROBE_TIMEOUT).await {
            Ok(d) => d,
            Err(err) => {
                tracing::debug!(%err, "KNXnet/IP Secure probe of {gateway} failed; trying plain");
                return Ok(Plan::Plain {
                    probed: None,
                    keyring_note: None,
                });
            }
        };
    let host = probed.individual_address;
    let candidates: Vec<&SecureUser> = secure
        .users
        .iter()
        .filter(|u| host.is_some() && u.host_ia == host)
        .collect();
    if candidates.is_empty() {
        let note = match host {
            Some(raw) => format!(
                "the keyring has no tunnelling user for interface {}",
                bussard_model::IndividualAddress::from_raw(raw)
            ),
            None => "the interface did not report its individual address, so no keyring \
                     tunnelling user could be matched to it"
                .to_string(),
        };
        return Ok(Plan::Plain {
            probed: Some(probed),
            keyring_note: Some(note),
        });
    }
    if !probed.secure_capable() {
        tracing::debug!("{gateway} does not advertise KNXnet/IP Secure; using the plain tunnel");
        return Ok(Plan::Plain {
            probed: Some(probed),
            keyring_note: None,
        });
    }
    let free: Vec<u16> = probed
        .tunnel_slots
        .as_ref()
        .map(|slots| {
            slots
                .iter()
                .filter(|s| s.free)
                .map(|s| s.individual_address)
                .collect()
        })
        .unwrap_or_default();
    let chosen = candidates
        .iter()
        .find(|u| u.tunnel_ia.is_some_and(|ia| free.contains(&ia)))
        .or_else(|| candidates.first())
        .map(|u| (*u).clone());
    match chosen {
        Some(user) => {
            tracing::debug!(
                user = user.user_id,
                "KNXnet/IP Secure: using keyring tunnelling user {} for {gateway}",
                user.user_id
            );
            Ok(Plan::Secure(Box::new(user)))
        }
        None => Ok(Plan::Plain {
            probed: Some(probed),
            keyring_note: None,
        }),
    }
}

/// Turns a refused plain CONNECT into its error: a secure-only interface
/// becomes [`TransportError::SecureRequired`] (issue #182), anything else
/// stays the gateway status (or `NoMoreConnections`).
async fn refusal(
    gateway: SocketAddrV4,
    status: u8,
    context: &'static str,
    probed: Option<GatewayDescription>,
    keyring_note: Option<String>,
) -> TransportError {
    let description = match probed {
        Some(d) => Some(d),
        None => crate::discovery::describe_gateway_extended(gateway, SECURE_PROBE_TIMEOUT)
            .await
            .ok(),
    };
    if description
        .as_ref()
        .is_some_and(GatewayDescription::tunnelling_secure_only)
    {
        return TransportError::SecureRequired {
            gateway,
            reason: keyring_note.unwrap_or_else(|| "no tunnelling credentials were given".into()),
        };
    }
    TransportError::GatewayStatus { status, context }
}

/// Decodes a CONNECT_RESPONSE body into the granted channel id and assigned
/// individual address, turning a refusal into its error.
fn accept_connect_response(body: &[u8]) -> Result<(u8, Option<u16>)> {
    let resp = knxnet::parse_connect_response(body)?;
    // A full interface is a capacity refusal, not a transport fault: give it
    // its own variant so the CLI can name the likely other clients and exit
    // with a distinct code (issue #105).
    if resp.status == crate::error::E_NO_MORE_CONNECTIONS {
        return Err(TransportError::NoMoreConnections);
    }
    if resp.status != 0 {
        return Err(TransportError::GatewayStatus {
            status: resp.status,
            context: "CONNECT_RESPONSE",
        });
    }
    Ok((resp.channel_id, resp.assigned_ia))
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
            Some(result) => {
                // Keep the task's depth meter honest (see the module docs).
                self.queued.fetch_sub(1, Ordering::Relaxed);
                result
            }
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
    /// The UDP socket or secure TCP session to the gateway.
    link: Link,
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
    /// Inbound delivery to the handle. Unbounded on purpose: see the module
    /// docs. Always written through `deliver`, never awaited.
    frames: mpsc::UnboundedSender<Result<TimestampedFrame>>,
    /// Undelivered items in `frames`, shared with the handle (which decrements
    /// it on every `recv`), so the task can meter its own queue depth.
    queued: Arc<AtomicUsize>,
    /// The queue depth the last "consumer falling behind" warning reported, so
    /// the warning repeats per `INBOUND_WARN_DEPTH` frames instead of per frame.
    warned_depth: usize,
    /// The gateway's control endpoint, for re-establishing and error hints.
    gateway: SocketAddrV4,
    /// The local interface, for re-opening a secure TCP session.
    local_interface: Ipv4Addr,
    /// The KNXnet/IP Secure user of this tunnel, if it is secure; a
    /// re-establish opens a fresh secure session with it.
    secure_user: Option<UserKeys>,
    /// How a lost link is re-established (issue #177).
    reconnect: TunnelReconnect,
    /// Publishes the link state to the handle (and through it the bus actor).
    link_state: watch::Sender<LinkState>,
}

impl TaskState {
    /// Hands one inbound item (a frame or a terminal error) to the [`Tunnel`]
    /// handle.
    ///
    /// Deliberately **not** `async`: the channel is unbounded precisely so the
    /// task can never block here while it still owes the caller the reply to an
    /// in-flight send (see the inbound buffering policy in the module docs —
    /// issue #82). A send that fails means the handle is gone; the task still
    /// runs until its command channel closes, so there is nothing to report.
    fn deliver(&mut self, item: Result<TimestampedFrame>) {
        if self.frames.send(item).is_err() {
            return;
        }
        let depth = self.queued.fetch_add(1, Ordering::Relaxed) + 1;
        if depth == 1 {
            // The queue had been drained: re-arm the warning for a future stall.
            self.warned_depth = 0;
        } else if depth >= self.warned_depth.saturating_add(INBOUND_WARN_DEPTH) {
            self.warned_depth = depth;
            tracing::warn!(
                depth,
                "inbound frame queue is deep; the connection consumer is not draining"
            );
        }
    }

    async fn run(mut self) {
        let mut heartbeat =
            time::interval_at(Instant::now() + HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
        let mut keepalive = time::interval_at(
            Instant::now() + SECURE_KEEPALIVE_INTERVAL,
            SECURE_KEEPALIVE_INTERVAL,
        );
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
                res = self.link.recv(&mut buf) => {
                    match res {
                        Ok(n) => {
                            if !self.handle_inbound(&buf[..n]).await {
                                return; // disconnected
                            }
                        }
                        Err(err) => {
                            if let Err(err) = self.recover(err, &mut buf).await {
                                self.deliver(Err(err));
                                return;
                            }
                        }
                    }
                }

                // Secure session keepalive (a no-op on a plain UDP tunnel).
                _ = keepalive.tick() => {
                    if let Err(e) = self.link.keepalive().await
                        && let Err(err) = self.recover(e, &mut buf).await
                    {
                        self.deliver(Err(err));
                        return;
                    }
                }

                // Heartbeat tick.
                _ = heartbeat.tick() => {
                    if let Err(e) = self.do_heartbeat(&mut buf).await
                        && let Err(err) = self.recover(e, &mut buf).await
                    {
                        self.deliver(Err(err));
                        return;
                    }
                }
            }
        }
    }

    /// Whether `err` signals a lost gateway link that the task should
    /// re-establish (issue #177) rather than surface.
    fn should_reestablish(&self, err: &TransportError) -> bool {
        self.reconnect.enabled()
            && matches!(
                err,
                TransportError::Timeout(_)
                    | TransportError::HeartbeatLost
                    | TransportError::Io { .. }
                    | TransportError::SecureSessionEnded(_)
                    | TransportError::BadHeader(..)
            )
    }

    /// Recovers from an idle-time error (heartbeat or socket): re-establishes
    /// the tunnel when the error is a lost link, otherwise returns it.
    async fn recover(&mut self, err: TransportError, buf: &mut [u8]) -> Result<()> {
        if self.should_reestablish(&err) {
            self.reestablish(err, Instant::now(), buf).await
        } else {
            Err(err)
        }
    }

    /// Sends a TUNNELING_REQUEST and awaits its ACK, retransmitting once. When
    /// the link is lost it re-establishes the tunnel and re-sends the frame on
    /// the new channel (issue #177), within the reconnect budget.
    async fn do_send(&mut self, frame: &CemiFrame, buf: &mut [u8]) -> Result<()> {
        crate::wire_trace::trace_frame(crate::wire_trace::Direction::Outbound, frame);
        // When the loss was first detected, so repeated losses of one pending
        // frame share a single budget.
        let mut lost_at: Option<Instant> = None;
        loop {
            match self.send_once(frame, buf).await {
                Ok(()) => return Ok(()),
                Err(err) if self.should_reestablish(&err) => {
                    let started = *lost_at.get_or_insert_with(Instant::now);
                    self.reestablish(err, started, buf).await?;
                    tracing::debug!(
                        channel = self.channel_id,
                        "re-sending the pending frame on the re-established tunnel"
                    );
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// One TUNNELING_REQUEST on the current channel: send, await the ACK, and
    /// retransmit once on timeout.
    async fn send_once(&mut self, frame: &CemiFrame, buf: &mut [u8]) -> Result<()> {
        let seq = self.outgoing_seq;
        let header = ConnectionHeader {
            channel_id: self.channel_id,
            seq,
        };
        let datagram = knxnet::tunneling_request(header, frame);

        if !self.link.acks() {
            // Over TCP there is no TUNNELING_ACK: the stream is reliable and a
            // broken one surfaces as a socket error (CONFIRMED, ETS capture).
            self.link.send(&datagram).await?;
            self.outgoing_seq = self.outgoing_seq.wrapping_add(1);
            return Ok(());
        }

        let mut attempt = 0;
        loop {
            self.link.send(&datagram).await?;
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
            let n = match time::timeout(remaining, self.link.recv(buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(TransportError::Timeout("TUNNELING_ACK")),
            };
            let datagram = buf[..n].to_vec();
            let parsed = match knxnet::parse(&datagram) {
                Ok(p) => p,
                Err(_) => continue, // ignore garbage while waiting
            };
            match parsed.service {
                ServiceType::TunnelingAck => {
                    if let Ok((hdr, status)) = knxnet::parse_tunneling_ack(parsed.body)
                        && hdr.seq == seq
                    {
                        if status != 0 {
                            return Err(TransportError::GatewayStatus {
                                status,
                                context: "TUNNELING_ACK",
                            });
                        }
                        return Ok(());
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
                    let _ = self.link.send(&resp).await;
                }
                self.deliver(Err(TransportError::Disconnected(self.channel_id)));
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
            if self.link.acks() {
                let ack = knxnet::tunneling_ack(self.channel_id, seq, 0);
                let _ = self.link.send(&ack).await;
            }
            self.incoming_seq = self.incoming_seq.wrapping_add(1);

            match CemiFrame::decode(cemi_bytes) {
                Ok(cemi) => {
                    crate::wire_trace::trace_frame(crate::wire_trace::Direction::Inbound, &cemi);
                    let stamped = TimestampedFrame {
                        received_at: SystemTime::now(),
                        frame: cemi,
                    };
                    self.deliver(Ok(stamped));
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
            if self.link.acks() {
                let ack = knxnet::tunneling_ack(self.channel_id, seq, 0);
                let _ = self.link.send(&ack).await;
            }
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
            self.link.send(&req).await?;
            let deadline = Instant::now() + HEARTBEAT_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break; // retry
                }
                match time::timeout(remaining, self.link.recv(buf)).await {
                    Ok(Ok(n)) => {
                        let datagram = buf[..n].to_vec();
                        if let Ok(parsed) = knxnet::parse(&datagram) {
                            if parsed.service == ServiceType::ConnectionstateResponse {
                                if let Ok(cs) = knxnet::parse_channel_status(parsed.body)
                                    && cs.channel_id == self.channel_id
                                {
                                    if cs.status == 0 {
                                        return Ok(());
                                    }
                                    // Non-zero status: retry.
                                    break;
                                }
                            } else {
                                // Interleaved traffic during heartbeat wait.
                                if !self.handle_inbound(&datagram).await {
                                    return Err(TransportError::Disconnected(self.channel_id));
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // timed out; retry
                }
            }
            tracing::warn!(attempt = attempt + 1, "heartbeat attempt failed");
        }
        Err(TransportError::HeartbeatLost)
    }

    /// Re-establishes the tunnel after a lost link (issue #177).
    ///
    /// `cause` is the error that signalled the loss and `started` the moment it
    /// was first detected; the [`TunnelReconnect`] budget runs from there. Each
    /// attempt sends a best-effort DISCONNECT_REQUEST for the old channel (until
    /// the gateway answers one), then a CONNECT_REQUEST. On success the new
    /// channel id is adopted and both sequence counters reset. When the budget
    /// runs out the result is [`TransportError::TunnelLost`] wrapping `cause`.
    async fn reestablish(
        &mut self,
        cause: TransportError,
        started: Instant,
        buf: &mut [u8],
    ) -> Result<()> {
        let deadline = started + self.reconnect.budget;
        let gateway = self.gateway;
        tracing::warn!(
            "gateway connection lost ({cause}); reconnecting to {gateway} for up to {} s",
            self.reconnect.budget.as_secs()
        );
        self.link_state.send_replace(LinkState::Reconnecting);
        let old_channel = self.channel_id;
        let mut old_open = true;
        let mut backoff = self.reconnect.initial_backoff;
        let mut attempt = 0u32;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            attempt += 1;
            if old_open {
                // Best effort: a gateway that still holds the old channel frees
                // its slot; an unreachable one simply never sees this.
                let req = knxnet::disconnect_request(old_channel, self.local_hpai);
                let _ = self.link.send(&req).await;
            }
            let wait = self.reconnect.attempt_timeout.min(remaining);
            match self
                .connect_attempt(wait, old_channel, &mut old_open, buf)
                .await
            {
                Ok((channel, assigned_ia)) => {
                    self.channel_id = channel;
                    self.outgoing_seq = 0;
                    self.incoming_seq = 0;
                    self.first_incoming = true;
                    tracing::warn!(
                        "gateway connection re-established ({gateway}, channel {channel}, \
                         attempt {attempt})"
                    );
                    self.link_state.send_replace(LinkState::Up { assigned_ia });
                    return Ok(());
                }
                Err(err) => {
                    tracing::debug!(attempt, %err, "tunnel re-establish attempt failed");
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            time::sleep(backoff.min(remaining)).await;
            backoff = backoff.saturating_mul(2).min(self.reconnect.max_backoff);
        }
        Err(TransportError::TunnelLost {
            gateway,
            budget: self.reconnect.budget,
            cause: Box::new(cause),
        })
    }

    /// One re-establish attempt: sends CONNECT_REQUEST and waits up to `wait`
    /// for the CONNECT_RESPONSE, returning the granted channel and assigned
    /// individual address.
    ///
    /// Stale traffic for the old channel is dropped unanswered meanwhile, except
    /// a DISCONNECT_RESPONSE for `old_channel` (which clears `old_open`, so the
    /// next attempt does not repeat the DISCONNECT) and a server
    /// DISCONNECT_REQUEST (answered).
    async fn connect_attempt(
        &mut self,
        wait: std::time::Duration,
        old_channel: u8,
        old_open: &mut bool,
        buf: &mut [u8],
    ) -> Result<(u8, Option<u16>)> {
        let deadline = Instant::now() + wait;
        if let Some(user) = &self.secure_user {
            // A secure tunnel needs a fresh TCP connection and session: the old
            // session died with the link. Closing its TCP connection releases
            // the old channel on the gateway, so no DISCONNECT is owed.
            let link = SecureLink::open(self.gateway, self.local_interface, user, wait).await?;
            self.link.close().await;
            self.link = Link::Secure(Box::new(link));
            *old_open = false;
        }
        let req = knxnet::connect_request(self.local_hpai, self.local_hpai);
        self.link.send(&req).await?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout("CONNECT_RESPONSE"));
            }
            let n = match time::timeout(remaining, self.link.recv(buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(TransportError::Timeout("CONNECT_RESPONSE")),
            };
            let Ok(parsed) = knxnet::parse(&buf[..n]) else {
                continue;
            };
            match parsed.service {
                ServiceType::ConnectResponse => return accept_connect_response(parsed.body),
                ServiceType::DisconnectResponse => {
                    if parsed.body.first() == Some(&old_channel) {
                        *old_open = false;
                    }
                }
                ServiceType::DisconnectRequest => {
                    if let Ok(channel) = knxnet::parse_disconnect_request(parsed.body) {
                        let resp = knxnet::disconnect_response(channel, 0);
                        let _ = self.link.send(&resp).await;
                        if channel == old_channel {
                            *old_open = false;
                        }
                    }
                }
                // Late ACKs, indications and heartbeat answers of the old
                // channel: nothing to do with them now.
                _ => {}
            }
        }
    }

    /// Sends a DISCONNECT_REQUEST and waits briefly for the response.
    async fn do_close(&mut self, buf: &mut [u8]) -> Result<()> {
        // The same real control HPAI as CONNECT and the heartbeat, for the same
        // interop reason. The DISCONNECT_RESPONSE is best-effort.
        let result = self.disconnect(buf).await;
        // End a secure session explicitly (a no-op on UDP).
        self.link.close().await;
        result
    }

    /// The DISCONNECT_REQUEST / DISCONNECT_RESPONSE exchange of [`do_close`].
    async fn disconnect(&mut self, buf: &mut [u8]) -> Result<()> {
        let control = self.local_hpai;
        let req = knxnet::disconnect_request(self.channel_id, control);
        self.link.send(&req).await?;

        let deadline = Instant::now() + DISCONNECT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Best-effort close: not receiving the response is not fatal.
                return Ok(());
            }
            match time::timeout(remaining, self.link.recv(buf)).await {
                Ok(Ok(n)) => {
                    if let Ok(parsed) = knxnet::parse(&buf[..n])
                        && parsed.service == ServiceType::DisconnectResponse
                    {
                        return Ok(());
                    }
                }
                Ok(Err(_)) | Err(_) => return Ok(()),
            }
        }
    }
}
