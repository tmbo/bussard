//! The KNXnet/IP connection machine shared by a tunnel ([`crate::tunnel`])
//! and a device management connection ([`crate::devmgmt`]).
//!
//! Both run the same channel over the same [`Link`]: a sequenced request
//! confirmed by an ACK and repeated when the ACK is missing or carries an
//! error status, a CONNECTIONSTATE heartbeat, the inbound sequence check
//! with a re-ACK of the repeated previous frame, and a best-effort
//! DISCONNECT on close (Core 3/8/2 §5.4, Device Management 3/8/3 §2.3.2,
//! Tunnelling 3/8/4 §2.6.1). A [`ChannelKind`] names what differs: the ACK
//! service and its timing. Each task keeps its own run loop and its own
//! handling of the inbound requests it delivers.

use std::time::Duration;

use tokio::time::{self, Instant};

use crate::config::DISCONNECT_TIMEOUT;
use crate::error::{Result, TransportError};
use crate::knxnet::{self, ConnectionHeader, Hpai, ServiceType};
use crate::tunnel::Link;

/// What distinguishes one kind of KNXnet/IP connection channel.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChannelKind {
    /// The service confirming a request (TUNNELING_ACK, ...).
    pub(crate) ack_service: ServiceType,
    /// Builds that ACK: channel id, sequence, status.
    pub(crate) ack: fn(u8, u8, u8) -> Vec<u8>,
    /// The ACK's name, the context of its timeout and error status.
    pub(crate) ack_context: &'static str,
    /// How long one request waits for its ACK.
    pub(crate) ack_timeout: Duration,
    /// How often an unconfirmed request is repeated.
    pub(crate) retransmits: u32,
}

/// The state of one open channel: its link, id and sequence counters.
pub(crate) struct Channel {
    /// The UDP socket or secure TCP session to the server.
    pub(crate) link: Link,
    /// What the channel's requests and ACKs are.
    pub(crate) kind: ChannelKind,
    /// The channel id the server granted.
    pub(crate) id: u8,
    /// The real local endpoint advertised in every HPAI.
    pub(crate) hpai: Hpai,
    /// Sequence counter for requests we send.
    pub(crate) outgoing_seq: u8,
    /// Next expected sequence counter for requests the server sends us.
    pub(crate) incoming_seq: u8,
    /// Whether the first inbound request sets the expected sequence.
    pub(crate) first_incoming: bool,
}

impl Channel {
    /// A channel with both counters at zero.
    pub(crate) fn new(link: Link, kind: ChannelKind, id: u8, hpai: Hpai) -> Self {
        Channel {
            link,
            kind,
            id,
            hpai,
            outgoing_seq: 0,
            incoming_seq: 0,
            first_incoming: false,
        }
    }

    /// The inbound sequence check for a request with sequence `seq`; `true`
    /// when it is the expected one and is to be delivered.
    ///
    /// * **Expected seq**: ACK (where the link has ACKs) and advance.
    /// * **Exact previous seq**: the server's repeat of a frame we already
    ///   accepted (our ACK was lost); ACK it with its own sequence so the
    ///   server stops resending, but neither advance nor deliver.
    /// * **Any other seq**: silently discard, no ACK (Tunnelling 3/8/4
    ///   §2.6.1). ACKing a frame we then drop would tell the server we
    ///   accepted it.
    pub(crate) async fn accept_incoming(&mut self, seq: u8) -> bool {
        if self.first_incoming {
            // Accept whatever the server starts at as the expected sequence.
            self.incoming_seq = seq;
            self.first_incoming = false;
        }
        // How far `seq` is behind the expected sequence, modulo 256.
        let behind = self.incoming_seq.wrapping_sub(seq);
        if behind > 1 {
            tracing::warn!(
                seq,
                expected = self.incoming_seq,
                "out-of-window request sequence; silently discarding (no ACK)"
            );
            return false;
        }
        if self.link.acks() {
            let ack = (self.kind.ack)(self.id, seq, 0);
            let _ = self.link.send_data(&ack).await;
        }
        if behind == 1 {
            tracing::debug!(seq, "ACK-and-drop of a repeated request");
            return false;
        }
        self.incoming_seq = self.incoming_seq.wrapping_add(1);
        true
    }

    /// The DISCONNECT_REQUEST / DISCONNECT_RESPONSE exchange (best effort:
    /// a missing response is not an error).
    pub(crate) async fn disconnect(&mut self, buf: &mut [u8]) -> Result<()> {
        let request = knxnet::disconnect_request(self.id, self.hpai);
        self.link.send(&request).await?;
        let deadline = Instant::now() + DISCONNECT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
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

/// A task that owns a [`Channel`]: it serves the inbound traffic that
/// arrives while the shared machine waits for an ACK or a heartbeat answer.
pub(crate) trait ChannelTask {
    /// The task's channel.
    fn channel(&mut self) -> &mut Channel;

    /// Serves one inbound datagram that is not the awaited answer; `false`
    /// when the server ended the connection.
    async fn handle_inbound(&mut self, datagram: &[u8]) -> bool;

    /// Sends one request under the next outgoing sequence (`build` makes it
    /// from the connection header). Over a link with ACKs it waits for the
    /// ACK and repeats the request up to [`ChannelKind::retransmits`] times
    /// when the ACK is missing or carries an error status; over TCP the
    /// stream is reliable and a broken one surfaces as a socket error.
    async fn send_sequenced(
        &mut self,
        build: impl Fn(ConnectionHeader) -> Vec<u8>,
        buf: &mut [u8],
    ) -> Result<()> {
        let channel = self.channel();
        let seq = channel.outgoing_seq;
        let kind = channel.kind;
        let datagram = build(ConnectionHeader {
            channel_id: channel.id,
            seq,
        });
        if !channel.link.acks() {
            channel.link.send_data(&datagram).await?;
            channel.outgoing_seq = seq.wrapping_add(1);
            return Ok(());
        }
        let mut attempt = 0;
        loop {
            self.channel().link.send_data(&datagram).await?;
            match self.await_ack(seq, buf).await {
                Ok(()) => {
                    self.channel().outgoing_seq = seq.wrapping_add(1);
                    return Ok(());
                }
                Err(TransportError::Timeout(_)) if attempt < kind.retransmits => {
                    attempt += 1;
                    tracing::warn!(seq, attempt, "{} timeout; retransmitting", kind.ack_context);
                }
                Err(TransportError::GatewayStatus { status, context })
                    if context == kind.ack_context && attempt < kind.retransmits =>
                {
                    attempt += 1;
                    tracing::warn!(
                        seq,
                        attempt,
                        status,
                        "{} with an error status; repeating the request",
                        kind.ack_context
                    );
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Waits for the ACK matching `seq`, serving other inbound datagrams
    /// meanwhile so nothing is lost.
    async fn await_ack(&mut self, seq: u8, buf: &mut [u8]) -> Result<()> {
        let kind = self.channel().kind;
        let deadline = Instant::now() + kind.ack_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout(kind.ack_context));
            }
            let n = match time::timeout(remaining, self.channel().link.recv(buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(TransportError::Timeout(kind.ack_context)),
            };
            let datagram = buf[..n].to_vec();
            let Ok(parsed) = knxnet::parse(&datagram) else {
                continue; // ignore garbage while waiting
            };
            if parsed.service == kind.ack_service {
                if let Ok((header, status)) = knxnet::parse_tunneling_ack(parsed.body)
                    && header.seq == seq
                {
                    if status != 0 {
                        return Err(TransportError::GatewayStatus {
                            status,
                            context: kind.ack_context,
                        });
                    }
                    return Ok(());
                }
            } else if !self.handle_inbound(&datagram).await {
                return Err(TransportError::Disconnected(self.channel().id));
            }
        }
    }

    /// Sends up to `attempts` CONNECTIONSTATE_REQUESTs, each waiting
    /// `timeout` for a successful response, serving interleaved traffic
    /// meanwhile (Core 3/8/2 §5.4).
    async fn heartbeat_with(
        &mut self,
        attempts: u32,
        timeout: Duration,
        buf: &mut [u8],
    ) -> Result<()> {
        let channel = self.channel();
        // The same real control HPAI the CONNECT used: wildcard route-back
        // breaks literal-minded gateways like KNX Virtual.
        let request = knxnet::connectionstate_request(channel.id, channel.hpai);
        for attempt in 0..attempts {
            self.channel().link.send(&request).await?;
            let deadline = Instant::now() + timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let n = match time::timeout(remaining, self.channel().link.recv(buf)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break,
                };
                let datagram = buf[..n].to_vec();
                let Ok(parsed) = knxnet::parse(&datagram) else {
                    continue;
                };
                if parsed.service == ServiceType::ConnectionstateResponse {
                    if let Ok(status) = knxnet::parse_channel_status(parsed.body)
                        && status.channel_id == self.channel().id
                    {
                        if status.status == 0 {
                            return Ok(());
                        }
                        break; // an error status: the next attempt
                    }
                } else if !self.handle_inbound(&datagram).await {
                    return Err(TransportError::Disconnected(self.channel().id));
                }
            }
            tracing::warn!(attempt = attempt + 1, "heartbeat attempt failed");
        }
        Err(TransportError::HeartbeatLost)
    }
}
