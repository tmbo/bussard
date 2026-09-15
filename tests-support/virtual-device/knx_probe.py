#!/usr/bin/env python3
"""
Bussard-independent KNX interop probe for the thelsing knx-linux-ip virtual
device, run from the root network namespace against a device already booted in
the `knxdev` namespace (see netns-setup.sh). It talks raw KNXnet/IP routing
multicast (service ROUTING_INDICATION 0x0530, cEMI L_Data) on 224.0.23.12:3671,
so it isolates the DEVICE's behaviour from anything bussard does.

It reports three facts that scope any ladder failure precisely:

  1. Multicast reaches the device (its own chatter / our frames cross the veth).
  2. The device is reachable CONNECTION-ORIENTED at its default individual
     address 15.15.255 (0xFFFF) and answers property reads/writes — including a
     PID_PROG_MODE write+read-back.
  3. Whether the device answers the BROADCAST A_IndividualAddress_Read that
     `bussard assign` relies on for programming-mode discovery (rung a).

# The interop wall this documents

The pinned thelsing commit defaults the device individual address to 0xFFFF, so
its demo's `main.cpp` guard `if (individualAddress()==0) knx.progMode(true)`
never fires: a factory-fresh device is NOT in programming mode. Even after we set
PID_PROG_MODE=1 over a connection (confirmed by reading it back as 0x01), the
device still does not answer the broadcast A_IndividualAddress_Read over routing.
So `bussard assign`'s prog-mode discovery finds nothing. This is a property of
thelsing's stack over IP routing, not a bussard bug and not a networking issue
(the connection-oriented path to 15.15.255 works fine on the same socket).

Exit status is always 0: this is a diagnostic, not a gate.
"""

import socket
import struct
import time

GROUP = "224.0.23.12"
PORT = 3671
HOST_IP = "10.213.0.1"  # bussard-side veth address (root ns)
DEVICE = 0xFFFF  # 15.15.255, the device's default individual address


def open_sockets():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("", PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(GROUP), socket.inet_aton(HOST_IP))
    rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    rx.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(HOST_IP))
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    return rx, tx


def wrap(cemi_body):
    """KNXnet/IP ROUTING_INDICATION (0x0530) around a cEMI body."""
    return bytes([0x06, 0x10, 0x05, 0x30]) + struct.pack(">H", 6 + len(cemi_body)) + cemi_body


def read_cemi(ctrl1):
    """A_IndividualAddress_Read broadcast (dst 0/0/0), src 0.0.255."""
    # msg L_Data.req 0x11, ai_len 0, ctrl1, ctrl2 0xE0 (group dst, hop 6),
    # src 0x00FF, dst 0x0000, npdu_len 1, TPDU 0x00 0x01 (APCI 0x0100).
    return bytes([0x11, 0x00, ctrl1, 0xE0, 0x00, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x01])


def co_frame(tpdu):
    """A point-to-point cEMI to DEVICE (connection-oriented management)."""
    body = (
        bytes([0x11, 0x00, 0xBC, 0x60, 0x00, 0xFF])
        + struct.pack(">H", DEVICE)
        + bytes([len(tpdu) - 1])
        + tpdu
    )
    return wrap(body)


def drain(rx):
    try:
        while True:
            rx.recvfrom(1024)
    except BlockingIOError:
        pass


def collect(rx, sent, secs, src=None):
    """Collect datagrams for `secs`, skipping our own echo, optionally filtering
    on cEMI source address."""
    out = []
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            data, _ = rx.recvfrom(1024)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        if data == sent:
            continue
        if src is not None and not (len(data) >= 12 and struct.unpack(">H", data[10:12])[0] == src):
            continue
        out.append(data)
    return out


def is_ind_addr_response(data):
    # APCI 0x0140 in the last two APDU octets.
    return len(data) >= 2 and (data[-2] & 0x03) == 0x01 and data[-1] == 0x40


def main():
    rx, tx = open_sockets()

    # --- Fact 3a: broadcast read of a factory-fresh (not-prog-mode) device ---
    drain(rx)
    f = wrap(read_cemi(0xB6))
    tx.sendto(f, (GROUP, PORT))
    replies = [d for d in collect(rx, f, 2.5) if is_ind_addr_response(d)]
    print(f"[probe] broadcast read (fresh device): {'ANSWERED' if replies else 'no reply'}")

    # --- Fact 2: connection-oriented management to 15.15.255 ---
    drain(rx)
    tx.sendto(co_frame(bytes([0x80])), (GROUP, PORT))  # T_Connect
    time.sleep(0.2)
    # A_PropertyValue_Write seq0: obj 0, PID 54 (PROG_MODE), count1/start1, val 1.
    apci_w = 0x3D7
    pw = bytes([0x40 | ((apci_w >> 8) & 0x03), apci_w & 0xFF, 0x00, 54]) + struct.pack(">H", (1 << 12) | 1) + bytes([0x01])
    tx.sendto(co_frame(pw), (GROUP, PORT))
    co = collect(rx, b"", 1.0, src=DEVICE)
    print(f"[probe] connection-oriented to 15.15.255: {'REACHABLE' if co else 'no reply'}")
    tx.sendto(co_frame(bytes([0xC2])), (GROUP, PORT))  # T_ACK seq0
    time.sleep(0.2)
    # Read PROG_MODE back (seq1) to confirm the write took.
    apci_r = 0x3D5
    rd = bytes([0x40 | (1 << 2) | ((apci_r >> 8) & 0x03), apci_r & 0xFF, 0x00, 54]) + struct.pack(">H", (1 << 12) | 1)
    tx.sendto(co_frame(rd), (GROUP, PORT))
    resp = collect(rx, b"", 1.0, src=DEVICE)
    progmode = any(d[-1] == 0x01 for d in resp if len(d) >= 1)
    print(f"[probe] PID_PROG_MODE after write: {'1 (on)' if progmode else 'unconfirmed'}")
    tx.sendto(co_frame(bytes([0xC6])), (GROUP, PORT))  # T_ACK seq1

    # --- Fact 3b: broadcast read with prog mode confirmed on ---
    drain(rx)
    f = wrap(read_cemi(0xB6))
    tx.sendto(f, (GROUP, PORT))
    replies = [d for d in collect(rx, f, 2.5) if is_ind_addr_response(d)]
    print(f"[probe] broadcast read (prog mode on): {'ANSWERED' if replies else 'no reply'}")

    tx.sendto(co_frame(bytes([0x81])), (GROUP, PORT))  # T_Disconnect
    print("[probe] done")


if __name__ == "__main__":
    main()
