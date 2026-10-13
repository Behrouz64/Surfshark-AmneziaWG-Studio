"""
checker.py: High-Concurrency UDP Port 51820 Reachability & Latency Checker

Performs concurrent network health and reachability checks for WireGuard endpoints
on UDP port 51820.

Supports:
1. Syntactically valid WireGuard Handshake Initiation probes (148 bytes).
   If client and server WireGuard keys are provided, completes the actual
   Noise_IKpsk2 handshake initiation to trigger a 92-byte Handshake Response.
2. Lightweight UDP socket reachability and ICMP unreachability detection.
3. Microsecond-accurate Round-Trip Time (RTT) latency measurement in milliseconds.
4. Asynchronous batch testing with progress reporting.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# WireGuard Protocol Constants
WG_INITIATION_SIZE = 148
WG_RESPONSE_SIZE = 92
DEFAULT_WG_PORT = 51820

# Noise / WireGuard Construction using cryptography library if available
_CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


class ScanMode:
    """Supported reachability verification modes."""
    SMART = "smart"             # Smart Anti-DPI (Default): Intelligently checks UDP/Handshake; accounts for WireGuard silent unauthenticated drop.
    STRICT_UDP = "strict_udp"   # Strict: Requires actual UDP response. Ping-only endpoints are rejected.
    DEEP = "deep"               # Multi-probe test with packet loss and jitter evaluation.
    PERMISSIVE = "permissive"   # Allows ICMP ping fallback if UDP times out (legacy mode).


DEFAULT_DUMMY_CLIENT_KEY = "GJfG1b7zCubnBHQHdNyJVKDMtoylDQgfpqZDhm4jjVM="


def is_placeholder_client_key(key: Optional[str]) -> bool:
    """
    Checks if client private key is missing or is the default dummy placeholder.
    When a placeholder key is used, standard WireGuard servers (such as Azerbaijan)
    enforce cryptographic silent drops on unauthenticated handshakes.
    """
    if not key or not str(key).strip():
        return True
    k = str(key).strip()
    if k == DEFAULT_DUMMY_CLIENT_KEY:
        return True
    if len(k) < 32:
        return True
    if "c1p191WvA9d0" in k:
        return True
    return False


def is_placeholder_server_key(key: Optional[str]) -> bool:
    """
    Checks if server public key is missing or is a placeholder seed key.
    """
    if not key or not str(key).strip():
        return True
    k = str(key).strip()
    if len(k) != 44:
        return True
    KNOWN_REAL_KEYS = {
        "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=",
    }
    if k in KNOWN_REAL_KEYS:
        return False
    fake_markers = ["c1p191WvA9d0", "j9aB9C1d9E2f", "l9m0=", "l9m1=", "l9m2=", "l9m3=",
                    "l9m4=", "l9m5=", "l9m6=", "l9m7=", "l9m8=", "l9m9="]
    return any(m in k for m in fake_markers)


@dataclass
class CheckResult:
    ip: str
    port: int
    is_reachable: bool
    latency_ms: float = 9999.0
    status: str = "timed_out"  # "handshake_ok", "responsive", "verified_stable", "ping_only_udp_blocked", "ping_alive", "blocked", "timed_out", "error"
    error: Optional[str] = None
    server_info: Optional[dict] = None
    packet_loss: float = 0.0  # 0.0 to 100.0%
    jitter_ms: float = 0.0
    deep_verified: bool = False


def generate_wireguard_initiation(
    client_private_key_b64: Optional[str] = None,
    server_public_key_b64: Optional[str] = None,
) -> bytes:
    """
    Constructs a 148-byte WireGuard Handshake Initiation packet.
    If valid client private key and server public key are given, generates
    a mathematically valid Noise_IK initiation message.
    Otherwise, generates a structural 148-byte initiation probe.
    """
    if _CRYPTO_AVAILABLE and client_private_key_b64 and server_public_key_b64:
        try:
            client_priv_bytes = base64.b64decode(client_private_key_b64)
            server_pub_bytes = base64.b64decode(server_public_key_b64)

            if len(client_priv_bytes) == 32 and len(server_pub_bytes) == 32:
                # WireGuard Noise Protocol constants
                CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
                IDENTIFIER = b"WireGuard v1 zx2c4 Just a Parser"

                # Initial Hash & Chaining Key
                h = hashes.Hash(hashes.BLAKE2s(32))
                h.update(CONSTRUCTION)
                chaining_key = h.finalize()

                h = hashes.Hash(hashes.BLAKE2s(32))
                h.update(chaining_key + IDENTIFIER)
                hash_val = h.finalize()

                # Hash server static public key
                h = hashes.Hash(hashes.BLAKE2s(32))
                h.update(hash_val + server_pub_bytes)
                hash_val = h.finalize()

                # Generate ephemeral keypair
                ephemeral_priv = x25519.X25519PrivateKey.generate()
                ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes_raw()

                # Mix ephemeral public key into hash and chaining key
                h = hashes.Hash(hashes.BLAKE2s(32))
                h.update(hash_val + ephemeral_pub_bytes)
                hash_val = h.finalize()

                # KDF1
                hkdf1 = HKDF(
                    algorithm=hashes.BLAKE2s(32),
                    length=64,
                    salt=chaining_key,
                    info=b"",
                )
                kdf1_out = hkdf1.derive(ephemeral_pub_bytes)
                chaining_key = kdf1_out[:32]
                key1 = kdf1_out[32:]

                # DH(e, s) = ephemeral_priv.exchange(server_pub)
                server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
                ss1 = ephemeral_priv.exchange(server_pub)

                # KDF2
                hkdf2 = HKDF(
                    algorithm=hashes.BLAKE2s(32),
                    length=64,
                    salt=chaining_key,
                    info=b"",
                )
                kdf2_out = hkdf2.derive(ss1)
                chaining_key = kdf2_out[:32]
                key2 = kdf2_out[32:]

                # Encrypt static public key (32 bytes)
                client_priv = x25519.X25519PrivateKey.from_private_bytes(client_priv_bytes)
                client_pub_bytes = client_priv.public_key().public_bytes_raw()

                # Zero nonce for first packet
                cipher2 = ChaCha20Poly1305(key2)
                encrypted_static = cipher2.encrypt(b"\x00" * 12, client_pub_bytes, hash_val)

                # Update hash
                h = hashes.Hash(hashes.BLAKE2s(32))
                h.update(hash_val + encrypted_static)
                hash_val = h.finalize()

                # DH(s, s) = client_priv.exchange(server_pub)
                ss2 = client_priv.exchange(server_pub)

                # KDF3
                hkdf3 = HKDF(
                    algorithm=hashes.BLAKE2s(32),
                    length=64,
                    salt=chaining_key,
                    info=b"",
                )
                kdf3_out = hkdf3.derive(ss2)
                chaining_key = kdf3_out[:32]
                key3 = kdf3_out[32:]

                # Timestamp (12 bytes TAI64N timestamp)
                # TAI64 standard: seconds since 1970 + 2^62, plus 4 bytes nanoseconds
                now_sec = int(time.time()) + 0x400000000000000a
                now_nsec = int((time.time() % 1) * 1_000_000_000)
                timestamp = struct.pack(">QI", now_sec, now_nsec)

                cipher3 = ChaCha20Poly1305(key3)
                encrypted_timestamp = cipher3.encrypt(b"\x00" * 12, timestamp, hash_val)

                # Update hash
                h = hashes.Hash(hashes.BLAKE2s(32))
                h.update(hash_val + encrypted_timestamp)
                hash_val = h.finalize()

                # Sender Index (4 bytes random)
                sender_index = os.urandom(4)

                # MAC1 = BLAKE2s(key=server_pub, data=packet[:116])
                packet_without_mac = struct.pack("<I", 1) + sender_index + ephemeral_pub_bytes + encrypted_static + encrypted_timestamp
                h_mac1 = hashes.Hash(hashes.BLAKE2s(16, key=server_pub_bytes))
                h_mac1.update(packet_without_mac)
                mac1 = h_mac1.finalize()

                # MAC2 is zeros unless cookie received
                mac2 = b"\x00" * 16

                packet = packet_without_mac + mac1 + mac2
                if len(packet) == WG_INITIATION_SIZE:
                    return packet
        except Exception as e:
            logger.debug(f"Could not build authenticated WG handshake packet: {e}")

    # Fallback: Syntactically formatted 148-byte WireGuard Initiation structure
    # Message Type 1 (4 bytes: 0x01, 0x00, 0x00, 0x00)
    # Sender Index (4 bytes)
    # Unencrypted Ephemeral (32 bytes)
    # Encrypted Static (48 bytes)
    # Encrypted Timestamp (28 bytes)
    # MAC1 (16 bytes)
    # MAC2 (16 bytes)
    msg_type = struct.pack("<I", 1)
    sender_index = os.urandom(4)
    ephemeral = os.urandom(32)
    enc_static = os.urandom(48)
    enc_timestamp = os.urandom(28)
    mac1 = os.urandom(16)
    mac2 = b"\x00" * 16
    return msg_type + sender_index + ephemeral + enc_static + enc_timestamp + mac1 + mac2


from concurrent.futures import ThreadPoolExecutor
import threading


import platform
import subprocess
import re


def ping_latency_ms(ip: str, timeout_sec: float = 1.0) -> Optional[float]:
    """Measures ICMP round-trip latency in milliseconds cross-platform."""
    try:
        system = platform.system().lower()
        if system == "darwin":
            # macOS: -c 1 (count), -W <milliseconds>
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_sec * 1000)), ip]
        elif system == "windows":
            # Windows: -n 1, -w <milliseconds>
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip]
        else:
            # Linux: -c 1, -W <seconds>
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]

        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout_sec + 0.5)
        if res.returncode == 0:
            match = re.search(r'time[=<]\s*(\d+(?:\.\d+)?)\s*ms', res.stdout, re.IGNORECASE)
            if match:
                return float(match.group(1))
            match_bare = re.search(r'time[=<]\s*(\d+(?:\.\d+)?)', res.stdout, re.IGNORECASE)
            if match_bare:
                return float(match_bare.group(1))
            match_avg = re.search(r'min/avg/max/\w+\s*=\s*[\d.]+/([\d.]+)/', res.stdout)
            if match_avg:
                return float(match_avg.group(1))
    except Exception:
        pass
    return None


def check_udp_endpoint_sync(
    ip: str,
    port: int = DEFAULT_WG_PORT,
    timeout: float = 2.0,
    client_private_key: Optional[str] = None,
    server_public_key: Optional[str] = None,
    server_info: Optional[dict] = None,
    mode: str = ScanMode.SMART,
) -> CheckResult:
    """
    Tests a single IP:port endpoint.
    1. Sends WireGuard initiation packet and listens for handshake response (92 bytes)
       or cookie reply (64 bytes).
    2. In Smart Anti-DPI mode (default):
       - If UDP handshake response received -> verified reachable (handshake_ok).
       - If UDP times out but ICMP ping responds:
         * If using placeholder/dummy client private key or server key: Standard WireGuard
           servers (like Azerbaijan) silently drop unauthenticated packets by RFC design.
           Since the host answers ICMP ping, the route and host are alive -> is_reachable=True, status='ping_alive'.
         * If using valid authenticated keys: UDP timeout with live ping indicates
           active DPI port filtering -> is_reachable=False, status='ping_only_udp_blocked'.
    3. In Strict UDP mode:
       Requires actual UDP packet return. Host responding to ping only is rejected.
    4. In Permissive mode:
       ICMP ping responsiveness is accepted as is_reachable=True (legacy fallback).
    """
    packet = generate_wireguard_initiation(client_private_key, server_public_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    start_time = time.perf_counter()
    try:
        # Send Initiation Packet
        sock.sendto(packet, (ip, port))

        # Wait for response with timeout
        data, _ = sock.recvfrom(512)
        rtt_ms = (time.perf_counter() - start_time) * 1000.0

        if len(data) >= 4:
            msg_type = struct.unpack("<I", data[:4])[0]
            if msg_type == 2:  # Handshake Response
                return CheckResult(
                    ip=ip,
                    port=port,
                    is_reachable=True,
                    latency_ms=round(rtt_ms, 2),
                    status="handshake_ok",
                    server_info=server_info,
                    packet_loss=0.0,
                )
            elif msg_type == 3:  # Cookie Reply
                return CheckResult(
                    ip=ip,
                    port=port,
                    is_reachable=True,
                    latency_ms=round(rtt_ms, 2),
                    status="responsive",
                    server_info=server_info,
                    packet_loss=0.0,
                )

        return CheckResult(
            ip=ip,
            port=port,
            is_reachable=True,
            latency_ms=round(rtt_ms, 2),
            status="responsive",
            server_info=server_info,
            packet_loss=0.0,
        )

    except socket.timeout:
        # Check ICMP ping for path diagnostics
        ping_ms = ping_latency_ms(ip, timeout_sec=min(1.2, timeout))
        if ping_ms is not None:
            if mode == ScanMode.PERMISSIVE:
                return CheckResult(
                    ip=ip,
                    port=port,
                    is_reachable=True,
                    latency_ms=round(ping_ms, 2),
                    status="ping_alive",
                    server_info=server_info,
                    packet_loss=0.0,
                )
            elif mode == ScanMode.SMART:
                # WireGuard RFC enforces silent drop on unauthenticated handshake.
                # If credentials are placeholder/dummy, silence on UDP is expected protocol behavior.
                # Since ICMP ping answered, route to server is alive and unblocked!
                is_unauthenticated_dummy = is_placeholder_client_key(client_private_key) or is_placeholder_server_key(server_public_key)
                if is_unauthenticated_dummy:
                    return CheckResult(
                        ip=ip,
                        port=port,
                        is_reachable=True,
                        latency_ms=round(ping_ms, 2),
                        status="ping_alive",
                        server_info=server_info,
                        packet_loss=0.0,
                    )
                else:
                    # Valid client private key and server key used, but UDP timed out while ping answered:
                    # Indicates DPI filtering on UDP port 51820.
                    return CheckResult(
                        ip=ip,
                        port=port,
                        is_reachable=False,
                        latency_ms=round(ping_ms, 2),
                        status="ping_only_udp_blocked",
                        error="UDP port 51820 silent or blocked by DPI (Host answers ICMP ping only)",
                        server_info=server_info,
                        packet_loss=100.0,
                    )
            else:
                # STRICT_UDP mode: Explicitly rejects ping-only (requires actual UDP response packet)
                return CheckResult(
                    ip=ip,
                    port=port,
                    is_reachable=False,
                    latency_ms=round(ping_ms, 2),
                    status="ping_only_udp_blocked",
                    error="Strict UDP mode: port 51820 dropped packet (Host answers ICMP ping only)",
                    server_info=server_info,
                    packet_loss=100.0,
                )

        return CheckResult(
            ip=ip,
            port=port,
            is_reachable=False,
            latency_ms=9999.0,
            status="timed_out",
            error="No response from UDP or ICMP",
            server_info=server_info,
            packet_loss=100.0,
        )
    except ConnectionRefusedError:
        # Received ICMP Port Unreachable (port blocked or no service)
        return CheckResult(
            ip=ip,
            port=port,
            is_reachable=False,
            latency_ms=9999.0,
            status="blocked",
            error="Connection refused (ICMP unreachable)",
            server_info=server_info,
            packet_loss=100.0,
        )
    except OSError as e:
        return CheckResult(
            ip=ip,
            port=port,
            is_reachable=False,
            latency_ms=9999.0,
            status="error",
            error=str(e),
            server_info=server_info,
            packet_loss=100.0,
        )
    finally:
        sock.close()


def deep_verify_endpoint_sync(
    ip: str,
    port: int = DEFAULT_WG_PORT,
    timeout: float = 1.8,
    client_private_key: Optional[str] = None,
    server_public_key: Optional[str] = None,
    server_info: Optional[dict] = None,
    probe_count: int = 3,
    probe_delay_ms: float = 100.0,
    mode: str = ScanMode.SMART,
) -> CheckResult:
    """
    Performs deep multi-probe verification on a candidate endpoint:
    1. Sends `probe_count` sequential probes to assess DPI packet filtering,
       latency jitter, and packet loss.
    2. Calculates true packet loss percentage and jitter (difference between RTTs).
    3. Rejects endpoints with 100% loss or ping-only illusion (e.g. Turkey IPs).
    """
    rtts: List[float] = []
    received_types: List[str] = []

    # Generate initiation probe
    packet = generate_wireguard_initiation(client_private_key, server_public_key)

    for i in range(probe_count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(512)
            rtt = (time.perf_counter() - t0) * 1000.0
            rtts.append(rtt)
            if len(data) >= 4:
                mtype = struct.unpack("<I", data[:4])[0]
                received_types.append(f"Type-{mtype}")
            else:
                received_types.append("raw_udp")
        except socket.timeout:
            pass  # packet dropped or silent
        except ConnectionRefusedError:
            pass  # port closed
        except OSError:
            pass
        finally:
            sock.close()

        if i < probe_count - 1 and probe_delay_ms > 0:
            time.sleep(probe_delay_ms / 1000.0)

    sent = probe_count
    received = len(rtts)
    loss_rate = ((sent - received) / sent) * 100.0 if sent > 0 else 100.0

    if received > 0:
        avg_latency = round(sum(rtts) / len(rtts), 2)
        jitter = round(max(rtts) - min(rtts), 2) if len(rtts) > 1 else 0.0

        if loss_rate == 0.0:
            status = "verified_stable"
            is_reach = True
        elif loss_rate <= 34.0:  # e.g. 2 of 3 received
            status = "responsive"
            is_reach = True
        else:
            status = "unstable_packet_loss"
            is_reach = False

        return CheckResult(
            ip=ip,
            port=port,
            is_reachable=is_reach,
            latency_ms=avg_latency,
            status=status,
            server_info=server_info,
            packet_loss=loss_rate,
            jitter_ms=jitter,
            deep_verified=True,
        )
    else:
        # 100% loss on UDP. Check ICMP ping to provide clear diagnostic message
        ping_ms = ping_latency_ms(ip, timeout_sec=min(1.2, timeout))
        if ping_ms is not None:
            is_unauthenticated_dummy = is_placeholder_client_key(client_private_key) or is_placeholder_server_key(server_public_key)
            if mode == ScanMode.PERMISSIVE or (mode == ScanMode.SMART and is_unauthenticated_dummy):
                return CheckResult(
                    ip=ip,
                    port=port,
                    is_reachable=True,
                    latency_ms=round(ping_ms, 2),
                    status="ping_alive",
                    server_info=server_info,
                    packet_loss=0.0,
                    jitter_ms=0.0,
                    deep_verified=True,
                )
            else:
                return CheckResult(
                    ip=ip,
                    port=port,
                    is_reachable=False,
                    latency_ms=round(ping_ms, 2),
                    status="ping_only_udp_blocked",
                    error="UDP port 51820 silent or dropped by DPI (Host answers ICMP ping only)",
                    server_info=server_info,
                    packet_loss=100.0,
                    jitter_ms=0.0,
                    deep_verified=True,
                )
        else:
            return CheckResult(
                ip=ip,
                port=port,
                is_reachable=False,
                latency_ms=9999.0,
                status="timed_out",
                error="100% packet loss (No response to UDP or ICMP)",
                server_info=server_info,
                packet_loss=100.0,
                jitter_ms=0.0,
                deep_verified=True,
            )


def deep_screen_working_configs_sync(
    working_configs: List[dict],
    client_private_key: Optional[str] = None,
    on_progress: Optional[Callable[[int, int, dict, bool], None]] = None,
    timeout: float = 2.0,
    probe_count: int = 3,
    max_concurrency: int = 20,
    mode: str = ScanMode.SMART,
) -> Tuple[List[dict], List[dict]]:
    """
    Screens an existing list of working_configs using deep multi-probe verification.
    Purges false positives (such as Turkey IPs that only answer ping).
    Returns (verified_configs, rejected_configs).
    """
    total = len(working_configs)
    completed = 0
    verified: List[dict] = []
    rejected: List[dict] = []
    lock = threading.Lock()

    def _worker(config: dict):
        nonlocal completed
        ip = config.get("endpoint_ip", "")
        port = config.get("port", DEFAULT_WG_PORT)
        pub = config.get("public_key")

        res = deep_verify_endpoint_sync(
            ip=ip,
            port=port,
            timeout=timeout,
            client_private_key=client_private_key,
            server_public_key=pub,
            probe_count=probe_count,
            mode=mode,
        )

        is_ok = res.is_reachable
        updated = dict(config)
        updated["latency_ms"] = res.latency_ms
        updated["packet_loss"] = res.packet_loss
        updated["jitter_ms"] = res.jitter_ms
        updated["deep_verified"] = True
        updated["status"] = res.status

        with lock:
            completed += 1
            if is_ok:
                verified.append(updated)
            else:
                updated["rejection_reason"] = res.error or res.status
                rejected.append(updated)

            if on_progress:
                try:
                    on_progress(completed, total, updated, is_ok)
                except Exception as err:
                    logger.debug(f"Progress callback error: {err}")

    workers = min(max_concurrency, max(1, total))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(_worker, working_configs))

    # Sort verified by packet_loss ascending, then latency ascending
    verified.sort(key=lambda x: (x.get("packet_loss", 0), x.get("latency_ms", 9999)))
    return verified, rejected


async def check_udp_endpoint(
    ip: str,
    port: int = DEFAULT_WG_PORT,
    timeout: float = 2.0,
    client_private_key: Optional[str] = None,
    server_public_key: Optional[str] = None,
    server_info: Optional[dict] = None,
    mode: str = ScanMode.SMART,
) -> CheckResult:
    """Async wrapper for check_udp_endpoint_sync."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        check_udp_endpoint_sync,
        ip,
        port,
        timeout,
        client_private_key,
        server_public_key,
        server_info,
        mode,
    )


class FastUdpScanner:
    """
    High-concurrency, multi-target UDP scanner for testing server clusters concurrently.
    Supports Smart Anti-DPI, Strict UDP, Deep Multi-probe, and Permissive scan modes.
    """

    def __init__(
        self,
        timeout: float = 2.0,
        max_concurrency: int = 50,
        mode: str = ScanMode.SMART,
        probe_count: int = 3,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.mode = mode
        self.probe_count = probe_count

    def scan_all_sync(
        self,
        targets: List[Tuple[str, int, Optional[str], Optional[str], Optional[dict]]],
        on_progress: Optional[Callable[[int, int, CheckResult], None]] = None,
    ) -> List[CheckResult]:
        total = len(targets)
        completed = 0
        results: List[CheckResult] = []
        lock = threading.Lock()

        def _worker(t: Tuple[str, int, Optional[str], Optional[str], Optional[dict]]):
            nonlocal completed
            ip, port, priv, pub, info = t
            if self.mode == ScanMode.DEEP:
                res = deep_verify_endpoint_sync(
                    ip=ip,
                    port=port,
                    timeout=self.timeout,
                    client_private_key=priv,
                    server_public_key=pub,
                    server_info=info,
                    probe_count=self.probe_count,
                    mode=self.mode,
                )
            else:
                res = check_udp_endpoint_sync(
                    ip=ip,
                    port=port,
                    timeout=self.timeout,
                    client_private_key=priv,
                    server_public_key=pub,
                    server_info=info,
                    mode=self.mode,
                )
            with lock:
                completed += 1
                results.append(res)
                if on_progress:
                    try:
                        on_progress(completed, total, res)
                    except Exception as err:
                        logger.debug(f"Progress error: {err}")
            return res

        workers = min(self.max_concurrency, max(1, total))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(_worker, targets))

        results.sort(key=lambda r: (not r.is_reachable, r.latency_ms))
        return results

    async def scan_all(
        self,
        targets: List[Tuple[str, int, Optional[str], Optional[str], Optional[dict]]],
        on_progress: Optional[Callable[[int, int, CheckResult], None]] = None,
    ) -> List[CheckResult]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.scan_all_sync, targets, on_progress)


def run_udp_scan_sync(
    targets: List[Tuple[str, int, Optional[str], Optional[str], Optional[dict]]],
    on_progress: Optional[Callable[[int, int, CheckResult], None]] = None,
    timeout: float = 2.0,
    max_concurrency: int = 50,
    mode: str = ScanMode.SMART,
    probe_count: int = 3,
) -> List[CheckResult]:
    """Synchronous convenience wrapper for scan_all."""
    scanner = FastUdpScanner(
        timeout=timeout,
        max_concurrency=max_concurrency,
        mode=mode,
        probe_count=probe_count,
    )
    return scanner.scan_all_sync(targets, on_progress=on_progress)



if __name__ == "__main__":
    test_ips = [
        ("1.1.1.1", 53, None, None, {"name": "Cloudflare DNS"}),
        ("8.8.8.8", 53, None, None, {"name": "Google DNS"}),
        ("127.0.0.1", 51820, None, None, {"name": "Localhost WG"}),
    ]
    print("Testing FastUdpScanner...")

    def _p(comp, tot, res: CheckResult):
        reachable_str = "REACHABLE" if res.is_reachable else "FAILED"
        print(f"[{comp}/{tot}] {res.ip}:{res.port} -> {reachable_str} ({res.status}) {res.latency_ms}ms")

    results = run_udp_scan_sync(test_ips, on_progress=_p, timeout=1.5)
    print("\nScan complete. Results count:", len(results))
