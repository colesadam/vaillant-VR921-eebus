#!/usr/bin/env python3
"""query_vr921.py

CLI and library for connecting to and querying the Vaillant VR921 gateway
over EEBUS (SHIP / SPINE).
"""

import argparse
import asyncio
from collections import OrderedDict
import json
import logging
import os
import socket
import ssl
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple
import websockets
from cryptography import x509
from zeroconf import IPVersion, ServiceListener
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("query_vr921")

DEFAULT_CERT_DIR = os.getenv("EEBUS_CERT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs"))


class MsgCounter:
    def __init__(self, start: int = 1):
        self._value = start
        self._lock = asyncio.Lock()

    async def next(self) -> int:
        async with self._lock:
            value = self._value
            self._value += 1
            return value


# ---------------------------------------------------------------------------
# EEBUS JSON encoding / decoding helpers
# ---------------------------------------------------------------------------

def json_into_eebus_json(payload: Any) -> str:
    def _to_eebus(value: Any) -> Any:
        if isinstance(value, (dict, OrderedDict)):
            return [{k: _to_eebus(v)} for k, v in value.items()]
        if isinstance(value, list):
            return [_to_eebus(v) for v in value]
        return value

    converted = _to_eebus(payload)
    text = json.dumps(converted, separators=(",", ":"), ensure_ascii=False)
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def json_text_into_eebus_json(payload_text: str) -> str:
    parsed = json.loads(payload_text, object_pairs_hook=OrderedDict)
    return json_into_eebus_json(parsed)


def json_from_eebus_json(payload_text: str) -> str:
    b = payload_text.encode("utf-8", errors="ignore")
    b = (
        b.replace(b"[{", b"{")
        .replace(b"},{", b",")
        .replace(b"}]", b"}")
        .replace(b"[]", b"{}")
        .strip(b"\x00")
    )
    return b.decode("utf-8", errors="ignore")


def _first_cmd(payload_cmd: Any) -> Optional[Dict[str, Any]]:
    if isinstance(payload_cmd, dict):
        return payload_cmd
    if not isinstance(payload_cmd, list) or not payload_cmd:
        return None
    first = payload_cmd[0]
    if isinstance(first, list) and first:
        inner = first[0]
        return inner if isinstance(inner, dict) else None
    return first if isinstance(first, dict) else None


def _parse_spine_datagram(
    message: Dict[str, Any]
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    data = message.get("data")
    if not isinstance(data, dict):
        return None
    payload = data.get("payload")
    if not isinstance(payload, dict):
        return None
    datagram = payload.get("datagram")
    if not isinstance(datagram, dict):
        return None
    header = datagram.get("header")
    if not isinstance(header, dict):
        return None
    d_payload = datagram.get("payload")
    if not isinstance(d_payload, dict):
        return None
    cmd = _first_cmd(d_payload.get("cmd"))
    if cmd is None:
        return None
    return header, cmd


def _make_spine_reply_addresses(
    request_header: Dict[str, Any], *, local_device_address: str
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    address_destination = request_header.get("addressSource")
    address_source = request_header.get("addressDestination")
    if not isinstance(address_destination, dict) or not isinstance(address_source, dict):
        return None
    address_source = dict(address_source)
    if "device" in address_source:
        address_source["device"] = local_device_address
    return address_source, dict(address_destination)


# ---------------------------------------------------------------------------
# mDNS Discovery
# ---------------------------------------------------------------------------

class MDNSHandler(ServiceListener):
    def __init__(self, local_ski: str):
        self.local_ski = local_ski
        self.target_info: Optional[AsyncServiceInfo] = None
        self.found_event = asyncio.Event()

    def add_service(self, zc, type_, name):
        asyncio.ensure_future(self.async_add_service(zc, type_, name))

    def update_service(self, zc, type_, name):
        asyncio.ensure_future(self.async_add_service(zc, type_, name))

    def remove_service(self, zc, type_, name):
        pass

    async def async_add_service(self, zc, type_, name):
        info = await zc.async_get_service_info(type_, name)
        if info and b"ski" in info.properties:
            try:
                remote_ski = info.properties.get(b"ski", b"").decode("utf-8")
            except Exception:
                remote_ski = ""
            if remote_ski and remote_ski == self.local_ski:
                return
            if not self.target_info:
                self.target_info = info
                self.found_event.set()


# ---------------------------------------------------------------------------
# VR921 Client
# ---------------------------------------------------------------------------

class VR921Client:
    """Async client for SHIP connection and SPINE queries against a Vaillant VR921."""

    def __init__(
        self,
        cert_dir: str = DEFAULT_CERT_DIR,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ):
        self.cert_dir = cert_dir
        self.cert_file = os.path.join(cert_dir, "cert.pem")
        self.key_file = os.path.join(cert_dir, "key.pem")
        self.host = host
        self.port = port

        self.ski = self._load_certificate_ski()
        self.local_ship_id = f"python-{self.ski[:12]}"
        self.local_device_address = f"d:_i:1_{self.local_ship_id}"
        self.msg_counter = MsgCounter(start=1)

        self.aiozc: Optional[AsyncZeroconf] = None
        self.ws: Optional[ Any ] = None

        self.remote_device_address: Optional[str] = None
        self.remote_discovery_data: Optional[Dict[str, Any]] = None
        self.remote_use_case_data: Optional[Dict[str, Any]] = None

    def _load_certificate_ski(self) -> str:
        if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file)):
            raise FileNotFoundError(
                f"Certificate or key not found in {self.cert_dir}. "
                "Existing paired cert.pem and key.pem are required."
            )
        with open(self.cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        ski = (
            cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            .value.digest.hex()
        )
        logger.info("Loaded paired certificate (SKI: %s)", ski)
        return ski

    @staticmethod
    def _get_local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    async def setup_mdns_and_discover(self, timeout: float = 15.0) -> Tuple[str, int]:
        local_ip = self._get_local_ip()
        self.aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        handler = MDNSHandler(self.ski)

        desc = {"txtvers": "1", "path": "/ship/", "ski": self.ski, "register": "true"}
        service_name = f"Python-{self.ski[:6]}-{uuid.uuid4().hex[:4]}._ship._tcp.local."
        info = AsyncServiceInfo(
            "_ship._tcp.local.",
            service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=54886,
            properties=desc,
        )
        await self.aiozc.async_register_service(info)
        AsyncServiceBrowser(self.aiozc.zeroconf, "_ship._tcp.local.", handler)

        if self.host and self.port:
            logger.info("Using explicit target %s:%d", self.host, self.port)
            return self.host, self.port

        logger.info("Searching for VR921 via mDNS (_ship._tcp.local.)...")
        try:
            await asyncio.wait_for(handler.found_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"mDNS discovery timed out after {timeout}s")

        assert handler.target_info is not None
        target_ip = socket.inet_ntoa(handler.target_info.addresses[0])
        target_port = int(handler.target_info.port or 12480)
        remote_ski = handler.target_info.properties.get(b"ski", b"").decode("utf-8", errors="ignore")
        logger.info("Discovered VR921 at %s:%d (remote SKI: %s)", target_ip, target_port, remote_ski)
        return target_ip, target_port

    async def send_ship_json(self, data: Dict[str, Any]) -> None:
        assert self.ws is not None
        eebus_text = json_into_eebus_json(data)
        await self.ws.send(b"\x01" + eebus_text.encode("utf-8"))

    async def send_ship_data(self, data: Dict[str, Any]) -> None:
        assert self.ws is not None
        spine_std = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        spine_eebus = json_text_into_eebus_json(spine_std)
        payload_placeholder = '{"place":"holder"}'
        ship_std_obj = {
            "data": {
                "header": {"protocolId": "ee1.0"},
                "payload": json.loads(payload_placeholder),
            }
        }
        ship_std = json.dumps(ship_std_obj, separators=(",", ":"), ensure_ascii=False)
        ship_eebus = json_text_into_eebus_json(ship_std).replace(
            f"[{payload_placeholder}]", spine_eebus
        )
        await self.ws.send(b"\x02" + ship_eebus.encode("utf-8"))

    async def perform_ship_handshake(self) -> bool:
        assert self.ws is not None
        await self.ws.send(b"\x00\x00")
        _init_ack = await self.ws.recv()

        logger.info("[SHIP] Sending connectionHello (phase: ready)...")
        await self.send_ship_json(
            {"connectionHello": {"phase": "ready", "waiting": 60000}}
        )

        state = "WAITING_HELLO"
        last_pending_sent = time.monotonic()

        while True:
            raw_msg = await self.ws.recv()
            if not isinstance(raw_msg, bytes) or len(raw_msg) < 2:
                continue
            if raw_msg[0] != 0x01:
                continue

            payload_text = json_from_eebus_json(
                raw_msg[1:].decode("utf-8", errors="ignore")
            )
            try:
                msg = json.loads(payload_text)
            except json.JSONDecodeError:
                continue

            if "connectionHello" in msg and state == "WAITING_HELLO":
                hello = msg.get("connectionHello") or {}
                phase = hello.get("phase")
                if phase == "pending":
                    logger.info("[SHIP] Status PENDING - waiting for approval/session cleanup...")
                    now = time.monotonic()
                    if hello.get("prolongationRequest") or (now - last_pending_sent > 5.0):
                        await self.send_ship_json(
                            {"connectionHello": {"phase": "pending", "waiting": 60000}}
                        )
                        last_pending_sent = now
                elif phase == "ready":
                    logger.info("[SHIP] ConnectionHello READY -> negotiating protocol...")
                    await self.send_ship_json(
                        {
                            "messageProtocolHandshake": {
                                "handshakeType": "announceMax",
                                "version": {"major": 1, "minor": 0},
                                "formats": {"format": ["JSON-UTF8"]},
                            }
                        }
                    )
                    state = "WAITING_PROTOCOL"
                elif phase == "aborted":
                    logger.error("[SHIP] ConnectionHello aborted by remote device: %s", hello)
                    return False

            elif "messageProtocolHandshake" in msg and state == "WAITING_PROTOCOL":
                handshake = msg.get("messageProtocolHandshake") or {}
                if handshake.get("handshakeType") != "select":
                    logger.error("[SHIP] Unexpected protocol handshake: %s", handshake)
                    return False
                await self.send_ship_json(
                    {
                        "messageProtocolHandshake": {
                            "handshakeType": "select",
                            "version": {"major": 1, "minor": 0},
                            "formats": {"format": ["JSON-UTF8"]},
                        }
                    }
                )
                await self.send_ship_json(
                    {"connectionPinState": {"pinState": "none"}}
                )
                state = "WAITING_PIN"

            elif "connectionPinState" in msg and state == "WAITING_PIN":
                await self.send_ship_json({"accessMethodsRequest": {}})
                state = "WAITING_ACCESS"

            elif "accessMethodsRequest" in msg and state == "WAITING_ACCESS":
                await self.send_ship_json(
                    {"accessMethods": {"id": self.local_ship_id}}
                )

            elif "accessMethods" in msg and state == "WAITING_ACCESS":
                remote_id = (msg.get("accessMethods") or {}).get("id")
                logger.info("[SHIP] Handshake complete! Remote SHIP ID: %s", remote_id)
                return True

    # -----------------------------------------------------------------------
    # SPINE helpers
    # -----------------------------------------------------------------------

    def build_local_detailed_discovery(self) -> Dict[str, Any]:
        return {
            "specificationVersionList": {"specificationVersion": ["1.3.0"]},
            "deviceInformation": {
                "description": {
                    "deviceAddress": {"device": self.local_device_address},
                    "deviceType": "EnergyManagementSystem",
                    "featureSet": "smart",
                    "brandName": "Python",
                    "deviceModel": "SHIP-Layer1",
                    "serialNumber": self.local_device_address,
                    "deviceCode": "python-ship",
                }
            },
            "entityInformation": [
                {
                    "description": {
                        "entityAddress": {"entity": [0]},
                        "entityType": "DeviceInformation",
                        "description": "DeviceInformation",
                    }
                },
                {
                    "description": {
                        "entityAddress": {"entity": [1]},
                        "entityType": "CEM",
                        "description": "CEM",
                    }
                },
            ],
            "featureInformation": [
                {
                    "description": {
                        "featureAddress": {"entity": [0], "feature": 0},
                        "featureType": "NodeManagement",
                        "role": "special",
                        "description": "NodeManagement",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [0], "feature": 1},
                        "featureType": "DeviceClassification",
                        "role": "server",
                        "description": "DeviceClassification",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [1], "feature": 1},
                        "featureType": "Measurement",
                        "role": "client",
                        "description": "MeasurementClient",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [1], "feature": 2},
                        "featureType": "Sensing",
                        "role": "client",
                        "description": "SensingClient",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [1], "feature": 3},
                        "featureType": "HVAC",
                        "role": "client",
                        "description": "HVACClient",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [1], "feature": 4},
                        "featureType": "Setpoint",
                        "role": "client",
                        "description": "SetpointClient",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [1], "feature": 5},
                        "featureType": "DeviceClassification",
                        "role": "client",
                        "description": "DeviceClassificationClient",
                    }
                },
                {
                    "description": {
                        "featureAddress": {"entity": [1], "feature": 6},
                        "featureType": "SmartEnergyManagementPs",
                        "role": "client",
                        "description": "SmartEnergyManagementPsClient",
                    }
                },
            ],
        }

    async def send_spine_datagram(
        self,
        *,
        address_source: Dict[str, Any],
        address_destination: Dict[str, Any],
        cmd_classifier: str,
        cmd: Dict[str, Any],
        ack_request: Optional[bool] = None,
        msg_counter_reference: Optional[int] = None,
        specification_version: str = "1.3.0",
    ) -> int:
        counter = await self.msg_counter.next()
        header: Dict[str, Any] = {
            "specificationVersion": specification_version,
            "addressSource": address_source,
            "addressDestination": address_destination,
            "msgCounter": counter,
        }
        if msg_counter_reference is not None:
            header["msgCounterReference"] = msg_counter_reference
        header["cmdClassifier"] = cmd_classifier
        if ack_request is not None:
            header["ackRequest"] = ack_request

        datagram = {
            "datagram": {
                "header": header,
                "payload": {"cmd": [cmd]},
            }
        }
        await self.send_ship_data(datagram)
        return counter

    async def send_spine_read(
        self,
        *,
        src_entity: List[int],
        src_feature: int,
        dst_entity: List[int],
        dst_feature: int,
        cmd: Dict[str, Any],
        ack_request: bool = True,
    ) -> int:
        if not self.remote_device_address:
            raise RuntimeError("remote_device_address is not yet known")
        src = {
            "device": self.local_device_address,
            "entity": src_entity,
            "feature": src_feature,
        }
        dst = {
            "device": self.remote_device_address,
            "entity": dst_entity,
            "feature": dst_feature,
        }
        return await self.send_spine_datagram(
            address_source=src,
            address_destination=dst,
            cmd_classifier="read",
            cmd=cmd,
            ack_request=ack_request,
        )

    async def send_spine_result_ok(self, request_header: Dict[str, Any]) -> None:
        ref = request_header.get("msgCounter")
        if ref is None:
            return
        addresses = _make_spine_reply_addresses(
            request_header, local_device_address=self.local_device_address
        )
        if addresses is None:
            return
        address_source, address_destination = addresses
        await self.send_spine_datagram(
            address_source=address_source,
            address_destination=address_destination,
            cmd_classifier="result",
            cmd={"resultData": {"errorNumber": 0}},
            msg_counter_reference=ref,
            specification_version=request_header.get("specificationVersion", "1.3.0"),
        )

    async def handle_incoming_spine_read(
        self, request_header: Dict[str, Any], cmd: Dict[str, Any]
    ) -> None:
        ref = request_header.get("msgCounter")
        if ref is None:
            return
        addresses = _make_spine_reply_addresses(
            request_header, local_device_address=self.local_device_address
        )
        if addresses is None:
            return
        address_source, address_destination = addresses
        spec_ver = request_header.get("specificationVersion", "1.3.0")

        if "nodeManagementDetailedDiscoveryData" in cmd:
            await self.send_spine_datagram(
                address_source=address_source,
                address_destination=address_destination,
                cmd_classifier="reply",
                cmd={
                    "nodeManagementDetailedDiscoveryData": self.build_local_detailed_discovery(),
                    "function": "nodeManagementDetailedDiscoveryData",
                },
                msg_counter_reference=ref,
                specification_version=spec_ver,
            )
        elif "deviceClassificationManufacturerData" in cmd:
            await self.send_spine_datagram(
                address_source=address_source,
                address_destination=address_destination,
                cmd_classifier="reply",
                cmd={
                    "deviceClassificationManufacturerData": {
                        "deviceName": "SHIP Python Client",
                        "deviceCode": "python-ship",
                        "brandName": "Python",
                        "powerSource": "mains3Phase",
                        "serialNumber": self.local_device_address,
                    }
                },
                msg_counter_reference=ref,
                specification_version=spec_ver,
            )
        elif "deviceClassificationUserData" in cmd:
            await self.send_spine_datagram(
                address_source=address_source,
                address_destination=address_destination,
                cmd_classifier="reply",
                cmd={
                    "deviceClassificationUserData": {
                        "deviceName": "SHIP Python Client"
                    }
                },
                msg_counter_reference=ref,
                specification_version=spec_ver,
            )

    async def connect_and_discover(self, timeout: float = 20.0, max_attempts: int = 3) -> None:
        """Connect over WebSocket, complete SHIP handshake, and run SPINE node discovery."""
        target_ip, target_port = await self.setup_mdns_and_discover(timeout=timeout)

        ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        ssl_ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5@SECLEVEL=1")

        uri = f"wss://{target_ip}:{target_port}/ship/"

        for attempt in range(1, max_attempts + 1):
            logger.info("Connecting to %s (attempt %d/%d)...", uri, attempt, max_attempts)
            try:
                self.ws = await websockets.connect(
                    uri,
                    ssl=ssl_ctx,
                    subprotocols=["ship"],  # type: ignore[arg-type]
                    open_timeout=timeout,
                    ping_interval=None,
                    ping_timeout=None,
                    close_timeout=5,
                )
                ok = await asyncio.wait_for(self.perform_ship_handshake(), timeout=timeout)
                if ok:
                    break
                raise ConnectionError("SHIP handshake returned False")
            except Exception as exc:
                if self.ws is not None:
                    try:
                        await self.ws.close()
                    except Exception:
                        pass
                    self.ws = None
                if attempt < max_attempts:
                    logger.info(
                        "[SHIP] Handshake closed (%s) - likely displacing active service session. Retrying in 1.5s...",
                        exc,
                    )
                    await asyncio.sleep(1.5)
                else:
                    raise

        assert self.ws is not None
        logger.info("[SPINE] Waiting for initial SPINE node discovery exchange...")
        discovery_requested = False
        start = time.monotonic()

        while (time.monotonic() - start) < timeout:
            raw = await asyncio.wait_for(
                self.ws.recv(), timeout=max(1.0, timeout - (time.monotonic() - start))
            )
            if not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != 0x02:
                continue

            payload_text = json_from_eebus_json(raw[1:].decode("utf-8", errors="ignore"))
            msg = json.loads(payload_text)
            parsed = _parse_spine_datagram(msg)
            if parsed is None:
                continue

            hdr, cmd = parsed
            cmd_classifier = hdr.get("cmdClassifier")

            if self.remote_device_address is None:
                addr_src = hdr.get("addressSource")
                if isinstance(addr_src, dict):
                    dev = addr_src.get("device")
                    if isinstance(dev, str) and dev:
                        self.remote_device_address = dev
                        logger.info("[SPINE] Remote device address: %s", self.remote_device_address)

            if self.remote_device_address and not discovery_requested:
                discovery_requested = True
                await self.send_spine_read(
                    src_entity=[0],
                    src_feature=0,
                    dst_entity=[0],
                    dst_feature=0,
                    cmd={"nodeManagementDetailedDiscoveryData": {}},
                )

            if cmd_classifier != "result":
                await self.send_spine_result_ok(hdr)

            if cmd_classifier == "read":
                await self.handle_incoming_spine_read(hdr, cmd)
            elif cmd_classifier == "reply":
                if "nodeManagementDetailedDiscoveryData" in cmd:
                    self.remote_discovery_data = cmd["nodeManagementDetailedDiscoveryData"]
                    logger.info("[SPINE] Received nodeManagementDetailedDiscoveryData")
                    await self.send_spine_read(
                        src_entity=[0],
                        src_feature=0,
                        dst_entity=[0],
                        dst_feature=0,
                        cmd={"nodeManagementUseCaseData": {}},
                    )
                elif "nodeManagementUseCaseData" in cmd:
                    self.remote_use_case_data = cmd["nodeManagementUseCaseData"]
                    logger.info("[SPINE] Received nodeManagementUseCaseData")
                    return

    async def query_functions(
        self,
        queries: List[Tuple[List[int], int, List[int], int, str]],
        wait_seconds: float = 4.0,
    ) -> List[Dict[str, Any]]:
        """Send SPINE reads for (src_ent, src_feat, dst_ent, dst_feat, func_name) and collect replies."""
        assert self.ws is not None
        sent_counters: Dict[int, Tuple[List[int], int, str]] = {}
        for src_ent, src_feat, dst_ent, dst_feat, func_name in queries:
            cnt = await self.send_spine_read(
                src_entity=src_ent,
                src_feature=src_feat,
                dst_entity=dst_ent,
                dst_feature=dst_feat,
                cmd={func_name: {}},
            )
            sent_counters[cnt] = (dst_ent, dst_feat, func_name)

        results: List[Dict[str, Any]] = []
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=max(0.2, remaining))
            except asyncio.TimeoutError:
                break
            if not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != 0x02:
                continue

            payload_text = json_from_eebus_json(raw[1:].decode("utf-8", errors="ignore"))
            try:
                msg = json.loads(payload_text)
            except Exception:
                continue
            parsed = _parse_spine_datagram(msg)
            if parsed is None:
                continue

            hdr, cmd = parsed
            cmd_classifier = hdr.get("cmdClassifier")

            if cmd_classifier != "result":
                await self.send_spine_result_ok(hdr)

            if cmd_classifier == "read":
                await self.handle_incoming_spine_read(hdr, cmd)
            elif cmd_classifier in ("reply", "result", "notify"):
                ref = hdr.get("msgCounterReference")
                results.append(
                    {
                        "classifier": cmd_classifier,
                        "source": hdr.get("addressSource"),
                        "msgCounterReference": ref,
                        "query": sent_counters.get(ref) if isinstance(ref, int) else None,
                        "cmd": cmd,
                    }
                )
        return results

    async def wait_for_result(self, target_counter: int, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Wait for a SPINE result referencing target_counter (handling intermediate reads/replies)."""
        assert self.ws is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=max(0.2, remaining))
            except asyncio.TimeoutError:
                break
            if not isinstance(raw, bytes) or len(raw) < 2 or raw[0] != 0x02:
                continue

            payload_text = json_from_eebus_json(raw[1:].decode("utf-8", errors="ignore"))
            try:
                msg = json.loads(payload_text)
            except Exception:
                continue
            parsed = _parse_spine_datagram(msg)
            if parsed is None:
                continue

            hdr, cmd = parsed
            cmd_classifier = hdr.get("cmdClassifier")

            if cmd_classifier != "result":
                await self.send_spine_result_ok(hdr)

            if cmd_classifier == "read":
                await self.handle_incoming_spine_read(hdr, cmd)
            elif cmd_classifier == "result":
                ref = hdr.get("msgCounterReference")
                if ref == target_counter:
                    return cmd.get("resultData", cmd)
        return None

    @staticmethod
    def _scaled_number_to_float(val: Any) -> Optional[float]:
        """Convert SPINE ScaledNumber {'number': N, 'scale': S} to float."""
        if not isinstance(val, dict) or "number" not in val:
            return None
        num = float(val["number"])
        scale = int(val.get("scale", 0))
        return round(num * (10 ** scale), 4)

    @staticmethod
    def _float_to_scaled_number(value: float, step: float = 0.5) -> Dict[str, int]:
        """Convert float temperature/setpoint into SPINE ScaledNumber {'number': int, 'scale': int}."""
        rounded = round(round(value / step) * step, 2)
        if abs(rounded - round(rounded)) < 1e-6:
            return {"number": int(round(rounded)), "scale": 0}
        return {"number": int(round(rounded * 10)), "scale": -1}

    async def request_binding(
        self,
        *,
        src_entity: List[int],
        src_feature: int,
        dst_entity: List[int],
        dst_feature: int,
        server_feature_type: str,
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """Send nodeManagementBindingRequestCall for a server feature and return resultData."""
        assert self.remote_device_address is not None
        src_nm = {"device": self.local_device_address, "entity": [0], "feature": 0}
        dst_nm = {"device": self.remote_device_address, "entity": [0], "feature": 0}
        bind_cmd = {
            "nodeManagementBindingRequestCall": {
                "bindingRequest": {
                    "clientAddress": {
                        "device": self.local_device_address,
                        "entity": src_entity,
                        "feature": src_feature,
                    },
                    "serverAddress": {
                        "device": self.remote_device_address,
                        "entity": dst_entity,
                        "feature": dst_feature,
                    },
                    "serverFeatureType": server_feature_type,
                }
            }
        }
        bind_cnt = await self.send_spine_datagram(
            address_source=src_nm,
            address_destination=dst_nm,
            cmd_classifier="call",
            cmd=bind_cmd,
            ack_request=True,
        )
        return await self.wait_for_result(bind_cnt, timeout=timeout)

    async def send_partial_write(
        self,
        *,
        src_entity: List[int],
        src_feature: int,
        dst_entity: List[int],
        dst_feature: int,
        function_name: str,
        payload: Dict[str, Any],
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """Send a SPINE partial write command and wait for resultData."""
        assert self.remote_device_address is not None
        src = {"device": self.local_device_address, "entity": src_entity, "feature": src_feature}
        dst = {"device": self.remote_device_address, "entity": dst_entity, "feature": dst_feature}
        cmd = OrderedDict(
            [
                ("function", function_name),
                ("filter", [{"cmdControl": {"partial": {}}}]),
                (function_name, payload),
            ]
        )
        write_cnt = await self.send_spine_datagram(
            address_source=src,
            address_destination=dst,
            cmd_classifier="write",
            cmd=cmd,
            ack_request=True,
        )
        return await self.wait_for_result(write_cnt, timeout=timeout)

    async def set_heating_mode(self, mode_name: str) -> Dict[str, Any]:
        """Set heating circuit [5, 1, 1] Feature 9 operation mode ('auto', 'on', 'off', 'eco')."""
        mode_map = {"auto": 0, "on": 1, "off": 2, "eco": 3}
        mode_key = mode_name.strip().lower()
        if mode_key not in mode_map:
            raise ValueError(f"Unsupported mode '{mode_name}'. Choose from: {list(mode_map.keys())}")
        mode_id = mode_map[mode_key]

        assert self.remote_device_address is not None

        # 1. Read current state before change
        before_res = await self.query_functions(
            [([1], 3, [5, 1, 1], 9, "hvacSystemFunctionListData")], wait_seconds=2.0
        )
        before_state = next(
            (r["cmd"] for r in before_res if r["classifier"] == "reply"), None
        )
        logger.info("Before state: %s", json.dumps(before_state))

        # 2. Request binding on HVAC feature ([1]/3 -> [5, 1, 1]/9)
        bind_result = await self.request_binding(
            src_entity=[1],
            src_feature=3,
            dst_entity=[5, 1, 1],
            dst_feature=9,
            server_feature_type="HVAC",
        )
        logger.info("Binding result: %s", bind_result)

        # 3. Send SPINE partial write to [5, 1, 1] Feature 9
        write_payload = {
            "hvacSystemFunctionData": [
                {
                    "systemFunctionId": 0,
                    "currentOperationModeId": mode_id,
                }
            ]
        }
        write_result = await self.send_partial_write(
            src_entity=[1],
            src_feature=3,
            dst_entity=[5, 1, 1],
            dst_feature=9,
            function_name="hvacSystemFunctionListData",
            payload=write_payload,
        )
        logger.info("Write result: %s", write_result)

        # 4. Read state after change to verify
        await asyncio.sleep(1.0)
        after_res = await self.query_functions(
            [([1], 3, [5, 1, 1], 9, "hvacSystemFunctionListData")], wait_seconds=2.0
        )
        after_state = next(
            (r["cmd"] for r in after_res if r["classifier"] == "reply"), None
        )
        logger.info("After state: %s", json.dumps(after_state))

        return {
            "requested_mode": mode_key,
            "requested_mode_id": mode_id,
            "binding_result": bind_result,
            "write_result": write_result,
            "before": before_state,
            "after": after_state,
        }

    async def set_heating_setpoint(self, temperature: float, setpoint_id: int = 1) -> Dict[str, Any]:
        """Set heating room setpoint on [5, 1, 1] Feature 18 (setpointId 1=comfort/day, 3=eco/setback)."""
        if setpoint_id not in (1, 3):
            raise ValueError(f"Unsupported heating setpoint_id {setpoint_id} (expected 1 or 3)")
        if not (5.0 <= temperature <= 30.0):
            raise ValueError(f"Heating setpoint {temperature}°C out of valid range (5.0..30.0°C)")

        scaled = self._float_to_scaled_number(temperature, step=0.5)
        before_res = await self.query_functions(
            [([1], 4, [5, 1, 1], 18, "setpointListData")], wait_seconds=2.0
        )
        before_state = next((r["cmd"] for r in before_res if r["classifier"] == "reply"), None)

        bind_result = await self.request_binding(
            src_entity=[1],
            src_feature=4,
            dst_entity=[5, 1, 1],
            dst_feature=18,
            server_feature_type="Setpoint",
        )
        write_payload = {
            "setpointData": [
                {
                    "setpointId": setpoint_id,
                    "value": scaled,
                }
            ]
        }
        write_result = await self.send_partial_write(
            src_entity=[1],
            src_feature=4,
            dst_entity=[5, 1, 1],
            dst_feature=18,
            function_name="setpointListData",
            payload=write_payload,
        )
        await asyncio.sleep(1.0)
        after_res = await self.query_functions(
            [([1], 4, [5, 1, 1], 18, "setpointListData")], wait_seconds=2.0
        )
        after_state = next((r["cmd"] for r in after_res if r["classifier"] == "reply"), None)
        return {
            "setpoint_id": setpoint_id,
            "requested_temperature_c": temperature,
            "scaled_value": scaled,
            "binding_result": bind_result,
            "write_result": write_result,
            "before": before_state,
            "after": after_state,
        }

    async def cancel_heating_override(
        self,
        restore_mode: str = "auto",
        restore_day_temp: Optional[float] = None,
        pause_seconds: float = 2.0,
    ) -> Dict[str, Any]:
        """Cancel an active heating override (Quick Veto / manual / setpoint shift) on [5, 1, 1].

        On Vaillant VRC700 + VR921, Quick Veto is an internal controller override on top of 'auto'
        (operationModeId=0). Cycling operationModeId to 'off' (2) and then to restore_mode ('auto'=0
        or 'off'=2) forces VRC700 to drop Quick Veto immediately without touching the cloud API.
        Optionally also restores the baseline day/comfort setpoint (setpointId=1).
        """
        mode_map = {"auto": 0, "on": 1, "off": 2, "eco": 3}
        target_mode = restore_mode.strip().lower()
        if target_mode not in mode_map:
            raise ValueError(f"Unsupported restore_mode '{restore_mode}'. Choose from: {list(mode_map.keys())}")

        # 1. Snapshot current HVAC mode and setpoints
        before_res = await self.query_functions(
            [
                ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionListData"),
                ([1], 4, [5, 1, 1], 18, "setpointListData"),
            ],
            wait_seconds=2.5,
        )
        before_snapshot = [r["cmd"] for r in before_res if r["classifier"] == "reply"]

        # 2. Bind HVAC feature and switch to 'off' (modeId=2) to clear Quick Veto on VRC700
        bind_hvac = await self.request_binding(
            src_entity=[1],
            src_feature=3,
            dst_entity=[5, 1, 1],
            dst_feature=9,
            server_feature_type="HVAC",
        )
        off_write = await self.send_partial_write(
            src_entity=[1],
            src_feature=3,
            dst_entity=[5, 1, 1],
            dst_feature=9,
            function_name="hvacSystemFunctionListData",
            payload={"hvacSystemFunctionData": [{"systemFunctionId": 0, "currentOperationModeId": 2}]},
        )
        logger.info("Override cancel step 1 (mode -> off) result: %s", off_write)

        restore_mode_write = None
        if target_mode != "off":
            await asyncio.sleep(pause_seconds)
            restore_mode_write = await self.send_partial_write(
                src_entity=[1],
                src_feature=3,
                dst_entity=[5, 1, 1],
                dst_feature=9,
                function_name="hvacSystemFunctionListData",
                payload={
                    "hvacSystemFunctionData": [
                        {"systemFunctionId": 0, "currentOperationModeId": mode_map[target_mode]}
                    ]
                },
            )
            logger.info("Override cancel step 2 (mode -> %s) result: %s", target_mode, restore_mode_write)

        setpoint_restore_summary = None
        if restore_day_temp is not None:
            setpoint_restore_summary = await self.set_heating_setpoint(restore_day_temp, setpoint_id=1)

        await asyncio.sleep(1.0)
        after_res = await self.query_functions(
            [
                ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionListData"),
                ([1], 4, [5, 1, 1], 18, "setpointListData"),
            ],
            wait_seconds=2.5,
        )
        after_snapshot = [r["cmd"] for r in after_res if r["classifier"] == "reply"]

        return {
            "action": "cancel_heating_override",
            "restore_mode": target_mode,
            "restore_day_temp_c": restore_day_temp,
            "bind_hvac_result": bind_hvac,
            "step1_off_write_result": off_write,
            "step2_restore_mode_write_result": restore_mode_write,
            "setpoint_restore": setpoint_restore_summary,
            "before": before_snapshot,
            "after": after_snapshot,
        }

    async def set_dhw_mode(self, mode_name: str) -> Dict[str, Any]:
        """Set DHW circuit [4] Feature 9 operation mode ('auto', 'on', 'off')."""
        mode_map = {"auto": 0, "on": 1, "off": 2}
        mode_key = mode_name.strip().lower()
        if mode_key not in mode_map:
            raise ValueError(f"Unsupported DHW mode '{mode_name}'. Choose from: {list(mode_map.keys())}")
        mode_id = mode_map[mode_key]

        before_res = await self.query_functions(
            [([1], 3, [4], 9, "hvacSystemFunctionListData")], wait_seconds=2.0
        )
        before_state = next((r["cmd"] for r in before_res if r["classifier"] == "reply"), None)

        bind_result = await self.request_binding(
            src_entity=[1],
            src_feature=3,
            dst_entity=[4],
            dst_feature=9,
            server_feature_type="HVAC",
        )
        write_result = await self.send_partial_write(
            src_entity=[1],
            src_feature=3,
            dst_entity=[4],
            dst_feature=9,
            function_name="hvacSystemFunctionListData",
            payload={"hvacSystemFunctionData": [{"systemFunctionId": 0, "currentOperationModeId": mode_id}]},
        )
        await asyncio.sleep(1.0)
        after_res = await self.query_functions(
            [([1], 3, [4], 9, "hvacSystemFunctionListData")], wait_seconds=2.0
        )
        after_state = next((r["cmd"] for r in after_res if r["classifier"] == "reply"), None)
        return {
            "requested_dhw_mode": mode_key,
            "requested_dhw_mode_id": mode_id,
            "binding_result": bind_result,
            "write_result": write_result,
            "before": before_state,
            "after": after_state,
        }

    async def set_dhw_setpoint(self, temperature: float) -> Dict[str, Any]:
        """Set DHW target temperature on [4] Feature 18 (setpointId=1, range 35..70°C, step 1°C)."""
        if not (35.0 <= temperature <= 70.0):
            raise ValueError(f"DHW setpoint {temperature}°C out of valid range (35.0..70.0°C)")
        scaled = self._float_to_scaled_number(temperature, step=1.0)
        before_res = await self.query_functions(
            [([1], 4, [4], 18, "setpointListData")], wait_seconds=2.0
        )
        before_state = next((r["cmd"] for r in before_res if r["classifier"] == "reply"), None)

        bind_result = await self.request_binding(
            src_entity=[1],
            src_feature=4,
            dst_entity=[4],
            dst_feature=18,
            server_feature_type="Setpoint",
        )
        write_result = await self.send_partial_write(
            src_entity=[1],
            src_feature=4,
            dst_entity=[4],
            dst_feature=18,
            function_name="setpointListData",
            payload={"setpointData": [{"setpointId": 1, "value": scaled}]},
        )
        await asyncio.sleep(1.0)
        after_res = await self.query_functions(
            [([1], 4, [4], 18, "setpointListData")], wait_seconds=2.0
        )
        after_state = next((r["cmd"] for r in after_res if r["classifier"] == "reply"), None)
        return {
            "requested_dhw_temperature_c": temperature,
            "scaled_value": scaled,
            "binding_result": bind_result,
            "write_result": write_result,
            "before": before_state,
            "after": after_state,
        }

    async def set_dhw_boost(self, active: bool) -> Dict[str, Any]:
        """Start or cancel one-time DHW boost (overrunId=0) on [4] Feature 9."""
        status_str = "active" if active else "inactive"
        before_res = await self.query_functions(
            [
                ([1], 3, [4], 9, "hvacSystemFunctionListData"),
                ([1], 3, [4], 9, "hvacOverrunListData"),
            ],
            wait_seconds=2.0,
        )
        before_state = [r["cmd"] for r in before_res if r["classifier"] == "reply"]

        bind_result = await self.request_binding(
            src_entity=[1],
            src_feature=3,
            dst_entity=[4],
            dst_feature=9,
            server_feature_type="HVAC",
        )
        write_result = await self.send_partial_write(
            src_entity=[1],
            src_feature=3,
            dst_entity=[4],
            dst_feature=9,
            function_name="hvacOverrunListData",
            payload={"hvacOverrunData": [{"overrunId": 0, "overrunStatus": status_str}]},
        )
        await asyncio.sleep(1.0)
        after_res = await self.query_functions(
            [
                ([1], 3, [4], 9, "hvacSystemFunctionListData"),
                ([1], 3, [4], 9, "hvacOverrunListData"),
            ],
            wait_seconds=2.0,
        )
        after_state = [r["cmd"] for r in after_res if r["classifier"] == "reply"]
        return {
            "requested_overrun_status": status_str,
            "binding_result": bind_result,
            "write_result": write_result,
            "before": before_state,
            "after": after_state,
        }

    async def get_status_summary(self) -> Dict[str, Any]:
        """Query all key entities on the VR921 and return a structured human-friendly summary."""
        queries: List[Tuple[List[int], int, List[int], int, str]] = [
            ([1], 5, [3], 4, "deviceClassificationManufacturerData"),
            ([1], 5, [5, 1], 4, "deviceClassificationUserData"),
            ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionListData"),
            ([1], 4, [5, 1, 1], 18, "setpointListData"),
            ([1], 1, [5, 1, 1], 11, "measurementListData"),
            ([1], 3, [4], 9, "hvacSystemFunctionListData"),
            ([1], 3, [4], 9, "hvacOverrunListData"),
            ([1], 4, [4], 18, "setpointListData"),
            ([1], 1, [4], 11, "measurementListData"),
            ([1], 1, [6], 11, "measurementListData"),
            ([1], 1, [3, 1], 11, "measurementDescriptionListData"),
            ([1], 1, [3, 1], 11, "measurementListData"),
        ]
        responses = await self.query_functions(queries, wait_seconds=3.5)

        mode_names = {0: "auto", 1: "on", 2: "off", 3: "eco"}
        summary: Dict[str, Any] = {
            "appliance": {},
            "outdoor_temperature_c": None,
            "heating": {
                "zone_label": None,
                "mode_id": None,
                "mode": None,
                "room_temperature_c": None,
                "day_setpoint_c": None,
                "override_setpoint_c": None,
                "eco_setpoint_c": None,
            },
            "dhw": {
                "mode_id": None,
                "mode": None,
                "overrun_active": None,
                "overrun_status": None,
                "tank_temperature_c": None,
                "target_setpoint_c": None,
            },
            "compressor_measurements": {},
        }

        comp_desc: Dict[int, Dict[str, Any]] = {}
        comp_vals: List[Dict[str, Any]] = []

        for r in responses:
            if r["classifier"] != "reply":
                continue
            q = r["query"]
            cmd = r["cmd"] or {}
            if not q:
                continue
            dst_ent, dst_feat, func_name = q

            if dst_ent == [3] and func_name == "deviceClassificationManufacturerData":
                summary["appliance"] = cmd.get("deviceClassificationManufacturerData", {})
            elif dst_ent == [5, 1] and func_name == "deviceClassificationUserData":
                summary["heating"]["zone_label"] = (
                    cmd.get("deviceClassificationUserData", {}).get("userLabel")
                )
            elif dst_ent == [5, 1, 1] and func_name == "hvacSystemFunctionListData":
                items = (cmd.get("hvacSystemFunctionListData") or {}).get("hvacSystemFunctionData", [])
                if items:
                    mid = items[0].get("currentOperationModeId")
                    summary["heating"]["mode_id"] = mid
                    summary["heating"]["mode"] = mode_names.get(mid, str(mid))
            elif dst_ent == [5, 1, 1] and func_name == "setpointListData":
                for sp in (cmd.get("setpointListData") or {}).get("setpointData", []):
                    sid = sp.get("setpointId")
                    val = self._scaled_number_to_float(sp.get("value"))
                    if sid == 1:
                        summary["heating"]["day_setpoint_c"] = val
                    elif sid == 2:
                        summary["heating"]["override_setpoint_c"] = val
                    elif sid == 3:
                        summary["heating"]["eco_setpoint_c"] = val
            elif dst_ent == [5, 1, 1] and func_name == "measurementListData":
                items = (cmd.get("measurementListData") or {}).get("measurementData", [])
                if items:
                    summary["heating"]["room_temperature_c"] = self._scaled_number_to_float(
                        items[0].get("value")
                    )
            elif dst_ent == [4] and func_name == "hvacSystemFunctionListData":
                items = (cmd.get("hvacSystemFunctionListData") or {}).get("hvacSystemFunctionData", [])
                if items:
                    mid = items[0].get("currentOperationModeId")
                    summary["dhw"]["mode_id"] = mid
                    summary["dhw"]["mode"] = mode_names.get(mid, str(mid))
                    summary["dhw"]["overrun_active"] = items[0].get("isOverrunActive")
            elif dst_ent == [4] and func_name == "hvacOverrunListData":
                items = (cmd.get("hvacOverrunListData") or {}).get("hvacOverrunData", [])
                if items:
                    summary["dhw"]["overrun_status"] = items[0].get("overrunStatus")
            elif dst_ent == [4] and func_name == "setpointListData":
                for sp in (cmd.get("setpointListData") or {}).get("setpointData", []):
                    if sp.get("setpointId") == 1:
                        summary["dhw"]["target_setpoint_c"] = self._scaled_number_to_float(
                            sp.get("value")
                        )
            elif dst_ent == [4] and func_name == "measurementListData":
                items = (cmd.get("measurementListData") or {}).get("measurementData", [])
                if items:
                    summary["dhw"]["tank_temperature_c"] = self._scaled_number_to_float(
                        items[0].get("value")
                    )
            elif dst_ent == [6] and func_name == "measurementListData":
                items = (cmd.get("measurementListData") or {}).get("measurementData", [])
                if items:
                    summary["outdoor_temperature_c"] = self._scaled_number_to_float(
                        items[0].get("value")
                    )
            elif dst_ent == [3, 1] and func_name == "measurementDescriptionListData":
                for d in (cmd.get("measurementDescriptionListData") or {}).get(
                    "measurementDescriptionData", []
                ):
                    mid = d.get("measurementId")
                    if isinstance(mid, int):
                        comp_desc[mid] = d
            elif dst_ent == [3, 1] and func_name == "measurementListData":
                comp_vals = (cmd.get("measurementListData") or {}).get("measurementData", [])

        for m in comp_vals:
            mid = m.get("measurementId")
            val = self._scaled_number_to_float(m.get("value"))
            desc = comp_desc.get(mid, {})
            scope = desc.get("scopeType", f"id_{mid}")
            unit = desc.get("unit", "")
            key = f"id_{mid}_{scope}"
            summary["compressor_measurements"][key] = {"value": val, "unit": unit}

        return summary

    async def close(self) -> None:
        if self.ws is not None:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None
        if self.aiozc is not None:
            try:
                await self.aiozc.async_unregister_all_services()
                await self.aiozc.async_close()
            except Exception:
                pass
            self.aiozc = None


async def async_main(args: argparse.Namespace) -> None:
    client = VR921Client(
        cert_dir=args.cert_dir,
        host=args.host,
        port=args.port,
    )
    try:
        await client.connect_and_discover(timeout=args.timeout)
        print("\n=== Connected to Vaillant VR921 over EEBUS (SHIP/SPINE) ===")
        print(f"Local Device Address : {client.local_device_address}")
        print(f"Remote Device Address: {client.remote_device_address}")

        if args.dump_discovery:
            print("\n=== Detailed Discovery Data ===")
            print(json.dumps(client.remote_discovery_data, indent=2, ensure_ascii=False))
            print("\n=== Use Case Data ===")
            print(json.dumps(client.remote_use_case_data, indent=2, ensure_ascii=False))
            return

        if args.status:
            summary = await client.get_status_summary()
            print("\n=== VR921 Status Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.cancel_heating_override:
            summary = await client.cancel_heating_override(
                restore_mode=args.restore_mode,
                restore_day_temp=args.restore_day_temp,
            )
            print("\n=== Cancel Heating Override Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.set_heating_mode:
            summary = await client.set_heating_mode(args.set_heating_mode)
            print("\n=== Set Heating Mode Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.set_heating_temp is not None:
            summary = await client.set_heating_setpoint(args.set_heating_temp, setpoint_id=1)
            print("\n=== Set Heating Comfort/Day Setpoint Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.set_eco_temp is not None:
            summary = await client.set_heating_setpoint(args.set_eco_temp, setpoint_id=3)
            print("\n=== Set Heating Eco/Setback Setpoint Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.set_dhw_mode:
            summary = await client.set_dhw_mode(args.set_dhw_mode)
            print("\n=== Set DHW Mode Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.set_dhw_temp is not None:
            summary = await client.set_dhw_setpoint(args.set_dhw_temp)
            print("\n=== Set DHW Setpoint Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.dhw_boost:
            summary = await client.set_dhw_boost(args.dhw_boost == "on")
            print("\n=== DHW One-Time Boost (Overrun) Summary ===")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.dhw:
            queries_dhw: List[Tuple[List[int], int, List[int], int, str]] = [
                ([1], 3, [4], 9, "hvacOperationModeDescriptionListData"),
                ([1], 3, [4], 9, "hvacSystemFunctionDescriptionListData"),
                ([1], 3, [4], 9, "hvacSystemFunctionOperationModeRelationListData"),
                ([1], 3, [4], 9, "hvacSystemFunctionSetpointRelationListData"),
                ([1], 3, [4], 9, "hvacSystemFunctionListData"),
                ([1], 3, [4], 9, "hvacOverrunDescriptionListData"),
                ([1], 3, [4], 9, "hvacOverrunListData"),
                ([1], 4, [4], 18, "setpointDescriptionListData"),
                ([1], 4, [4], 18, "setpointConstraintsListData"),
                ([1], 4, [4], 18, "setpointListData"),
                ([1], 1, [4], 11, "measurementDescriptionListData"),
                ([1], 1, [4], 11, "measurementConstraintsListData"),
                ([1], 1, [4], 11, "measurementListData"),
            ]
            responses = await client.query_functions(queries_dhw, wait_seconds=4.0)
            print(f"\n=== DHW Circuit [4] Query Responses ({len(responses)}) ===")
            for r in responses:
                if r["classifier"] == "result":
                    r_data = (r["cmd"] or {}).get("resultData", {})
                    if r_data.get("errorNumber") != 0:
                        print(f"[RESULT ERROR] query={r['query']} -> {r_data}")
                    continue
                print(f"\n--- [{r['classifier'].upper()}] from {r['source']} (query={r['query']}) ---")
                print(json.dumps(r["cmd"], indent=2, ensure_ascii=False))
            return

        if args.measurements:
            queries_meas: List[Tuple[List[int], int, List[int], int, str]] = [
                ([1], 5, [3], 4, "deviceClassificationManufacturerData"),
                ([1], 1, [3, 1], 11, "measurementDescriptionListData"),
                ([1], 1, [3, 1], 11, "measurementListData"),
                ([1], 1, [4], 11, "measurementDescriptionListData"),
                ([1], 1, [4], 11, "measurementListData"),
                ([1], 1, [5, 1, 1], 11, "measurementDescriptionListData"),
                ([1], 1, [5, 1, 1], 11, "measurementListData"),
                ([1], 1, [6], 11, "measurementDescriptionListData"),
                ([1], 1, [6], 11, "measurementListData"),
            ]
            responses = await client.query_functions(queries_meas, wait_seconds=4.0)
            print(f"\n=== All VR921 Measurements ({len(responses)}) ===")
            for r in responses:
                if r["classifier"] == "result":
                    continue
                print(f"\n--- [{r['classifier'].upper()}] from {r['source']} (query={r['query']}) ---")
                print(json.dumps(r["cmd"], indent=2, ensure_ascii=False))
            return

        if args.heating:
            queries: List[Tuple[List[int], int, List[int], int, str]] = [
                # NodeManagement bindings & subscriptions
                ([0], 0, [0], 0, "nodeManagementBindingData"),
                ([0], 0, [0], 0, "nodeManagementSubscriptionData"),
                # HeatingCircuit / HeatingZone / HVACRoom names (DeviceClassification)
                ([1], 5, [5], 4, "deviceClassificationUserData"),
                ([1], 5, [5, 1], 4, "deviceClassificationUserData"),
                ([1], 5, [5, 1, 1], 4, "deviceClassificationUserData"),
                # HVACRoom [5, 1, 1] Feature 9 (HVAC)
                ([1], 3, [5, 1, 1], 9, "hvacOperationModeDescriptionListData"),
                ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionDescriptionListData"),
                ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionOperationModeRelationListData"),
                ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionSetpointRelationListData"),
                ([1], 3, [5, 1, 1], 9, "hvacSystemFunctionListData"),
                # HVACRoom [5, 1, 1] Feature 18 (Setpoint)
                ([1], 4, [5, 1, 1], 18, "setpointDescriptionListData"),
                ([1], 4, [5, 1, 1], 18, "setpointConstraintsListData"),
                ([1], 4, [5, 1, 1], 18, "setpointListData"),
                # HVACRoom [5, 1, 1] Feature 11 (Measurement)
                ([1], 1, [5, 1, 1], 11, "measurementDescriptionListData"),
                ([1], 1, [5, 1, 1], 11, "measurementConstraintsListData"),
                ([1], 1, [5, 1, 1], 11, "measurementListData"),
                # Compressor [3, 1] Feature 19 (SmartEnergyManagementPs)
                ([1], 6, [3, 1], 19, "smartEnergyManagementPsData"),
            ]
            responses = await client.query_functions(queries, wait_seconds=4.0)
            print(f"\n=== Heating Circuit & Control Query Responses ({len(responses)}) ===")
            for r in responses:
                if r["classifier"] == "result":
                    r_data = (r["cmd"] or {}).get("resultData", {})
                    if r_data.get("errorNumber") != 0:
                        print(f"[RESULT ERROR] query={r['query']} -> {r_data}")
                    continue
                print(f"\n--- [{r['classifier'].upper()}] from {r['source']} (query={r['query']}) ---")
                print(json.dumps(r["cmd"], indent=2, ensure_ascii=False))
            return

        if isinstance(client.remote_discovery_data, dict):
            entities = client.remote_discovery_data.get("entityInformation", [])
            features = client.remote_discovery_data.get("featureInformation", [])
            print(f"Discovered Entities  : {len(entities)}")
            for ent in entities:
                desc = (ent or {}).get("description", {})
                addr = (desc.get("entityAddress") or {}).get("entity")
                etype = desc.get("entityType")
                print(f"  - Entity {addr}: {etype}")
            print(f"Discovered Features  : {len(features)}")
            for feat in features:
                desc = (feat or {}).get("description", {})
                faddr = desc.get("featureAddress") or {}
                ent = faddr.get("entity")
                fnum = faddr.get("feature")
                ftype = desc.get("featureType")
                role = desc.get("role")
                funcs = desc.get("supportedFunction", [])
                func_summaries = []
                for fn in funcs:
                    if isinstance(fn, dict):
                        fname = fn.get("function")
                        ops = list((fn.get("possibleOperations") or {}).keys())
                        func_summaries.append(f"{fname}({','.join(ops)})")
                print(
                    f"  - Entity {ent} Feature {fnum}: {ftype} [role={role}] -> {', '.join(func_summaries)}"
                )
    finally:
        await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Connect to, query, and control Vaillant VR921 over EEBUS/SPINE."
    )
    parser.add_argument(
        "--host",
        help="Optional VR921 IP address (skips mDNS discovery wait if --port is also set)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=12480,
        help="VR921 SHIP port when --host is specified (default: 12480)",
    )
    parser.add_argument(
        "--cert-dir",
        default=DEFAULT_CERT_DIR,
        help=f"Directory containing cert.pem and key.pem (default: {DEFAULT_CERT_DIR})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="Connection and discovery timeout in seconds (default: 20)",
    )
    # Query / inspection commands
    parser.add_argument(
        "--status",
        action="store_true",
        help="Query a complete human-readable status summary (heating, DHW, outdoor temp, compressor)",
    )
    parser.add_argument(
        "--dump-discovery",
        action="store_true",
        help="Dump full JSON of nodeManagementDetailedDiscoveryData and nodeManagementUseCaseData",
    )
    parser.add_argument(
        "--heating",
        action="store_true",
        help="Query all heating circuit / zone / room / compressor control and status features",
    )
    parser.add_argument(
        "--dhw",
        action="store_true",
        help="Query all domestic hot water (DHW) circuit [4] control, setpoint, and measurement features",
    )
    parser.add_argument(
        "--measurements",
        action="store_true",
        help="Query all live measurements across compressor [3,1], DHW [4], room [5,1,1], and outdoor [6]",
    )
    # Heating control commands
    parser.add_argument(
        "--set-heating-mode",
        choices=["auto", "on", "off", "eco"],
        help="Set the heating circuit (Entity [5, 1, 1] Feature 9) operation mode",
    )
    parser.add_argument(
        "--set-heating-temp",
        type=float,
        metavar="DEGC",
        help="Set the heating comfort/day target temperature (Entity [5, 1, 1] Feature 18, setpointId=1, 5..30°C)",
    )
    parser.add_argument(
        "--set-eco-temp",
        type=float,
        metavar="DEGC",
        help="Set the heating eco/setback target temperature (Entity [5, 1, 1] Feature 18, setpointId=3, 5..30°C)",
    )
    parser.add_argument(
        "--cancel-heating-override",
        action="store_true",
        help="Cancel an active heating override (Quick Veto / manual override) by cycling HVAC mode off -> restore-mode",
    )
    parser.add_argument(
        "--restore-mode",
        choices=["auto", "off", "eco", "on"],
        default="auto",
        help="Target heating mode after --cancel-heating-override (default: auto)",
    )
    parser.add_argument(
        "--restore-day-temp",
        type=float,
        metavar="DEGC",
        help="Optional baseline comfort/day temperature (°C) to restore during --cancel-heating-override",
    )
    # DHW control commands
    parser.add_argument(
        "--set-dhw-mode",
        choices=["auto", "on", "off"],
        help="Set the DHW circuit (Entity [4] Feature 9) operation mode",
    )
    parser.add_argument(
        "--set-dhw-temp",
        type=float,
        metavar="DEGC",
        help="Set the DHW target temperature (Entity [4] Feature 18, setpointId=1, 35..70°C)",
    )
    parser.add_argument(
        "--dhw-boost",
        choices=["on", "off"],
        help="Start ('on') or cancel ('off') one-time DHW boost / overrun (Entity [4] Feature 9, overrunId=0)",
    )
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
