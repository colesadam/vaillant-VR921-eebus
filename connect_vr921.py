"""connect_vr921.py

Diagnostic SHIP/SPINE client for Vaillant VR921/EEBUS devices.
"""

import ssl
import socket
import datetime
import asyncio
import logging
import json
import os
import time
import re
import sys
import uuid
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple, cast
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceInfo, AsyncServiceBrowser
from zeroconf import IPVersion, ServiceListener
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger("VR921")

CERT_DIR = "/opt/Vaillant-VR921/certs"
os.makedirs(CERT_DIR, exist_ok=True)

class MsgCounter:
    def __init__(self, start: int = 1):
        self._value = start
        self._lock = asyncio.Lock()

    async def next(self) -> int:
        async with self._lock:
            value = self._value
            self._value += 1
            return value

def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    if v is None: return default
    return str(v)

def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None: return default
    try: return int(str(v).strip())
    except Exception: return default

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None: return default
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}: return True
    if s in {"0", "false", "no", "n", "off"}: return False
    return default

def _slug(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "unknown"

def _unit_to_ha(unit: Any) -> str:
    if unit is None: return ""
    if isinstance(unit, str):
        u = unit.strip()
        if u == "degC": return "°C"
        if u == "degF": return "°F"
        return u
    if isinstance(unit, dict):
        u = unit.get("unit") or unit.get("name")
        return _unit_to_ha(str(u)) if u is not None else ""
    return str(unit)

def _guess_ha_metadata(scope_type: str, unit: str) -> Dict[str, str]:
    s = (scope_type or "").lower()
    u = (unit or "").strip()
    if "temperature" in s: return {"device_class": "temperature", "state_class": "measurement", "unit": u or "°C"}
    if "power" in s: return {"device_class": "power", "state_class": "measurement", "unit": u or "W"}
    if "energy" in s: return {"device_class": "energy", "state_class": "total_increasing", "unit": u or "Wh"}
    if "current" in s: return {"device_class": "current", "state_class": "measurement", "unit": u or "A"}
    if "voltage" in s: return {"device_class": "voltage", "state_class": "measurement", "unit": u or "V"}
    return {"device_class": "", "state_class": "measurement", "unit": u}

def _is_energy_measurement_meta(meta: Dict[str, Any]) -> bool:
    if not isinstance(meta, dict): return False
    scope = str(meta.get("scopeType") or "").lower()
    mtype = str(meta.get("measurementType") or "").lower()
    return "energy" in scope or "acenergy" in scope or "energy" in mtype

def _is_acpowertotal_measurement_meta(meta: Dict[str, Any]) -> bool:
    if not isinstance(meta, dict): return False
    scope = str(meta.get("scopeType") or "").lower()
    mtype = str(meta.get("measurementType") or "").lower()
    return "acpowertotal" in scope or "acpowertotal" in mtype

def _friendly_sensor_name(scope_type: str, *, source_entity: Optional[list[int]] = None) -> str:
    s = (scope_type or "").strip()
    low = s.lower()
    if low == "outsideairtemperature": return "Outdoor Temperature"
    if low == "dhwtemperature": return "DHW Temperature"
    if low == "roomairtemperature": return "Room Temperature"
    if low == "acenergyconsumed": return "Energy Consumed"
    if low == "acenergyproduced": return "Energy Produced"
    if low == "acpowertotal" or low.startswith("acpower"):
        if source_entity == [3, 1]: return "Compressor Power"
        elif source_entity == [4]: return "DHW Power"
        elif source_entity and source_entity[:2] == [5, 1]: return "Heating Circuit Power"
        else: return "Power"

    if source_entity:
        entity_names = {
            (3, 1): "Compressor",
            (4,): "DHW",
            (5, 1, 1): "Heating Circuit",
            (6,): "Outdoor Sensor"
        }
        entity_key = tuple(source_entity) if source_entity else None
        entity_name = entity_names.get(entity_key, f"entity={source_entity}")
        return f"{s} ({entity_name})"
    return s or "Measurement"

class HAMqttPublisher:
    def __init__(self, *, device_id: str, device_name: str):
        self.device_id = device_id
        self.device_name = device_name
        self.base_prefix = _env_str("HA_MQTT_PREFIX", "homeassistant").strip("/")
        self.state_prefix = _env_str("HA_MQTT_STATE_PREFIX", "ship").strip("/")

        secrets_host = ""
        secrets_port = 1883
        secrets_user = ""
        secrets_password = ""
        try:
            import mqtt_secrets as _mqtt_secrets
            secrets_host = str(getattr(_mqtt_secrets, "HA_MQTT_HOST", "") or "").strip()
            secrets_port = int(getattr(_mqtt_secrets, "HA_MQTT_PORT", 1883) or 1883)
            secrets_user = str(getattr(_mqtt_secrets, "HA_MQTT_USER", "") or "").strip()
            secrets_password = str(getattr(_mqtt_secrets, "HA_MQTT_PASSWORD", "") or "")
        except Exception: pass

        self.host = _env_str("HA_MQTT_HOST", secrets_host).strip()
        self.port = _env_int("HA_MQTT_PORT", secrets_port)
        self.username = _env_str("HA_MQTT_USER", secrets_user)
        self.password = _env_str("HA_MQTT_PASSWORD", secrets_password)
        self.enabled = bool(self.host)
        self.retain_state = _env_bool("SHIP_MQTT_RETAIN_STATE", False)
        self._discovered_object_ids: set[str] = set()
        self._mqtt = None

    def connect(self) -> None:
        if not self.enabled: return
        try: import paho.mqtt.client as mqtt
        except Exception:
            print("⚠️  [MQTT] paho-mqtt fehlt.")
            self.enabled = False
            return

        client_kwargs: Dict[str, Any] = {"client_id": f"ship-{self.device_id}"}
        cb_api = getattr(mqtt, "CallbackAPIVersion", None)
        if cb_api is not None:
            try: client_kwargs["callback_api_version"] = cb_api.VERSION2
            except Exception: pass

        client = mqtt.Client(**client_kwargs)
        if self.username: client.username_pw_set(self.username, self.password or None)
        try: client.will_set(self._topic_availability(), payload="offline", qos=0, retain=True)
        except Exception: pass
        try:
            client.connect(self.host, self.port, keepalive=30)
            client.loop_start()
            self._mqtt = client
            self.publish_availability(True)
            print(f"✅ [MQTT] Connected to mqtt://{self.host}:{self.port}")
        except Exception as e:
            print(f"⚠️  [MQTT] Connect failed: {e}")
            self.enabled = False
            self._mqtt = None

    def close(self) -> None:
        if not self.enabled or self._mqtt is None: return
        try: self.publish_availability(False)
        except Exception: pass
        try:
            self._mqtt.loop_stop()
            self._mqtt.disconnect()
        except Exception: pass
        self._mqtt = None

    def _topic_availability(self) -> str: return f"{self.state_prefix}/{self.device_id}/availability"
    def _topic_state(self, object_id: str) -> str: return f"{self.state_prefix}/{self.device_id}/{object_id}/state"
    def _topic_config(self, object_id: str) -> str: return f"{self.base_prefix}/sensor/{self.device_id}/{object_id}/config"

    def publish_availability(self, online: bool) -> None:
        if not self.enabled or self._mqtt is None: return
        self._mqtt.publish(self._topic_availability(), payload=("online" if online else "offline"), qos=0, retain=True)

    def ensure_discovery(self, *, object_id: str, name: str, unit: str, device_class: str, state_class: str) -> None:
        if not self.enabled or self._mqtt is None: return
        if object_id in self._discovered_object_ids: return
        payload: Dict[str, Any] = {
            "name": name,
            "unique_id": f"{self.device_id}_{object_id}",
            "state_topic": self._topic_state(object_id),
            "availability_topic": self._topic_availability(),
            "payload_available": "online",
            "payload_not_available": "offline",
            "device": {"identifiers": [self.device_id], "name": self.device_name},
        }
        if unit: payload["unit_of_measurement"] = unit
        if device_class: payload["device_class"] = device_class
        if state_class: payload["state_class"] = state_class
        self._mqtt.publish(self._topic_config(object_id), json.dumps(payload, ensure_ascii=False), qos=0, retain=True)
        self._discovered_object_ids.add(object_id)

    def publish_state(self, *, object_id: str, value: float) -> None:
        if not self.enabled or self._mqtt is None: return
        self._mqtt.publish(self._topic_state(object_id), payload=str(value), qos=0, retain=self.retain_state)


def json_into_eebus_json(payload: Any) -> str:
    def _to_eebus(value: Any) -> Any:
        if isinstance(value, (dict, OrderedDict)): return [{k: _to_eebus(v)} for k, v in value.items()]
        if isinstance(value, list): return [_to_eebus(v) for v in value]
        return value
    converted = _to_eebus(payload)
    text = json.dumps(converted, separators=(",", ":"), ensure_ascii=False)
    if text.startswith("[") and text.endswith("]"): return text[1:-1]
    return text

def json_text_into_eebus_json(payload_text: str) -> str:
    parsed = json.loads(payload_text, object_pairs_hook=OrderedDict)
    return json_into_eebus_json(parsed)

def json_from_eebus_json(payload_text: str) -> str:
    b = payload_text.encode("utf-8", errors="ignore")
    b = b.replace(b"[{", b"{").replace(b"},{", b",").replace(b"}]", b"}").replace(b"[]", b"{}").strip(b"\x00")
    return b.decode("utf-8", errors="ignore")

def _first_cmd(payload_cmd: Any) -> Optional[Dict[str, Any]]:
    if isinstance(payload_cmd, dict): return payload_cmd
    if not isinstance(payload_cmd, list) or not payload_cmd: return None
    first = payload_cmd[0]
    if isinstance(first, list) and first:
        inner = first[0]
        return inner if isinstance(inner, dict) else None
    return first if isinstance(first, dict) else None

def _parse_spine_datagram(message: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    data = message.get("data")
    if not isinstance(data, dict): return None
    payload = data.get("payload")
    if not isinstance(payload, dict): return None
    datagram = payload.get("datagram")
    if not isinstance(datagram, dict): return None
    header = datagram.get("header")
    if not isinstance(header, dict): return None
    d_payload = datagram.get("payload")
    if not isinstance(d_payload, dict): return None
    cmd = _first_cmd(d_payload.get("cmd"))
    if cmd is None: return None
    return header, cmd

def _make_spine_reply_addresses(request_header: Dict[str, Any], *, local_device_address: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    address_destination = request_header.get("addressSource")
    address_source = request_header.get("addressDestination")
    if not isinstance(address_destination, dict) or not isinstance(address_source, dict): return None
    address_source = dict(address_source)
    if "device" in address_source: address_source["device"] = local_device_address
    return address_source, dict(address_destination)

def get_or_create_certificate():
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file = os.path.join(CERT_DIR, "key.pem")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        with open(cert_file, "rb") as f: cert = x509.load_pem_x509_certificate(f.read())
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
        print(f"🔄 Zertifikat wiederverwendet (SKI: {ski})")
        return ski
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"EEBUS-Python-Client")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
            now - datetime.timedelta(days=1)).not_valid_after(
            now + datetime.timedelta(days=3650)
        ).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256())
        with open(cert_file, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
        print(f"📜 Neues Zertifikat erstellt (SKI: {ski})")
        return ski

class MDNSHandler(ServiceListener):
    def __init__(self, ski):
        self.ski, self.target_info = ski, None
    def add_service(self, zc, type, name): asyncio.ensure_future(self.async_add_service(zc, type, name))
    def update_service(self, zc, type, name): asyncio.ensure_future(self.async_add_service(zc, type, name))
    def remove_service(self, zc, type, name): pass
    async def async_add_service(self, zc, type, name):
        info = await zc.async_get_service_info(type, name)
        if info and b"ski" in info.properties:
            try: remote_ski = info.properties.get(b"ski", b"").decode("utf-8")
            except Exception: remote_ski = ""
            if remote_ski and remote_ski == self.ski: return
            if not self.target_info: self.target_info = info

async def send_ship_json(ws, data):
    eebus_text = json_into_eebus_json(data)
    msg = b"\x01" + eebus_text.encode("utf-8")
    await ws.send(msg)

async def send_ship_data(ws, data):
    spine_std = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    spine_eebus = json_text_into_eebus_json(spine_std)
    payload_placeholder = '{"place":"holder"}'
    ship_std_obj = {"data": {"header": {"protocolId": "ee1.0"}, "payload": json.loads(payload_placeholder)}}
    ship_std = json.dumps(ship_std_obj, separators=(",", ":"), ensure_ascii=False)
    ship_eebus = json_text_into_eebus_json(ship_std).replace(f"[{payload_placeholder}]", spine_eebus)
    await ws.send(b"\x02" + ship_eebus.encode("utf-8"))

async def send_access_methods(ws, local_ship_id: str):
    await send_ship_json(ws, {"accessMethods": {"id": local_ship_id}})

def build_local_detailed_discovery(local_device_address: str) -> Dict[str, Any]:
    return {
        "specificationVersionList": {"specificationVersion": ["1.3.0"]},
        "deviceInformation": {"description": {"deviceAddress": {"device": local_device_address}, "deviceType": "EnergyManagementSystem", "featureSet": "smart", "brandName": "Python", "deviceModel": "SHIP-Layer1", "serialNumber": local_device_address, "deviceCode": "python-ship"}},
        "entityInformation": [
            {"description": {"entityAddress": {"entity": [0]}, "entityType": "DeviceInformation", "description": "DeviceInformation"}},
            {"description": {"entityAddress": {"entity": [1]}, "entityType": "CEM", "description": "CEM"}},
        ],
        "featureInformation": [
            {"description": {"featureAddress": {"entity": [0], "feature": 0}, "featureType": "NodeManagement", "role": "special", "description": "NodeManagement"}},
            {"description": {"featureAddress": {"entity": [0], "feature": 1}, "featureType": "DeviceClassification", "role": "server", "description": "DeviceClassification"}},
            {"description": {"featureAddress": {"entity": [1], "feature": 1}, "featureType": "Measurement", "role": "client", "description": "MeasurementClient"}},
            {"description": {"featureAddress": {"entity": [1], "feature": 2}, "featureType": "Sensing", "role": "client", "description": "SensingClient"}},
        ],
    }

def build_device_classification_manufacturer_data(local_device_address: str) -> Dict[str, Any]:
    return {"deviceName": "SHIP Python Client", "deviceCode": "python-ship", "brandName": "Python", "powerSource": "mains3Phase", "serialNumber": local_device_address}

def build_device_classification_user_data() -> Dict[str, Any]:
    return {"deviceName": "SHIP Python Client"}

def _spine_addr(*, device: str, entity: int, feature: int) -> Dict[str, Any]:
    return {"device": device, "entity": [entity], "feature": feature}

async def send_spine_read(ws, *, address_source: Dict[str, Any], address_destination: Dict[str, Any], cmd: Dict[str, Any], msg_counter: MsgCounter, specification_version: str = "1.3.0", ack_request: bool = True):
    datagram: Dict[str, Any] = {
        "datagram": {
            "header": {"specificationVersion": specification_version, "addressSource": address_source, "addressDestination": address_destination, "msgCounter": await msg_counter.next(), "cmdClassifier": "read", "ackRequest": ack_request},
            "payload": {"cmd": [cmd]},
        }
    }
    await send_ship_data(ws, datagram)

async def send_spine_call(ws, *, address_source: Dict[str, Any], address_destination: Dict[str, Any], cmd: Dict[str, Any], msg_counter: MsgCounter, specification_version: str = "1.3.0", ack_request: bool = True):
    datagram: Dict[str, Any] = {
        "datagram": {
            "header": {"specificationVersion": specification_version, "addressSource": address_source, "addressDestination": address_destination, "msgCounter": await msg_counter.next(), "cmdClassifier": "call", "ackRequest": ack_request},
            "payload": {"cmd": [cmd]},
        }
    }
    await send_ship_data(ws, datagram)

async def send_spine_result_ok(ws, *, request_header: Dict[str, Any], local_device_address: str, msg_counter: MsgCounter):
    ref = request_header.get("msgCounter")
    if ref is None: return
    addresses = _make_spine_reply_addresses(request_header, local_device_address=local_device_address)
    if addresses is None: return
    address_source, address_destination = addresses
    result_datagram: Dict[str, Any] = {
        "datagram": {
            "header": {"specificationVersion": request_header.get("specificationVersion", "1.3.0"), "addressSource": address_source, "addressDestination": address_destination, "msgCounter": await msg_counter.next(), "msgCounterReference": ref, "cmdClassifier": "result"},
            "payload": {"cmd": [{"resultData": {"errorNumber": 0}}]},
        }
    }
    await send_ship_data(ws, result_datagram)

def _extract_remote_landmap(discovery: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    heat_pump_entity_addr: Optional[Dict[str, Any]] = None
    feature_type_to_addr: Dict[str, Dict[str, Any]] = {}
    entity_info = discovery.get("entityInformation")
    if isinstance(entity_info, list):
        for item in entity_info:
            if not isinstance(item, dict): continue
            desc = item.get("description")
            if not isinstance(desc, dict): continue
            if desc.get("entityType") == "HeatPumpAppliance":
                ent_addr = desc.get("entityAddress")
                if isinstance(ent_addr, dict):
                    heat_pump_entity_addr = ent_addr
                    break
    feature_info = discovery.get("featureInformation")
    if isinstance(feature_info, list):
        for item in feature_info:
            if not isinstance(item, dict): continue
            desc = item.get("description")
            if not isinstance(desc, dict): continue
            feature_type = desc.get("featureType")
            feature_addr = desc.get("featureAddress")
            if isinstance(feature_type, str) and isinstance(feature_addr, dict):
                feature_type_to_addr[feature_type] = feature_addr
    return heat_pump_entity_addr, feature_type_to_addr

def _extract_measurement_servers(discovery: Dict[str, Any]) -> list[Dict[str, Any]]:
    all_servers: list[Dict[str, Any]] = []
    entity_one_servers: list[Dict[str, Any]] = []
    feature_info = discovery.get("featureInformation")
    if not isinstance(feature_info, list): return []
    for item in feature_info:
        if not isinstance(item, dict): continue
        desc = item.get("description")
        if not isinstance(desc, dict): continue
        if desc.get("role") != "server" or desc.get("featureType") != "Measurement": continue
        faddr = desc.get("featureAddress")
        if not isinstance(faddr, dict): continue
        entity = faddr.get("entity")
        feature = faddr.get("feature")
        if not isinstance(entity, list) or not entity or not all(isinstance(x, int) for x in entity): continue
        if not isinstance(feature, int): continue
        server = {"entity": [int(x) for x in entity], "feature": int(feature)}
        all_servers.append(server)
        if entity == [1]:
            entity_one_servers.append(server)
    if entity_one_servers:
        logger.info("📌 Found %d measurement server(s) on entity [1]", len(entity_one_servers))
        return entity_one_servers
    if all_servers:
        logger.warning("⚠️ No measurement servers on entity [1]; falling back to %d available measurement server(s)", len(all_servers))
        return all_servers
    logger.warning("⚠️ No measurement servers found in discovery response")
    return []

async def request_remote_detailed_discovery(ws, *, local_device_address: str, remote_device_address: str, msg_counter: MsgCounter):
    src = _spine_addr(device=local_device_address, entity=0, feature=0)
    dst = _spine_addr(device=remote_device_address, entity=0, feature=0)
    await send_spine_read(ws, address_source=src, address_destination=dst, cmd={"nodeManagementDetailedDiscoveryData": {}}, msg_counter=msg_counter)

async def request_remote_node_management_use_case_data(ws, *, local_device_address: str, remote_device_address: str, msg_counter: MsgCounter):
    src = _spine_addr(device=local_device_address, entity=0, feature=0)
    dst = _spine_addr(device=remote_device_address, entity=0, feature=0)
    await send_spine_read(ws, address_source=src, address_destination=dst, cmd={"nodeManagementUseCaseData": {}}, msg_counter=msg_counter)

async def request_remote_measurement_once(ws, *, local_device_address: str, remote_device_address: str, remote_measurement_feature: Dict[str, Any], msg_counter: MsgCounter):
    entity_list = remote_measurement_feature.get("entity")
    feature = remote_measurement_feature.get("feature")
    if not isinstance(entity_list, list) or not entity_list or not all(isinstance(x, int) for x in entity_list): return
    if not isinstance(feature, int): return
    logger.info("📤 Polling measurement once for server entity=%s feature=%s", entity_list, feature)
    src = _spine_addr(device=local_device_address, entity=1, feature=1)
    dst = {"device": remote_device_address, "entity": [int(x) for x in entity_list], "feature": int(feature)}
    await send_spine_read(ws, address_source=src, address_destination=dst, cmd={"measurementDescriptionListData": {}}, msg_counter=msg_counter, ack_request=True)
    await send_spine_read(ws, address_source=src, address_destination=dst, cmd={"measurementListData": {}}, msg_counter=msg_counter, ack_request=True)

async def subscribe_remote_measurement(ws, *, local_device_address: str, remote_device_address: str, remote_measurement_feature: Dict[str, Any], msg_counter: MsgCounter):
    entity_list = remote_measurement_feature.get("entity")
    feature = remote_measurement_feature.get("feature")
    if not isinstance(entity_list, list) or not entity_list or not all(isinstance(x, int) for x in entity_list): return
    if not isinstance(feature, int): return
    logger.info("📡 Sending measurement subscription request for server entity=%s feature=%s", entity_list, feature)
    src_nm = _spine_addr(device=local_device_address, entity=0, feature=0)
    dst_nm = _spine_addr(device=remote_device_address, entity=0, feature=0)
    local_meas_client = _spine_addr(device=local_device_address, entity=1, feature=1)
    remote_meas_server = {"device": remote_device_address, "entity": [int(x) for x in entity_list], "feature": int(feature)}
    sub_call = {"subscriptionRequest": {"clientAddress": local_meas_client, "serverAddress": remote_meas_server, "serverFeatureType": "Measurement"}}
    await send_spine_call(ws, address_source=src_nm, address_destination=dst_nm, cmd={"nodeManagementSubscriptionRequestCall": sub_call}, msg_counter=msg_counter, ack_request=True)

async def reply_node_management_detailed_discovery(ws, *, request_header: Dict[str, Any], local_device_address: str, msg_counter: MsgCounter):
    ref = request_header.get("msgCounter")
    if ref is None: return
    addresses = _make_spine_reply_addresses(request_header, local_device_address=local_device_address)
    if addresses is None: return
    address_source, address_destination = addresses
    reply_datagram: Dict[str, Any] = {
        "datagram": {
            "header": {"specificationVersion": request_header.get("specificationVersion", "1.3.0"), "addressSource": address_source, "addressDestination": address_destination, "msgCounter": await msg_counter.next(), "msgCounterReference": ref, "cmdClassifier": "reply"},
            "payload": {"cmd": [{"nodeManagementDetailedDiscoveryData": build_local_detailed_discovery(local_device_address), "function": "nodeManagementDetailedDiscoveryData"}]},
        }
    }
    await send_ship_data(ws, reply_datagram)

async def reply_device_classification_manufacturer_data(ws, *, request_header: Dict[str, Any], local_device_address: str, msg_counter: MsgCounter):
    ref = request_header.get("msgCounter")
    if ref is None: return
    addresses = _make_spine_reply_addresses(request_header, local_device_address=local_device_address)
    if addresses is None: return
    address_source, address_destination = addresses
    reply_datagram: Dict[str, Any] = {
        "datagram": {
            "header": {"specificationVersion": request_header.get("specificationVersion", "1.3.0"), "addressSource": address_source, "addressDestination": address_destination, "msgCounter": await msg_counter.next(), "msgCounterReference": ref, "cmdClassifier": "reply"},
            "payload": {"cmd": [{"deviceClassificationManufacturerData": build_device_classification_manufacturer_data(local_device_address)}]},
        }
    }
    await send_ship_data(ws, reply_datagram)

async def reply_device_classification_user_data(ws, *, request_header: Dict[str, Any], local_device_address: str, msg_counter: MsgCounter):
    ref = request_header.get("msgCounter")
    if ref is None: return
    addresses = _make_spine_reply_addresses(request_header, local_device_address=local_device_address)
    if addresses is None: return
    address_source, address_destination = addresses
    reply_datagram: Dict[str, Any] = {
        "datagram": {
            "header": {"specificationVersion": request_header.get("specificationVersion", "1.3.0"), "addressSource": address_source, "addressDestination": address_destination, "msgCounter": await msg_counter.next(), "msgCounterReference": ref, "cmdClassifier": "reply"},
            "payload": {"cmd": [{"deviceClassificationUserData": build_device_classification_user_data()}]},
        }
    }
    await send_ship_data(ws, reply_datagram)

async def handle_spine_read(ws, *, request_header: Dict[str, Any], cmd: Dict[str, Any], local_device_address: str, msg_counter: MsgCounter):
    if "nodeManagementDetailedDiscoveryData" in cmd:
        await reply_node_management_detailed_discovery(ws, request_header=request_header, local_device_address=local_device_address, msg_counter=msg_counter)
        return
    if "deviceClassificationManufacturerData" in cmd:
        await reply_device_classification_manufacturer_data(ws, request_header=request_header, local_device_address=local_device_address, msg_counter=msg_counter)
        return
    if "deviceClassificationUserData" in cmd:
        await reply_device_classification_user_data(ws, request_header=request_header, local_device_address=local_device_address, msg_counter=msg_counter)
        return

def parse_measurement_description(cmd: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    desc_map: Dict[int, Dict[str, Any]] = {}
    mdl = cmd.get("measurementDescriptionListData")
    mdl_list: Optional[list] = None
    if isinstance(mdl, list): mdl_list = mdl
    elif isinstance(mdl, dict):
        if isinstance(mdl.get("measurementDescriptionListData"), list): mdl_list = cast(list, mdl.get("measurementDescriptionListData"))
        elif isinstance(mdl.get("measurementDescriptionData"), list): mdl_list = cast(list, mdl.get("measurementDescriptionData"))

    if not isinstance(mdl_list, list): return desc_map

    for entry in mdl_list:
        if not isinstance(entry, dict): continue
        mid = entry.get("measurementId")
        if not isinstance(mid, int): continue
        desc_map[mid] = {"scopeType": entry.get("scopeType"), "unit": entry.get("unit"), "measurementType": entry.get("measurementType")}

    energy_ids = [(mid, meta) for mid, meta in desc_map.items() if _is_energy_measurement_meta(meta)]
    if energy_ids:
        print(f"⚡ [MEASUREMENT] Energy-related descriptions: {len(energy_ids)} IDs")
        for mid, meta in energy_ids:
            scope = meta.get("scopeType")
            unit = meta.get("unit")
            mtype = meta.get("measurementType")
            if isinstance(unit, dict): unit = unit.get("unit") or unit.get("name") or json.dumps(unit, separators=(",", ":"), ensure_ascii=False)
            print(f"   ID {mid}: scope={scope} unit={unit} type={mtype}")

    return desc_map

def parse_measurement_list(cmd: Dict[str, Any], desc_map: Dict[int, Dict[str, Any]], *, source_address: Optional[Dict[str, Any]] = None) -> list[Dict[str, Any]]:
    def _scaled_number_to_float(v: Any) -> Optional[float]:
        if not isinstance(v, dict): return None
        number = v.get("number")
        scale = v.get("scale", 0)
        try: num = float(number)
        except (TypeError, ValueError): return None
        try: scale_int = int(scale)
        except (TypeError, ValueError): scale_int = 0
        try: return num * (10.0 ** float(scale_int))
        except Exception: return None

    ml = cmd.get("measurementListData")
    ml_list: Optional[list] = None
    if isinstance(ml, list): ml_list = ml
    elif isinstance(ml, dict):
        if isinstance(ml.get("measurementListData"), list): ml_list = cast(list, ml.get("measurementListData"))
        elif isinstance(ml.get("measurementData"), list): ml_list = cast(list, ml.get("measurementData"))

    if not isinstance(ml_list, list): return []

    updates: list[Dict[str, Any]] = []
    src_entity: Optional[list[int]] = None
    src_feature: Optional[int] = None
    if isinstance(source_address, dict):
        ent = source_address.get("entity")
        feat = source_address.get("feature")
        if isinstance(ent, list) and all(isinstance(x, int) for x in ent): src_entity = [int(x) for x in ent]
        if isinstance(feat, int): src_feature = int(feat)

    for entry in ml_list:
        if not isinstance(entry, dict): continue
        mid = entry.get("measurementId")
        mdata = entry.get("measurementData")
        if not isinstance(mid, int): continue
        
        val = None
        if isinstance(mdata, dict): val = _scaled_number_to_float(mdata.get("value"))
        if val is None: val = _scaled_number_to_float(entry.get("value"))
        if val is None: continue

        meta = desc_map.get(mid, {})
        scope = meta.get("scopeType") or "unknown"
        unit = meta.get("unit") or ""
        mtype = meta.get("measurementType") or ""

        if isinstance(unit, dict): unit = unit.get("unit") or unit.get("name") or json.dumps(unit, separators=(",", ":"), ensure_ascii=False)
        scope_str = scope if isinstance(scope, str) else str(scope)
        unit_str = unit if isinstance(unit, str) else str(unit)
        mtype_str = mtype if isinstance(mtype, str) else str(mtype)

        if not _is_acpowertotal_measurement_meta(meta) and "acpowertotal" not in scope_str.lower():
            continue

        update = {"measurementId": mid, "scopeType": scope_str, "unit": unit_str, "measurementType": mtype_str, "value": val, "source": {"entity": src_entity, "feature": src_feature}}
        updates.append(update)
        logger.info("🔧 Parsed update accepted: %s", update)

        friendly_name = _friendly_sensor_name(scope_str, source_entity=src_entity)
        entity_desc = f" (entity={src_entity})" if src_entity else ""
        
        logger.info("⚡ %s: %s %s (ID %s, scope=%s)%s", friendly_name, val, unit_str, mid, scope_str, entity_desc)

    return updates

# ---------------------------------------------------------------------------
# SHIP handshake
# ---------------------------------------------------------------------------

async def perform_ship_handshake(ws, local_ship_id: str):
    init_ack = await ws.recv()
    logger.info("📤 [HELLO] Sending connectionHello (phase: ready)...")
    await send_ship_json(ws, {"connectionHello": {"phase": "ready", "waiting": 60000}})

    state = "WAITING_HELLO"
    last_pending_hello_sent = 0.0
    
    while True:
        try: raw_msg = await ws.recv()
        except Exception: return False
        if not isinstance(raw_msg, bytes) or len(raw_msg) < 2: continue
        if raw_msg[0] != 0x01: continue

        payload_text = json_from_eebus_json(raw_msg[1:].decode("utf-8", errors="ignore"))
        try: msg = json.loads(payload_text)
        except json.JSONDecodeError: continue

        if "connectionHello" in msg and state == "WAITING_HELLO":
            hello = msg.get("connectionHello") or {}
            phase = hello.get("phase")
            if phase == "pending":
                logger.info("⏳ [HELLO] STATUS: PENDING - waiting for confirmation in the myVAILLANT app...")
                now = time.monotonic()
                if now - last_pending_hello_sent > 5.0:
                    await send_ship_json(ws, {"connectionHello": {"phase": "pending", "waiting": 60000}})
                    last_pending_hello_sent = now
            elif phase == "ready":
                logger.info("✅ [HELLO] Phase complete - both sides READY")
                logger.info("📤 [PROTOCOL] Sending messageProtocolHandshake...")
                await send_ship_json(ws, {"messageProtocolHandshake": {"handshakeType": "announceMax", "version": {"major": 1, "minor": 0}, "formats": {"format": ["JSON-UTF8"]}}})
                state = "WAITING_PROTOCOL"
            elif phase == "aborted":
                return False

        elif "messageProtocolHandshake" in msg and state == "WAITING_PROTOCOL":
            handshake = msg.get("messageProtocolHandshake") or {}
            if handshake.get("handshakeType") != "select": return False
            logger.info("✅ [PROTOCOL] Protocol handshake confirmed")
            logger.info("📤 [PROTOCOL] Confirm selection (select)...")
            await send_ship_json(ws, {"messageProtocolHandshake": {"handshakeType": "select", "version": {"major": 1, "minor": 0}, "formats": {"format": ["JSON-UTF8"]}}})
            logger.info("📤 [PIN] Sending connectionPinState (none)...")
            await send_ship_json(ws, {"connectionPinState": {"pinState": "none"}})
            state = "WAITING_PIN"

        elif "connectionPinState" in msg and state == "WAITING_PIN":
            logger.info("📤 [ACCESS] Sending accessMethodsRequest...")
            await send_ship_json(ws, {"accessMethodsRequest": {}})
            state = "WAITING_ACCESS"

        elif "accessMethodsRequest" in msg and state == "WAITING_ACCESS":
            logger.info("📥 [ACCESS] accessMethodsRequest received from device -> sending accessMethods...")
            await send_access_methods(ws, local_ship_id)

        elif "accessMethods" in msg and state == "WAITING_ACCESS":
            logger.info("💎 SHIP handshake completed successfully!")
            return True

async def main():
    logger.info("🚀 EEBUS SHIP Client started")
    my_ski = get_or_create_certificate()
    local_ship_id = f"python-{my_ski[:12]}"
    local_device_address = f"d:_i:1_{local_ship_id}"
    msg_counter = MsgCounter(start=1)

    ha_device_id = _slug(_env_str("HA_DEVICE_ID", f"eebus_{local_ship_id}"))
    ha_device_name = _env_str("HA_DEVICE_NAME", "EEBUS HeatPump")
    mqtt_pub = HAMqttPublisher(device_id=ha_device_id, device_name=ha_device_name)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()

    aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
    handler = MDNSHandler(my_ski)
    
    desc = {'txtvers': '1', 'path': '/ship/', 'ski': my_ski, 'register': 'true'}
    service_name_base = f"Python-{my_ski[:6]}"
    service_name = f"{service_name_base}._ship._tcp.local."
    info = AsyncServiceInfo("_ship._tcp.local.", service_name,
                            addresses=[socket.inet_aton(local_ip)], port=54885, properties=desc)
    try:
        await aiozc.async_register_service(info)
    except Exception as exc:
        logger.warning(f"⚠️ Zeroconf name collision or registration failure: {exc}. Retrying with a unique service name.")
        service_name = f"{service_name_base}-{uuid.uuid4().hex[:6]}._ship._tcp.local."
        info = AsyncServiceInfo("_ship._tcp.local.", service_name,
                                addresses=[socket.inet_aton(local_ip)], port=54885, properties=desc)
        await aiozc.async_register_service(info)
    AsyncServiceBrowser(aiozc.zeroconf, "_ship._tcp.local.", handler)
    
    try:
        while True:  # Retry loop for connections
            try:
                logger.info("🔎 Searching for VR921...")
                timeout = 30
                elapsed = 0
                while handler.target_info is None and elapsed < timeout:
                    await asyncio.sleep(1)
                    elapsed += 1
            
                if handler.target_info is None:
                    logger.error("❌ No VR921 found. Retrying in 60 seconds...")
                    await asyncio.sleep(60)
                    continue
                
                target_ip = socket.inet_ntoa(handler.target_info.addresses[0])
                target_port = handler.target_info.port
                logger.info(f"✅ VR921 found: {target_ip}:{target_port}")

                ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ssl_ctx.load_cert_chain(certfile=os.path.join(CERT_DIR, "cert.pem"), keyfile=os.path.join(CERT_DIR, "key.pem"))
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                ssl_ctx.set_ciphers('HIGH:!aNULL:!eNULL:!MD5@SECLEVEL=1')

                import websockets
                async with websockets.connect(
                    f"wss://{target_ip}:{target_port}/ship/",
                    ssl=ssl_ctx,
                    subprotocols=cast(Any, ["ship"]),
                    open_timeout=20,
                    ping_interval=None,
                    ping_timeout=None,
                    close_timeout=10,
                ) as ws:
                    await ws.send(b'\x00\x00')
                    
                    try:
                        success = await asyncio.wait_for(perform_ship_handshake(ws, local_ship_id), timeout=120)
                    except asyncio.TimeoutError:
                        logger.error("❌ Handshake timed out")
                        await asyncio.sleep(10)
                        continue
                    if not success:
                        logger.error("❌ Handshake failed")
                        await asyncio.sleep(10)
                        continue
                    
                    logger.info("🎯 SHIP layer is up! Waiting for SPINE data...")

                    await asyncio.to_thread(mqtt_pub.connect)
                    
                    message_count = 0
                    remote_device_address: Optional[str] = None
                    discovery_requested = False
                    peer_use_case_received = False
                    measurement_subscription_sent = False
                    polled_once = False
                    
                    measurement_desc_maps: Dict[tuple[tuple[int, ...], int], Dict[int, Dict[str, Any]]] = {}
                    ha_published: set[str] = set()
                    selected_measurement_servers: list[Dict[str, Any]] = []

                    def _desc_key_from_address(addr: Any) -> Optional[tuple[tuple[int, ...], int]]:
                        if not isinstance(addr, dict): return None
                        ent = addr.get("entity")
                        feat = addr.get("feature")
                        if not (isinstance(ent, list) and ent and all(isinstance(x, int) for x in ent)): return None
                        if not isinstance(feat, int): return None
                        return (tuple(int(x) for x in ent), int(feat))

                    while True:
                        data = None
                        try:
                            data = await asyncio.wait_for(ws.recv(), timeout=300)
                        except asyncio.TimeoutError:
                            logger.debug("⏳ SPINE receive timeout, connection still alive")
                            continue
                        else:
                            message_count += 1
                            logger.info(f"📨 SPINE frame received (#%d) length=%d", message_count, len(data) if isinstance(data, (bytes, str)) else 0)

                        if isinstance(data, bytes) and len(data) > 0:
                            if data[0] == 1:
                                logger.debug("🔁 Received SHIP keepalive / acknowledgement frame")
                                pass
                            elif data[0] == 2:
                                try:
                                    payload_text = data[1:].decode("utf-8", errors="ignore")
                                    payload_text = json_from_eebus_json(payload_text)
                                    msg = json.loads(payload_text)

                                    parsed = _parse_spine_datagram(msg)
                                    if parsed is None: continue

                                    hdr, cmd = parsed
                                    cmd_classifier = hdr.get("cmdClassifier")

                                    if remote_device_address is None:
                                        addr_src = hdr.get("addressSource")
                                        if isinstance(addr_src, dict):
                                            dev = addr_src.get("device")
                                            if isinstance(dev, str) and dev:
                                                remote_device_address = dev

                                    if remote_device_address is not None and not discovery_requested:
                                        discovery_requested = True
                                        await request_remote_detailed_discovery(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, msg_counter=msg_counter)

                                    try:
                                        if cmd_classifier != "result":
                                            await send_spine_result_ok(ws, request_header=hdr, local_device_address=local_device_address, msg_counter=msg_counter)

                                        if cmd_classifier == "read":
                                            await handle_spine_read(ws, request_header=hdr, cmd=cmd, local_device_address=local_device_address, msg_counter=msg_counter)
                                                
                                        elif cmd_classifier == "reply":
                                            if "nodeManagementDetailedDiscoveryData" in cmd:
                                                discovery = cmd.get("nodeManagementDetailedDiscoveryData")
                                                if isinstance(discovery, dict):
                                                    remote_measurement_servers = _extract_measurement_servers(discovery)
                                                    if remote_measurement_servers:
                                                        selected_measurement_servers = list(remote_measurement_servers)
                                                        logger.info("✅ Selected %d remote measurement server(s): %s", len(selected_measurement_servers), selected_measurement_servers)
                                                    else:
                                                        logger.warning("⚠️ Discovery returned no usable measurement servers")

                                                    if remote_device_address is not None:
                                                        logger.info("🔎 Remote device identified: %s", remote_device_address)
                                                        await request_remote_node_management_use_case_data(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, msg_counter=msg_counter)
                                                        logger.info("📤 Requested remote node management use case data")
                                                        
                                                    if peer_use_case_received and selected_measurement_servers and not measurement_subscription_sent:
                                                        logger.info("▶ Triggering measurement subscription because peer use case has already been received")
                                                        measurement_subscription_sent = True
                                                        logger.info("📡 Subscribing to %d remote measurement servers", len(selected_measurement_servers))
                                                        for server in selected_measurement_servers:
                                                            await subscribe_remote_measurement(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, remote_measurement_feature=server, msg_counter=msg_counter)
                                                        logger.info("📤 Measurement subscription request(s) sent")
                                                        if not polled_once:
                                                            polled_once = True
                                                            logger.info("⏱️ Initial poll for all measurement values")
                                                            for server in selected_measurement_servers:
                                                                await request_remote_measurement_once(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, remote_measurement_feature=server, msg_counter=msg_counter)
                                                                logger.info("📤 Measurement discovery poll sent for server: entity=%s feature=%s", server.get("entity"), server.get("feature"))

                                            elif "nodeManagementUseCaseData" in cmd:
                                                peer_use_case_received = True
                                                logger.info("✅ Remote peer use case data received")
                                                if selected_measurement_servers and not measurement_subscription_sent:
                                                    logger.info("▶ Triggering measurement subscription because measurement servers are already known")
                                                    measurement_subscription_sent = True
                                                    logger.info("📡 Subscribing to %d remote measurement servers", len(selected_measurement_servers))
                                                    for server in selected_measurement_servers:
                                                        await subscribe_remote_measurement(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, remote_measurement_feature=server, msg_counter=msg_counter)
                                                    logger.info("📤 Measurement subscription request(s) sent")
                                                    if not polled_once:
                                                        polled_once = True
                                                        logger.info("⏱️ Initial poll for all measurement values")
                                                        for server in selected_measurement_servers:
                                                            await request_remote_measurement_once(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, remote_measurement_feature=server, msg_counter=msg_counter)
                                                            logger.info("📤 Measurement discovery poll sent for server: entity=%s feature=%s", server.get("entity"), server.get("feature"))

                                            elif "measurementDescriptionListData" in cmd:
                                                logger.info("📥 Received measurementDescriptionListData reply from %s", hdr.get("addressSource"))
                                                desc_map = parse_measurement_description(cmd)
                                                key = _desc_key_from_address(hdr.get("addressSource"))
                                                if key is not None and desc_map:
                                                    measurement_desc_maps[key] = desc_map

                                            elif "measurementListData" in cmd:
                                                logger.info("📥 Received measurementListData reply from %s", hdr.get("addressSource"))
                                                key = _desc_key_from_address(hdr.get("addressSource"))
                                                desc_map = measurement_desc_maps.get(key, {}) if key is not None else {}
                                                updates = parse_measurement_list(cmd, desc_map, source_address=hdr.get("addressSource") if isinstance(hdr, dict) else None)
                                                logger.info("📊 Parsed %d measurement update(s) from reply", len(updates))
                                                
                                                # --- RESTORED MQTT PUBLISHING LOOP ---
                                                for u in updates:
                                                    scope = str(u.get("scopeType") or "unknown")
                                                    unit = _unit_to_ha(u.get("unit"))
                                                    mid = u.get("measurementId")
                                                    src = u.get("source") if isinstance(u.get("source"), dict) else {}
                                                    ent = src.get("entity") if isinstance(src, dict) else None
                                                    feat = src.get("feature") if isinstance(src, dict) else None

                                                    object_id = _slug(f"{scope}_e{'_'.join(str(x) for x in ent) if isinstance(ent, list) else 'na'}_f{feat if isinstance(feat, int) else 'na'}_id{mid}")

                                                    if isinstance(u.get("value"), (int, float)):
                                                        meta = _guess_ha_metadata(scope, unit)
                                                        if object_id not in ha_published:
                                                            friendly_name = _friendly_sensor_name(scope, source_entity=ent if isinstance(ent, list) else None)
                                                            mqtt_pub.ensure_discovery(
                                                                object_id=object_id,
                                                                name=friendly_name,
                                                                unit=meta.get("unit", unit),
                                                                device_class=meta.get("device_class", ""),
                                                                state_class=meta.get("state_class", "measurement")
                                                            )
                                                            ha_published.add(object_id)
                                                        mqtt_pub.publish_state(object_id=object_id, value=float(u["value"]))
                                                        logger.info("📡 MQTT published %s = %s", object_id, float(u["value"]))

                                        elif cmd_classifier == "notify":
                                            if "measurementDescriptionListData" in cmd:
                                                logger.info("📥 Received measurementDescriptionListData notify from %s", hdr.get("addressSource"))
                                                desc_map = parse_measurement_description(cmd)
                                                key = _desc_key_from_address(hdr.get("addressSource"))
                                                if key is not None and desc_map:
                                                    measurement_desc_maps[key] = desc_map

                                            elif "measurementListData" in cmd:
                                                logger.info("📥 Received measurementListData notify from %s", hdr.get("addressSource"))
                                                key = _desc_key_from_address(hdr.get("addressSource"))
                                                desc_map = measurement_desc_maps.get(key, {}) if key is not None else {}
                                                updates = parse_measurement_list(cmd, desc_map, source_address=hdr.get("addressSource") if isinstance(hdr, dict) else None)
                                                logger.info("📊 Parsed %d measurement update(s) from notify", len(updates))
                                                
                                                # --- RESTORED MQTT PUBLISHING LOOP ---
                                                for u in updates:
                                                    scope = str(u.get("scopeType") or "unknown")
                                                    unit = _unit_to_ha(u.get("unit"))
                                                    mid = u.get("measurementId")
                                                    src = u.get("source") if isinstance(u.get("source"), dict) else {}
                                                    ent = src.get("entity") if isinstance(src, dict) else None
                                                    feat = src.get("feature") if isinstance(src, dict) else None

                                                    object_id = _slug(f"{scope}_e{'_'.join(str(x) for x in ent) if isinstance(ent, list) else 'na'}_f{feat if isinstance(feat, int) else 'na'}_id{mid}")

                                                    if isinstance(u.get("value"), (int, float)):
                                                        meta = _guess_ha_metadata(scope, unit)
                                                        if object_id not in ha_published:
                                                            friendly_name = _friendly_sensor_name(scope, source_entity=ent if isinstance(ent, list) else None)
                                                            mqtt_pub.ensure_discovery(
                                                                object_id=object_id,
                                                                name=friendly_name,
                                                                unit=meta.get("unit", unit),
                                                                device_class=meta.get("device_class", ""),
                                                                state_class=meta.get("state_class", "measurement")
                                                            )
                                                            ha_published.add(object_id)
                                                        mqtt_pub.publish_state(object_id=object_id, value=float(u["value"]))
                                                        logger.info("📡 MQTT published %s = %s", object_id, float(u["value"]))

                                    except Exception as e:
                                        print(f"⚠️  [SPINE] Error processing: {e}")

                                except Exception as e:
                                    print(f"\n📨 Message #{message_count} (SPINE decode error): {e}")
                                    
                    # --- SUBSCRIPTION ---
                    if peer_use_case_received and remote_device_address is not None and selected_measurement_servers:
                        if not measurement_subscription_sent:
                            measurement_subscription_sent = True
                            logger.info("📡 Subscribing to %d remote measurement servers", len(selected_measurement_servers))
                            for server in selected_measurement_servers:
                                await subscribe_remote_measurement(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, remote_measurement_feature=server, msg_counter=msg_counter)
                            logger.info("📤 Measurement subscription request(s) sent")

                            if not polled_once:
                                polled_once = True
                                logger.info("⏱️ Initial poll for all measurement values")
                                for server in selected_measurement_servers:
                                    await request_remote_measurement_once(ws, local_device_address=local_device_address, remote_device_address=remote_device_address, remote_measurement_feature=server, msg_counter=msg_counter)
                                    logger.info("📤 Measurement discovery poll sent for server: entity=%s feature=%s", server.get("entity"), server.get("feature"))
                                    
                                    ent = server.get("entity")
                                    feat = server.get("feature")
                                    
            except Exception as e:
                logger.error(f"❌ Connection error: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(60)  # Wait before retrying
            finally:
                try: mqtt_pub.close()
                except Exception: pass
    finally:
        await aiozc.async_unregister_all_services()
        await aiozc.async_close()
        logger.info("👋 Exiting.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Abgebrochen durch Benutzer")