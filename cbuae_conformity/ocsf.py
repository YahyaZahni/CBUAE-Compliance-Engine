"""OCSF 1.6.0 normalisation and validation.

The schema is compiled from the official ocsf-schema repository (tag 1.6.0, in vendor/) with the ocsf-lib
package, and cached as a compact JSON file. Validation checks the core (non-profile) required attributes,
attribute names, data types, and enum values, recursively through objects.
"""
import gzip
import json
from pathlib import Path

from .config import ROOT

VENDOR = ROOT / "vendor"
CACHE = VENDOR / "ocsf_1.6.0_compiled.json"
PRODUCT = {"name": "cbuae-conformity evidence pipeline", "vendor_name": "MSc thesis prototype"}
VERSION = "1.6.0"
INT_TYPES = {"integer_t", "long_t", "timestamp_t", "port_t"}


def _compile():
    from ocsf.compile import Compilation
    from ocsf.repository import read_repo
    s = Compilation(read_repo(str(VENDOR / "ocsf-schema"))).build()
    assert s.version == VERSION, s.version

    def attrs(d):
        return {k: {"type": a.type, "req": a.requirement == "required" and not a.profile, "array": bool(a.is_array),
                    "obj": a.object_type, "enum": sorted(a.enum.keys()) if a.enum else None} for k, a in d.items()}
    out = {"classes": {c.name: {"uid": c.uid, "attrs": attrs(c.attributes)} for c in s.classes.values()},
           "objects": {o.name: {"attrs": attrs(o.attributes)} for o in s.objects.values()}}
    CACHE.write_text(json.dumps(out), encoding="utf-8")
    return out


_SCHEMA = None


def schema():
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else _compile()
    return _SCHEMA


def _check(value, spec, path, errors):
    t = spec["type"]
    if spec["array"]:
        if not isinstance(value, list):
            errors.append(f"{path}: expected array")
            return
        for i, v in enumerate(value):
            _check(v, {**spec, "array": False}, f"{path}[{i}]", errors)
        return
    obj_name = spec["obj"] or (t if t in schema()["objects"] else None)
    if t == "object_t" or obj_name or t == "object":
        if not isinstance(value, dict):
            errors.append(f"{path}: expected object {obj_name or t}")
        elif obj_name and obj_name != "object":
            _check_attrs(value, schema()["objects"][obj_name]["attrs"], path, errors)
        # the generic 'object' type (e.g. unmapped) accepts any key/value pairs
    elif t in INT_TYPES:
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"{path}: expected integer")
        elif spec["enum"] and str(value) not in spec["enum"]:
            errors.append(f"{path}: {value} not in enum")
    elif t == "float_t":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            errors.append(f"{path}: expected number")
    elif t == "boolean_t":
        if not isinstance(value, bool):
            errors.append(f"{path}: expected boolean")
    elif t == "json_t":
        pass
    else:
        if not isinstance(value, str):
            errors.append(f"{path}: expected string ({t})")
        elif spec["enum"] and value not in spec["enum"]:
            errors.append(f"{path}: {value!r} not in enum")


def _check_attrs(obj, attrs, path, errors):
    for k, spec in attrs.items():
        if spec["req"] and k not in obj:
            errors.append(f"{path}.{k}: required attribute missing")
    for k, v in obj.items():
        if k not in attrs:
            errors.append(f"{path}.{k}: unknown attribute")
        elif v is not None:
            _check(v, attrs[k], f"{path}.{k}", errors)


def validate(event):
    cls = next((c for c in schema()["classes"].values() if c["uid"] == event.get("class_uid")), None)
    if cls is None:
        return [f"unknown class_uid {event.get('class_uid')}"]
    errors = []
    _check_attrs(event, cls["attrs"], "$", errors)
    if event.get("type_uid") != event["class_uid"] * 100 + event.get("activity_id", -1):
        errors.append("$.type_uid: must equal class_uid * 100 + activity_id")
    return errors


# ------------------------------------------------------------------ event builders
def _base(class_uid, category_uid, activity_id, time_ms, uid, log_name, original_time=None):
    meta = {"product": PRODUCT, "version": VERSION, "uid": uid, "log_name": log_name}
    if original_time is not None:
        meta["original_time"] = str(original_time)
    return {"class_uid": class_uid, "category_uid": category_uid, "activity_id": activity_id,
            "type_uid": class_uid * 100 + activity_id, "severity_id": 1, "time": int(time_ms), "metadata": meta}


def authentication(uid, time_ms, identity, account_name, src_host, dst_host, dst_asset, activity_id, success,
                   logon_type_id, log_name, auth_protocol_id=0, original_time=None, src_asset=None):
    e = _base(3002, 3, activity_id, time_ms, uid, log_name, original_time)
    e.update({"user": {"uid": identity, "name": account_name}, "status_id": 1 if success else 2,
              "logon_type_id": logon_type_id, "auth_protocol_id": auth_protocol_id,
              "src_endpoint": {"hostname": src_host, **({"uid": src_asset} if src_asset else {})},
              "dst_endpoint": {"hostname": dst_host, "uid": dst_asset}})
    return e


def account_change(uid, time_ms, identity, activity_id, log_name, activity_name=None, unmapped=None):
    e = _base(3001, 3, activity_id, time_ms, uid, log_name)
    e["user"] = {"uid": identity}
    if activity_name:
        e["activity_name"] = activity_name
    if unmapped:
        e["unmapped"] = unmapped
    return e


def user_access(uid, time_ms, identity, entitlement, asset_id, grant, log_name, approval_id=None):
    e = _base(3005, 3, 1 if grant else 2, time_ms, uid, log_name)
    e.update({"user": {"uid": identity}, "privileges": [entitlement], "resource": {"uid": asset_id}})
    if approval_id:
        e["unmapped"] = {"approval_id": approval_id}
    return e


def network_activity(uid, time_ms, end_ms, src_ip, src_port, dst_ip, dst_port, proto_num, src_asset, dst_asset,
                     src_zone, dst_zone, bytes_in, bytes_out, pkts_in, pkts_out, tcp_flags, log_name):
    e = _base(4001, 4, 6, time_ms, uid, log_name)
    e.update({"start_time": int(time_ms), "end_time": int(end_ms), "duration": int(end_ms - time_ms),
              "src_endpoint": {"ip": src_ip, "port": int(src_port), "uid": src_asset, "zone": src_zone},
              "dst_endpoint": {"ip": dst_ip, "port": int(dst_port), "uid": dst_asset, "zone": dst_zone},
              "connection_info": {"protocol_num": int(proto_num), "tcp_flags": int(tcp_flags),
                                  # 1 Inbound, 2 Outbound, 3 Lateral (OCSF enum)
                                  "direction_id": 1 if src_zone == "INTERNET" else 2 if dst_zone == "INTERNET" else 3},
              "traffic": {"bytes_in": int(bytes_in), "bytes_out": int(bytes_out),
                          "packets_in": int(pkts_in), "packets_out": int(pkts_out)}})
    return e


def write_jsonl_gz(events, path: Path, check=True):
    """Write events; validate every event (check=True) and fail loudly on the first invalid one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for e in events:
            if check:
                errs = validate(e)
                if errs:
                    raise ValueError(f"OCSF validation failed for {e['metadata']['uid']}: {errs[:5]}")
            f.write(json.dumps(e, separators=(",", ":"), allow_nan=False) + "\n")  # strict JSON: NaN is an error
            n += 1
    return n


def read_jsonl_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)
