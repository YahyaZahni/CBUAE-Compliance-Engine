"""Load raw sources and resolve entities across them (Step 2: link the same user, service account, AI agent,
application or host across every source).

Crosswalk tables (raw/crosswalk/*.csv) map each source's native identifiers to institution entities:
  identities.csv  source, source_id, identity        e.g. cert ABC1234 -> U:ABC1234, lanl U12@DOM1 -> U:ABC1234
  hosts.csv       source, host, asset_id             e.g. cert PC-1234 -> WS:PC-1234, lanl C455 -> CORE-DB
  ips.csv         ip, asset_id, zone
For the public datasets, which do not share identifiers, build_public_crosswalk() creates these tables with
documented heuristics; the crosswalk is saved so the composition of the institution is reproducible.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from . import formats
from .config import Config
from .simulate_state import simulate_state


def _monday(ts):
    ts = pd.Timestamp(ts).normalize()
    return ts - pd.Timedelta(days=ts.weekday())


def build_public_crosswalk(raw: Path, cfg: Config, people, logon, lanl, flows, seed=11):
    """Heuristic composition of one institution from unrelated public datasets (documented limitation).

    - CERT users are the workforce; LANL user accounts are assigned to CERT users at random (seeded);
    - the most-authenticated-to LANL computers become the institution's servers (one per asset), the rest
      become workstations; CERT PCs are workstations;
    - NetFlow destination IPs are assigned to assets whose zone accepts the IP's dominant destination port,
      busiest first; all other private IPs become workstations and public IPs are INTERNET.
    """
    rng = np.random.default_rng(seed)
    cw = raw / "crosswalk"
    cw.mkdir(parents=True, exist_ok=True)
    ids = [{"source": "cert", "source_id": u, "identity": f"U:{u}"} for u in people.user_id]
    if lanl is not None:
        lusers = lanl.src_user[lanl.src_user.str.startswith("U")].value_counts().index
        # busiest LANL accounts go to people employed for the whole window, leavers last
        stay = people.termination.isna().to_numpy()
        targets = np.concatenate([rng.permutation(people.user_id.to_numpy()[stay]),
                                  rng.permutation(people.user_id.to_numpy()[~stay])])
        ids += [{"source": "lanl", "source_id": u, "identity": f"U:{targets[i % len(targets)]}"} for i, u in enumerate(lusers)]
    pd.DataFrame(ids).to_csv(cw / "identities.csv", index=False)
    pcs = sorted(logon.pc.unique())
    hosts = [{"source": "cert", "host": pc, "asset_id": f"WS:{pc}"} for pc in pcs]
    if lanl is not None:
        busiest = lanl.dst_computer.value_counts().index
        directory = list(cfg.settings.get("directory_assets", []))
        assets = directory + [a for a in cfg.assets.asset_id if a not in directory]  # busiest LANL host = directory
        hosts += [{"source": "lanl", "host": c, "asset_id": assets[i] if i < len(assets) else f"WS:{pcs[i % len(pcs)]}"}
                  for i, c in enumerate(busiest)]
    pd.DataFrame(hosts).to_csv(cw / "hosts.csv", index=False)
    ips = []
    if flows is not None:
        free = cfg.assets.set_index("asset_id")
        used = set()
        dom = flows.groupby("IPV4_DST_ADDR").L4_DST_PORT.agg(lambda s: s.mode().iloc[0])
        for ip in flows.IPV4_DST_ADDR.value_counts().index:
            if not _private(ip):
                continue
            svc = cfg.port_service.get(("tcp", int(dom[ip]))) or cfg.port_service.get(("udp", int(dom[ip])))
            match = [a for a in free.index if a not in used and any(svc in s for (src, dst), s in cfg.zone_matrix.items()
                                                                     if dst == free.zone[a])]
            # a host whose main service is cleartext (DNS, NTP, syslog) must not become a Critical Information Asset,
            # or its normal traffic would read as a POL-CIA-02 breach
            clear = svc in set(cfg.services.loc[~cfg.services.encrypted, "service"])
            match = [a for a in match if not (clear and free.critical_information_asset[a])]
            if svc and match:
                used.add(match[0])
                ips.append({"ip": ip, "asset_id": match[0], "zone": free.zone[match[0]]})
        known = {r["ip"] for r in ips}
        for i, ip in enumerate(sorted(set(flows.IPV4_SRC_ADDR) | set(flows.IPV4_DST_ADDR))):
            if ip not in known and _private(ip):
                ips.append({"ip": ip, "asset_id": f"WS:{pcs[i % len(pcs)]}", "zone": "USER"})
    pd.DataFrame(ips, columns=["ip", "asset_id", "zone"]).to_csv(cw / "ips.csv", index=False)


def _private(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or any(ip.startswith(f"172.{i}.") for i in range(16, 32)) \
        or ip.startswith("59.166.") or ip.startswith("149.171.")  # UNSW-NB15 internal ranges


def align_entitlements_with_activity(state, auth, cfg: Config):
    """Public mode: grant (with valid approval) an entitlement for every asset an identity is observed to use, so the
    composed institution starts conforming for AC-04/AC-07/AC-08 and injected cases are the planted ones."""
    ev, apr = state["iam_events"], state["approvals"]
    held = set(zip(ev.loc[ev.event == "grant", "identity"], ev.loc[ev.event == "grant", "entitlement"].map(cfg.ent_asset)))
    use = auth[auth.dst_asset.isin(cfg.assets.asset_id) & ~cfg.directory_logon(auth)]
    first = use.groupby(["identity", "dst_asset"]).time.min()
    by_asset = cfg.entitlements.sort_values("privileged", kind="stable").groupby("asset_id").entitlement.first()
    new_ev, new_apr = [], []
    for (ident, asset), t in first.items():
        if (ident, asset) in held or asset not in by_asset:
            continue
        ent = by_asset[asset]
        tg = t - pd.Timedelta(days=2)
        aid = f"APR-AL{len(new_apr) + 1:05d}"
        approvers = "asset_owner;ciso" if cfg.ent_privileged[ent] and asset in cfg.cia_assets else "line_manager;asset_owner"
        new_apr.append({"approval_id": aid, "identity": ident, "entitlement": ent, "requested_at": tg - pd.Timedelta(days=2),
                        "approved_at": tg - pd.Timedelta(days=1), "approvers": approvers, "status": "approved"})
        new_ev.append({"event_id": f"IAM-AL{len(new_ev) + 1:05d}", "time": tg, "event": "grant", "identity": ident,
                       "entitlement": ent, "approval_id": aid, "owner": ""})
    state["iam_events"] = pd.concat([ev, pd.DataFrame(new_ev)], ignore_index=True).sort_values("time", kind="stable")
    state["approvals"] = pd.concat([apr, pd.DataFrame(new_apr)], ignore_index=True)
    return len(new_ev)


def load(raw: Path, cfg: Config):
    """Load every raw source into normalised tables keyed by institution entities."""
    raw = Path(raw)
    ldap = formats.load_cert_ldap(raw / "cert" / "LDAP")
    people = formats.people_timeline(ldap)
    logon = formats.load_cert_logon(raw / "cert" / "logon.csv")
    logon["user_id"] = logon.user.str.split("/").str[-1]
    meta_path = raw / "crosswalk" / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    epoch = pd.Timestamp(meta.get("epoch", _monday(logon.time.min())))
    lanl = formats.load_lanl_auth(raw / "lanl" / "auth.txt", epoch) if (raw / "lanl" / "auth.txt").exists() else None
    nf_files = sorted((raw / "netflow").glob("*.csv")) if (raw / "netflow").exists() else []
    flows = pd.concat([formats.load_netflow_v3(p) for p in nf_files], ignore_index=True) if nf_files else None
    if flows is not None and "netflow_shift_ms" not in meta:
        meta["netflow_shift_ms"] = int(epoch.value // 10**6 - flows.FLOW_START_MILLISECONDS.min())
    if not (raw / "crosswalk" / "identities.csv").exists():
        build_public_crosswalk(raw, cfg, people, logon, lanl, flows)
    meta.setdefault("epoch", str(epoch))
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    cw_id = pd.read_csv(raw / "crosswalk" / "identities.csv", dtype=str)
    cw_host = pd.read_csv(raw / "crosswalk" / "hosts.csv", dtype=str)
    cw_ip = pd.read_csv(raw / "crosswalk" / "ips.csv", dtype=str)
    idmap = {(r.source, r.source_id): r.identity for r in cw_id.itertuples()}
    hostmap = {(r.source, r.host): r.asset_id for r in cw_host.itertuples()}

    # ---- authentication activity (CERT workstation sessions + LANL server authentications)
    a1 = pd.DataFrame({"time": logon.time, "identity": [idmap.get(("cert", u)) for u in logon.user_id],
                       "account_name": logon.user, "src_asset": [hostmap.get(("cert", p)) for p in logon.pc],
                       "dst_asset": [hostmap.get(("cert", p)) for p in logon.pc], "src_host": logon.pc, "dst_host": logon.pc,
                       "activity": logon.activity, "success": True, "logon_type": 2, "auth_protocol": 0,
                       "source": "cert", "source_id": logon["id"]})
    parts = [a1]
    if lanl is not None:
        a2 = pd.DataFrame({"time": lanl.time, "identity": [idmap.get(("lanl", u)) for u in lanl.src_user],
                           "account_name": lanl.src_user, "src_asset": [hostmap.get(("lanl", c)) for c in lanl.src_computer],
                           "dst_asset": [hostmap.get(("lanl", c)) for c in lanl.dst_computer],
                           "src_host": lanl.src_computer, "dst_host": lanl.dst_computer, "activity": "Logon",
                           "success": lanl.outcome.eq("Success"), "logon_type": 3,
                           "auth_protocol": lanl.auth_type.map({"Kerberos": 2, "NTLM": 1}).fillna(0).astype(int),
                           "source": "lanl", "source_id": lanl.index.astype(str)})
        parts.append(a2)
    auth = pd.concat(parts, ignore_index=True)
    unresolved = auth.identity.isna().sum()
    # composition rule: a composed identity's server activity ends at its HR termination (LANL accounts are not
    # real leavers); CERT's own logons are kept as published
    term = dict(zip("U:" + people.user_id, people.termination))
    after = (auth.source == "lanl") & (auth.time >= (auth.identity.map(term) + pd.Timedelta(days=1)).fillna(pd.Timestamp.max))
    auth = auth[~after]
    auth = auth.dropna(subset=["identity"]).sort_values("time", kind="stable").reset_index(drop=True)

    # ---- flows
    if flows is not None:
        ipmap = dict(zip(cw_ip.ip, cw_ip.asset_id))
        zmap = dict(zip(cw_ip.ip, cw_ip.zone))
        shift = meta["netflow_shift_ms"]
        f = pd.DataFrame({"time_ms": flows.FLOW_START_MILLISECONDS + shift, "end_ms": flows.FLOW_END_MILLISECONDS + shift,
                          "src_ip": flows.IPV4_SRC_ADDR, "src_port": flows.L4_SRC_PORT,
                          "dst_ip": flows.IPV4_DST_ADDR, "dst_port": flows.L4_DST_PORT, "proto": flows.PROTOCOL,
                          "bytes_in": flows.IN_BYTES, "bytes_out": flows.OUT_BYTES, "pkts_in": flows.IN_PKTS,
                          "pkts_out": flows.OUT_PKTS, "tcp_flags": flows.TCP_FLAGS, "ndpi_master": flows.ndpi_master})
        f["src_asset"] = f.src_ip.map(ipmap).fillna("EXTERNAL")
        f["dst_asset"] = f.dst_ip.map(ipmap).fillna("EXTERNAL")
        f["src_zone"] = f.src_ip.map(zmap).fillna("INTERNET")
        f["dst_zone"] = f.dst_ip.map(zmap).fillna("INTERNET")
        f["time"] = pd.to_datetime(f.time_ms, unit="ms")
        f = f.sort_values("time_ms", kind="stable").reset_index(drop=True)
    else:
        f = None

    # ---- institution state (simulated when no export is present)
    start, end = _monday(auth.time.min()), _monday(auth.time.max()) + pd.Timedelta(days=7)
    iam = raw / "iam"
    if (iam / "iam_events.csv").exists():
        state = {n: pd.read_csv(iam / f"{n}.csv", keep_default_na=False, na_values=[""])
                 for n in ("identities", "iam_events", "approvals", "firewall_rules")}
        for df, cols in ((state["iam_events"], ["time"]), (state["approvals"], ["requested_at", "approved_at"]),
                         (state["firewall_rules"], ["valid_from", "valid_to"]), (state["identities"], ["hr_start", "hr_termination"])):
            for c in df.columns:
                if c in cols:
                    df[c] = pd.to_datetime(df[c])
                else:  # text column: empty cells are empty strings, never NaN (pandas string dtype keeps NaN otherwise)
                    df[c] = df[c].astype(object).where(df[c].notna(), "").astype(str)
        aligned = 0
    else:
        state = simulate_state(people, cfg, start, end, seed=cfg.settings["sample"]["seed"], grant_baseline=False)
        aligned = align_entitlements_with_activity(state, auth, cfg)
        iam.mkdir(parents=True, exist_ok=True)
        for n, df in state.items():
            df.to_csv(iam / f"{n}.csv", index=False)
    return {"people": people, "auth": auth, "flows": f, "start": start, "end": end, "meta": meta,
            "unresolved_auth": int(unresolved), "composition_dropped_auth": int(after.sum()),
            "aligned_grants": aligned, **state}
