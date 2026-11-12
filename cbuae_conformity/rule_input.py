"""Build the per-period input document that the Rego rules evaluate (Step 3 / Step 6 evidence view).

Only processed evidence is read: OCSF events, the state exports (approvals, HR, identity registry, firewall change
log) and the institution configuration. Ground truth (truth/), hidden labels and injection metadata are never read.
All times are epoch milliseconds so Rego can compare them directly.
"""
import json
from pathlib import Path

import pandas as pd

from . import ocsf
from .config import Config, business_deadline

FAR_MS = 9_000_000_000_000


def ms(t):
    return None if pd.isna(t) else int(pd.Timestamp(t).value // 10**6)


def policy_params(cfg: Config):
    return {
        "leaver_grace_days": cfg.settings["leaver_grace_days"],
        "review_window_ms": cfg.settings["review_window_days"] * 86_400_000,
        "directory_assets": cfg.settings.get("directory_assets", []),
        "sod_pairs": [[a, b] for a, b, _ in cfg.sod_pairs],
        "role_baselines": {r: sorted(e) for r, e in cfg.roles.items()},
        "zone_matrix": {f"{s}->{d}": sorted(v) for (s, d), v in cfg.zone_matrix.items()},
        "services": {r.service: {"protocol": r.protocol, "port": int(r.port), "encrypted": bool(r.encrypted),
                                 "prohibited": bool(r.prohibited)} for r in cfg.services.itertuples()},
        "port_service": {f"{p}/{n}": s for (p, n), s in cfg.port_service.items()},
        "assets": {r.asset_id: {"zone": r.zone, "cia": bool(r.critical_information_asset), "owner_role": r.owner_role}
                   for r in cfg.assets.itertuples()},
        "entitlements": {r.entitlement: {"asset_id": r.asset_id, "privileged": bool(r.privileged)}
                         for r in cfg.entitlements.itertuples()},
    }


class EvidenceView:
    """Loads the evidence once and slices it per period."""

    def __init__(self, ev_dir: Path, cfg: Config):
        self.cfg = cfg
        st = ev_dir / "state"
        self.P = pd.read_csv(ev_dir / "periods.csv", parse_dates=["start", "end"])
        self.hr = pd.read_csv(st / "hr_people.csv", parse_dates=["start", "termination"])
        self.reg = pd.read_csv(st / "identity_registry.csv", keep_default_na=False)
        self.apr = pd.read_csv(st / "approvals.csv", parse_dates=["requested_at", "approved_at"], keep_default_na=False)
        self.fw = pd.read_csv(st / "firewall_changes.csv", parse_dates=["valid_from", "valid_to"])
        oc = ev_dir / "ocsf"
        auth = [{"t": e["time"], "identity": e["user"]["uid"], "dst": e["dst_endpoint"].get("uid"),
                 "src": e["src_endpoint"].get("uid"), "ok": e["status_id"] == 1, "type": e["logon_type_id"]}
                for e in ocsf.read_jsonl_gz(oc / "3002_authentication.jsonl.gz")]
        self.auth = pd.DataFrame(auth)
        acc = [{"t": e["time"], "identity": e["user"]["uid"], "activity": e["activity_id"],
                "owner": e.get("unmapped", {}).get("owner")} for e in ocsf.read_jsonl_gz(oc / "3001_account_change.jsonl.gz")]
        self.acc = pd.DataFrame(acc)
        ua = [{"t": e["time"], "identity": e["user"]["uid"], "ent": e["privileges"][0], "grant": e["activity_id"] == 1,
               "approval_id": (e.get("unmapped") or {}).get("approval_id", "")}
              for e in ocsf.read_jsonl_gz(oc / "3005_user_access.jsonl.gz")]
        self.ua = pd.DataFrame(ua).sort_values("t", kind="stable")
        fp = oc / "4001_network_activity.jsonl.gz"
        self.flows = pd.DataFrame([{"t": e["time"], "src_zone": e["src_endpoint"].get("zone"), "dst": e["dst_endpoint"].get("uid"),
                                    "dst_zone": e["dst_endpoint"].get("zone"), "port": e["dst_endpoint"]["port"],
                                    "proto": e["connection_info"]["protocol_num"]} for e in ocsf.read_jsonl_gz(fp)]) \
            if fp.exists() else None
        mgmt = set(cfg.assets.loc[cfg.assets.zone == "MANAGEMENT", "asset_id"])
        directory = set(cfg.settings.get("directory_assets", []))
        # server use = network logons, excluding routine directory logons from outside the MANAGEMENT zone
        a = self.auth
        self.use = a[(a.type == 3) & a.ok & ~(a.dst.isin(directory) & ~a.src.isin(mgmt))]
        self.data_start = self.P.start.min()

    def intervals(self, upto_ms):
        rows, open_ = [], {}
        for r in self.ua[self.ua.t <= upto_ms].itertuples():
            k = (r.identity, r.ent)
            if r.grant and k not in open_:
                open_[k] = (r.t, r.approval_id)
            elif not r.grant and k in open_:
                t0, aid = open_.pop(k)
                rows.append((r.identity, r.ent, t0, r.t, aid))
        rows += [(i, e, t0, FAR_MS, aid) for (i, e), (t0, aid) in open_.items()]
        return rows

    def build(self, p) -> dict:
        cfg = self.cfg
        s_ms, e_ms = ms(p.start), ms(p.end)
        # Point-in-time view: nothing dated after the end of the period is visible. An approval requested later does
        # not exist yet; one requested but not yet approved is pending; a termination not yet effective is unknown.
        apr = {}
        for r in self.apr[self.apr.requested_at <= p.end].itertuples():
            done = pd.notna(r.approved_at) and r.approved_at <= p.end
            apr[r.approval_id] = {"status": r.status if done else "pending", "approved_at": ms(r.approved_at) if done else None,
                                  "approvers": str(r.approvers).split(";") if done else []}
        ents = [{"identity": i, "entitlement": e, "granted_at": g, "revoked_at": rv, "approval": apr.get(aid)}
                for i, e, g, rv, aid in self.intervals(e_ms)]
        acc = self.acc[self.acc.t <= e_ms]
        created = acc[acc.activity == 1].groupby("identity").t.min()
        disabled = acc[acc.activity == 5].groupby("identity").t.max()
        owners = acc[acc.activity == 99].groupby("identity").owner.last()
        hr = self.hr.set_index("identity")
        identities = []
        for r in self.reg.itertuples():
            if r.identity not in created.index:
                continue
            h = hr.loc[r.identity] if r.identity in hr.index else None
            term = h.termination if h is not None else pd.NaT
            if pd.notna(term) and term > p.end:
                term = pd.NaT  # future termination: not known at assessment time
            identities.append({
                "identity": r.identity, "kind": r.kind, "role": (h.role if h is not None else ""),
                "created_at": int(created[r.identity]), "disabled_at": int(disabled[r.identity]) if r.identity in disabled.index else None,
                "owner": (owners.get(r.identity) or "") if r.kind != "human" else None,
                "hr_start": ms(h.start) if h is not None else None,
                "hr_termination": ms(term),
                # end of the termination day, and the POL-IM-02 deadline (derived from HR + policy parameter)
                "hr_active_until": ms(term + pd.Timedelta(days=1)) if pd.notna(term) else None,
                "disable_deadline": ms(business_deadline(term, cfg.settings["leaver_grace_days"])) if pd.notna(term) else None,
            })
        use = self.use[self.use.t <= e_ms]
        last_use = use.groupby(["identity", "dst"]).t.max().reset_index()
        in_p = self.auth[(self.auth.t >= s_ms) & (self.auth.t <= e_ms) & self.auth.ok]  # successful logons in the period
        fw = self.fw[(self.fw.valid_from <= p.end) & (self.fw.valid_to.isna() | (self.fw.valid_to > p.start))]
        out = {
            "period": {"id": int(p.period), "start": s_ms, "end": e_ms, "data_start": ms(self.data_start)},
            "params": policy_params(cfg),
            "identities": identities,
            "entitlements": ents,
            "last_use": [{"identity": r.identity, "asset_id": r.dst, "t": int(r.t)} for r in last_use.itertuples()],
            "authentications": [{"identity": r.identity, "dst_asset": r.dst, "src_asset": r.src if isinstance(r.src, str) else None,
                                 "t": int(r.t),
                                 "server": bool(r.type == 3) and r.Index in self.use.index}
                                for r in in_p.itertuples()],
            "firewall_rules": [{"rule_id": r.rule_id, "src_zone": r.src_zone, "dst_zone": r.dst_zone, "service": r.service,
                                "action": r.action} for r in fw.itertuples()],
            "flows": [],
        }
        if self.flows is not None:
            f = self.flows[(self.flows.t >= s_ms) & (self.flows.t <= e_ms) & (self.flows.dst != "EXTERNAL")]
            g = f.groupby(["dst", "src_zone", "dst_zone", "proto", "port"]).size().reset_index(name="count")
            out["flows"] = [{"dst_asset": r.dst, "src_zone": r.src_zone, "dst_zone": r.dst_zone,
                             "proto": "tcp" if r.proto == 6 else "udp", "port": int(r.port), "count": int(r.count)}
                            for r in g.itertuples()]
        return out

    def write_all(self, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = []
        for p in self.P.itertuples():
            path = out_dir / f"period_{p.period:03d}.json"
            path.write_text(json.dumps(self.build(p), allow_nan=False), encoding="utf-8")
            paths.append(path)
        return paths
