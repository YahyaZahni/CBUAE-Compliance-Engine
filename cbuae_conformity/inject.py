"""Plant known nonconformities (the answer key's positives) into the loaded evidence.

Every injection is written as a specification BEFORE any checker or model sees the data (settings: injection.seed,
injection.per_criterion), is recorded in injections.csv, and is designed to violate its target criterion. Side
effects on other criteria are not suppressed: the oracles in truth.py label every case from the true state, so a
cross-effect becomes a correctly labelled case of the other criterion.
"""
import hashlib

import numpy as np
import pandas as pd

from .config import Config, business_deadline
from .simulate_state import plausible_extras
from .truth import FAR, account_intervals, grant_intervals

PROHIBITED_FLOWS = [("JUMP-HOST", "CORE-DB", "telnet"), ("JUMP-HOST", "CUST-DB", "ftp"), ("WS", "PAY-APP", "http"),
                    ("WS", "GL-APP", "telnet"), ("JUMP-HOST", "AD-DC", "telnet")]
DISGUISED = [("WS", "PAY-APP", 7, 443), ("WS", "LOAN-APP", 7, 443), ("JUMP-HOST", "CORE-DB", 77, 22),
             ("JUMP-HOST", "FW-MGMT", 77, 22), ("WS", "TRADE-APP", 1, 443)]
OFF_MATRIX_FLOWS = [("WS", "CORE-DB", "db-tls"), ("WS", "FW-MGMT", "ssh"), ("WEB-PORTAL", "CUST-DB", "db-tls"),
                    ("WS", "HR-DB", "db-tls"), ("WEB-PORTAL", "AD-DC", "ldaps")]
OFF_MATRIX_RULES = [("USER", "DATABASE", "db-tls"), ("DMZ", "DATABASE", "db-tls"), ("USER", "MANAGEMENT", "ssh"),
                    ("DMZ", "MANAGEMENT", "https"), ("INTERNET", "SERVER", "https")]


class Injector:
    def __init__(self, d, cfg: Config, seed):
        self.d, self.cfg, self.rng = d, cfg, np.random.default_rng(seed)
        self.records, self.n = [], 0
        self.start, self.end = d["start"], d["end"]
        self.weeks = int((self.end - self.start).days // 7)
        self.used = set()
        self.ac07_done = set()
        crosswalk_ips = d["flows"][["src_asset", "src_ip"]].drop_duplicates() if d["flows"] is not None else None
        self.ip_of = dict(zip(crosswalk_ips.src_asset, crosswalk_ips.src_ip)) if crosswalk_ips is not None else {}
        self.ip_of.update(dict(zip(cfg.assets.asset_id, cfg.assets.ip)))
        self.ws_of = (d["auth"][d["auth"].source == "cert"].groupby("identity").src_asset.agg(lambda s: s.mode().iloc[0])
                      .to_dict())
        # Planted records must be indistinguishable from ordinary ones in every field a checker can see, so they are
        # written in the server log's own naming (account names, host names) and with donor flow statistics.
        srv = d["auth"][d["auth"].source != "cert"]
        self.server_source = srv.source.iloc[0] if len(srv) else "lanl"
        self.account_of = srv.groupby("identity").account_name.first().to_dict()
        self.host_of = {**dict(zip(srv.src_asset, srv.src_host)), **dict(zip(srv.dst_asset, srv.dst_host))}
        self.base_flows = d["flows"].copy() if d["flows"] is not None else None
        # within-minute offsets seen in the server log: planted logons copy one, so their timestamps have the same
        # granularity as the log's own (whole minutes in the sample, seconds in LANL)
        self.auth_offsets = ((srv.time - srv.time.dt.floor("min")) // pd.Timedelta(milliseconds=1)).to_numpy() \
            if len(srv) else np.array([0])   # timedelta arithmetic: independent of the column's time unit
        self.donor_note = {}

    # ---------------------------------------------------------------- helpers
    def when(self, lo_week=1, hi_week=None):
        hi = hi_week if hi_week is not None else self.weeks - 1
        w = int(self.rng.integers(lo_week, max(lo_week + 1, hi)))
        return self.start + pd.Timedelta(days=7 * w + int(self.rng.integers(0, 5)), minutes=int(self.rng.integers(480, 1020)))

    def lead(self):
        """How long before a grant its approval is dated: the same 5 hours to 3 days spread as ordinary approvals."""
        return pd.Timedelta(hours=int(self.rng.integers(5, 72)))

    def record(self, criterion, variant, entity, t, description, entitlement="", t_end=None):
        self.n += 1
        iid = f"INJ-{self.n:04d}"
        self.records.append({"injection_id": iid, "criterion": criterion, "variant": variant, "entity": entity,
                             "entitlement": entitlement, "time": t, "time_end": t_end, "description": description})
        return iid

    def iam(self, t, event, identity, entitlement="", approval_id="", owner="", tag=""):
        self.d["iam_events"] = pd.concat([self.d["iam_events"], pd.DataFrame([{
            "event_id": f"tmp-{len(self.d['iam_events'])}{tag}", "time": t, "event": event, "identity": identity,
            "entitlement": entitlement, "approval_id": approval_id, "owner": owner}])], ignore_index=True)

    def approval(self, identity, ent, approved_at, approvers):
        aid = f"tmp-apr-{len(self.d['approvals']) + 1}"
        self.d["approvals"] = pd.concat([self.d["approvals"], pd.DataFrame([{
            "approval_id": aid, "identity": identity, "entitlement": ent,
            "requested_at": approved_at - pd.Timedelta(hours=int(self.rng.integers(2, 20))),  # same spread as ordinary approvals
            "approved_at": approved_at, "approvers": approvers, "status": "approved"}])], ignore_index=True)
        return aid

    def auth(self, t, identity, src, dst):
        """A server logon written exactly like the server log's own rows (same source, account and host naming)."""
        t = t.floor("min") + pd.Timedelta(milliseconds=int(self.pick(self.auth_offsets)))
        self.d["auth"] = pd.concat([self.d["auth"], pd.DataFrame([{
            "time": t, "identity": identity, "account_name": self.account_of.get(identity, identity.split(":", 1)[1]),
            "src_asset": src, "dst_asset": dst, "src_host": self.host_of.get(src, src), "dst_host": self.host_of.get(dst, dst),
            "activity": "Logon", "success": True, "logon_type": 3, "auth_protocol": 2,
            "source": self.server_source, "source_id": f"p{len(self.d['auth'])}"}])], ignore_index=True)

    def flow(self, t, src, dst, port, ndpi, proto=6):
        """A planted flow reuses the statistics (bytes, packets, duration, flags, source port, sub-minute timing) of
        a real 'donor' flow from the dataset: one with the same application protocol if the data has any, otherwise
        any flow of the same transport protocol. Only the addresses, destination port and minute are rewritten, so the
        planted flow carries no synthetic signature."""
        if self.d["flows"] is None:
            return "none"
        zone = self.cfg.asset_zone | {a: "USER" for a in self.ip_of if a.startswith("WS:")}
        b = self.base_flows
        donors = b[b.ndpi_master == ndpi]
        kind = "same_application"
        if not len(donors):
            donors, kind = b[b.proto == proto], "same_transport"
        dn = donors.iloc[int(self.rng.integers(len(donors)))]
        ms = int(t.floor("min").value // 10**6) + int(dn.time_ms % 60_000)
        self.d["flows"] = pd.concat([self.d["flows"], pd.DataFrame([{
            "time_ms": ms, "end_ms": ms + int(dn.end_ms - dn.time_ms), "src_ip": self.ip_of[src],
            "src_port": int(dn.src_port), "dst_ip": self.ip_of[dst], "dst_port": port, "proto": proto,
            "bytes_in": int(dn.bytes_in), "bytes_out": int(dn.bytes_out), "pkts_in": int(dn.pkts_in),
            "pkts_out": int(dn.pkts_out), "tcp_flags": int(dn.tcp_flags),
            "ndpi_master": ndpi, "src_asset": src, "dst_asset": dst, "src_zone": zone[src], "dst_zone": zone[dst],
            "time": pd.Timestamp(ms, unit="ms")}])], ignore_index=True)
        return kind

    def state(self):
        return grant_intervals(self.d["iam_events"], self.cfg), account_intervals(self.d["iam_events"])

    def active_humans(self, t, min_remaining_days=30):
        p = self.d["people"]
        ok = (p.start <= t) & (p.termination.isna() | (p.termination > t + pd.Timedelta(days=min_remaining_days)))
        return [f"U:{u}" for u in p.loc[ok, "user_id"] if f"U:{u}" not in self.used]

    def pick(self, seq):
        return seq[int(self.rng.integers(len(seq)))]

    # ---------------------------------------------------------------- criteria
    def ac01(self):
        t = self.when()
        G, _ = self.state()
        role = self.d["people"].set_index("user_id").role
        for ident in self.rng.permutation(self.active_humans(t)):
            held = set(G[(G.identity == ident) & (G.granted_at <= t) & (G.revoked_at > t)].entitlement)
            partners = sorted(b for b in {b for e in held for b in self.cfg.conflicts(e)} - held
                              if not self.cfg.ent_privileged[b])  # keep the planted case specific to AC-01
            if partners:
                ent = self.pick(partners)
                aid = self.approval(ident, ent, t - self.lead(), "line_manager;asset_owner")
                self.iam(t, "grant", ident, ent, aid)
                self.used.add(ident)
                return self.record("AC-01", "approved_conflicting_grant", ident, t,
                                   f"{role[ident[2:]]} granted {ent}, which conflicts with a held entitlement", ent)

    def ac02(self):
        p = self.d["people"]
        leavers = [u for u in p.loc[p.termination.notna(), "user_id"] if f"U:{u}" not in self.used
                   and p.set_index("user_id").termination[u] < self.end - pd.Timedelta(days=10)]
        if not leavers:
            return None
        u = self.pick(leavers)
        ident = f"U:{u}"
        term = p.set_index("user_id").termination[u]
        deadline = business_deadline(term, self.cfg.settings["leaver_grace_days"])
        ev = self.d["iam_events"]
        self.d["iam_events"] = ev[~((ev.identity == ident) & (ev.event == "account_disable"))]
        delay = int(self.rng.integers(2, 25))
        variant = "late_disable"
        late = deadline + pd.Timedelta(days=delay)
        if late < self.end:
            self.iam(late, "account_disable", ident)
        else:
            variant = "never_disabled"
        if self.rng.random() < 0.5 and self.ws_of.get(ident):
            tu = deadline + pd.Timedelta(days=1, hours=1)
            self.auth(tu, ident, self.ws_of[ident], "FILE-SRV")
            variant += "+used_after_termination"
        self.used.add(ident)
        return self.record("AC-02", variant, ident, deadline, f"leaver terminated {term:%Y-%m-%d}; disable delayed {delay} days",
                           t_end=min(late, self.end))

    def ac03(self):
        ids = self.d["identities"]
        nh = [i for i in ids.loc[ids.kind != "human", "identity"] if i not in self.used]
        p = self.d["people"]
        lv = p[p.termination.notna() & (p.termination > self.start + pd.Timedelta(days=14))
               & (p.termination < self.end - pd.Timedelta(days=10))]
        if not nh:
            return None
        ident = self.pick(nh)
        ev = self.d["iam_events"]
        if len(lv) and self.rng.random() < 0.7:
            owner = lv.iloc[int(self.rng.integers(len(lv)))]
            t = owner.termination - pd.Timedelta(days=int(self.rng.integers(5, 12)))
            self.d["iam_events"] = ev[~((ev.identity == ident) & (ev.event == "owner_set") & (ev.time > t))]
            self.iam(t, "owner_set", ident, owner=f"U:{owner.user_id}")
            variant, desc = "owner_left_not_reassigned", f"owner set to {owner.user_id}, who leaves {owner.termination:%Y-%m-%d}"
        else:
            t = self.when()
            self.d["iam_events"] = ev[~((ev.identity == ident) & (ev.event == "owner_set") & (ev.time > t))]
            self.iam(t, "owner_set", ident, owner="")
            variant, desc = "owner_removed", "owner cleared, no accountable person"
        self.used.add(ident)
        return self.record("AC-03", variant, ident, t, desc)

    def ac04(self):
        t = self.when()
        G, _ = self.state()
        role = self.d["people"].set_index("user_id").role
        for ident in self.rng.permutation(self.active_humans(t)):
            held = set(G[(G.identity == ident) & (G.granted_at <= t) & (G.revoked_at > t)].entitlement)
            opts = [e for e in plausible_extras(self.cfg, role[ident[2:]]) if e not in held and not (self.cfg.conflicts(e) & held)]
            if opts:
                ent = self.pick(opts)
                if self.rng.random() < 0.6:
                    self.iam(t, "grant", ident, ent, "")
                    variant = "no_approval"
                else:
                    aid = self.approval(ident, ent, t + self.lead(), "line_manager;asset_owner")
                    self.iam(t, "grant", ident, ent, aid)
                    variant = "approval_after_grant"
                self.used.add(ident)
                return self.record("AC-04", variant, ident, t, f"{ent} granted outside role baseline", ent)

    def ac05(self):
        t = self.start + pd.Timedelta(days=int(self.rng.integers(0, 10)), hours=10)
        G, _ = self.state()
        role = self.d["people"].set_index("user_id").role
        auth = self.d["auth"]
        horizon = t + pd.Timedelta(days=self.cfg.settings["review_window_days"] + 7)
        for ident in self.rng.permutation(self.active_humans(t, min_remaining_days=(horizon - t).days + 14)):
            if horizon > self.end:
                return None
            held = set(G[G.identity == ident].entitlement)
            touched = set(auth.loc[auth.identity == ident, "dst_asset"])
            opts = [e for e in plausible_extras(self.cfg, role[ident[2:]]) if e not in held
                    and self.cfg.ent_asset[e] not in touched and not (self.cfg.conflicts(e) & held)]
            if opts:
                ent = self.pick(opts)
                aid = self.approval(ident, ent, t - self.lead(), "line_manager;asset_owner")
                self.iam(t, "grant", ident, ent, aid)
                self.used.add(ident)
                return self.record("AC-05", "never_used", ident, t, f"{ent} approved and granted but never used", ent)

    def ac06(self):
        t = self.when(hi_week=self.weeks - 2)
        G, _ = self.state()
        role = self.d["people"].set_index("user_id").role
        for ident in self.rng.permutation(self.active_humans(t)):
            r = role[ident[2:]]
            held = set(G[(G.identity == ident) & (G.granted_at <= t) & (G.revoked_at > t)].entitlement)
            ok = set(plausible_extras(self.cfg, r)) | self.cfg.roles[r]
            opts = [e for e in self.cfg.entitlements.entitlement if e not in ok and e not in held
                    and not self.cfg.ent_privileged[e] and not (self.cfg.conflicts(e) & held)]
            if opts:
                ent = self.pick(opts)
                aid = self.approval(ident, ent, t - self.lead(), "line_manager;asset_owner")
                self.iam(t, "grant", ident, ent, aid)
                variant = "approved_unused"
                if self.rng.random() < 0.6 and self.ws_of.get(ident):
                    variant = "approved_and_used"
                    for k in range(1, 4):
                        tu = t + pd.Timedelta(days=7 * k + int(self.rng.integers(-2, 3)), minutes=int(self.rng.integers(-180, 180)))
                        if tu < self.end:
                            self.auth(tu, ident, self.ws_of[ident], self.cfg.ent_asset[ent])
                self.used.add(ident)
                return self.record("AC-06", variant, ident, t,
                                   f"{r} granted {ent} with a rubber-stamped approval; not justified by role", ent)

    def ac07(self):
        G, A = self.state()
        # the pool is small (a few administrator roles), so AC-07 is planted first (see inject_all) and may use two
        # different privileged entitlements of the same administrator, but never the same grant twice
        priv = G[G.privileged & G.asset_id.isin(self.cfg.cia_assets) & G.identity.str.startswith("U:")
                 & (G.revoked_at == FAR)]
        priv = priv[[(i, e) not in self.ac07_done for i, e in zip(priv.identity, priv.entitlement)]]
        if not len(priv):
            return None
        t = self.when()
        r = priv.iloc[int(self.rng.integers(len(priv)))]
        if A.disabled_at.get(r.identity, pd.Timestamp.max) < t + pd.Timedelta(days=14):
            return None
        self.iam(t - pd.Timedelta(minutes=10), "revoke", r.identity, r.entitlement, tag="r")
        v = self.pick(["no_approval", "owner_only", "approved_after_grant"])
        aid = "" if v == "no_approval" else self.approval(
            r.identity, r.entitlement, t + (self.lead() if v == "approved_after_grant" else -self.lead()),
            "asset_owner" if v == "owner_only" else "asset_owner;ciso")
        self.iam(t, "grant", r.identity, r.entitlement, aid)
        self.used.add(r.identity)
        self.ac07_done.add((r.identity, r.entitlement))
        return self.record("AC-07", v, r.identity, t, f"privileged {r.entitlement} re-granted without valid CISO pre-approval",
                           r.entitlement)

    def ac08(self):
        t = self.when()
        G, _ = self.state()
        for ident in self.rng.permutation(self.active_humans(t)):
            have = set(G[(G.identity == ident) & (G.granted_at <= t) & (G.revoked_at > t)].asset_id)
            opts = sorted(a for a in self.cfg.cia_assets - have if self.cfg.asset_zone[a] in ("SERVER", "DATABASE"))
            if opts and self.ws_of.get(ident):
                asset = self.pick(opts)
                self.auth(t, ident, self.ws_of[ident], asset)
                if self.cfg.asset_zone[asset] == "SERVER":
                    self.flow(t, self.ws_of[ident], asset, 443, 91)
                self.used.add(ident)
                return self.record("AC-08", "access_without_entitlement", ident, t, f"authenticated to {asset} without entitlement")

    def fw_rule(self, src, dst, service, t, t_end, ref):
        fw = self.d["firewall_rules"]
        rid = f"tmp-fw-{len(fw) + 1}"
        self.d["firewall_rules"] = pd.concat([fw, pd.DataFrame([{"rule_id": rid, "src_zone": src, "dst_zone": dst,
                                              "service": service, "action": "permit", "valid_from": t,
                                              "valid_to": t_end, "change_ref": ref}])], ignore_index=True)
        return rid

    def nw(self, criterion):
        t = self.when()
        temp = self.rng.random() < 0.4
        t_end = t + pd.Timedelta(days=int(self.rng.integers(2, 20))) if temp else pd.NaT
        if criterion == "NW-01":
            (src, dst), svc = self.pick(sorted(self.cfg.zone_matrix)), self.pick(["telnet", "ftp", "http", "smbv1"])
        elif criterion == "NW-02":
            src, dst, svc = self.pick([("ANY", "DATABASE", "db-tls"), ("ANY", "MANAGEMENT", "ssh"),
                                       ("USER", "MANAGEMENT", "ANY"), ("SERVER", "DATABASE", "ANY")])
        else:
            src, dst, svc = self.pick(OFF_MATRIX_RULES)
        rid = self.fw_rule(src, dst, svc, t, t_end, "")
        return self.record(criterion, "temporary_rule" if temp else "permanent_rule", rid, t, f"{src}->{dst}:{svc}",
                           t_end=None if pd.isna(t_end) else t_end)

    def src_for(self, kind):
        if kind != "WS":
            return kind
        return self.pick(sorted(v for v in self.ws_of.values() if v in self.ip_of))

    def nw04(self):
        t = self.when()
        src, dst, svc = self.pick(OFF_MATRIX_FLOWS)
        s = self.cfg.services.set_index("service").loc[svc]
        src = self.src_for(src)
        for k in range(int(self.rng.integers(1, 6))):
            donor = self.flow(t + pd.Timedelta(minutes=int(self.rng.integers(1, 240)) * k), src, dst, int(s.port), int(s.ndpi_id))
        return self.record("NW-04", "flow_outside_zone_matrix", dst, t, f"{src}->{dst}:{svc}; donor={donor}")

    def nw05(self):
        t = self.when()
        if self.rng.random() < 0.5:
            src, dst, svc = self.pick(PROHIBITED_FLOWS)
            s = self.cfg.services.set_index("service").loc[svc]
            port, ndpi, variant = int(s.port), int(s.ndpi_id), "cleartext_standard_port"
        else:
            src, dst, ndpi, port = self.pick(DISGUISED)
            variant = "cleartext_disguised_port"
        src = self.src_for(src)
        for k in range(int(self.rng.integers(1, 6))):
            donor = self.flow(t + pd.Timedelta(minutes=int(self.rng.integers(1, 240)) * k), src, dst, port, ndpi)
        return self.record("NW-05", variant, dst, t, f"{src}->{dst} port {port}, nDPI {ndpi} (cleartext); donor={donor}")


def _hid(prefix, *parts, n=8):
    return f"{prefix}-{hashlib.sha1('|'.join(str(x) for x in parts).encode()).hexdigest()[:n].upper()}"


def neutral_ids(d, records):
    """Give EVERY record (ordinary and planted) an identifier derived from its content, so that nothing in an id,
    its prefix or its numeric order reveals which records were planted. Updates references and the injection log."""
    apr = d["approvals"]
    amap = {r.approval_id: _hid("APR", r.identity, r.entitlement, r.requested_at, r.approved_at, i)
            for i, r in enumerate(apr.itertuples())}
    apr["approval_id"] = apr.approval_id.map(amap)
    ev = d["iam_events"]
    ev["approval_id"] = ev.approval_id.map(lambda a: amap.get(a, "") if a else "")
    ev["event_id"] = [_hid("IAM", r.time, r.event, r.identity, r.entitlement, i) for i, r in enumerate(ev.itertuples())]
    fw = d["firewall_rules"]
    fmap = {r.rule_id: _hid("FW", r.src_zone, r.dst_zone, r.service, r.valid_from, n=6) for r in fw.itertuples()}
    assert len(set(fmap.values())) == len(fmap) and len(set(amap.values())) == len(amap), "id collision"
    fw["rule_id"] = fw.rule_id.map(fmap)
    fw["change_ref"] = [_hid("CHG", r.rule_id, r.valid_from, n=5) for r in fw.itertuples()]
    if len(records):
        records["entity"] = records.entity.map(lambda e: fmap.get(e, e))
    d["firewall_rules"] = fw.sample(frac=1.0, random_state=0).reset_index(drop=True)  # row order carries no signal either
    d["approvals"] = apr.sort_values("requested_at", kind="stable").reset_index(drop=True)


def inject_all(d, cfg: Config):
    s = cfg.settings["injection"]
    inj = Injector(d, cfg, s["seed"])
    plan = {"AC-07": inj.ac07, "AC-01": inj.ac01, "AC-02": inj.ac02, "AC-03": inj.ac03, "AC-04": inj.ac04, "AC-05": inj.ac05,
            "AC-06": inj.ac06, "AC-08": inj.ac08, "NW-01": lambda: inj.nw("NW-01"),
            "NW-02": lambda: inj.nw("NW-02"), "NW-03": lambda: inj.nw("NW-03"), "NW-04": inj.nw04, "NW-05": inj.nw05}
    shortfall = {}
    for crit, fn in plan.items():
        made = 0
        for _ in range(s["per_criterion"] * 5):
            if made == s["per_criterion"]:
                break
            if fn() is not None:
                made += 1
        if made < s["per_criterion"]:
            shortfall[crit] = made
    records = pd.DataFrame(inj.records)
    for k in ("iam_events", "auth"):
        d[k] = d[k].sort_values("time", kind="stable").reset_index(drop=True)
    neutral_ids(d, records)
    if d["flows"] is not None:
        d["flows"] = d["flows"].sort_values("time_ms", kind="stable").reset_index(drop=True)
    return records, shortfall
