"""Ground truth (answer key) for every case = criterion x entity x period.

These 'oracles' apply each criterion's pass condition (catalogue/criteria.json) to the COMPLETE, TRUE state of the
institution, including information hidden from the checkers (e.g. the nDPI application label of each flow).
They define the answer key; they are not the system under test. For crisp criteria a rule-based checker that
sees the same evidence will match the oracle by design: the experiment's value lies in timeliness (vs. periodic
audit) and in the judgement-based criteria (AC-06, NW-05 on disguised ports), whose truth comes from injection
metadata and hidden labels that checkers cannot see.
"""
import numpy as np
import pandas as pd

from .config import Config, business_deadline

FAR = pd.Timestamp("2262-01-01")


# ------------------------------------------------------------------ state reconstruction
def grant_intervals(ev, cfg: Config):
    g = ev[ev.event.isin(["grant", "revoke"])].sort_values("time", kind="stable")
    rows, open_ = [], {}
    for r in g.itertuples():
        k = (r.identity, r.entitlement)
        if r.event == "grant":
            if k not in open_:
                open_[k] = (r.time, r.approval_id, r.event_id)
        elif k in open_:
            t0, aid, eid = open_.pop(k)
            rows.append((r.identity, r.entitlement, t0, r.time, aid, eid))
    rows += [(i, e, t0, FAR, aid, eid) for (i, e), (t0, aid, eid) in open_.items()]
    df = pd.DataFrame(rows, columns=["identity", "entitlement", "granted_at", "revoked_at", "approval_id", "event_id"])
    df["asset_id"] = df.entitlement.map(cfg.ent_asset)
    df["privileged"] = df.entitlement.map(cfg.ent_privileged)
    return df


def account_intervals(ev):
    c = ev[ev.event == "account_create"].groupby("identity").time.min()
    d = ev[ev.event == "account_disable"].groupby("identity").time.max()
    out = pd.DataFrame({"created_at": c}).join(pd.DataFrame({"disabled_at": d}))
    out["disabled_at"] = out.disabled_at.fillna(FAR)
    return out


def periods(start, end):
    s = pd.date_range(start, end, freq="7D")
    return pd.DataFrame({"period": range(len(s) - 1), "start": s[:-1],
                         "end": s[1:] - pd.Timedelta(milliseconds=1)})


def approval_ok(approvals, aid, granted_at, need=("line_manager", "asset_owner", "ciso"), any_of=True):
    """True if approval exists, is approved, dated on/before the grant, and has the required approvers."""
    if not isinstance(aid, str) or not aid or aid not in approvals.index:
        return False
    a = approvals.loc[aid]
    if a.status != "approved" or pd.isna(a.approved_at) or a.approved_at > granted_at:
        return False
    have = set(str(a.approvers).split(";"))
    return bool(have & set(need)) if any_of else set(need) <= have


# ------------------------------------------------------------------ oracles
def build_cases(d, cfg: Config, injections: pd.DataFrame):
    ev, apr = d["iam_events"], d["approvals"].set_index("approval_id")
    G = grant_intervals(ev, cfg)
    A = account_intervals(ev)
    P = periods(d["start"], d["end"])
    people = d["people"].assign(identity=lambda x: "U:" + x.user_id).set_index("identity")
    kinds = d["identities"].set_index("identity").kind
    role = people.role
    auth = d["auth"][d["auth"].success]
    srv_auth = auth[(auth.source != "cert") & ~cfg.directory_logon(auth)]
    window = pd.Timedelta(days=cfg.settings["review_window_days"])
    inappropriate = set(zip(injections.loc[injections.criterion == "AC-06", "entity"],
                            injections.loc[injections.criterion == "AC-06", "entitlement"]))
    owners = ev[ev.event == "owner_set"].sort_values("time", kind="stable")
    cases = []

    def add(cid, entity, p, nonconf, detail=""):
        cases.append({"criterion": cid, "entity": entity, "period": p.period, "period_start": p.start,
                      "period_end": p.end, "truth": "nonconforming" if nonconf else "conforming", "detail": detail})

    sod = [(a, b) for a, b, _ in cfg.sod_pairs]
    for p in P.itertuples():
        enabled = A[(A.created_at <= p.end) & (A.disabled_at > p.end)].index
        held = G[(G.granted_at <= p.end) & (G.revoked_at > p.end) & G.identity.isin(enabled)]
        by_id = held.groupby("identity")
        for ident, h in by_id:
            ents = set(h.entitlement)
            # AC-01 segregation of duties
            bad = [f"{a}+{b}" for a, b in sod if a in ents and b in ents]
            add("AC-01", ident, p, bool(bad), ";".join(bad))
            # AC-04 out-of-baseline entitlements need a prior approval
            base = cfg.roles.get(role.get(ident, ""), set())
            bad = [r.entitlement for r in h.itertuples() if r.entitlement not in base
                   and not approval_ok(apr, r.approval_id, r.granted_at)]
            add("AC-04", ident, p, bool(bad), ";".join(bad))
            # AC-07 privileged entitlements on Critical Information Assets need owner + CISO approval before grant
            priv = h[h.privileged & h.asset_id.isin(cfg.cia_assets)]
            if len(priv):
                bad = [r.entitlement for r in priv.itertuples()
                       if not approval_ok(apr, r.approval_id, r.granted_at, ("asset_owner", "ciso"), any_of=False)]
                add("AC-07", ident, p, bool(bad), ";".join(bad))
            # AC-06 least privilege (judgement): truth from injected inappropriate grants only
            if kinds.get(ident) == "human":
                bad = [e for e in ents if (ident, e) in inappropriate]
                add("AC-06", ident, p, bool(bad), ";".join(bad))
            # AC-05 unused entitlements (only once a full review window of evidence exists)
            if p.end - d["start"] >= window:
                used = srv_auth[(srv_auth.identity == ident) & (srv_auth.time <= p.end)].groupby("dst_asset").time.max()
                bad = [r.entitlement for r in h.itertuples() if r.granted_at <= p.end - window
                       and used.get(r.asset_id, pd.Timestamp.min) < p.end - window]
                add("AC-05", ident, p, bool(bad), ";".join(bad))
        # AC-03 non-human identities need an owner who is an active employee
        for ident in [i for i in enabled if kinds.get(i) in ("service_account", "ai_agent")]:
            o = owners[(owners.identity == ident) & (owners.time <= p.end)]
            owner = o.owner.iloc[-1] if len(o) else ""
            ok = bool(owner) and owner in people.index and people.start[owner] <= p.end and \
                (pd.isna(people.termination[owner]) or people.termination[owner] + pd.Timedelta(days=1) > p.end)
            add("AC-03", ident, p, not ok, f"owner={owner or 'none'}")
        # AC-08 access to Critical Information Assets only by entitled identities
        pa = srv_auth[(srv_auth.time >= p.start) & (srv_auth.time <= p.end) & srv_auth.dst_asset.isin(cfg.cia_assets)]
        for ident, rows in pa.groupby("identity"):
            gi = G[G.identity == ident]
            bad = [f"{r.dst_asset}@{r.time}" for r in rows.itertuples()
                   if not ((gi.asset_id == r.dst_asset) & (gi.granted_at <= r.time) & (gi.revoked_at > r.time)).any()]
            add("AC-08", ident, p, bool(bad), ";".join(bad[:3]))

    # AC-02 leavers disabled within one business day of HR termination, and no use after the deadline
    grace = cfg.settings["leaver_grace_days"]
    for ident, pr in people[people.termination.notna()].iterrows():
        deadline = business_deadline(pr.termination, grace)
        dis = A.disabled_at.get(ident, FAR)
        after = auth[(auth.identity == ident) & (auth.time > deadline)]
        last = max([deadline, min(dis, d["end"])] + list(after.time))
        for p in P[(P.end >= deadline) & (P.start <= last)].itertuples():
            lo = max(deadline, p.start)
            late = dis > lo and lo <= p.end
            used = after[(after.time >= p.start) & (after.time <= p.end)]
            add("AC-02", ident, p, bool(late or len(used)),
                f"deadline={deadline:%Y-%m-%d}; disabled={'never' if dis == FAR else f'{dis:%Y-%m-%d %H:%M}'}; uses={len(used)}")

    # NW-01..03 firewall rule base: every rule in force at any time during the period
    fw = d["firewall_rules"]
    prohibited = set(cfg.services.loc[cfg.services.prohibited, "service"])
    for p in P.itertuples():
        live = fw[(fw.valid_from <= p.end) & (fw.valid_to.isna() | (fw.valid_to > p.start)) & (fw.action == "permit")]
        for r in live.itertuples():
            add("NW-01", r.rule_id, p, r.service in prohibited, r.service)
            add("NW-02", r.rule_id, p, r.dst_zone in ("DATABASE", "MANAGEMENT") and "ANY" in (r.src_zone, r.service),
                f"{r.src_zone}->{r.dst_zone}:{r.service}")
            add("NW-03", r.rule_id, p, r.service not in cfg.zone_matrix.get((r.src_zone, r.dst_zone), set()),
                f"{r.src_zone}->{r.dst_zone}:{r.service}")

    # NW-04 / NW-05 observed traffic
    f = d["flows"]
    if f is not None:
        svc = [cfg.port_service.get(("tcp" if pr == 6 else "udp", int(pt))) for pr, pt in zip(f.proto, f.dst_port)]
        allowed = np.array([s in cfg.zone_matrix.get((a, b), set()) for s, a, b in zip(svc, f.src_zone, f.dst_zone)])
        clear = f.ndpi_master.isin(cfg.cleartext_ndpi).to_numpy()
        internal = ~f.dst_asset.eq("EXTERNAL").to_numpy()
        cia = f.dst_asset.isin(cfg.cia_assets).to_numpy()
        pidx = np.searchsorted(P.start.to_numpy(), f.time.to_numpy(), side="right") - 1
        tab = pd.DataFrame({"period": pidx, "asset": f.dst_asset, "bad4": ~allowed, "bad5": clear})
        for (pi, asset), g in tab[internal & (pidx >= 0) & (pidx < len(P))].groupby(["period", "asset"]):
            p = P.iloc[pi]
            add("NW-04", asset, p, bool(g.bad4.any()), f"{int(g.bad4.sum())} flows outside zone matrix")
        for (pi, asset), g in tab[cia & (pidx >= 0) & (pidx < len(P))].groupby(["period", "asset"]):
            p = P.iloc[pi]
            add("NW-05", asset, p, bool(g.bad5.any()), f"{int(g.bad5.sum())} cleartext flows")

    cases = pd.DataFrame(cases)
    cases.insert(0, "case_id", [f"CASE-{i:06d}" for i in range(1, len(cases) + 1)])
    return cases, P
