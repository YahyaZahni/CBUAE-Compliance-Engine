"""Institution state that no public dataset provides: identities, entitlement grants, approvals, owners of
non-human identities, and the firewall rule base.

The simulated state is CONFORMING by construction (baseline). Nonconformities are added afterwards by
inject.py, so the answer key is exact. The state is written to raw/iam/*.csv in documented, plain formats so it
can be replaced by real exports (e.g. an IAM system and a firewall manager) without code changes.
"""
import numpy as np
import pandas as pd

from .config import Config

NONHUMAN = {
    "service_account": [("svc-payments-batch", ["PAY-INITIATE", "REPORT-READ"]), ("svc-gl-interface", ["GL-POST"]),
                        ("svc-reporting", ["REPORT-READ", "FILE-SHARE"]), ("svc-kyc-sync", ["CUST-READ"]),
                        ("svc-backup", ["FILE-SHARE"]), ("svc-hr-sync", ["HR-READ"]),
                        ("svc-trade-feed", ["TRADE-SETTLE"]), ("svc-loan-scoring", ["LOAN-CREATE", "CUST-READ"]),
                        ("svc-archive", ["FILE-SHARE", "REPORT-READ"]), ("svc-monitoring", ["REPORT-READ"]),
                        ("svc-deploy", ["DEV-DEPLOY"]), ("svc-statements", ["CUST-READ", "REPORT-READ"])],
    "ai_agent": [("agent-kyc-assistant", ["CUST-READ"]), ("agent-report-writer", ["REPORT-READ"]),
                 ("agent-helpdesk", ["FILE-SHARE"]), ("agent-credit-memo", ["CUST-READ", "REPORT-READ"])],
}
OWNER_POOL = {"service_account": ["ITAdmin", "Developer", "DBAdmin"],
              "ai_agent": ["ComplianceOfficer", "RelationshipManager", "Developer"]}


class Ids:
    def __init__(self, prefix):
        self.prefix, self.n = prefix, 0

    def __call__(self):
        self.n += 1
        return f"{self.prefix}-{self.n:05d}"


def plausible_extras(cfg: Config, role):
    """Entitlements a person in this role may legitimately be granted with approval: other baselines in the same
    business function plus generic read entitlements, excluding SoD conflicts and privileged entitlements."""
    fn = cfg.role_function[role]
    pool = set().union(*[cfg.roles[r] for r in cfg.roles if cfg.role_function[r] == fn]) | {"REPORT-READ", "FILE-SHARE"}
    base = cfg.roles[role]
    return sorted(e for e in pool - base if not cfg.ent_privileged[e] and not (cfg.conflicts(e) & base))


def simulate_state(people: pd.DataFrame, cfg: Config, start: pd.Timestamp, end: pd.Timestamp, seed: int,
                   grant_baseline: bool = True):
    """people: user_id, role, start, termination (NaT if still employed). Returns dict of state tables."""
    rng = np.random.default_rng(seed)
    n_weeks = max(2, (end - start).days // 7)

    def working_time(last_week):
        """A weekday business-hours moment in the window: the same clock pattern inject.py uses for planted changes,
        so that neither the weekday nor the time of day of a change separates ordinary changes from planted ones."""
        return start + pd.Timedelta(days=7 * int(rng.integers(0, last_week)) + int(rng.integers(0, 5)),
                                    minutes=int(rng.integers(480, 1020)))
    ev_id, apr_id = Ids("IAM"), Ids("APR")
    events, approvals, identities = [], [], []
    cia, owner_role = cfg.cia_assets, cfg.asset_owner_role

    def approve(identity, ent, grant_time, approvers):
        aid = apr_id()
        req = grant_time - pd.Timedelta(days=int(rng.integers(1, 4)), hours=int(rng.integers(0, 8)))
        approvals.append({"approval_id": aid, "identity": identity, "entitlement": ent, "requested_at": req,
                          "approved_at": req + pd.Timedelta(hours=int(rng.integers(2, 20))),
                          "approvers": approvers, "status": "approved"})
        return aid

    def grant(identity, ent, t, extra):
        aid = ""
        if cfg.ent_privileged[ent] and cfg.ent_asset[ent] in cia:
            aid = approve(identity, ent, t, "asset_owner;ciso")          # POL-AC-03
        elif extra:
            aid = approve(identity, ent, t, "line_manager;asset_owner")  # POL-AC-01
        events.append({"event_id": ev_id(), "time": t, "event": "grant", "identity": identity, "entitlement": ent,
                       "approval_id": aid, "owner": ""})

    for p in people.itertuples():
        ident = f"U:{p.user_id}"
        t0 = max(p.start, start - pd.Timedelta(days=1)) + pd.Timedelta(hours=9)
        identities.append({"identity": ident, "kind": "human", "account_name": p.user_id, "role": p.role,
                           "hr_start": p.start, "hr_termination": p.termination})
        events.append({"event_id": ev_id(), "time": t0, "event": "account_create", "identity": ident,
                       "entitlement": "", "approval_id": "", "owner": ""})
        # public mode grants only what activity shows is used (align_entitlements_with_activity), so no blind baselines
        for e in sorted(cfg.roles[p.role]) if grant_baseline else []:
            grant(ident, e, t0 + pd.Timedelta(minutes=5), extra=False)
        if grant_baseline and rng.random() < 0.30:  # benign, approved extra entitlement (negative examples for AC-06)
            extras = plausible_extras(cfg, p.role)
            if extras:
                # spread over the whole window: ordinary approved changes keep happening, so "granted after the
                # first weeks" is not a tell for a planted grant
                tg = working_time(n_weeks - 2)
                if tg > t0 and (pd.isna(p.termination) or tg < p.termination - pd.Timedelta(days=14)):
                    grant(ident, extras[int(rng.integers(len(extras)))], tg, extra=True)
        if pd.notna(p.termination):  # conforming leaver: disabled on the termination day or next business day
            lag = pd.Timedelta(hours=int(rng.integers(17, 20))) if rng.random() < 0.85 else pd.Timedelta(days=1, hours=10)
            td = p.termination + lag
            if td.weekday() >= 5:  # move a weekend disable to Monday morning (still within one business day)
                td = (td + pd.offsets.Week(weekday=0)).normalize() + pd.Timedelta(hours=8)
            events.append({"event_id": ev_id(), "time": td, "event": "account_disable", "identity": ident,
                           "entitlement": "", "approval_id": "", "owner": ""})

    # non-human identities with an accountable owner who is an active employee (POL-IM-03)
    def active_people(at, roles):
        m = people.role.isin(roles) & (people.start <= at) & (people.termination.isna() | (people.termination > at))
        return people[m]

    for kind, items in NONHUMAN.items():
        n = cfg.settings["sample"]["service_accounts" if kind == "service_account" else "ai_agents"]
        for name, ents in items[:n]:
            ident = f"{'S' if kind == 'service_account' else 'A'}:{name}"
            t = start - pd.Timedelta(days=1) + pd.Timedelta(hours=10)
            cand = active_people(start, OWNER_POOL[kind])
            owner = cand.sample(1, random_state=int(rng.integers(1e9))).iloc[0]
            identities.append({"identity": ident, "kind": kind, "account_name": name, "role": "",
                               "hr_start": pd.NaT, "hr_termination": pd.NaT})
            events.append({"event_id": ev_id(), "time": t, "event": "account_create", "identity": ident,
                           "entitlement": "", "approval_id": "", "owner": ""})
            events.append({"event_id": ev_id(), "time": t, "event": "owner_set", "identity": ident,
                           "entitlement": "", "approval_id": "", "owner": f"U:{owner.user_id}"})
            for e in ents:
                grant(ident, e, t + pd.Timedelta(minutes=5), extra=True)
            # reassign ownership before the owner leaves, repeatedly if needed
            cur = owner
            while pd.notna(cur.termination) and cur.termination < end:
                tr = cur.termination - pd.Timedelta(days=2) + pd.Timedelta(hours=11)
                cand = active_people(cur.termination + pd.Timedelta(days=1), OWNER_POOL[kind])
                cur = cand.sample(1, random_state=int(rng.integers(1e9))).iloc[0]
                events.append({"event_id": ev_id(), "time": tr, "event": "owner_set", "identity": ident,
                               "entitlement": "", "approval_id": "", "owner": f"U:{cur.user_id}"})

    # firewall rule base: one permit rule per zone-matrix entry (conforming), default deny implied (POL-NS-02)
    rules = []
    for i, ((src, dst), svcs) in enumerate(sorted(cfg.zone_matrix.items())):
        for s in sorted(svcs):
            rule = {"rule_id": f"FW-{len(rules) + 1:04d}", "src_zone": src, "dst_zone": dst, "service": s,
                    "action": "permit", "valid_from": start - pd.Timedelta(days=30), "valid_to": pd.NaT,
                    "change_ref": "baseline"}
            if rng.random() < 0.2:
                # ordinary rule-base maintenance: the rule is re-issued under a new id during the window (conforming
                # before and after), so a rule that appears or disappears mid-window is not by itself a finding
                tc = working_time(n_weeks - 1)
                rules.append({**rule, "valid_to": tc})
                rule = {**rule, "rule_id": f"FW-{len(rules) + 1:04d}", "valid_from": tc}
            rules.append(rule)
    return {"identities": pd.DataFrame(identities),
            "iam_events": pd.DataFrame(events).sort_values("time", kind="stable").reset_index(drop=True),
            "approvals": pd.DataFrame(approvals), "firewall_rules": pd.DataFrame(rules)}
