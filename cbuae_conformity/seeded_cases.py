"""Seeded test cases for rule validation (hand-written; independent of the evaluation answer key).

The same scenarios as rules/tests/rules_test.rego, expressed as data so that ANY rule package (reference or
LLM-generated) exposing `scope` and `violations` can be checked by the validator.
"""
import copy

FAR = 9_000_000_000_000
PARAMS = {
    "leaver_grace_days": 1, "review_window_ms": 1000, "directory_assets": ["AD-DC"],
    "sod_pairs": [["PAY-INITIATE", "PAY-APPROVE"]],
    "role_baselines": {"PaymentsOfficer": ["PAY-INITIATE", "CUST-READ"]},
    "zone_matrix": {"USER->SERVER": ["https"], "SERVER->DATABASE": ["db-tls"]},
    "services": {"https": {"protocol": "tcp", "port": 443, "encrypted": True, "prohibited": False},
                 "db-tls": {"protocol": "tcp", "port": 1433, "encrypted": True, "prohibited": False},
                 "telnet": {"protocol": "tcp", "port": 23, "encrypted": False, "prohibited": True}},
    "port_service": {"tcp/443": "https", "tcp/1433": "db-tls", "tcp/23": "telnet"},
    "assets": {"PAY-APP": {"zone": "SERVER", "cia": True, "owner_role": "x"},
               "CORE-DB": {"zone": "DATABASE", "cia": True, "owner_role": "x"},
               "FILE-SRV": {"zone": "SERVER", "cia": False, "owner_role": "x"}},
    "entitlements": {"PAY-INITIATE": {"asset_id": "PAY-APP", "privileged": False},
                     "PAY-APPROVE": {"asset_id": "PAY-APP", "privileged": False},
                     "CUST-READ": {"asset_id": "FILE-SRV", "privileged": False},
                     "CORE-ADMIN": {"asset_id": "CORE-DB", "privileged": True}},
}
OK_APPROVAL = {"status": "approved", "approved_at": 5, "approvers": ["line_manager", "asset_owner", "ciso"]}
# requested but not yet approved at assessment time (approved_at is null: a rule must not compare it as a number)
PENDING = {"status": "pending", "approved_at": None, "approvers": []}


def human(i, role="PaymentsOfficer", **kw):
    return {"identity": i, "kind": "human", "role": role, "created_at": 0, "disabled_at": None, "owner": None,
            "hr_start": 0, "hr_termination": None, "hr_active_until": None, "disable_deadline": None, **kw}


def svc(owner):
    return {"identity": "S:svc", "kind": "service_account", "role": "", "created_at": 0, "disabled_at": None,
            "owner": owner, "hr_start": None, "hr_termination": None, "hr_active_until": None, "disable_deadline": None}


def grant(i, ent, approval=None):
    return {"identity": i, "entitlement": ent, "granted_at": 10, "revoked_at": FAR, "approval": approval}


def base(**patch):
    d = {"period": {"id": 0, "start": 1000, "end": 2000, "data_start": 0}, "params": copy.deepcopy(PARAMS),
         "identities": [human("U:A")], "entitlements": [grant("U:A", "PAY-INITIATE")],
         "last_use": [{"identity": "U:A", "asset_id": "PAY-APP", "t": 1900}], "authentications": [],
         "firewall_rules": [], "flows": []}
    d.update(patch)
    return d


def leaver(disabled_at):
    return human("U:L", hr_termination=500, hr_active_until=600, disable_deadline=1200, disabled_at=disabled_at)


def auth(dst, ident="U:A", t=1500):
    return [{"identity": ident, "dst_asset": dst, "src_asset": "WS:1", "t": t, "server": True}]


def rule(src, dst, svc_):
    return [{"rule_id": "R1", "src_zone": src, "dst_zone": dst, "service": svc_, "action": "permit"}]


def flow(src, dst, asset, port):
    return [{"dst_asset": asset, "src_zone": src, "dst_zone": dst, "proto": "tcp", "port": port, "count": 1}]


def with_ents(*extra):
    return base(entitlements=[grant("U:A", "PAY-INITIATE"), *extra])


# (criterion, name, input, expected number of violating entities). Every case has exactly one entity in scope,
# given by subject() below.
CASES = [
    ("AC-01", "conflict", with_ents(grant("U:A", "PAY-APPROVE", OK_APPROVAL)), 1),
    ("AC-01", "clean", base(), 0),
    ("AC-02", "late_disable", base(identities=[leaver(1500)]), 1),
    ("AC-02", "never_disabled", base(identities=[leaver(None)]), 1),
    ("AC-02", "on_time", base(identities=[leaver(1100)]), 0),
    ("AC-02", "used_after_deadline", base(identities=[leaver(1100)], authentications=auth("FILE-SRV", "U:L", 1300)), 1),
    ("AC-03", "owner_active", base(identities=[human("U:A"), svc("U:A")]), 0),
    ("AC-03", "no_owner", base(identities=[human("U:A"), svc("")]), 1),
    ("AC-03", "owner_left", base(identities=[human("U:A", hr_active_until=1500), svc("U:A")]), 1),
    ("AC-04", "unapproved", with_ents(grant("U:A", "CORE-ADMIN")), 1),
    ("AC-04", "approval_after_grant", with_ents(grant("U:A", "PAY-APPROVE", {"status": "approved", "approved_at": 50,
                                                                            "approvers": ["line_manager"]})), 1),
    ("AC-04", "pending_approval", with_ents(grant("U:A", "PAY-APPROVE", PENDING)), 1),
    ("AC-04", "baseline_only", base(), 0),
    ("AC-05", "unused", base(last_use=[{"identity": "U:A", "asset_id": "PAY-APP", "t": 900}]), 1),
    ("AC-05", "used", base(), 0),
    ("AC-07", "missing_ciso", with_ents(grant("U:A", "CORE-ADMIN", {"status": "approved", "approved_at": 5,
                                                                   "approvers": ["asset_owner"]})), 1),
    ("AC-07", "pending_approval", with_ents(grant("U:A", "CORE-ADMIN", PENDING)), 1),
    ("AC-07", "owner_and_ciso", with_ents(grant("U:A", "CORE-ADMIN", OK_APPROVAL)), 0),
    ("AC-08", "unentitled", base(authentications=auth("CORE-DB")), 1),
    ("AC-08", "entitled", base(authentications=auth("PAY-APP")), 0),
    ("NW-01", "telnet_rule", base(firewall_rules=rule("USER", "SERVER", "telnet")), 1),
    ("NW-01", "https_rule", base(firewall_rules=rule("USER", "SERVER", "https")), 0),
    ("NW-02", "any_to_db", base(firewall_rules=rule("ANY", "DATABASE", "db-tls")), 1),
    ("NW-02", "specific", base(firewall_rules=rule("SERVER", "DATABASE", "db-tls")), 0),
    ("NW-03", "off_matrix", base(firewall_rules=rule("USER", "DATABASE", "db-tls")), 1),
    ("NW-03", "in_matrix", base(firewall_rules=rule("USER", "SERVER", "https")), 0),
    ("NW-04", "user_to_db", base(flows=flow("USER", "DATABASE", "CORE-DB", 1433)), 1),
    ("NW-04", "allowed", base(flows=flow("USER", "SERVER", "PAY-APP", 443)), 0),
    ("NW-05", "telnet_to_cia", base(flows=flow("USER", "SERVER", "PAY-APP", 23)), 1),
    ("NW-05", "tls_to_cia", base(flows=flow("USER", "SERVER", "PAY-APP", 443)), 0),
]


def subject(criterion, inp):
    """The single entity each seeded case is about. A correct rule assesses exactly this entity (scope) and, when a
    violation is expected, flags exactly this entity."""
    if criterion == "AC-02":
        return "U:L"
    if criterion == "AC-03":
        return "S:svc"
    if criterion in ("NW-01", "NW-02", "NW-03"):
        return "R1"
    if criterion in ("NW-04", "NW-05"):
        return inp["flows"][0]["dst_asset"]
    return "U:A"
