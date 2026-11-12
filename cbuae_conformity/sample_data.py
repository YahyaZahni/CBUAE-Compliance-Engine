"""Small SAMPLE data set in the exact file formats of the public datasets, for a fictional institution.

Purpose: exercise the full pipeline end to end before the real datasets are downloaded, and give a test
fixture with fully known ground truth. Sample activity is synthetic: it must NOT be used to report model
performance (Steps 4 and 5 are evaluated on the real public datasets).

Writes, under the target raw directory:
  cert/LDAP/YYYY-MM.csv, cert/logon.csv          (CERT r6.2 formats)
  lanl/auth.txt                                   (LANL auth.txt format, server authentications)
  netflow/NF-SAMPLE-v3.csv                        (UQ NetFlow v3 column names)
  iam/*.csv                                       (simulated institution state, see simulate_state.py)
  crosswalk/*.csv                                 (entity resolution tables)
"""
import string
import uuid
from pathlib import Path

import numpy as np
import pandas as pd

from .config import Config
from .simulate_state import simulate_state

ROLE_WEIGHTS = {"Teller": 14, "PaymentsOfficer": 12, "PaymentsSupervisor": 5, "Accountant": 12, "FinanceManager": 4,
                "LoanOfficer": 12, "CreditManager": 4, "Trader": 8, "SettlementOfficer": 6, "RelationshipManager": 20,
                "HRSpecialist": 5, "ITAdmin": 6, "DBAdmin": 3, "NetworkEngineer": 3, "Developer": 10,
                "ChangeManager": 2, "Auditor": 4, "ComplianceOfficer": 5}
FRONT = {"CORE-DB": "GL-APP", "CUST-DB": "PAY-APP", "HR-DB": "REPORT-SRV"}  # app tier in front of each database
EPH = (49152, 65535)


def sample_people(cfg: Config, rng, start, end):
    n = cfg.settings["sample"]["people"]
    roles = list(ROLE_WEIGHTS)
    w = np.array(list(ROLE_WEIGHTS.values()), float)
    months = pd.period_range(start, end - pd.Timedelta(days=1), freq="M")
    ids, rows = set(), []
    while len(ids) < n:
        uid = "".join(rng.choice(list(string.ascii_uppercase), 3)) + f"{int(rng.integers(0, 10000)):04d}"
        ids.add(uid)
    for i, uid in enumerate(sorted(ids)):
        role = roles[i % len(roles)] if i < len(roles) else rng.choice(roles, p=w / w.sum())
        first, last = months[0], months[-1]
        r = rng.random()
        if r < 0.08:
            first = months[int(rng.integers(1, len(months) - 1))]          # joiner
        elif r < 0.20:
            last = months[int(rng.integers(0, len(months) - 1))]           # leaver
        rows.append({"user_id": uid, "employee_name": f"Employee {uid}", "role": role, "first": first, "last": last,
                     "functional_unit": cfg.role_function[role], "department": cfg.role_function[role]})
    ppl = pd.DataFrame(rows)
    ppl["start"] = ppl["first"].dt.start_time
    ppl["termination"] = ppl["last"].dt.end_time.dt.normalize().where(ppl["last"] < months[-1])
    return ppl, months


def write_sample(raw: Path, cfg: Config):
    s = cfg.settings["sample"]
    rng = np.random.default_rng(s["seed"])
    start = pd.Timestamp(s["start"])
    end = start + pd.Timedelta(weeks=s["weeks"])
    people, months = sample_people(cfg, rng, start, end)
    state = simulate_state(people, cfg, start, end, seed=s["seed"] + 1)

    # ---- CERT LDAP monthly snapshots
    (raw / "cert" / "LDAP").mkdir(parents=True, exist_ok=True)
    for m in months:
        cur = people[(people["first"] <= m) & (people["last"] >= m)]
        out = cur.assign(email=cur.user_id + "@example-lfi.test", projects="", business_unit="1", team="1",
                         supervisor="")[["employee_name", "user_id", "email", "role", "projects", "business_unit",
                                         "functional_unit", "department", "team", "supervisor"]]
        out.to_csv(raw / "cert" / "LDAP" / f"{m}.csv", index=False)

    # ---- workstations
    people = people.reset_index(drop=True)
    people["pc"] = [f"PC-{int(x):04d}" for x in rng.choice(9000, len(people), replace=False) + 1000]
    people["ip"] = [f"10.10.{i // 250}.{i % 250 + 1}" for i in range(len(people))]

    # ---- CERT logon.csv (weekday workstation sessions until termination)
    days = pd.date_range(start, end - pd.Timedelta(days=1), freq="D")
    rows = []
    for p in people.itertuples():
        for d in days:
            if d.weekday() >= 5 or d < p.start or (pd.notna(p.termination) and d > p.termination) or rng.random() > 0.9:
                continue
            on = d + pd.Timedelta(minutes=int(rng.integers(450, 570)))
            off = d + pd.Timedelta(minutes=int(rng.integers(960, 1110)))
            for t, act in ((on, "Logon"), (off, "Logoff")):
                rows.append({"id": "{" + str(uuid.UUID(int=int(rng.integers(2**63)))).upper()[:23] + "}",
                             "date": t.strftime("%m/%d/%Y %H:%M:%S"), "user": f"DTAA/{p.user_id}", "pc": p.pc,
                             "activity": act})
    (raw / "cert").mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(raw / "cert" / "logon.csv", index=False)

    # ---- crosswalk: LANL-style names for identities and computers
    ids = state["identities"]
    lanl_user = {i: f"U{n + 10}@DOM1" for n, i in enumerate(ids.identity)}
    comps = list(cfg.assets.asset_id) + [f"WS:{pc}" for pc in people.pc]
    lanl_comp = {a: f"C{n + 100}" for n, a in enumerate(comps)}
    ip_of = dict(zip(cfg.assets.asset_id, cfg.assets.ip)) | {f"WS:{p.pc}": p.ip for p in people.itertuples()}
    zone_of = cfg.asset_zone | {f"WS:{pc}": "USER" for pc in people.pc}
    cw = raw / "crosswalk"
    cw.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([{"source": "cert", "source_id": i.split(":", 1)[1], "identity": i} for i in ids.identity if i.startswith("U:")]
                 + [{"source": "lanl", "source_id": u, "identity": i} for i, u in lanl_user.items()]).to_csv(cw / "identities.csv", index=False)
    pd.DataFrame([{"source": "cert", "host": pc, "asset_id": f"WS:{pc}"} for pc in people.pc]
                 + [{"source": "lanl", "host": c, "asset_id": a} for a, c in lanl_comp.items()]).to_csv(cw / "hosts.csv", index=False)
    pd.DataFrame([{"ip": ip, "asset_id": a, "zone": zone_of[a]} for a, ip in ip_of.items()]).to_csv(cw / "ips.csv", index=False)
    (cw / "meta.json").write_text(f'{{"epoch": "{start}", "netflow_shift_ms": 0}}\n', encoding="utf-8")  # sample times are already aligned

    # ---- server authentications (LANL format) and matching flows (NetFlow v3 format)
    ev = state["iam_events"]
    held = {}  # identity -> list of (entitlement, from, to)
    for r in ev[ev.event.isin(["grant", "revoke"])].itertuples():
        held.setdefault(r.identity, []).append((r.entitlement, r.time, pd.NaT))
    disabled = ev[ev.event == "account_disable"].set_index("identity").time.to_dict()
    pc_of = {f"U:{p.user_id}": f"WS:{p.pc}" for p in people.itertuples()}
    weeks = pd.date_range(start, end, freq="7D")[:-1]
    auth, flows = [], []
    svc_port = {r.service: (r.protocol, int(r.port), int(r.ndpi_id)) for r in cfg.services.itertuples()}

    def flow(t, src, dst, service, size=1.0):
        proto, port, ndpi = svc_port[service]
        dur = int(rng.gamma(2.0, 400 * size))
        ob, ib = int(rng.lognormal(7.5, 1.0) * size), int(rng.lognormal(8.5, 1.2) * size)
        flows.append({"FLOW_START_MILLISECONDS": int(t.value // 10**6), "FLOW_END_MILLISECONDS": int(t.value // 10**6) + dur,
                      "IPV4_SRC_ADDR": ip_of.get(src, src), "L4_SRC_PORT": int(rng.integers(*EPH)),
                      "IPV4_DST_ADDR": ip_of.get(dst, dst), "L4_DST_PORT": port,
                      "PROTOCOL": 6 if proto == "tcp" else 17, "L7_PROTO": float(ndpi),
                      "IN_BYTES": ob, "IN_PKTS": max(1, ob // 600), "OUT_BYTES": ib, "OUT_PKTS": max(1, ib // 900),
                      "TCP_FLAGS": 27 if proto == "tcp" else 0, "FLOW_DURATION_MILLISECONDS": dur,
                      "Label": 0, "Attack": "Benign"})

    for ident, grants in held.items():
        kind = ids.set_index("identity").kind[ident]
        src = pc_of.get(ident, "JUMP-HOST" if kind != "human" else None)
        if kind != "human":
            src = "REPORT-SRV" if kind == "ai_agent" else "FILE-SRV"
        for ent, t_from, _ in grants:
            asset = cfg.ent_asset[ent]
            rate = 1.0 if kind != "human" else 0.85
            for w in weeks:
                if w + pd.Timedelta(days=7) < t_from or rng.random() > rate:
                    continue
                t = w + pd.Timedelta(days=int(rng.integers(0, 5)), minutes=int(rng.integers(480, 1080)))
                if t < t_from or (ident in disabled and t > disabled[ident]):
                    continue
                if cfg.ent_privileged[ent]:
                    via = "JUMP-HOST"
                else:
                    via = src
                auth.append({"time": int((t - start).total_seconds()), "src_user": lanl_user[ident],
                             "dst_user": lanl_user[ident], "src_computer": lanl_comp[via if via in lanl_comp else src],
                             "dst_computer": lanl_comp[asset], "auth_type": "Kerberos", "logon_type": "Network",
                             "auth_orientation": "LogOn", "outcome": "Success"})
                # network path for this access, following the zone matrix
                zsrc, zdst = zone_of[via], zone_of[asset]
                if cfg.ent_privileged[ent]:
                    flow(t - pd.Timedelta(seconds=30), src, "JUMP-HOST", "rdp")
                    flow(t, "JUMP-HOST", asset, "ssh" if zdst in ("DATABASE", "MANAGEMENT") else "rdp")
                elif zdst == "DATABASE":
                    front = FRONT[asset]
                    flow(t, src, front, "https")
                    flow(t + pd.Timedelta(seconds=1), front, asset, "db-tls")
                elif zdst == "MANAGEMENT":
                    flow(t, src, asset, "ldaps")
                else:
                    flow(t, src, asset, "smb3" if asset == "FILE-SRV" else "https")

    # background traffic: DNS, directory, internet, web portal, server logs
    for p in people.itertuples():
        for w in weeks:
            if pd.notna(p.termination) and w > p.termination:
                break
            for _ in range(2):
                t = w + pd.Timedelta(days=int(rng.integers(0, 5)), minutes=int(rng.integers(450, 1100)))
                flow(t, f"WS:{p.pc}", "DNS-SRV", "dns", 0.1)
                flow(t + pd.Timedelta(seconds=2), f"WS:{p.pc}", "AD-DC", "kerberos", 0.2)
                flow(t + pd.Timedelta(seconds=5), f"WS:{p.pc}", f"203.0.113.{int(rng.integers(1, 250))}", "https")
    ip_of.update({f"203.0.113.{i}": f"203.0.113.{i}" for i in range(1, 251)})
    for w in weeks:
        for _ in range(40):
            t = w + pd.Timedelta(minutes=int(rng.integers(0, 7 * 1440)))
            flow(t, f"198.51.100.{int(rng.integers(1, 250))}", "WEB-PORTAL", "https")
        for srv in ("PAY-APP", "GL-APP", "LOAN-APP", "TRADE-APP", "FILE-SRV", "REPORT-SRV"):
            for _ in range(5):
                flow(w + pd.Timedelta(minutes=int(rng.integers(0, 7 * 1440))), srv, "LOG-SRV", "syslog", 0.2)

    (raw / "lanl").mkdir(parents=True, exist_ok=True)
    pd.DataFrame(auth).sort_values("time").to_csv(raw / "lanl" / "auth.txt", header=False, index=False)
    (raw / "netflow").mkdir(parents=True, exist_ok=True)
    pd.DataFrame(flows).sort_values("FLOW_START_MILLISECONDS").to_csv(raw / "netflow" / "NF-SAMPLE-v3.csv", index=False)

    # ---- institution state
    iam = raw / "iam"
    iam.mkdir(parents=True, exist_ok=True)
    for name, df in state.items():
        df.to_csv(iam / f"{name}.csv", index=False)
    (raw / "SAMPLE_DATA_README.txt").write_text(
        "Synthetic sample in public-dataset formats for a fictional institution. For pipeline testing only; "
        "do not report model performance on it.\n", encoding="utf-8")
    return {"people": len(people), "logon_rows": len(rows), "auth_rows": len(auth), "flows": len(flows),
            "start": str(start.date()), "end": str(end.date())}
