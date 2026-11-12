"""Step 2 pipeline: evidence base (OCSF events + state snapshots + policy clauses), entity resolution,
planted nonconformities, answer key and time-based split.

  python -m cbuae_conformity.pipeline sample            # build the sample raw data, then process it
  python -m cbuae_conformity.pipeline run --raw DIR     # process real public datasets placed under DIR
"""
import argparse
import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

from . import entities, ocsf, policy_variants
from .config import ROOT, load_config
from .inject import inject_all
from .sample_data import write_sample
from .truth import account_intervals, build_cases, grant_intervals

LOG = {"cert": "CERT r6.2 logon.csv", "lanl": "LANL auth.txt"}


def write_ocsf(d, out: Path):
    counts = {}
    a = d["auth"].reset_index(drop=True)
    a["uid"] = [f"AUTH-{i:07d}" for i in range(len(a))]
    counts["3002_authentication"] = ocsf.write_jsonl_gz(
        (ocsf.authentication(r.uid, r.time.value // 10**6, r.identity, str(r.account_name), str(r.src_host), str(r.dst_host),
                             str(r.dst_asset), 1 if r.activity == "Logon" else 2, bool(r.success), int(r.logon_type),
                             LOG[r.source], int(r.auth_protocol), src_asset=str(r.src_asset) if pd.notna(r.src_asset) else None)
         for r in a.itertuples()), out / "3002_authentication.jsonl.gz")
    ev = d["iam_events"]
    ent_asset = d["cfg"].ent_asset

    def iam_events():
        for r in ev.itertuples():
            t = r.time.value // 10**6
            if r.event in ("grant", "revoke"):
                yield ocsf.user_access(r.event_id, t, r.identity, r.entitlement, ent_asset[r.entitlement],
                                       r.event == "grant", "IAM entitlement log", r.approval_id or None)
    counts["3005_user_access"] = ocsf.write_jsonl_gz(iam_events(), out / "3005_user_access.jsonl.gz")

    def acct_events():
        for r in ev.itertuples():
            t = r.time.value // 10**6
            if r.event == "account_create":
                yield ocsf.account_change(r.event_id, t, r.identity, 1, "IAM account log")
            elif r.event == "account_disable":
                yield ocsf.account_change(r.event_id, t, r.identity, 5, "IAM account log")
            elif r.event == "owner_set":
                yield ocsf.account_change(r.event_id, t, r.identity, 99, "IAM account log", "Owner Change",
                                          {"owner": r.owner or ""})
    counts["3001_account_change"] = ocsf.write_jsonl_gz(acct_events(), out / "3001_account_change.jsonl.gz")
    f = d["flows"]
    if f is not None:
        f = f.reset_index(drop=True)
        f["uid"] = [f"FLOW-{i:07d}" for i in range(len(f))]
        counts["4001_network_activity"] = ocsf.write_jsonl_gz(
            (ocsf.network_activity(r.uid, r.time_ms, r.end_ms, r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.proto,
                                   r.src_asset, r.dst_asset, r.src_zone, r.dst_zone, r.bytes_in, r.bytes_out, r.pkts_in,
                                   r.pkts_out, r.tcp_flags, "UQ NetFlow v3") for r in f.itertuples()),
            out / "4001_network_activity.jsonl.gz")
        # hidden ground truth: application protocol per flow (never given to the checkers)
        cleartext = d["cfg"].cleartext_ndpi
        pd.DataFrame({"uid": f.uid, "ndpi_master": f.ndpi_master, "cleartext": f.ndpi_master.isin(cleartext)}) \
            .to_csv(out.parent / "truth" / "flow_application_labels.csv", index=False)
    return counts


def write_snapshots(d, cfg, P, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    G = grant_intervals(d["iam_events"], cfg)
    A = account_intervals(d["iam_events"])
    owners = d["iam_events"][d["iam_events"].event == "owner_set"]
    base = cfg.roles
    role = d["people"].assign(identity="U:" + d["people"].user_id).set_index("identity").role
    ent_rows, id_rows, fw_rows = [], [], []
    for p in P.itertuples():
        h = G[(G.granted_at <= p.end) & (G.revoked_at > p.end)]
        for r in h.itertuples():
            ent_rows.append({"period": p.period, "snapshot_at": p.end, "identity": r.identity, "entitlement": r.entitlement,
                             "asset_id": r.asset_id, "privileged": r.privileged, "granted_at": r.granted_at,
                             "approval_id": r.approval_id, "in_role_baseline": r.entitlement in base.get(role.get(r.identity, ""), set())})
        for ident, a in A.iterrows():
            if a.created_at <= p.end:
                o = owners[(owners.identity == ident) & (owners.time <= p.end)]
                id_rows.append({"period": p.period, "snapshot_at": p.end, "identity": ident,
                                "status": "enabled" if a.disabled_at > p.end else "disabled",
                                "owner": o.owner.iloc[-1] if len(o) else ""})
        fw = d["firewall_rules"]
        live = fw[(fw.valid_from <= p.end) & (fw.valid_to.isna() | (fw.valid_to > p.end))]
        fw_rows += [{"period": p.period, "snapshot_at": p.end, **r} for r in live.drop(columns=["valid_to"]).to_dict("records")]
    pd.DataFrame(ent_rows).to_csv(out / "entitlements.csv", index=False)
    pd.DataFrame(id_rows).to_csv(out / "identities.csv", index=False)
    pd.DataFrame(fw_rows).to_csv(out / "firewall_rules.csv", index=False)
    # change log of the rule base (when each rule entered and left it): the continuous view of the configuration
    d["firewall_rules"].to_csv(out / "firewall_changes.csv", index=False)
    d["approvals"].to_csv(out / "approvals.csv", index=False)
    hr = d["people"][["user_id", "role", "start", "termination"]].assign(identity=lambda x: "U:" + x.user_id)
    hr.to_csv(out / "hr_people.csv", index=False)
    d["identities"].to_csv(out / "identity_registry.csv", index=False)
    return {"entitlement_rows": len(ent_rows), "identity_rows": len(id_rows), "firewall_rule_rows": len(fw_rows)}


def link(cases, inj):
    """Attach injection ids to the cases they affect (same criterion and entity, overlapping in time)."""
    cases["injection_ids"] = ""
    for r in inj.itertuples():
        t_end = r.time_end if pd.notna(r.time_end) else pd.Timestamp.max
        m = (cases.criterion == r.criterion) & (cases.entity == r.entity) & (cases.period_end >= r.time) & \
            (cases.period_start <= t_end)
        cases.loc[m, "injection_ids"] = cases.loc[m, "injection_ids"].map(lambda s: f"{s};{r.injection_id}".strip(";"))
    # a nonconforming case with no injection of its own criterion is either a side effect of an injection on the same
    # entity (e.g. a planted telnet rule also breaks the zone matrix) or a natural nonconformity in the source data
    cases["related_injection_ids"] = ""
    orphan = (cases.truth == "nonconforming") & (cases.injection_ids == "")
    by_entity = inj.groupby("entity")
    for i in cases.index[orphan]:
        e, pe = cases.at[i, "entity"], cases.at[i, "period_end"]
        if e in by_entity.groups:
            g = by_entity.get_group(e)
            cases.at[i, "related_injection_ids"] = ";".join(g.loc[g.time <= pe, "injection_id"])
    cases["truth_source"] = np.select(
        [cases.truth == "conforming", cases.injection_ids != "", cases.related_injection_ids != ""],
        ["", "injected", "side_effect"], default="natural")
    return cases


def split_periods(P, s):
    n = len(P)
    a, b = int(round(n * s["train"])), int(round(n * (s["train"] + s["validation"])))
    P["split"] = ["train" if i < a else "validation" if i < b else "test" for i in range(n)]
    return P


def run(raw: Path, out: Path):
    cfg = load_config()
    if out.exists():
        shutil.rmtree(out)
    (out / "truth").mkdir(parents=True)
    d = entities.load(raw, cfg)
    d["cfg"] = cfg
    inj, shortfall = inject_all(d, cfg)
    inj.to_csv(out / "truth" / "injections.csv", index=False)
    cases, P = build_cases(d, cfg, inj)
    P = split_periods(P, cfg.settings["split"])
    cases = link(cases, inj).merge(P[["period", "split"]], on="period")
    cases.to_csv(out / "truth" / "answer_key_technical.csv", index=False)
    P.to_csv(out / "periods.csv", index=False)
    counts = write_ocsf(d, out / "ocsf")
    snaps = write_snapshots(d, cfg, P, out / "state")
    pk = policy_variants.build(out / "policy" / "variants", cfg.settings["injection"]["policy_variants"],
                               cfg.settings["injection"]["seed"])
    pk.to_csv(out / "truth" / "answer_key_policy.csv", index=False)
    policy = json.loads((ROOT / "catalogue" / "sample_policy.json").read_text(encoding="utf-8"))
    (out / "policy" / "policy_clauses.json").write_text(json.dumps(policy_variants.clauses(policy), indent=2), encoding="utf-8")

    # ---- verification: every planted injection must surface as a nonconforming case of its criterion
    missed = []
    for r in inj.itertuples():
        hit = cases[(cases.criterion == r.criterion) & cases.injection_ids.str.contains(r.injection_id, regex=False)]
        if not (hit.truth == "nonconforming").any():
            missed.append(r.injection_id)
    summary = {
        "window": [str(d["start"].date()), str(d["end"].date())], "periods": len(P),
        "split_periods": P.split.value_counts().to_dict(),
        "ocsf_events": counts, "state_snapshot_rows": snaps,
        "unresolved_authentications_dropped": d["unresolved_auth"],
        "composition_dropped_authentications": d["composition_dropped_auth"], "grants_aligned_with_activity": d["aligned_grants"],
        "injections": inj.criterion.value_counts().sort_index().to_dict(), "injection_shortfall": shortfall,
        "injections_not_surfacing": missed,
        "cases_by_criterion": cases.groupby(["criterion", "truth"]).size().unstack(fill_value=0).to_dict("index"),
        "nonconforming_by_source": cases[cases.truth == "nonconforming"].truth_source.value_counts().to_dict(),
        "policy_key": pk.truth.value_counts().to_dict(),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["sample", "run"])
    ap.add_argument("--raw", type=Path, default=ROOT / "data" / "raw")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "processed" / "evidence")
    a = ap.parse_args()
    if a.mode == "sample":
        a.raw = ROOT / "data" / "raw_sample"
        if a.raw.exists():
            shutil.rmtree(a.raw)
        print("sample raw data:", write_sample(a.raw, load_config()))
    s = run(a.raw, a.out)
    print(json.dumps({k: s[k] for k in ("window", "periods", "ocsf_events", "injections_not_surfacing",
                                        "nonconforming_by_source", "injection_shortfall")}, indent=2, default=str))


if __name__ == "__main__":
    main()
