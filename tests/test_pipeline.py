import gzip
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import pytest

from cbuae_conformity import ocsf
from cbuae_conformity.config import business_deadline, load_config

ROOT = Path(__file__).resolve().parents[1]


def test_config_is_consistent():
    cfg = load_config()  # asserts baselines are SoD-clean and reference known entitlements/assets
    assert cfg.cia_assets and cfg.zone_matrix


@pytest.mark.parametrize("term,expected", [
    ("2026-01-09", "2026-01-12"),  # Friday termination -> Monday deadline (UAE weekend Sat-Sun)
    ("2026-01-06", "2026-01-07"),  # Tuesday -> Wednesday
    ("2026-01-10", "2026-01-12"),  # Saturday -> Monday
])
def test_business_deadline(term, expected):
    assert business_deadline(pd.Timestamp(term), 1).date() == pd.Timestamp(expected).date()


def test_ocsf_validator():
    good = ocsf.authentication("t1", 1, "U:A", "A", "PC-1", "core-db01", "CORE-DB", 1, True, 3, "test", 2)
    assert ocsf.validate(good) == []
    bad = dict(good, activity_id=42, user={"uid": 5})
    errs = " ".join(ocsf.validate(bad))
    assert "not in enum" in errs and "expected string" in errs and "type_uid" in errs


@pytest.fixture(scope="module")
def sample_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("evidence")
    subprocess.run([sys.executable, "-m", "cbuae_conformity.pipeline", "sample", "--out", str(out)], cwd=ROOT, check=True,
                   capture_output=True)
    return out


def test_every_injection_surfaces(sample_run):
    s = json.loads((sample_run / "summary.json").read_text(encoding="utf-8"))
    assert s["injections_not_surfacing"] == []
    assert s["injection_shortfall"] == {}


def test_sample_has_no_unexplained_nonconformities(sample_run):
    cases = pd.read_csv(sample_run / "truth" / "answer_key_technical.csv")
    assert (cases.truth_source == "natural").sum() == 0


def test_ocsf_files_are_valid(sample_run):
    for p in (sample_run / "ocsf").glob("*.jsonl.gz"):
        for i, e in enumerate(ocsf.read_jsonl_gz(p)):
            assert ocsf.validate(e) == [], p.name
            if i > 2000:
                break


def test_time_split_is_ordered(sample_run):
    P = pd.read_csv(sample_run / "periods.csv")
    order = {"train": 0, "validation": 1, "test": 2}
    assert P.split.map(order).is_monotonic_increasing


def test_hidden_labels_not_in_events(sample_run):
    e = next(ocsf.read_jsonl_gz(sample_run / "ocsf" / "4001_network_activity.jsonl.gz"))
    assert "ndpi" not in json.dumps(e).lower()


def test_policy_key(sample_run):
    key = pd.read_csv(sample_run / "truth" / "answer_key_policy.csv")
    assert (key[key.entity == "POLICY-V00"].truth == "conforming").all()
    assert (key.truth == "nonconforming").sum() > 0


# ------------------------------------------------------------------ the evidence must not give the answer key away
def _shape(v):
    """Format of a value: letters -> A, digits -> 9, runs collapsed (e.g. 'C1234@DOM1' -> 'A9@A9')."""
    return re.sub(r"9+", "9", re.sub(r"A+", "A", re.sub(r"\d", "9", re.sub(r"[A-Za-z]", "A", str(v)))))


def test_evidence_has_no_answer_key_markers(sample_run):
    marker = re.compile(r"planted|inject|answer.?key|tmp-|INJ-", re.I)
    for p in (sample_run / "ocsf").glob("*.jsonl.gz"):
        text = gzip.open(p, "rt", encoding="utf-8").read()
        assert not marker.search(text), p.name
        assert "NaN" not in text, p.name                      # strict JSON, no missing-value artefacts
    st = sample_run / "state"
    for p in st.glob("*.csv"):
        assert not marker.search(p.read_text(encoding="utf-8")), p.name
    # one identifier format per record type, for ordinary and planted records alike
    assert pd.read_csv(st / "approvals.csv").approval_id.str.fullmatch(r"APR-[0-9A-F]{8}").all()
    fw = pd.read_csv(st / "firewall_changes.csv")
    assert fw.rule_id.str.fullmatch(r"FW-[0-9A-F]{6}").all() and fw.change_ref.str.fullmatch(r"CHG-[0-9A-F]{5}").all()
    for name in ("3001_account_change", "3005_user_access"):
        assert all(re.fullmatch(r"IAM-[0-9A-F]{8}", e["metadata"]["uid"])
                   for e in ocsf.read_jsonl_gz(sample_run / "ocsf" / f"{name}.jsonl.gz"))


def test_planted_logons_look_like_ordinary_ones(sample_run):
    inj = pd.read_csv(sample_run / "truth" / "injections.csv", parse_dates=["time"])
    ev = list(ocsf.read_jsonl_gz(sample_run / "ocsf" / "3002_authentication.jsonl.gz"))

    def sig(e):
        return (e["metadata"]["log_name"], _shape(e["user"]["name"]), _shape(e["src_endpoint"]["hostname"]),
                _shape(e["dst_endpoint"]["hostname"]), e["logon_type_id"], e["auth_protocol_id"], e["time"] % 60_000 == 0)
    common = Counter(sig(e) for e in ev)
    found = 0
    for r in inj[inj.criterion == "AC-08"].itertuples():
        t = int(r.time.value // 10**6)
        hits = [e for e in ev if e["user"]["uid"] == r.entity and abs(e["time"] - t) < 60_000 and e["logon_type_id"] == 3]
        assert hits, r.injection_id
        for e in hits:
            assert common[sig(e)] > 100, (r.injection_id, sig(e))   # same format as >100 ordinary events
            found += 1
    assert found >= 12


def test_planted_flows_reuse_real_flow_statistics(sample_run):
    inj = pd.read_csv(sample_run / "truth" / "injections.csv", parse_dates=["time"])
    ev = list(ocsf.read_jsonl_gz(sample_run / "ocsf" / "4001_network_activity.jsonl.gz"))

    def stats(e):
        return (e["traffic"]["bytes_in"], e["traffic"]["bytes_out"], e["traffic"]["packets_in"], e["traffic"]["packets_out"],
                e["duration"], e["connection_info"]["tcp_flags"], e["src_endpoint"]["port"])
    seen = Counter(stats(e) for e in ev)
    # planted flows are told apart from ordinary ones on the same route only by the hidden application label
    label = pd.read_csv(sample_run / "truth" / "flow_application_labels.csv").set_index("uid").ndpi_master
    svc = load_config().services.set_index("service")
    found = 0
    for r in inj[inj.criterion.isin(["NW-04", "NW-05"])].itertuples():
        assert "donor=same_" in r.description, r.injection_id
        src = r.description.split("->")[0]
        if r.criterion == "NW-04":
            s = svc.loc[r.description.split(";")[0].rsplit(":", 1)[1]]
            port, ndpi = int(s.port), int(s.ndpi_id)
        else:
            port, ndpi = (int(x) for x in re.search(r"port (\d+), nDPI (\d+)", r.description).groups())
        t = int(r.time.value // 10**6)
        hits = [e for e in ev if e["src_endpoint"]["uid"] == src and e["dst_endpoint"]["uid"] == r.entity
                and e["dst_endpoint"]["port"] == port and label[e["metadata"]["uid"]] == ndpi
                and t - 60_000 <= e["time"] <= t + 5 * 240 * 60_000]
        assert hits, r.injection_id
        for e in hits:
            assert seen[stats(e)] >= 2, r.injection_id   # the same statistics occur on at least one other flow
            found += 1
    assert found >= 24


def test_changes_inside_the_window_are_not_all_planted(sample_run):
    """Ordinary, conforming changes keep happening throughout the window, so 'changed recently' is not the answer."""
    start = pd.read_csv(sample_run / "periods.csv", parse_dates=["start"]).start.min()
    key = pd.read_csv(sample_run / "truth" / "answer_key_technical.csv")
    inj = pd.read_csv(sample_run / "truth" / "injections.csv")
    fw = pd.read_csv(sample_run / "state" / "firewall_changes.csv", parse_dates=["valid_from"])
    bad_rules = set(key[key.criterion.isin(["NW-01", "NW-02", "NW-03"]) & (key.truth == "nonconforming")].entity)
    assert (~fw[fw.valid_from >= start].rule_id.isin(bad_rules)).sum() >= 5
    ent = pd.read_csv(sample_run / "state" / "entitlements.csv", parse_dates=["granted_at"]).drop_duplicates(["identity", "entitlement"])
    planted = set(zip(inj.entity, inj.entitlement.fillna("")))
    late = ent[~ent.in_role_baseline & ent.identity.str.startswith("U:") & (ent.granted_at > start + pd.Timedelta(days=60))]
    late = late[[(i, e) not in planted for i, e in zip(late.identity, late.entitlement)]]
    assert len(late) >= 5
