"""Step 3 tests with a scripted stand-in for the LLM (no model is called).

The scripted model returns the reference rules for some criteria (should pass the validator and match the reference
behaviour exactly) and deliberately broken rules for others (each should be stopped by a specific check).
"""
import json
import re

import pandas as pd
import pytest

from cbuae_conformity import policy_reader, step3
from cbuae_conformity.config import ROOT
from cbuae_conformity.llm_client import parse_json

BROKEN = {
    "NW-01": "package cbuae.gen.nw01\nimport rego.v1\nscope contains x if {",                        # does not compile
    "NW-04": ("package cbuae.gen.nw04\nimport rego.v1\nscope contains f.dst_asset if some f in input.flows\n"
              "violations contains {\"entity\": f.dst_asset, \"detail\": \"x\"} if {some f in input.netflow_raw}"),  # field
    "NW-02": "package cbuae.gen.nw02\nimport rego.v1\nscope contains r.rule_id if some r in input.firewall_rules\nviolations := set()",
}


def _overbroad_scope():
    """Reference AC-03 logic with the right violations but a scope that also lists humans."""
    rego = (ROOT / "rules" / "cbuae" / "ac03.rego").read_text(encoding="utf-8").replace("package cbuae.ac03", "package cbuae.gen.ac03")
    return rego.replace("scope contains i.identity if some i in nonhuman", "scope contains i.identity if some i in input.identities")


class ScriptedLLM:
    provider, model = "scripted", "scripted"

    def complete(self, system, user, max_tokens=4000):
        if "Required topics" in user:   # coverage: say everything is addressed, citing one real and one invented clause
            ids = re.findall(r"- (DOC-[\w.-]+):", user)
            first = re.search(r"\[(POL-[\w-]+)\]", user).group(1)
            return json.dumps({"results": [{"criterion": c, "addressed": True, "clause_ids": [first if i % 2 else "POL-FAKE-99"],
                                            "reason": "x"} for i, c in enumerate(ids)]})
        cid = re.match(r"Criterion ([A-Z]{2}-\d{2})", user).group(1)
        if cid in BROKEN:
            rego = BROKEN[cid]
        elif cid == "AC-03":
            rego = _overbroad_scope()
        else:
            stem = cid.lower().replace("-", "")
            rego = (ROOT / "rules" / "cbuae" / f"{stem}.rego").read_text(encoding="utf-8").replace(f"package cbuae.{stem}", f"package cbuae.gen.{stem}")
        return "Here is the rule:\n```json\n" + json.dumps({"package": policy_reader.package_for(cid), "rego": rego,
                                                          "assumptions": ["scripted"]}) + "\n```"


@pytest.fixture()
def tmp_step3(tmp_path, monkeypatch):
    monkeypatch.setattr(step3, "OUT", tmp_path)
    monkeypatch.setattr(step3, "CAND", tmp_path / "rule_candidates")
    monkeypatch.setattr(step3, "APPROVED", tmp_path / "approved")
    return tmp_path


def test_parse_json_handles_fences():
    assert parse_json('blah ```json\n{"a": "x}y", "b": {"c": 1}}\n``` tail') == {"a": "x}y", "b": {"c": 1}}


def test_validator_gates(tmp_step3):
    df = step3.translate_all(ScriptedLLM(), ["AC-01", "AC-02", "AC-03", "AC-04", "AC-07", "NW-01", "NW-02", "NW-04"]).set_index("criterion")
    assert set(df.index[df.status == "pending_review"]) == {"AC-01", "AC-02", "AC-04", "AC-07"}
    # right violations, wrong statement of who was assessed: stopped by the scope check alone
    assert df.loc["AC-03", "seeded_cases"] and not df.loc["AC-03", "seeded_scope"]
    assert not df.loc["NW-01", "compiles"]
    assert not df.loc["NW-04", "fields_in_contract"]
    assert df.loc["NW-02", "compiles"] and not df.loc["NW-02", "seeded_cases"]


def test_behaviour_matches_reference(tmp_step3):
    if not (ROOT / "data" / "processed" / "rule_inputs").exists():
        pytest.skip("run `python -m cbuae_conformity.step3 inputs` first")
    step3.translate_all(ScriptedLLM(), ["AC-01", "AC-04"])
    sc = step3.evaluate("candidates").set_index("criterion")
    assert (sc.agreement_with_reference == 1.0).all()
    assert (sc.recall == 1.0).all() and (sc.precision == 1.0).all()


def test_coverage_grounding():
    reqs, crit = policy_reader.load_catalogue()
    policy = json.loads((ROOT / "catalogue" / "sample_policy.json").read_text(encoding="utf-8"))
    out = pd.DataFrame(policy_reader.check_coverage(ScriptedLLM(), policy, reqs, crit))
    # topics answered with only an invented clause id are downgraded to "not addressed"
    assert (out[out.invalid_citations != ""].addressed == False).all()  # noqa: E712
    assert (out[out.invalid_citations == ""].addressed == True).all()  # noqa: E712


class GarbageLLM:
    provider, model = "scripted", "garbage"

    def __init__(self, text):
        self.text = text

    def complete(self, system, user, max_tokens=4000):
        return self.text


@pytest.mark.parametrize("text", ["I cannot answer that.", '{"results": "none"}', '{"results": [{"criterion": "DOC-8.6.1"}, 7]}',
                                  '{"results": [{"criterion": "DOC-8.6.1", "addressed": "yes", "clause_ids": "POL-GOV-01"}]}'])
def test_coverage_survives_malformed_answers(text):
    reqs, crit = policy_reader.load_catalogue()
    policy = json.loads((ROOT / "catalogue" / "sample_policy.json").read_text(encoding="utf-8"))
    out = pd.DataFrame(policy_reader.check_coverage(GarbageLLM(text), policy, reqs, crit))
    assert len(out) == 16 and not out.answered.any() and not out.addressed.any()


def test_no_answer_is_scored_as_wrong():
    df = pd.DataFrame({"truth": ["conforming", "nonconforming", "conforming"], "pred": ["no_answer", "no_answer", "conforming"]})
    m = step3.metrics(df)
    assert m["no_answer"] == 2 and m["accuracy"] == pytest.approx(1 / 3) and m["fn"] == 1


def test_rule_inputs_are_point_in_time():
    """Nothing dated after the end of a period is visible in that period's input."""
    inputs = sorted((ROOT / "data" / "processed" / "rule_inputs").glob("period_*.json"))
    if not inputs:
        pytest.skip("run `python -m cbuae_conformity.step3 inputs` first")
    for p in inputs[:: max(1, len(inputs) // 6)]:
        d = json.loads(p.read_text(encoding="utf-8"))
        end = d["period"]["end"]
        for i in d["identities"]:
            assert i["hr_termination"] is None or i["hr_termination"] <= end
            assert i["created_at"] <= end and (i["disabled_at"] is None or i["disabled_at"] <= end)
        for e in d["entitlements"]:
            assert e["granted_at"] <= end
            a = e["approval"]
            assert a is None or a["approved_at"] is None or a["approved_at"] <= end
            assert a is None or (a["status"] == "pending") == (a["approved_at"] is None) or a["status"] != "approved"
        assert all(u["t"] <= end for u in d["last_use"]) and all(a["t"] <= end for a in d["authentications"])


def test_review_ui_approves(tmp_step3, monkeypatch):
    flask = pytest.importorskip("flask")  # noqa: F841
    from cbuae_conformity import review_app
    monkeypatch.setattr(review_app, "OUT", tmp_step3)
    monkeypatch.setattr(review_app, "CAND", tmp_step3 / "rule_candidates")
    monkeypatch.setattr(review_app, "APPROVED", tmp_step3 / "approved")
    monkeypatch.setattr(review_app, "LOG", tmp_step3 / "review_log.jsonl")
    step3.translate_all(ScriptedLLM(), ["AC-01", "NW-01"])
    c = review_app.app.test_client()
    assert b"AC-01" in c.get("/").data
    assert b"Seeded test cases" in c.get("/rule/AC-01").data
    c.post("/rule/AC-01/decide", data={"reviewer": "Y. Zahni", "decision": "approved", "comment": "matches POL-AC-02"})
    assert (tmp_step3 / "approved" / "ac01.rego").exists()
    log = [json.loads(x) for x in (tmp_step3 / "review_log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert log[0]["decision"] == "approved" and len(log[0]["rule_sha256"]) == 64
    assert c.post("/rule/NW-01/decide", data={"reviewer": "x", "decision": "approved"}).status_code == 400
    # only catalogue ids and the two known decisions are accepted
    assert c.post("/rule/..%2F..%2Fetc/decide", data={"reviewer": "x", "decision": "approved"}).status_code == 404
    assert c.post("/rule/AC-01/decide", data={"reviewer": "x", "decision": "maybe"}).status_code == 400
    assert c.post("/rule/AC-01/decide", data={"reviewer": " ", "decision": "approved"}).status_code == 400
