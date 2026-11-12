"""Step 1 build: criteria catalogue (Excel), OSCAL catalog (JSON) and the sample policy (Word).

Run from the project root:  python catalogue/build_catalogue.py
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
from docx import Document
from docx.shared import Pt
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parents[1]
CAT = ROOT / "catalogue"
OUT = ROOT / "outputs" / "step1"
NS = uuid.UUID("6f1c2b0e-8a8e-4d3b-9b8e-2f5d1c0a7e11")  # fixed namespace -> stable UUIDs


def load(name):
    return json.loads((CAT / name).read_text(encoding="utf-8"))


def policy_clauses(policy):
    """Flatten the policy into rows: clause id, section, measure, CBUAE topic, text."""
    rows = []
    for s in policy["sections"]:
        for c in s.get("clauses", []):
            rows.append({"clause_id": c["id"], "section": f'{s["id"]} {s["title"]}', "cbuae_topic": s["cbuae_topic"],
                         "measure": "", "text": c["text"]})
        for sub in s.get("subsections", []):
            for c in sub["clauses"]:
                rows.append({"clause_id": c["id"], "section": f'{sub["id"]} {sub["title"]}', "cbuae_topic": s["cbuae_topic"],
                             "measure": sub["measure"], "text": c["text"]})
    return rows


# ---------------------------------------------------------------- Excel
def build_excel(reqs, crit, clauses):
    req_text = {r["id"]: r["text"] for r in reqs["requirements"]}
    clause_text = {c["clause_id"]: c["text"] for c in clauses}
    wb = Workbook()
    head_font, head_fill = Font(bold=True, color="FFFFFF"), PatternFill("solid", fgColor="14213D")
    wrap = Alignment(wrap_text=True, vertical="top")

    def sheet(ws, headers, rows, widths):
        ws.append(headers)
        for cell in ws[1]:
            cell.font, cell.fill, cell.alignment = head_font, head_fill, wrap
        for r in rows:
            ws.append(r)
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = wrap
        ws.freeze_panes = "B2"
        ws.auto_filter.ref = ws.dimensions

    ws = wb.active
    ws.title = "Criteria"
    rows = []
    for c in crit["criteria"]:
        rows.append([c["id"], c["title"], c["level"], ", ".join(c["cbuae"]),
                     " | ".join(f'{a}: {req_text.get(a, "")}' for a in c["cbuae"]),
                     ", ".join(c["policy_clauses"]),
                     " | ".join(f'{p}: {clause_text.get(p, "MISSING")}' for p in c["policy_clauses"]),
                     c["pass_condition"], "; ".join(c["evidence"]), c["method"], c["checker"], c["entity"],
                     ", ".join(crit["determinations"]), c["truth_source"], c.get("note", "")])
    sheet(ws, ["Criterion ID", "Title", "Level", "CBUAE sub-article(s)", "CBUAE text (verbatim)", "Policy clause(s)",
               "Policy clause text", "Pass condition", "Evidence", "Method", "Checker", "Entity",
               "Possible determinations", "Ground truth source", "Note"],
          rows, [12, 34, 11, 14, 60, 18, 60, 60, 50, 10, 12, 16, 22, 30, 40])

    ws2 = wb.create_sheet("CBUAE requirements")
    sheet(ws2, ["Sub-article", "Text (verbatim)", "In scope", "Scope note"],
          [[r["id"], r["text"], str(r["in_scope"]), r.get("scope_note", "")] for r in reqs["requirements"]],
          [12, 90, 14, 70])

    ws3 = wb.create_sheet("Policy clauses")
    sheet(ws3, ["Clause ID", "Section", "CBUAE topic", "8.6.3 measure", "Text"],
          [[c["clause_id"], c["section"], c["cbuae_topic"], c["measure"], c["text"]] for c in clauses],
          [14, 36, 12, 30, 100])

    ws4 = wb.create_sheet("Out of scope")
    sheet(ws4, ["Sub-article", "Reason"], [[o["id"], o["reason"]] for o in reqs["out_of_scope"]], [40, 100])

    import csv
    for title, name, widths in (("Annex A SoD matrix", "sod_matrix.csv", [18, 18, 60]),
                                ("Annex B Services", "services.csv", [12, 9, 7, 9, 10, 10, 60]),
                                ("Annex C Zone matrix", "zone_matrix.csv", [14, 14, 50]),
                                ("Role baselines", "role_entitlements.csv", [20, 20, 60]),
                                ("Assets", "assets.csv", [12, 14, 13, 12, 10, 13, 18, 45])):
        rows_ = list(csv.reader((ROOT / "config" / name).open(encoding="utf-8")))
        sheet(wb.create_sheet(title), rows_[0], rows_[1:], widths)

    ws5 = wb.create_sheet("Source")
    s = reqs["source"]
    sheet(ws5, ["Field", "Value"], [[k, v] for k, v in s.items()], [16, 110])

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "CBUAE_Criteria_Catalogue.xlsx"
    wb.save(path)
    return path


# ---------------------------------------------------------------- OSCAL
def build_oscal(reqs, crit):
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    by_req = {}
    for c in crit["criteria"]:
        for a in c["cbuae"]:
            by_req.setdefault(a, []).append(c)

    def control(r):
        cid = "cbuae-orm-" + r["id"].replace(".", "-")
        parts = [{"id": f"{cid}_smt", "name": "statement", "prose": r["text"]}]
        for c in by_req.get(r["id"], []):
            pid = f'{cid}_obj_{c["id"].lower().replace(".", "-")}'
            parts.append({
                "id": pid, "name": "assessment-objective",
                "props": [{"name": "label", "value": c["id"]}],
                "prose": c["pass_condition"],
                "parts": [{"id": f"{pid}_mth", "name": "assessment-method",
                           "props": [{"name": "method", "value": c["method"]}],
                           "parts": [{"id": f"{pid}_mth_obj", "name": "assessment-objects",
                                      "prose": "; ".join(c["evidence"])}]}],
            })
        ctrl = {"id": cid, "title": f'Art. {r["id"]}', "props": [{"name": "label", "value": r["id"]}], "parts": parts}
        if r.get("scope_note"):
            ctrl["parts"].append({"id": f"{cid}_gdn", "name": "guidance", "prose": r["scope_note"]})
        return ctrl

    groups = []
    for art, title in [("7", "Article 7: Internal Control System"), ("8", "Article 8: ICT and Cybersecurity Management")]:
        ctrls = []
        for r in reqs["requirements"]:
            if r["article"] != art or r["in_scope"] is False:
                continue
            if r["parent"]:
                continue  # attached as a child control, or added directly below if its parent is out of scope
            ctrl = control(r)
            kids = [control(k) for k in reqs["requirements"] if k["parent"] == r["id"] and k["in_scope"] is not False]
            if kids:
                ctrl["controls"] = kids
            ctrls.append(ctrl)
        # 7.4 itself is out of scope, so its in-scope children (7.4.2, 7.4.5) sit directly in the group
        for r in reqs["requirements"]:
            if r["article"] == art and r["parent"] and r["in_scope"] is not False and \
               any(x["id"] == r["parent"] and x["in_scope"] is False for x in reqs["requirements"]):
                ctrls.append(control(r))
        ctrls.sort(key=lambda c: [int(p) for p in c["props"][0]["value"].split(".")])
        groups.append({"id": f"art-{art}", "title": title, "controls": ctrls})

    s = reqs["source"]
    catalog = {"catalog": {
        "uuid": str(uuid.uuid5(NS, "cbuae-orm-catalog")),
        "metadata": {"title": "CBUAE Operational Risk Management Regulation (C 1/2026): Articles 7 and 8, thesis scope",
                     "last-modified": now, "version": "0.1", "oscal-version": "1.1.3",
                     "props": [{"name": "keywords", "value": "CBUAE, conformity, ICT, cybersecurity"}],
                     "remarks": f'Verbatim text retrieved {s["retrieved"]} from {s["url"]}. Assessment objectives are the thesis criteria.'},
        "groups": groups,
        "back-matter": {"resources": [{"uuid": str(uuid.uuid5(NS, "rulebook")), "title": s["title"],
                                        "rlinks": [{"href": s["url"]}]}]},
    }}
    # NIST's schema uses \p{L} / \p{N} Unicode classes, which Python's re module lacks; translate to equivalents.
    raw = (ROOT / "vendor" / "oscal_catalog_schema.json").read_text(encoding="utf-8")
    raw = raw.replace("\\\\p{L}", "[^\\\\W\\\\d_]").replace("\\\\p{N}", "\\\\d")
    validator = jsonschema.Draft7Validator(json.loads(raw))
    errors = sorted(validator.iter_errors(catalog), key=lambda e: list(e.path))
    if errors:
        raise SystemExit("OSCAL validation failed:\n" + "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:20]))
    seen = []  # OSCAL requires document-unique ids; the JSON schema does not enforce this, so check it here

    def collect(o):
        if isinstance(o, dict):
            if "id" in o:
                seen.append(o["id"])
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)
    collect(catalog)
    dupes = {i for i in seen if seen.count(i) > 1}
    if dupes:
        raise SystemExit(f"Duplicate OSCAL ids: {sorted(dupes)}")
    path = OUT / "oscal" / "cbuae_orm_catalog.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------- Word
def build_policy_doc(policy):
    doc = Document()
    st = doc.styles["Normal"]
    st.font.name, st.font.size = "Times New Roman", Pt(12)
    for name in ("Title", "Heading 1", "Heading 2"):
        doc.styles[name].font.name = "Times New Roman"
        doc.styles[name].font.color.rgb = None
    doc.add_heading(f'{policy["institution"]}: {policy["title"]}', level=0)
    doc.add_paragraph(f'Version {policy["version"]}, effective {policy["effective"]}. {policy["note"]}')
    for s in policy["sections"]:
        doc.add_heading(f'{s["id"]}. {s["title"]} (CBUAE Art. {s["cbuae_topic"]})', level=1)
        for c in s.get("clauses", []):
            p = doc.add_paragraph()
            p.add_run(c["id"] + "  ").bold = True
            p.add_run(c["text"])
        for sub in s.get("subsections", []):
            doc.add_heading(f'{sub["id"]} {sub["title"]}', level=2)
            for c in sub["clauses"]:
                p = doc.add_paragraph()
                p.add_run(c["id"] + "  ").bold = True
                p.add_run(c["text"])
    doc.add_heading("Annexes", level=1)
    for k, v in policy["annexes"].items():
        doc.add_paragraph(f"Annex {k[0]}: see {v}")
    path = OUT / "Sample_LFI_ICT_Cybersecurity_Policy.docx"
    doc.save(path)
    return path


def check_consistency(reqs, crit, clauses):
    ids = {c["clause_id"] for c in clauses}
    req_ids = {r["id"] for r in reqs["requirements"]}
    problems = []
    for c in crit["criteria"]:
        problems += [f'{c["id"]}: unknown clause {p}' for p in c["policy_clauses"] if p not in ids]
        problems += [f'{c["id"]}: unknown CBUAE ref {a}' for a in c["cbuae"] if a not in req_ids]
    covered = {a for c in crit["criteria"] for a in c["cbuae"]}
    for r in reqs["requirements"]:
        if r["in_scope"] not in (False, "justification") and r["id"] not in covered and r["id"] != "8.6":
            problems.append(f'requirement {r["id"]} in scope but no criterion')
    if problems:
        raise SystemExit("Catalogue inconsistencies:\n" + "\n".join(problems))


if __name__ == "__main__":
    reqs, crit, policy = load("cbuae_requirements.json"), load("criteria.json"), load("sample_policy.json")
    clauses = policy_clauses(policy)
    check_consistency(reqs, crit, clauses)
    (ROOT / "data" / "processed").mkdir(parents=True, exist_ok=True)
    (ROOT / "data" / "processed" / "policy_clauses.json").write_text(json.dumps(clauses, indent=2), encoding="utf-8")
    for p in (build_excel(reqs, crit, clauses), build_oscal(reqs, crit), build_policy_doc(policy)):
        print("wrote", p.relative_to(ROOT))
    print(f'{len(crit["criteria"])} criteria, {len(clauses)} policy clauses; OSCAL catalog valid against schema 1.1.3')
