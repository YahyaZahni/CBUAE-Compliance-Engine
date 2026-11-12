package cbuae.tests

import rego.v1

import data.cbuae.ac01
import data.cbuae.ac02
import data.cbuae.ac03
import data.cbuae.ac04
import data.cbuae.ac05
import data.cbuae.ac07
import data.cbuae.ac08
import data.cbuae.fixtures as fx
import data.cbuae.nw

ents(extra) := object.union(fx.base_input, {"entitlements": array.concat(fx.base_input.entitlements, extra)})

# AC-01
test_ac01_conflict if count(ac01.violations) == 1 with input as ents([fx.grant("U:A", "PAY-APPROVE", fx.ok_approval)])
test_ac01_clean if count(ac01.violations) == 0 with input as fx.base_input
test_ac01_scope if "U:A" in ac01.scope with input as fx.base_input

# AC-02
leaver(dis) := object.union(fx.human("U:L", "PaymentsOfficer"), {"hr_termination": 500, "hr_active_until": 600, "disable_deadline": 1200, "disabled_at": dis})
test_ac02_late if count(ac02.violations) == 1 with input as object.union(fx.base_input, {"identities": [leaver(1500)]})
test_ac02_never if count(ac02.violations) == 1 with input as object.union(fx.base_input, {"identities": [leaver(null)]})
test_ac02_on_time if count(ac02.violations) == 0 with input as object.union(fx.base_input, {"identities": [leaver(1100)]})
test_ac02_used_after if count(ac02.violations) == 1 with input as object.union(fx.base_input, {"identities": [leaver(1100)],
	"authentications": [{"identity": "U:L", "dst_asset": "FILE-SRV", "src_asset": "WS:1", "t": 1300, "server": true}]})

# AC-03
svc(owner) := {"identity": "S:svc", "kind": "service_account", "role": "", "created_at": 0, "disabled_at": null, "owner": owner,
	"hr_start": null, "hr_termination": null, "hr_active_until": null, "disable_deadline": null}
test_ac03_ok if count(ac03.violations) == 0 with input as object.union(fx.base_input, {"identities": [fx.human("U:A", "PaymentsOfficer"), svc("U:A")]})
test_ac03_no_owner if count(ac03.violations) == 1 with input as object.union(fx.base_input, {"identities": [fx.human("U:A", "PaymentsOfficer"), svc("")]})
test_ac03_owner_left if count(ac03.violations) == 1 with input as object.union(fx.base_input, {"identities": [
	object.union(fx.human("U:A", "PaymentsOfficer"), {"hr_active_until": 1500}), svc("U:A")]})

# AC-04
test_ac04_unapproved if count(ac04.violations) == 1 with input as ents([fx.grant("U:A", "CORE-ADMIN", null)])
test_ac04_late_approval if count(ac04.violations) == 1 with input as ents([fx.grant("U:A", "PAY-APPROVE", {"status": "approved", "approved_at": 50, "approvers": ["line_manager"]})])
test_ac04_pending_approval if count(ac04.violations) == 1 with input as ents([fx.grant("U:A", "PAY-APPROVE", fx.pending_approval)])
test_ac04_baseline_ok if count(ac04.violations) == 0 with input as fx.base_input

# AC-05 (window 1000 ms; end 2000 -> cutoff 1000)
test_ac05_unused if count(ac05.violations) == 1 with input as object.union(fx.base_input, {"last_use": [{"identity": "U:A", "asset_id": "PAY-APP", "t": 900}]})
test_ac05_used if count(ac05.violations) == 0 with input as fx.base_input
test_ac05_window_not_covered if count(ac05.scope) == 0 with input as object.union(fx.base_input, {"period": object.union(fx.period, {"data_start": 1500})})

# AC-07
test_ac07_missing_ciso if count(ac07.violations) == 1 with input as ents([fx.grant("U:A", "CORE-ADMIN", {"status": "approved", "approved_at": 5, "approvers": ["asset_owner"]})])
test_ac07_pending_approval if count(ac07.violations) == 1 with input as ents([fx.grant("U:A", "CORE-ADMIN", fx.pending_approval)])
test_ac07_ok if count(ac07.violations) == 0 with input as ents([fx.grant("U:A", "CORE-ADMIN", fx.ok_approval)])

# AC-08
auth(dst) := [{"identity": "U:A", "dst_asset": dst, "src_asset": "WS:1", "t": 1500, "server": true}]
test_ac08_unentitled if count(ac08.violations) == 1 with input as object.union(fx.base_input, {"authentications": auth("CORE-DB")})
test_ac08_entitled if count(ac08.violations) == 0 with input as object.union(fx.base_input, {"authentications": auth("PAY-APP")})

# NW-01..03
rule(src, dst, svc) := [{"rule_id": "R1", "src_zone": src, "dst_zone": dst, "service": svc, "action": "permit"}]
test_nw01 if count(nw.nw01) == 1 with input as object.union(fx.base_input, {"firewall_rules": rule("USER", "SERVER", "telnet")})
test_nw02 if count(nw.nw02) == 1 with input as object.union(fx.base_input, {"firewall_rules": rule("ANY", "DATABASE", "db-tls")})
test_nw03 if count(nw.nw03) == 1 with input as object.union(fx.base_input, {"firewall_rules": rule("USER", "DATABASE", "db-tls")})
test_nw_clean if count(nw.nw01 | nw.nw02 | nw.nw03) == 0 with input as object.union(fx.base_input, {"firewall_rules": rule("USER", "SERVER", "https")})

# NW-04 / NW-05
flow(src, dst, asset, port) := [{"dst_asset": asset, "src_zone": src, "dst_zone": dst, "proto": "tcp", "port": port, "count": 1}]
test_nw04 if count(nw.nw04) == 1 with input as object.union(fx.base_input, {"flows": flow("USER", "DATABASE", "CORE-DB", 1433)})
test_nw04_ok if count(nw.nw04) == 0 with input as object.union(fx.base_input, {"flows": flow("USER", "SERVER", "PAY-APP", 443)})
test_nw05 if count(nw.nw05) == 1 with input as object.union(fx.base_input, {"flows": flow("USER", "SERVER", "PAY-APP", 23)})
test_nw05_ok if count(nw.nw05) == 0 with input as object.union(fx.base_input, {"flows": flow("USER", "SERVER", "PAY-APP", 443)})
