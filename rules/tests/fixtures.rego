# Seeded test cases (hand-written, independent of the evaluation answer key). Times are small integers (ms).
package cbuae.fixtures

import rego.v1

params := {
	"leaver_grace_days": 1, "review_window_ms": 1000, "directory_assets": ["AD-DC"],
	"sod_pairs": [["PAY-INITIATE", "PAY-APPROVE"]],
	"role_baselines": {"PaymentsOfficer": ["PAY-INITIATE", "CUST-READ"]},
	"zone_matrix": {"USER->SERVER": ["https"], "SERVER->DATABASE": ["db-tls"]},
	"services": {"https": {"protocol": "tcp", "port": 443, "encrypted": true, "prohibited": false},
	             "db-tls": {"protocol": "tcp", "port": 1433, "encrypted": true, "prohibited": false},
	             "telnet": {"protocol": "tcp", "port": 23, "encrypted": false, "prohibited": true}},
	"port_service": {"tcp/443": "https", "tcp/1433": "db-tls", "tcp/23": "telnet"},
	"assets": {"PAY-APP": {"zone": "SERVER", "cia": true, "owner_role": "x"}, "CORE-DB": {"zone": "DATABASE", "cia": true, "owner_role": "x"},
	           "FILE-SRV": {"zone": "SERVER", "cia": false, "owner_role": "x"}},
	"entitlements": {"PAY-INITIATE": {"asset_id": "PAY-APP", "privileged": false}, "PAY-APPROVE": {"asset_id": "PAY-APP", "privileged": false},
	                 "CUST-READ": {"asset_id": "FILE-SRV", "privileged": false}, "CORE-ADMIN": {"asset_id": "CORE-DB", "privileged": true}},
}

period := {"id": 0, "start": 1000, "end": 2000, "data_start": 0}

human(id, role) := {"identity": id, "kind": "human", "role": role, "created_at": 0, "disabled_at": null, "owner": null,
	"hr_start": 0, "hr_termination": null, "hr_active_until": null, "disable_deadline": null}

ok_approval := {"status": "approved", "approved_at": 5, "approvers": ["line_manager", "asset_owner", "ciso"]}

pending_approval := {"status": "pending", "approved_at": null, "approvers": []}

grant(id, ent, approval) := {"identity": id, "entitlement": ent, "granted_at": 10, "revoked_at": 9000000000000, "approval": approval}

base_input := {"period": period, "params": params, "identities": [human("U:A", "PaymentsOfficer")],
	"entitlements": [grant("U:A", "PAY-INITIATE", null)], "last_use": [{"identity": "U:A", "asset_id": "PAY-APP", "t": 1900}],
	"authentications": [], "firewall_rules": [], "flows": []}
