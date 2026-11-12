# Shared helpers for the CBUAE conformity rules. Input: one assessment period (see cbuae_conformity/rule_input.py).
package cbuae.lib

import rego.v1

enabled(i) if {
	i.created_at <= input.period.end
	not disabled_by(i, input.period.end)
}

disabled_by(i, t) if {
	i.disabled_at != null
	i.disabled_at <= t
}

enabled_ids contains i.identity if {
	some i in input.identities
	enabled(i)
}

identity(id) := i if {
	some i in input.identities
	i.identity == id
}

# entitlements held at the end of the period
held contains e if {
	some e in input.entitlements
	e.granted_at <= input.period.end
	e.revoked_at > input.period.end
	e.identity in enabled_ids
}

held_ids contains e.identity if some e in held

asset_of(ent) := input.params.entitlements[ent].asset_id

privileged(ent) if input.params.entitlements[ent].privileged

cia(asset) if input.params.assets[asset].cia

# an approval that exists, is approved, and is dated on or before the grant
approved_before_grant(e) if {
	e.approval != null
	e.approval.status == "approved"
	e.approval.approved_at <= e.granted_at
}

has_approver(e, who) if {
	some a in e.approval.approvers
	a == who
}

baseline(role) := {x | some x in input.params.role_baselines[role]}

default_baseline(id) := baseline(identity(id).role) if identity(id).role != ""

default_baseline(id) := set() if identity(id).role == ""

default_baseline(id) := set() if not identity(id)

service_of(proto, port) := input.params.port_service[sprintf("%s/%d", [proto, port])]

zone_allows(src, dst, svc) if {
	some s in input.params.zone_matrix[sprintf("%s->%s", [src, dst])]
	s == svc
}
