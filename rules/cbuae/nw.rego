# NW-01..NW-05 network criteria | CBUAE 8.6.3 (and 8.3 for NW-05)
package cbuae.nw

import rego.v1

import data.cbuae.lib

permit contains r if {
	some r in input.firewall_rules
	r.action == "permit"
}

rule_scope contains r.rule_id if some r in permit

# NW-01 no rule permits a prohibited service (POL-NS-03)
nw01 contains {"entity": r.rule_id, "detail": r.service} if {
	some r in permit
	input.params.services[r.service].prohibited
}

# NW-02 no ANY source or ANY service to DATABASE / MANAGEMENT (POL-NS-02)
nw02 contains {"entity": r.rule_id, "detail": sprintf("%s->%s:%s", [r.src_zone, r.dst_zone, r.service])} if {
	some r in permit
	r.dst_zone in {"DATABASE", "MANAGEMENT"}
	"ANY" in {r.src_zone, r.service}
}

# NW-03 every rule is in the zone matrix (POL-NS-01)
nw03 contains {"entity": r.rule_id, "detail": sprintf("%s->%s:%s", [r.src_zone, r.dst_zone, r.service])} if {
	some r in permit
	not lib.zone_allows(r.src_zone, r.dst_zone, r.service)
}

flow_scope contains f.dst_asset if some f in input.flows

flow_allowed(f) if lib.zone_allows(f.src_zone, f.dst_zone, lib.service_of(f.proto, f.port))

# NW-04 observed traffic follows the zone matrix (POL-NS-01)
nw04 contains {"entity": f.dst_asset, "detail": sprintf("%s->%s %s/%d x%d", [f.src_zone, f.dst_zone, f.proto, f.port, f.count])} if {
	some f in input.flows
	not flow_allowed(f)
}

cia_flow_scope contains f.dst_asset if {
	some f in input.flows
	lib.cia(f.dst_asset)
}

# NW-05, rule part: flows to Critical Information Assets on the port of a cleartext service (POL-CIA-02).
# Cleartext on a port that belongs to an encrypted service is invisible to this rule (the ML part, Step 5).
nw05 contains {"entity": f.dst_asset, "detail": sprintf("%s/%d x%d", [f.proto, f.port, f.count])} if {
	some f in input.flows
	lib.cia(f.dst_asset)
	svc := lib.service_of(f.proto, f.port)
	not input.params.services[svc].encrypted
}
