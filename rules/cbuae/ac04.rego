# AC-04 Entitlements outside the role baseline are approved before the grant | CBUAE 8.6.3, 7.4.5 | POL-AC-01
package cbuae.ac04

import rego.v1

import data.cbuae.lib

scope contains id if some id in lib.held_ids

approved(e) if {
	lib.approved_before_grant(e)
	some who in {"line_manager", "asset_owner", "ciso"}
	lib.has_approver(e, who)
}

violations contains {"entity": e.identity, "detail": e.entitlement} if {
	some e in lib.held
	not e.entitlement in lib.default_baseline(e.identity)
	not approved(e)
}
