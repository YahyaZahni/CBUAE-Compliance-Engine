# AC-05 Entitlements unused for longer than the review window are removed | CBUAE 8.6.3, 7.4.5 | POL-AC-04
package cbuae.ac05

import rego.v1

import data.cbuae.lib

window_covered if input.period.end - input.period.data_start >= input.params.review_window_ms

cutoff := input.period.end - input.params.review_window_ms

scope contains id if {
	window_covered
	some id in lib.held_ids
}

used_since_cutoff(e) if {
	some u in input.last_use
	u.identity == e.identity
	u.asset_id == lib.asset_of(e.entitlement)
	u.t >= cutoff
}

violations contains {"entity": e.identity, "detail": e.entitlement} if {
	window_covered
	some e in lib.held
	e.granted_at <= cutoff
	not used_since_cutoff(e)
}
