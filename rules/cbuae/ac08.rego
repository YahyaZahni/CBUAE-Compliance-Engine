# AC-08 Critical Information Assets accessed only by identities entitled to them | CBUAE 7.4.5, 8.6.3 | POL-CIA-03
package cbuae.ac08

import rego.v1

import data.cbuae.lib

cia_access contains a if {
	some a in input.authentications
	a.server
	lib.cia(a.dst_asset)
}

scope contains a.identity if some a in cia_access

entitled_at(id, asset, t) if {
	some e in input.entitlements
	e.identity == id
	lib.asset_of(e.entitlement) == asset
	e.granted_at <= t
	e.revoked_at > t
}

violations contains {"entity": a.identity, "detail": sprintf("%s@%d", [a.dst_asset, a.t])} if {
	some a in cia_access
	not entitled_at(a.identity, a.dst_asset, a.t)
}
