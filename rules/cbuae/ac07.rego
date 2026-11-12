# AC-07 Privileged access to Critical Information Assets approved by the asset owner and the CISO before the grant
# CBUAE 8.6.3, 7.4.5 | POL-AC-03
package cbuae.ac07

import rego.v1

import data.cbuae.lib

priv_cia contains e if {
	some e in lib.held
	lib.privileged(e.entitlement)
	lib.cia(lib.asset_of(e.entitlement))
}

scope contains e.identity if some e in priv_cia

valid(e) if {
	lib.approved_before_grant(e)
	lib.has_approver(e, "asset_owner")
	lib.has_approver(e, "ciso")
}

violations contains {"entity": e.identity, "detail": e.entitlement} if {
	some e in priv_cia
	not valid(e)
}
