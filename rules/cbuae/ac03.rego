# AC-03 Non-human identities have an owner who is an active employee | CBUAE 8.6.3 | POL-IM-03
package cbuae.ac03

import rego.v1

import data.cbuae.lib

nonhuman contains i if {
	some i in input.identities
	i.kind in {"service_account", "ai_agent"}
	lib.enabled(i)
}

scope contains i.identity if some i in nonhuman

active_employee(id) if {
	o := lib.identity(id)
	o.hr_start <= input.period.end
	o.hr_active_until == null
}

active_employee(id) if {
	o := lib.identity(id)
	o.hr_start <= input.period.end
	o.hr_active_until > input.period.end
}

violations contains {"entity": i.identity, "detail": sprintf("owner=%s", [i.owner])} if {
	some i in nonhuman
	not active_employee(i.owner)
}
