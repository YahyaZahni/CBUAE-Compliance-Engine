# AC-02 Leavers disabled within one business day of HR termination, no use after the deadline
# CBUAE 8.6.3, 7.4.5 | POL-IM-02
package cbuae.ac02

import rego.v1

leavers contains i if {
	some i in input.identities
	i.disable_deadline != null
	i.disable_deadline <= input.period.end
}

used_after_deadline(i) if {
	some a in input.authentications
	a.identity == i.identity
	a.t > i.disable_deadline
}

enabled_after(i, t) if i.disabled_at == null

enabled_after(i, t) if i.disabled_at > t

relevant(i) if i.disable_deadline >= input.period.start

relevant(i) if enabled_after(i, input.period.start)

relevant(i) if used_after_deadline(i)

scope contains i.identity if {
	some i in leavers
	relevant(i)
}

violations contains {"entity": i.identity, "detail": "account enabled after the disable deadline"} if {
	some i in leavers
	enabled_after(i, max([i.disable_deadline, input.period.start]))
}

violations contains {"entity": i.identity, "detail": "successful authentication after the disable deadline"} if {
	some i in leavers
	used_after_deadline(i)
}
