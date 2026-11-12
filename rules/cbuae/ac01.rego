# AC-01 Segregation of duties | CBUAE 7.4.2, 8.6.3 | POL-AC-02
package cbuae.ac01

import rego.v1

import data.cbuae.lib

scope contains id if some id in lib.held_ids

violations contains {"entity": e1.identity, "detail": sprintf("%s+%s", [pair[0], pair[1]])} if {
	some pair in input.params.sod_pairs
	some e1 in lib.held
	e1.entitlement == pair[0]
	some e2 in lib.held
	e2.identity == e1.identity
	e2.entitlement == pair[1]
}
