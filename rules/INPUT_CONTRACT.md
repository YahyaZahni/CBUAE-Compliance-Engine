# Rule input contract (one assessment period)

Rules are OPA Rego v1 (`import rego.v1`). Every rule package defines two sets:

* `scope` — entity ids assessed in this period (strings);
* `violations` — objects `{"entity": <id>, "detail": <string>}` for nonconforming entities.

An entity in `scope` without a violation is *conforming*. All times are epoch milliseconds (integers).
Helpers in `data.cbuae.lib` may be imported (`import data.cbuae.lib`). Rules must not call `http.send`, `net.*`,
`opa.runtime`, or read anything other than `input` and `data.cbuae.lib`.

```
input.period            {id, start, end, data_start}
input.params.leaver_grace_days      business days allowed to disable a leaver (POL-IM-02)
input.params.review_window_ms       entitlement review window in ms (POL-AC-04)
input.params.directory_assets       [asset_id]
input.params.sod_pairs              [[entitlement_a, entitlement_b]]          conflicting pairs (Annex A)
input.params.role_baselines         {role: [entitlement]}                     baseline per role (POL-AC-01)
input.params.zone_matrix            {"SRC->DST": [service]}                   allowed inter-zone services (Annex C)
input.params.services               {service: {protocol, port, encrypted, prohibited}}   (Annex B)
input.params.port_service           {"tcp/443": service}
input.params.assets                 {asset_id: {zone, cia, owner_role}}       cia = Critical Information Asset
input.params.entitlements           {entitlement: {asset_id, privileged}}
input.identities[_]                 {identity, kind (human|service_account|ai_agent), role, created_at, disabled_at|null,
                                     owner|null (non-human only), hr_start|null, hr_termination|null,
                                     hr_active_until|null (end of last employed day), disable_deadline|null}
input.entitlements[_]               {identity, entitlement, granted_at, revoked_at (far future if still held), approval|null}
                                     approval = {status (approved|pending), approved_at|null, approvers: [line_manager|asset_owner|ciso]}
                                     approved_at is null while pending: test status before comparing times
input.last_use[_]                   {identity, asset_id, t}                   last server use of an asset up to period end
input.authentications[_]            {identity, dst_asset, src_asset|null, t, server}   successful logons in the period;
                                     server = network logon that is use of the asset (not a routine directory logon)
input.firewall_rules[_]             {rule_id, src_zone, dst_zone, service, action}   rules in force at any time in the period
input.flows[_]                      {dst_asset, src_zone, dst_zone, proto (tcp|udp), port, count}   observed traffic
```

`data.cbuae.lib` helpers: `enabled(i)`, `enabled_ids`, `identity(id)`, `held` (entitlements held at period end by
enabled identities), `held_ids`, `asset_of(ent)`, `privileged(ent)`, `cia(asset)`, `approved_before_grant(e)`,
`has_approver(e, who)`, `default_baseline(id)`, `service_of(proto, port)`, `zone_allows(src, dst, svc)`.

The input is a point-in-time view: it holds only what was knowable at `input.period.end`. Entitlement grants after
that moment, approvals not yet requested, and HR terminations not yet effective are absent; an approval requested
but not yet decided has status `pending`. A rule therefore gives the determination an assessor could have reached
at the end of that week, which is what the time-to-identify comparison (RQ4) needs.
