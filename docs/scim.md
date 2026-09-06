# The SCIM 2.0 surface

Base URL, per GLPI instance:

```
https://your-glpi.example.com/plugins/glpiidentity/front/scim.php/v2
```

Authentication is a bearer token, issued per source. The token *is* the tenant:
it resolves to exactly one identity source, and everything the request can see
or change is reached through that source's links. There is no code path that
reaches a user another source provisioned.

```
Authorization: Bearer scim_…
Content-Type: application/scim+json
```

Responses are `application/scim+json`, including errors. A connector shown an
HTML error page reports that the URL is not a SCIM endpoint, which sends the
customer looking in entirely the wrong place.

---

## What is implemented

| | |
|---|---|
| `GET /ServiceProviderConfig` | ✔ |
| `GET /ResourceTypes`, `/ResourceTypes/{id}` | ✔ |
| `GET /Schemas`, `/Schemas/{id}` | ✔ |
| `GET /Users`, `/Users/{id}` | ✔ |
| `POST /Users` | ✔ |
| `PUT /Users/{id}` | ✔ |
| `PATCH /Users/{id}` | ✔ |
| `DELETE /Users/{id}` | ✔ deactivates; never purges |
| `GET /Groups`, `/Groups/{id}` | ✔ |
| `POST /Groups` | ✔ |
| `PUT /Groups/{id}` | ✔ |
| `PATCH /Groups/{id}` | ✔ including `members[value eq "…"]` |
| `DELETE /Groups/{id}` | ✔ |
| Filtering | one comparison — see below |
| Paging | `startIndex` / `count`, 1-based |
| Bulk | ✘ declared unsupported |
| Sorting | ✘ declared unsupported |
| ETags | ✘ declared unsupported |
| `/Me` | ✘ |
| `changePassword` | ✘ and never will be |

The unsupported ones are declared honestly in `ServiceProviderConfig`, which is
how they stop being a problem: connectors read that document and adapt. Claiming
a feature that is not implemented is how a customer's sync fails in a way nobody
can reproduce.

`changePassword` is a deliberate no rather than an omission. GLPI is not where
these passwords live, and a SCIM endpoint that offered to set one would be
inviting a directory to write a credential that could then be used to bypass it.

---

## User attributes

Eight, and no more. Every attribute exposed is one a customer's connector can
overwrite.

| SCIM | GLPI | Notes |
|---|---|---|
| `id` | — | A UUID on the link, not the GLPI user id |
| `externalId` | `links.external_id` | The directory's own identifier |
| `userName` | `users.name` | Must be unique across GLPI — see conflicts |
| `name.givenName` | `users.firstname` | |
| `name.familyName` | `users.realname` | |
| `displayName` | derived | Read-only |
| `emails` | `glpi_useremails` | Only the primary address is written |
| `active` | `users.is_active` | |
| `groups` | directory groups | Read-only; change membership on the group |

`id` is a UUID rather than the GLPI user id on purpose. Every query is already
scoped to the calling source, so the id is not the access control — but an
unguessable id means a mistake in that scoping is not *also* a disclosure of how
many users another customer has.

A created user gets `authtype = EXTERNAL` and no password. A provisioned account
that could also be signed into with a password would be a way around the
directory that provisioned it.

---

## Filtering

One comparison, on one attribute:

```
filter=userName eq "alice@acme.test"
filter=externalId eq "8f21…"
filter=displayName sw "Ali"
```

Operators: `eq`, `sw`, `co`. Attributes: `userName`, `externalId`, `id`,
`displayName`, `active` for users; `displayName`, `id`, `externalId` for groups.
Attribute names may be schema-qualified or prefixed with `profile.` — both are
normalised — and comparison is case-insensitive.

Everything else — `and`, `or`, `not`, grouping, value paths — is refused:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidFilter",
  "detail": "Only a single \"attribute eq \\\"value\\\"\" comparison is supported."
}
```

That refusal is the point. SCIM's full filter grammar is a parser, and
implementing it *badly* is worse than not implementing it: a filter that is
silently misread returns the wrong user and the connector cheerfully overwrites
them. One comparison is what Entra, Okta, Google and OneLogin all send, because
they are all asking the same question — "do you already have this person?" — and
a connector that gets an honest 400 falls back to listing.

A filter naming an attribute this server does not carry is also a 400, not an
empty list. An empty list would tell the connector the directory is empty, and
it would provision everybody a second time.

---

## Conflicts

A create whose `userName` already belongs to a GLPI account outside this source:

```json
{ "status": "409", "scimType": "uniqueness",
  "detail": "A GLPI user with this userName already exists and is not managed by this directory." }
```

This is the check that makes the endpoint safe to hand to a customer. GLPI
usernames are global, so without it a directory could provision a user called
`glpi` and take over the administrator's account.

If a customer legitimately needs a username somebody else already has, the fix
is on their side: provision the UPN (`alice@acme.test`) rather than the short
name. Entra and Okta both send the UPN by default.

**A replayed create is answered `200`, not `409`.** The spec prefers 409 for
"you asked to create someone who exists", but connectors replay creates after a
timeout, and answering 409 to a replay makes a transient network fault
permanent.

---

## Deprovisioning

Three things mean the same thing, and all three are handled:

- `PATCH` with `{"op":"replace","path":"active","value":false}` — what Entra and
  Okta actually send
- `PATCH` with no path and `{"active": false}` in the value object
- `DELETE /Users/{id}`

What happens is the source's **When a user is deprovisioned** setting:

| Setting | Effect |
|---|---|
| Deactivate the GLPI user | `is_active = 0`; they cannot sign in, and stay visible in reports |
| Move the GLPI user to the bin | GLPI's soft delete; recoverable, and they leave the pickers |

Neither purges, whichever is chosen. A GLPI user is referenced by every ticket
they raised or solved.

Reactivation is the same patch with `true`, and works whichever action was
taken. Connectors are inconsistent about spelling — `Replace`, `"True"`, `1` —
and all of them are accepted.

---

## Groups

A SCIM group is the *customer's* group. It is recorded against the source with
the directory's own id and display name, and it does **not** become a GLPI group
unless the source's **Mirror unmapped groups** setting says so.

That separation is the whole point of the feature. What reaches GLPI proper is
decided by the mappings, so `Executive` can become `VIP` — and a dozen
customers' "All Staff" groups do not all land in one shared tree.

Membership changes re-apply mappings to **both sides** of the change: whoever
joined, and whoever left. The person who just left `Executive` is precisely the
one whose VIP membership needs taking away, and they are no longer in the list
of members to iterate over.

Members that resolve to nothing are dropped, not refused. A connector routinely
sends a membership before it sends the member — Entra does it whenever a group
is assigned before its users have synced — and failing the whole group for one
unknown id turns a transient ordering quirk into a permanently broken group. The
count of ignored members is recorded in the event log.

---

## Status codes

| Code | When |
|---|---|
| `200` | Read, update, or a replayed create |
| `201` | Created |
| `204` | Deleted |
| `400` | Malformed body, unsupported filter, unsupported patch path |
| `401` | No token, an unknown token, or a token whose source is inactive |
| `404` | The resource does not exist **or belongs to another source** |
| `405` | A method this resource does not accept |
| `409` | `userName` taken by an account outside this source |
| `500` | A fault on this end — still in a SCIM error envelope |
| `503` | Federated identity is switched off instance-wide |

`503` rather than `401` for the master switch is deliberate: the credentials may
be perfect. A connector seeing 503 retries; one seeing 401 raises a credential
alert at the customer.

A resource belonging to another source is `404` rather than `403`. There is
nothing to tell a caller about a resource they have no business knowing exists.

---

## Testing it by hand

```sh
TOKEN=scim_…
BASE=https://your-glpi.example.com/plugins/glpiidentity/front/scim.php/v2

# Does the endpoint answer at all?
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/ServiceProviderConfig" | jq

# Who does this source have?
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/Users" | jq '.totalResults'

# The lookup every connector makes first
curl -s -H "Authorization: Bearer $TOKEN" \
  --get --data-urlencode 'filter=userName eq "alice@acme.test"' "$BASE/Users" | jq
```

If the first returns HTML, the URL is wrong. If it returns `401`, the token is.
If it returns `503`, the master switch is off.

---

## What gets recorded

Every create, update, deprovision, group sync and refusal, with the source, the
entity, the user, the subject and the reason. Refusals are recorded as loudly as
successes — a rejected token is the interesting event, not the boring one — and
a token that matched no source at all is still recorded, without one.

Retention is a setting; the default is 180 days and a daily cron task prunes.
