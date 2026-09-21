# GLPI Identity

OpenID Connect sign-in and SCIM 2.0 provisioning for GLPI 11, with each entity
bringing its own identity provider.

A GLPI instance can hold several organisations' people. Each can sign in with
their own IdP, be provisioned into their own entity by their own SCIM
connector, and land in the GLPI groups and profiles that a mapping says their
directory's groups mean.

No new dependencies: GLPI already ships `league/oauth2-client`,
`firebase/php-jwt` and `ramsey/uuid`.

## Features

- **Sign-in** — OIDC authorisation-code flow with PKCE, against as many providers
  as you have organisations. The login page takes an email address and routes on its
  domain; a "house" provider covers your own technicians.
- **Provisioning** — a SCIM 2.0 endpoint per source, with its own bearer token,
  writing only into that source's entity.
- **Mapping** — rules turning what a directory says into what GLPI does:
  *groups contains Executive → add to the VIP group*, *groups is IT Staff → grant
  the Technician profile in Internal > IT*, *department is Field Services → set
  their location to the depot*.
- **An audit trail** of who signed in, what was provisioned and what was refused.
- **`identity_status` and `identity_events`** read-only tools for `glpiai`.

OIDC only, no SAML. Every provider you are likely to meet speaks OIDC, and SAML would mean
vendoring an XML-signature library into a GLPI install — and XML signature
verification is the one place a subtle mistake is a silent authentication bypass
rather than an error.

## The safety model

Worth reading before the setup instructions, because it is what makes it safe to
hand an outside organisation a credential that writes into your GLPI.

**Identity is not email.** Addresses change on marriage and rebrand, get reused
when someone leaves, and belong to whoever controls the domain today. Every
lookup goes through a *link* — a record that this GLPI user came from that
source, keyed on the directory's own identifiers (an OIDC `sub`, a SCIM
`externalId`). Nothing is matched on email alone; an email match across sources
is how one organisation's directory ends up owning another's account, and it would
look like an ordinary successful login.

**A directory never adopts an account it does not own.** A SCIM create naming a
username that already exists outside this source is answered `409 uniqueness`,
and the equivalent sign-in is refused. Without that, provisioning a user called
`admin` would be a privilege escalation with a REST API in front of it.

**Everything is scoped through the source.** A SCIM request resolves to exactly
one source before anything else, and the only way to reach a user is through that
source's links. Tenant isolation is a property of the structure rather than of
each handler remembering to filter, and it is tested from the wrong side with one
organisation's token asking for another's people.

**Only what the plugin granted can be taken away.** Profiles and groups it
assigns are marked `is_dynamic` and recomputed on every sign-in and SCIM change.
Anything an administrator granted by hand is left alone.

**Mappings can only write descriptive fields** — an allowlist, not a denylist:
location, title, category, phone, administrative number, comments. The
interesting fields on a GLPI user are `authtype`, `password`, `is_active` and
`profiles_id`, and a mapping engine that could reach them would be a way for a
directory to disable an administrator. Attribute maps share that one allowlist
rather than keeping a second copy of it.

**Deprovisioning never purges.** Deactivate or move to the bin, both recoverable.
A GLPI user is referenced by every ticket they raised or solved.

**Keep the password form on**, longer than feels necessary. The configuration
that fixes a broken identity provider lives inside the instance that provider is
the only way into.

## The "clear your cookies" failure

A widely-met bug in SSO plugins for GLPI: you sign in, land in GLPI, and the next
page says your session cannot be validated. Signing in again does the same.
Clearing cookies fixes it.

`Session::checkValidSessionId()` runs on every request and checks a session key
called `glpi_remote_user`, set when somebody authenticates through GLPI's
built-in EXTERNAL mode. Once present, the check demands the configured SSO
variable still match it on every request — and `Session::init()` deliberately
*preserves* the key across the session regeneration it performs at login. So a
browser that has ever held such a session carries the key forward through every
subsequent sign-in by any method.

This plugin does three things about it:

1. **It never authenticates through EXTERNAL mode.** It verifies an id token
   itself and calls `Session::init()` directly, so it never sets that key.
2. **It removes the key and two like it before establishing a session** —
   `phpCAS` and a half-finished `glpi_password_expired` flow. A session
   established here is not a remote-user session and not a CAS session, so those
   markers are not merely stale, they are untrue.
3. **It checks the session will survive** before handing it over: user id,
   `valid_id`, an active profile and an active entity. If any is missing the
   session is destroyed and the sign-in refused with a reason.

There is a fourth, structural reason it cannot get stuck: `sso.php` runs with
GLPI's session check turned off, so a user whose session is broken can always
start a fresh sign-in.

The regression test plants a poisoned session the way GLPI's own EXTERNAL auth
would, signs in through it, and asserts the two requests afterwards still work.
Removing the purge turns it red.

## Setup

**Setup → Plugins → GLPI Identity** for the instance-wide switches:

![Instance-wide settings](docs/screenshots/identity-01-settings.png)

**Administration → Identity sources**, one per organisation's directory:

![An identity source](docs/screenshots/identity-02-source.png)

| Section | What it is |
|---|---|
| Single sign-on | The issuer, client id and secret, which claims carry what, and the email domains that route here |
| Provisioning | The SCIM endpoint URL and its bearer token |
| Placement | The default profile, and whether unmapped directory groups get mirrored |

The **redirect URI** to register with the provider is shown on the form and is
the same for every source:

```
https://your-glpi.example.com/plugins/glpiidentity/front/sso.php/callback
```

The **SCIM endpoint** is per source and also shown on the form:

```
https://your-glpi.example.com/plugins/glpiidentity/front/scim.php/v2
```

Press **Refresh metadata** after saving the issuer: the endpoints come from the
provider's own `.well-known/openid-configuration`, not from anything you type.
Press **Generate a token** for SCIM — displayed once and never again, since only
its hash is stored. A lost token is regenerated, which revokes the old one.

A provider publishing metadata somewhere other than under its issuer needs the
**Metadata URL** filled in instead. Azure AD B2C is the one you will meet: its
document lives under the user flow rather than the issuer, and the issuer it then
declares is a third URL again. Whatever the document says is authoritative.

Entra ID, Okta, Google Workspace and Keycloak have all been set up against this,
including the awkward bits: Entra sends group GUIDs in its token by default, and
Google sends no groups at all.

## Accounts that already exist

A GLPI instance is full of contacts before any of this is switched on. The
first time one signs in through their provider the sign-in is refused: a GLPI
account with that username exists and no link says this source owns it. That
refusal is the same one that stops a directory provisioning itself an `admin`.

The **Identity links** tab on a source is where that is answered. It lists what
the source owns, and underneath it the accounts in the source's entity that hold
an email address and belong to nobody yet. Ticking them, or *Link all listed*,
records an invitation.

An invitation grants nothing on its own. It is claimed the first time somebody
signs in through that provider presenting a **verified address the account
already holds**, and never again; a link bound once is never rebound by a login.
So an account changes hands only when an administrator and the provider both say
so.

Two accounts invited with the same address is refused rather than guessed at.

A link bound to a subject that no longer exists — a tenant migration, a rebuilt
IdP, a person deleted and recreated — is **reopened**, clearing the subject and
leaving the invitation for the next sign-in to claim. **Unlinking** is the other
direction: the source no longer owns the account.

## The login page

![The login page](docs/screenshots/identity-05-login.png)

One box beside GLPI's own password form. It asks for an email address rather than
showing a list of providers: that list would be a directory of who your organisations
are, and their employees do not know which of a dozen providers is theirs
anyway. An address at a claimed domain goes to that organisation's provider; one at
no claimed domain falls back to the house provider.

A domain can be claimed by exactly one source, enforced on save. Two organisations
claiming the same domain is not an ambiguity to break at sign-in time; it is a
misconfiguration that would route one organisation's people into another's
entity.

There is no "Sign in with us" button by default — it would be a second primary
action next to GLPI's own Sign in, which reads as a choice rather than a
shortcut. Filling in a source's **Button label** adds one. Only the house
provider can have one; a button naming an organisation would put their name on a
public page.

### Single sign-on only

Switching **Keep the username and password form** off removes GLPI's own login
controls from the page:

![The login page with only single sign-on](docs/screenshots/identity-06-login-sso-only.png)

Removed, not hidden — a hidden password field is still filled by autofill and
still submitted.

Two things stop this locking you out:

- **`index.php?local=1` always shows the form.** Not a bypass; it still wants
  valid credentials, and the link on the page points at it.
- **It only applies while single sign-on can work.** The markup that removes the
  local controls is emitted as part of the sign-in block, and that block renders
  only for a source that is ready. Break every provider and the password form is
  back. That is a property of the ordering rather than a check somebody has to
  remember, and there is a test for it.

**This changes the login page, not what GLPI accepts.** A password still works
for any account that has one. What makes the posture sound is that accounts this
plugin provisions are created with `authtype = EXTERNAL` and no password at all,
so the only accounts a password can reach are the GLPI-internal break-glass set.

The block renders inside GLPI's login form, which is a trap if you touch it: a
nested `<form>` is dropped by the HTML parser, a `<button>` without an explicit
type submits the login form, and a `required` field stops GLPI's own password
login working at all. Nothing this plugin renders is a form, has a name, is
required, or is a submit button.

## Mapping

Every rule that matches applies; this is not first-match-wins. Someone in both
`Executive` and `IT Staff` gets the VIP group *and* the Technician profile.

Rules belong to a source, not the instance. GLPI has a good global
authorisation-rules engine, and a single global list is the wrong shape here:
forty entities' rules in one ordered list, where the isolation between them
depends on every rule remembering to test which directory it came from.

A profile rule also says **which entity** to grant the profile in — the source's
own entity, or any entity beneath it. That is what lets one directory describe
somebody who is a technician in one part of the tree and an ordinary requester in
another: *groups is Support → Support Technician in Customers, and below* beside
*everyone → Self-Service in Internal > IT*. Without it a source could only ever
grant in one entity, and a person whose role differs across two of them could not
be expressed at all.

The choice is bounded by the source's subtree, on save and again when the rule is
applied. Acme's rules still cannot reach Beta's tree, so the property that makes
this safe to hand to an outside directory is unchanged; only the granularity is.
Rules written before this existed keep their old meaning — the upgrade fills the
column in with each rule's source entity, which is exactly what the engine did
for them before.

Group membership reaches a mapping by two routes and needs only one:

- the **groups claim** in the id token, at sign-in;
- the **directory groups** recorded from SCIM's `/Groups` endpoint.

The second is what makes group mapping work where the first is unavailable, and
is why SCIM groups are stored as the organisation's groups rather than mirrored into
GLPI's group tree. Mirroring is available and off by default: one shared tree
filling up with a dozen organisations' "All Staff" helps nobody.

## Attribute maps

A mapping rule answers *who is this person* — group membership, the same answer
for everyone in the group — and sets a field to a constant. That is the right
shape for a location and the wrong shape for a phone number, which is different
for every person and would need one rule each.

**Administration → Identity sources → a source → Attribute maps** is the other
half. A row names a GLPI field and where its value comes from:

| GLPI field | From SCIM | From an id token claim |
|---|---|---|
| Phone | `phoneNumbers[type eq "work"].value` | `phone_number` |
| Administrative number | `urn:…:enterprise:2.0:User:employeeNumber` | `employee_id` |
| Location | `addresses[type eq "work"].locality` | |
| Supervisor | `urn:…:enterprise:2.0:User:manager.value` | `manager` |

Both sides may be filled in and usually are: the same field is fed by SCIM when
a connector pushes an update and by the id token when the person signs in, and
the two vocabularies name it differently. Whichever key the run carries is used.

Multi-valued attributes get three addressable forms, because a connector decides
which it sends and an administrator should not have to guess:

```
phoneNumbers.value                    every number, in order
phoneNumbers[type eq "work"].value    the one typed work
phoneNumbers[primary eq true].value   the one flagged primary
```

An extension is named by its full urn, with sub-attributes below it in dot
form — `urn:…:2.0:User:manager.displayName` — which is what SCIM says and, more
usefully, what Entra's own mapping screen shows. The same flattened bag is what
rules match on, so a rule can now test `title` or `department` on a SCIM update
and not only at sign-in.

**Supervisor is a reference, not a value.** Connectors disagree about what they
put in a manager attribute — Entra's is a Reference-type mapping whose
Referenced Object Attribute is set per tenant, so it may be `objectId`,
`userPrincipalName` or `mail`, and Okta sends the manager's login. All of them
work: the value is tried as a directory id (our SCIM resource id, the
`externalId`, then the OIDC `sub`), then as a GLPI username, then as a verified
email address.

Every one of those steps is confined to **this source's own links**, which is
what makes offering username and email safe here at all. The "identity is not
email" rule above is about matching *across* sources; inside one source the
directory already owns every candidate. It matters more than it looks, because
`users_id_supervisor` steers GLPI's validation and approval routing — a
reference that could escape the source would be a way to route another
organisation's approvals through a stranger. Two candidates matching is refused
rather than guessed at.

A manager who has not been provisioned yet resolves to nothing and is left for
the next sync, rather than failing the update: connectors provision people in no
particular order, and a manager routinely arrives after their reports. A manager
who resolves to the person themselves is refused — GLPI would store it and then
route their own approvals back to them.

Three things worth knowing before you map a field:

- **One field, one source of truth.** A field written by a static rule cannot
  also be written by an attribute map, refused from both directions on save.
  Two things writing one field with a documented winner is a configuration
  nobody can read off the screen, so there is no precedence to learn.
- **Absent is not empty.** A key missing from the payload leaves the field
  alone; a key present and empty clears it. Entra omits null attributes rather
  than sending them empty, so the other reading would wipe a field on every
  cycle that happened not to carry it. The cost is that clearing an attribute
  upstream does not clear it here until something says so explicitly.
- **The directory wins, including over a person.** A mapped value overwrites
  what is in GLPI on every sign-in and every SCIM update, an edit an
  administrator made by hand included. Profiles and groups carry `is_dynamic`
  so the plugin knows what it granted and leaves the rest alone; a field has no
  such marker, so the only way to keep one editable in GLPI is not to map it.

`phoneNumbers` is not something to add to the **user** attribute mapping in
Entra — check it is in the default template, which usually sends
`telephoneNumber → phoneNumbers[type eq "work"].value` already.

## SCIM

Users and Groups: create, read, replace, patch, delete, one filter comparison,
index paging. Bulk, sort, ETags and `/Me` are declared unsupported in
`ServiceProviderConfig` rather than half-built — a connector reads that document
and adapts, and a half-built feature is one it will trust.

The filter grammar is one comparison, `attribute eq "value"` and its `sw`/`co`
siblings, which is what every connector sends when asking "do you already have
this person?". Anything else is refused with `invalidFilter` rather than guessed:
a connector that gets an honest 400 falls back to listing, while one that gets a
wrong answer overwrites the wrong person.

### When there is no connector

Deprovisioning only happens because a SCIM request asked for it, so a source
whose organisation has no connector — Azure AD B2C and Zitadel are service providers
rather than provisioning clients, and Google Workspace needs a paid tier — never
hears that anybody has left.

**Deactivate after (days idle)** on a source is the answer, off (`0`) until
somebody sets it. It is narrower than it sounds:

- only accounts that have **actually signed in** are considered, so an invitation
  nobody took up never deactivates a long-standing contact;
- the last sign-in is taken across **every** source the person is linked to, so a
  consultant working for two of the organisations you support is not idle because one has not
  seen them;
- they are **deactivated, never binned**, whatever *When a user is deprovisioned*
  says. "Has not signed in lately" is a weaker statement than "the directory says
  they are gone".

## glpi-ai tools

| Tool | Answers |
|---|---|
| `identity_status` | Why one person can or cannot sign in: linked or not, active or not, and what their recent attempts did |
| `identity_events` | What has been failing across the providers — refusals, denials, deactivations, group syncs |

"They can't log in" is the most common ticket a service desk takes. An account
that was never provisioned, one the organisation's directory deactivated last night,
and one being refused by a mapping rule all look identical from outside, and none
is a forgotten password.

`identity_status` returns a one-line reading alongside the facts, because the
combination is what means something: a disabled GLPI account refuses every
sign-in however healthy the provider is. `identity_events` answers the other
shape — a run of refusals at the same minute is a tenant problem, not eleven
forgotten passwords.

Both are gated on `plugin_glpiidentity_source`, the same right the pages use; the
event log carries denial reasons and IP addresses.

**Read only, and this is the plugin where that matters most.** The code beside
these tools creates accounts, disables them and maps them into profiles. A model
that could provision could grant access to your GLPI, and one that could
deprovision could lock a real person out.

## Install

```bash
# from the GLPI root — the directory must be named for the plugin key,
# which is not the repository name
git clone https://github.com/bijstaan/glpi-identity.git plugins/glpiidentity
php bin/console plugin:install -u glpi glpiidentity
php bin/console plugin:activate glpiidentity
```

## Tests

```bash
docker compose -p glpi exec glpi sh -c 'cd /var/www/glpi/plugins/glpiidentity && tests/run.sh'
```

Four suites, no real credentials and no network egress.

- **`tests/attributes.php`** covers the pass-through: flattening a payload the
  way a connector names it, the overlap refusal from both directions, and the
  absent-versus-empty rule. Needs neither the web server nor the mock provider.
- **`tests/login.php`** covers what the login page offers and, more to the
  point, that it never takes GLPI's own password form away without putting a
  working route in its place.
- **`tests/scim.php`** drives the real HTTP endpoint rather than calling the
  server class. Half of what makes a SCIM endpoint work is outside the handler —
  URL routing, the exemption that lets a request with no GLPI session through,
  the Authorization header surviving the web server, the content type — and a
  test calling the class directly would pass on a plugin nobody could reach. It
  also tests tenancy from the wrong side: Beta's token asking for Acme's user,
  Beta's token adding Acme's user to a group.
- **`tests/oidc.php`** signs in against `tests/mock-idp.php`, a provider that
  signs its tokens properly. The value is in the negative cases, each a named
  attack: a token signed with the wrong key, from a different issuer, issued for
  a different client, echoing the wrong nonce, and a callback carrying the wrong
  state. A mock returning unsigned tokens would let every one of those checks rot
  unnoticed.

## Layout

```
setup.php            hooks, the firewall exemption and the stateless-path
                     declaration that SCIM needs
hook.php             install/uninstall: six tables, one right, three cron tasks
src/Source.php       one organisation's identity configuration
src/Link.php         the fact that a GLPI user came from a source
src/Mapping.php      one rule, and the form for it
src/Mapper.php       applying rules, and the dynamic/manual split
src/AttributeMap.php one GLPI field, filled from a directory attribute
src/Provisioning.php creating, updating and retiring GLPI users
src/SignIn.php       verified claims → a GLPI session
src/IdpGroup.php     a group the directory told us about
src/EventLog.php     who signed in, what was provisioned, what was refused
src/Oidc/Flow.php    the authorisation-code flow and its checks
src/Scim/            the SCIM server: routing, filters, resources, schemas
front/sso.php        start and callback
front/scim.php       the SCIM endpoint
```

Two GLPI details, if you extend this:

- **`$_SERVER['PATH_INFO']` is always empty.** GLPI 11 routes every request
  through Symfony's front controller, so `SCRIPT_NAME` is `/index.php` and the
  legacy script is `require`d without PHP computing a path info. The information
  is in `REQUEST_URI`; see `Url::pathAfter()`.
- **The firewall and the session manager are two separate opt-outs.**
  `Firewall::addPluginStrategyForLegacyScripts(..., STRATEGY_NO_CHECK)` stops
  GLPI redirecting an unauthenticated request to the login page.
  `SessionManager::registerPluginStatelessPath(...)` stops it starting a session
  and, the part that bites, stops the CSRF listener rejecting every POST, PUT,
  PATCH and DELETE. SCIM needs both; `sso.php` needs only the first, being
  GET-only and wanting a session.

## Independence

We have never had a GLPI Network subscription. We have not seen the source of
GLPI's "Exclusive" plugins, or their screens, or their docs. Nothing in here
came from them.

It was built from GLPI's own source, which is GPL and public, and from its API.
That is the whole list.

If it looks like theirs in places, that is because core only gives you so many
places to hook into.

GLPI is a trademark of Teclib'. This plugin is not affiliated with Teclib' or
the GLPI project.

## Licence

GPL-3.0-or-later, the same licence as GLPI. The plugin is loaded into GLPI's
process and extends its classes, so it is a derivative work. See
[LICENSE](LICENSE).
