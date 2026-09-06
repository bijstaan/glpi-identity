<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The OpenID Connect sign-in, against a provider that signs properly.
 *
 * The whole value of this suite is in the negative cases. A sign-in that works
 * proves very little — it is what happens when the token is *wrong* that
 * separates authentication from a decorated redirect, and each of those cases
 * is a named attack that has worked against real implementations:
 *
 *   a token signed with the wrong key      → forged identity
 *   a token from a different issuer        → cross-tenant impersonation
 *   a token issued for a different client  → token substitution
 *   a token echoing the wrong nonce        → replay
 *   a callback carrying the wrong state    → login CSRF
 *
 * Driven with a cookie jar rather than a browser, because everything under test
 * is protocol: redirects, state, and what verifies.
 *
 * Usage, inside the GLPI container:
 *   php -S 127.0.0.1:9097 tests/mock-idp.php &
 *   php tests/oidc.php
 */

require '/var/www/glpi/vendor/autoload.php';

(new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Cookie\CookieJar;

/** @var DBmysql $DB */
global $DB;

const IDP  = 'http://127.0.0.1:9097';
// Must match GLPI's configured url_base, because that is what the redirect URI
// is built from: driving the flow against a different hostname puts the
// cookies on one host and the callback on another, and the pending sign-in is
// simply not there when it returns.
const GLPI = 'http://localhost';

if (!(new Auth())->login('glpi', 'glpi', true)) {
    fwrite(STDERR, "could not log in as glpi/glpi\n");
    exit(1);
}

(new Plugin())->init(true);

// The provider signing keys are cached for fifteen minutes, which is right in
// production and wrong here: the mock generates a fresh key each run, so a
// cached key set from a previous run would fail every signature and look like
// a verification bug.
(new Glpi\Cache\CacheManager())->getCacheInstance('plugin:glpiidentity')->clear();

$failures = [];

function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    echo ($ok ? "  \033[32mPASS\033[0m  " : "  \033[31mFAIL\033[0m  ") . $name
       . ($detail !== '' ? " :: $detail" : '') . "\n";
    if (!$ok) {
        $failures[] = $name;
    }
}

// ------------------------------------------------------------------ fixtures

$before      = Config::getConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT);
$made_entity = [];
$made_source = [];
$made_group  = [];

register_shutdown_function(static function () use ($before, &$made_entity, &$made_source, &$made_group): void {
    global $DB;

    foreach ($made_source as $sources_id) {
        foreach (getAllDataFromTable(Link::getTable(), ['plugin_glpiidentity_sources_id' => $sources_id]) as $row) {
            (new User())->delete(['id' => $row['users_id']], true);
        }
        (new Source())->delete(['id' => $sources_id], true);
    }
    foreach ($made_group as $groups_id) {
        (new Group())->delete(['id' => $groups_id], true);
    }
    foreach (array_reverse($made_entity) as $id) {
        (new Entity())->delete(['id' => $id], true);
    }

    $now   = Config::getConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT);
    $stale = array_diff(array_keys($now), array_keys($before));
    if ($stale !== []) {
        Config::deleteConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT, $stale);
    }
    if ($before !== []) {
        Config::setConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT, $before);
    }

    $DB->delete(EventLog::TABLE, [1]);
});

$entity = new Entity();
$acme   = (int) $entity->add(['name' => 'glpiid-oidc-acme', 'entities_id' => 0]);
$made_entity[] = $acme;

$group = new Group();
$vip   = (int) $group->add(['name' => 'glpiid-oidc-VIP', 'entities_id' => $acme, 'is_usergroup' => 1]);
$made_group[] = $vip;

$source = new Source();
$sid    = (int) $source->add([
    'name'                => 'glpiid OIDC Acme',
    'entities_id'         => $acme,
    'is_active'           => 1,
    'sso_enabled'         => 1,
    // A real issuer to get past validation; the mock is pointed at below.
    'issuer'              => 'https://placeholder.invalid',
    'client_id'           => 'glpi-test-client',
    'client_secret'       => 'a-test-secret',
    'email_domains'       => 'acme.test',
    'jit_provision'       => 1,
    'default_profiles_id' => 1,
]);
$made_source[] = $sid;

if ($sid <= 0) {
    fwrite(STDERR, "could not create the test source\n");
    exit(1);
}

// The mock provider speaks http on loopback, and the https rule refuses that
// for a good reason — an issuer URL is where a browser goes to type a password.
// Written straight to the table rather than through update(), so the rule stays
// under test rather than being relaxed for the convenience of the test.
$DB->update(
    Source::getTable(),
    ['issuer' => IDP, 'discovery_url' => IDP . '/.well-known/openid-configuration'],
    ['id' => $sid]
);
$source->getFromDB($sid);

Settings::save(['enabled' => '1']);

echo "\nDiscovery\n";

$result = $source->discover();
$source->getFromDB($sid);

check('metadata is fetched', $result['ok'], $result['message']);
check('the endpoints are remembered', $source->endpoint('token_endpoint') === IDP . '/token');
check('the issuer comes from the document, not from what was typed',
    $source->endpoint('issuer') === IDP);
check('the source reports itself ready for sign-in', $source->ssoReady());

echo "\nIssuer validation\n";
$probe = new Source();
$probe->getFromDB($sid);
check('an http issuer is refused outright',
    @$probe->update(['id' => $sid, 'issuer' => 'http://insecure.example']) === false);
$probe->getFromDB($sid);
check('and the stored issuer is unchanged', $probe->fields['issuer'] === IDP);

echo "\nHome-realm discovery\n";
check('an address routes to the source claiming its domain',
    Source::forEmail('someone@acme.test')?->getID() === $sid);
check('an address at an unclaimed domain routes nowhere',
    Source::forEmail('someone@elsewhere.test') === null);
check('a second source cannot claim the same domain', (static function () use ($acme, &$made_source): bool {
    $clash = new Source();
    $id    = @$clash->add([
        'name'          => 'glpiid clash',
        'entities_id'   => $acme,
        'email_domains' => 'acme.test',
    ]);

    // Tracked for cleanup even though it is expected not to exist: if the
    // check ever fails, the row it leaves behind would claim acme.test and
    // make every subsequent run of this suite fail at the fixture instead of
    // here, which hides the actual regression.
    if ($id !== false) {
        $made_source[] = (int) $id;
    }

    return $id === false;
})());

// --------------------------------------------------------------- the round trip

/**
 * Is this cookie jar signed in?
 *
 * Asked of `/index.php`, following redirects, because that page is reachable
 * whatever profile the user has: it renders the login form for a stranger and
 * redirects a signed-in user to whichever interface their profile gives them.
 * `central.php` was tried first and is wrong — a Self-Service user is signed in
 * and still cannot open it, so it reports a working sign-in as a failure.
 */
function isSignedIn(CookieJar $jar): bool
{
    $http = new HttpClient(['http_errors' => false, 'cookies' => $jar, 'timeout' => 20]);
    $body = (string) $http->get(GLPI . '/index.php')->getBody();

    return !str_contains($body, 'name="login_name"') && !str_contains($body, 'id="login_name"');
}

/**
 * Walk a sign-in from the login page to the session, following redirects by
 * hand so each hop can be inspected.
 *
 * The outcome is decided by asking GLPI for a page that requires a session,
 * not by where the callback redirected. Both success and refusal end at
 * index.php — GLPI carries the reason as a flash message rather than in the
 * URL — so the redirect target cannot tell them apart, and an assertion built
 * on it passes for the wrong reason.
 *
 * @return array{signed_in:bool,status:int,location:string,stopped:string,jar:CookieJar}
 */
function signIn(string $query = '', ?CookieJar $jar = null): array
{
    $jar  = $jar ?? new CookieJar();
    $http = new HttpClient(['http_errors' => false, 'allow_redirects' => false, 'cookies' => $jar, 'timeout' => 20]);

    // 1. GLPI decides which provider and sends the browser there.
    $start = $http->get(GLPI . '/plugins/glpiidentity/front/sso.php/start?email=alice@acme.test');
    $to    = $start->getHeaderLine('Location');

    if (!str_starts_with($to, IDP)) {
        // The sign-in never reached the provider. Reported as its own outcome
        // rather than as a callback result, because "bounced at the start" and
        // "the provider refused" are different failures and an assertion that
        // cannot tell them apart passes for the wrong reason.
        return [
            'signed_in' => false,
            'status'    => $start->getStatusCode(),
            'location'  => $to,
            'stopped'   => 'start',
            'jar'       => $jar,
        ];
    }

    // 2. The provider redirects straight back with a code.
    $authorize = $http->get($to . ($query !== '' ? '&' . $query : ''));
    $back      = $authorize->getHeaderLine('Location');

    // 3. GLPI verifies and, if it is happy, establishes a session.
    $callback = $http->get($back);

    return [
        // 4. The only question that matters.
        'signed_in' => isSignedIn($jar),
        'status'    => $callback->getStatusCode(),
        'location'  => $callback->getHeaderLine('Location'),
        'stopped'   => 'callback',
        'jar'       => $jar,
    ];
}

echo "\nA successful sign-in\n";

$mapping = new Mapping();
$mapping->add([
    'plugin_glpiidentity_sources_id' => $sid,
    'claim'          => 'groups',
    'match_operator' => Mapping::OP_EQUALS,
    'match_value'    => 'Executive',
    'action'         => Mapping::ACTION_GROUP,
    'groups_id'      => $vip,
    'is_active'      => 1,
]);

$round = signIn();

check('the sign-in reaches the identity provider', $round['stopped'] === 'callback', $round['location']);
check('and ends with a usable GLPI session', $round['signed_in']);

$user = new User();
check('the user was created on first sign-in', $user->getFromDBbyName('alice@acme.test'));
check('in the source\'s entity', (int) $user->fields['entities_id'] === $acme);
check('with their name from the claims',
    $user->fields['firstname'] === 'Alice' && $user->fields['realname'] === 'Anderson');
check('and an email from the claims',
    count(getAllDataFromTable(UserEmail::getTable(), ['users_id' => $user->getID()])) === 1);

check('the groups claim was mapped to the GLPI group',
    count(getAllDataFromTable(Group_User::getTable(), [
        'users_id'  => $user->getID(),
        'groups_id' => $vip,
    ])) === 1);

check('and the default profile was granted in that entity',
    count(getAllDataFromTable(Profile_User::getTable(), [
        'users_id'    => $user->getID(),
        'entities_id' => $acme,
        'is_dynamic'  => 1,
    ])) === 1);

$link = Link::forSubject($sid, 'mock-subject-0001');
check('a link records which directory this account came from', $link !== null);
check('and when they last signed in', !empty($link?->fields['date_lastlogin']));

check('the session cookie was actually set',
    count(array_filter(
        $round['jar']->toArray(),
        static fn(array $c): bool => str_contains((string) $c['Name'], 'glpi')
    )) > 0);

echo "\nSigning in again\n";
$second = signIn();
check('a second sign-in reuses the same account', (static function () use ($sid): bool {
    return count(getAllDataFromTable(Link::getTable(), ['plugin_glpiidentity_sources_id' => $sid])) === 1;
})());
check('and still signs them in', $second['signed_in']);

echo "\nToken verification\n";

foreach (
    [
        'signature' => 'a token signed with the wrong key is refused',
        'issuer'    => 'a token from a different issuer is refused',
        'audience'  => 'a token issued for another application is refused',
        'nonce'     => 'a token echoing the wrong nonce is refused',
    ] as $flaw => $label
) {
    $bad = signIn('bad=' . $flaw);

    // The sign-in must have got as far as the callback for this to mean
    // anything, and then have been refused there.
    check($label, $bad['stopped'] === 'callback' && !$bad['signed_in'], $bad['stopped']);
}

$events = array_column(EventLog::recent(100, $sid), 'event');
check('every refusal was recorded', count(array_filter(
    $events,
    static fn(string $e): bool => $e === EventLog::SSO_DENIED
)) >= 4);

echo "\nCallback tampering\n";

$http = new HttpClient(['http_errors' => false, 'allow_redirects' => false, 'timeout' => 20]);
$jar  = new CookieJar();
$http2 = new HttpClient(['http_errors' => false, 'allow_redirects' => false, 'cookies' => $jar, 'timeout' => 20]);

$start     = $http2->get(GLPI . '/plugins/glpiidentity/front/sso.php/start?email=alice@acme.test');
$to        = $start->getHeaderLine('Location');
if (!str_starts_with($to, IDP)) {
    // Nothing to tamper with if the sign-in never started; failing here rather
    // than throwing keeps the rest of the suite reportable.
    check('a sign-in can be started at all', false, $to);
    $to = IDP . '/authorize';
}
$authorize = $http2->get($to);
$back      = $authorize->getHeaderLine('Location');

$tampered = preg_replace('/state=[^&]+/', 'state=not-the-state', $back);
$http2->get($tampered);
check('a callback with the wrong state is refused', !isSignedIn($jar));

$fresh = new CookieJar();
$http3 = new HttpClient(['http_errors' => false, 'allow_redirects' => false, 'cookies' => $fresh, 'timeout' => 20]);
$http3->get(GLPI . '/plugins/glpiidentity/front/sso.php/callback?code=x&state=y');
check('a callback with no sign-in in progress is refused', !isSignedIn($fresh));

echo "\nWhen the id token carries no groups\n";

$DB->delete(Group_User::getTable(), ['users_id' => $user->getID(), 'groups_id' => $vip]);
$fallback = signIn('claims=nogroups');
check('the sign-in still succeeds', $fallback['signed_in']);
check('and userinfo supplied the groups the token left out',
    count(getAllDataFromTable(Group_User::getTable(), [
        'users_id'  => $user->getID(),
        'groups_id' => $vip,
    ])) === 1);

echo "\nDeactivated accounts\n";

$user->update(['id' => $user->getID(), 'is_active' => 0]);
$blocked = signIn();
check('a deactivated user cannot sign in', !$blocked['signed_in']);
$user->update(['id' => $user->getID(), 'is_active' => 1]);

echo "\nWhen just-in-time provisioning is off\n";

$DB->update(Source::getTable(), ['jit_provision' => 0], ['id' => $sid]);
foreach (getAllDataFromTable(Link::getTable(), ['plugin_glpiidentity_sources_id' => $sid]) as $row) {
    (new User())->delete(['id' => $row['users_id']], true);
    $DB->delete(Link::getTable(), ['id' => $row['id']]);
}

$refused = signIn();
check('an unknown person is refused rather than created', !$refused['signed_in']);
check('and no account was made',
    !(new User())->getFromDBbyName('alice@acme.test'));

$DB->update(Source::getTable(), ['jit_provision' => 1], ['id' => $sid]);

echo "\nName collisions\n";

// Somebody who already answers to that name and is nothing to do with Acme.
$outsider = new User();
$outsider_id = (int) $outsider->add(['name' => 'alice@acme.test', 'entities_id' => 0]);

$hijack = signIn();
check('a directory cannot take over a GLPI account it does not own', !$hijack['signed_in']);
check('and the existing account is untouched',
    Link::forUser($sid, $outsider_id) === null);

(new User())->delete(['id' => $outsider_id], true);

echo "\nA browser arriving with a poisoned session\n";

// The reported bug, reproduced. GLPI's built-in EXTERNAL auth leaves
// `glpi_remote_user` in the session; checkValidSessionId() then demands a
// matching server variable on every request, and Session::init() *preserves*
// the key across the regeneration it performs. A browser that ever held such a
// session therefore signs in successfully and is thrown out on the next click,
// for ever, until its cookies are cleared.
//
// There is no way to plant that key from outside the server, so it is planted
// the way GLPI would: through a real session file, under a session id the test
// then presents as a cookie.
$poisoned = new CookieJar();
$http     = new HttpClient(['http_errors' => false, 'cookies' => $poisoned, 'timeout' => 20]);

// A session cookie, made by GLPI itself.
$http->get(GLPI . '/index.php');
$cookie = null;
foreach ($poisoned->toArray() as $entry) {
    if (str_starts_with((string) $entry['Name'], 'glpi_')) {
        $cookie = $entry;
        break;
    }
}
check('GLPI issued a session cookie to work with', $cookie !== null);

if ($cookie !== null) {
    // Write the poison directly into that session's file, which is what the
    // EXTERNAL auth path would have done.
    $planted = false;
    foreach (glob('/var/glpi/files/_sessions/sess_*') as $file) {
        if (str_contains($file, (string) $cookie['Value'])) {
            file_put_contents(
                $file,
                (string) file_get_contents($file) . 'glpi_remote_user|s:11:"someoneelse";'
            );
            $planted = true;
            break;
        }
    }
    check('a stale glpi_remote_user was planted in that session', $planted);

    $recovered = signIn('', $poisoned);
    check('the sign-in still succeeds', $recovered['signed_in'], $recovered['stopped']);

    // The real test: does the *next* page still work, or does GLPI throw the
    // user out because the marker survived?
    check('and the session survives the next request', isSignedIn($poisoned));
    check('and the one after that', isSignedIn($poisoned));
}

echo "\nAn account with no rights at all\n";

// The other way a session passes at sign-in and fails on the next click:
// GLPI sets the user id and stops, because there is no profile to activate.
$DB->update(Source::getTable(), ['default_profiles_id' => 0], ['id' => $sid]);
foreach (getAllDataFromTable(Link::getTable(), ['plugin_glpiidentity_sources_id' => $sid]) as $row) {
    $DB->delete(Profile_User::getTable(), ['users_id' => $row['users_id']]);
}

$rightless = signIn();
check('a user with no profile is refused at sign-in, not one click later',
    !$rightless['signed_in']);
check('and no half-built session is left behind', !isSignedIn($rightless['jar']));

$denials = array_filter(
    EventLog::recent(20, $sid),
    static fn(array $e): bool => str_contains((string) $e['detail'], 'no profile in any entity')
);
check('with an explanation an administrator can act on', $denials !== []);

$DB->update(Source::getTable(), ['default_profiles_id' => 1], ['id' => $sid]);

echo "\nSigning in twice over, and as somebody else\n";

$shared = new CookieJar();
check('a first sign-in works', signIn('', $shared)['signed_in']);
check('and signing in again in the same browser still works', signIn('', $shared)['signed_in']);
check('the session is usable afterwards', isSignedIn($shared));

echo "\nThe master switch\n";
Settings::save(['enabled' => '0']);
$off = signIn();
check('sign-on is refused when federation is off', !$off['signed_in']);
Settings::save(['enabled' => '1']);

echo "\n" . ($failures === []
    ? "\033[32mall checks passed\033[0m\n"
    : "\033[31mFAILED\033[0m: " . implode('; ', $failures) . "\n");

exit($failures === [] ? 0 : 1);
