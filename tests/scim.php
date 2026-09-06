<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The SCIM endpoint, over real HTTP.
 *
 * Driven through the web server rather than by calling the Server class, on
 * purpose: half of what makes a SCIM endpoint work is outside the handler — the
 * URL routing, the firewall exemption that lets a request with no GLPI session
 * through, the Authorization header surviving the web server, the content type.
 * A test that called the class directly would pass on a plugin nobody could
 * reach.
 *
 * The other half of what it checks is tenancy. Two sources are created, each in
 * its own entity, and every scoping claim is tested from the wrong side: Beta's
 * token asking for Acme's user, Beta's token adding Acme's user to a group.
 * Those are the failures that would not look like failures.
 *
 * Usage, inside the GLPI container:
 *   php tests/scim.php
 */

require '/var/www/glpi/vendor/autoload.php';

(new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\IdpGroup;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;
use GuzzleHttp\Client as HttpClient;

/** @var DBmysql $DB */
global $DB;

const SCIM = 'http://127.0.0.1/plugins/glpiidentity/front/scim.php/v2';

if (!(new Auth())->login('glpi', 'glpi', true)) {
    fwrite(STDERR, "could not log in as glpi/glpi\n");
    exit(1);
}

(new Plugin())->init(true);

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

    // Users provisioned by the test are found through the links, so they are
    // cleaned up before the links that point at them.
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
$acme   = (int) $entity->add(['name' => 'glpiid-acme', 'entities_id' => 0]);
$beta   = (int) $entity->add(['name' => 'glpiid-beta', 'entities_id' => 0]);
$made_entity = [$acme, $beta];

$group = new Group();
$vip   = (int) $group->add(['name' => 'glpiid-VIP', 'entities_id' => $acme, 'is_usergroup' => 1]);
$made_group[] = $vip;

$make_source = static function (string $name, int $entities_id) use (&$made_source): array {
    $source = new Source();
    $id     = (int) $source->add([
        'name'                => $name,
        'entities_id'         => $entities_id,
        'is_active'           => 1,
        'scim_enabled'        => 1,
        'deprovision_action'  => Source::DEPROVISION_DISABLE,
        'default_profiles_id' => 1,   // Self-Service, present in every GLPI
    ]);
    $made_source[] = $id;

    $source->getFromDB($id);
    $token = $source->rotateScimToken();
    $source->getFromDB($id);

    return ['source' => $source, 'token' => $token];
};

['source' => $acme_source, 'token' => $acme_token] = $make_source('glpiid Acme', $acme);
['source' => $beta_source, 'token' => $beta_token] = $make_source('glpiid Beta', $beta);

Settings::save(['enabled' => '1']);

echo "\nInstall defaults\n";

// Asserted here rather than in the browser suite, which has to switch
// federation on before it can test anything. That the switch is *obeyed* is
// covered further down, once there is an HTTP client to ask with.
check('federation is off as installed', (int) Settings::DEFAULTS['enabled'] === 0);
check('the local password form is kept as installed',
    (int) Settings::DEFAULTS['allow_local_login'] === 1);
echo "\nFixtures\n";
check('two sources, each with its own entity and token',
    $acme_source->getID() > 0 && $beta_source->getID() > 0 && $acme_token !== $beta_token);
check('the token is not stored in a form anyone can use',
    ($DB->request(['FROM' => Source::getTable(), 'WHERE' => ['id' => $acme_source->getID()]])
        ->current()['scim_token_hash'] ?? '') === hash('sha256', $acme_token));

// --------------------------------------------------------------------- HTTP

$http = new HttpClient(['http_errors' => false, 'timeout' => 20]);

/** @return array{status:int,type:string,body:array,raw:string} */
function scim(string $method, string $path, ?string $token, array $body = null): array
{
    global $http;

    $headers = ['Accept' => 'application/scim+json'];
    if ($token !== null) {
        $headers['Authorization'] = 'Bearer ' . $token;
    }

    $options = ['headers' => $headers];
    if ($body !== null) {
        $options['headers']['Content-Type'] = 'application/scim+json';
        $options['body'] = json_encode($body, JSON_UNESCAPED_SLASHES);
    }

    $response = $http->request($method, SCIM . $path, $options);
    $raw      = (string) $response->getBody();

    return [
        'status' => $response->getStatusCode(),
        'type'   => $response->getHeaderLine('Content-Type'),
        'body'   => json_decode($raw, true) ?: [],
        'raw'    => $raw,
    ];
}

echo "\nAuthentication\n";

$r = scim('GET', '/Users', null);
check('no token is 401', $r['status'] === 401, (string) $r['status']);
check('and the response is a SCIM error, not an HTML login page',
    ($r['body']['schemas'][0] ?? '') === 'urn:ietf:params:scim:api:messages:2.0:Error');
check('with a Bearer challenge', str_contains($r['type'], 'scim+json'));

check('a wrong token is 401', scim('GET', '/Users', 'scim_not-a-real-token')['status'] === 401);

$r = scim('GET', '/ServiceProviderConfig', $acme_token);
check('a valid token gets through', $r['status'] === 200, (string) $r['status']);
check('the content type is application/scim+json', str_contains($r['type'], 'application/scim+json'));

echo "\nService metadata\n";
check('patch is advertised as supported', ($r['body']['patch']['supported'] ?? null) === true);
check('bulk is advertised as unsupported', ($r['body']['bulk']['supported'] ?? null) === false);
check('filtering advertises its ceiling', ($r['body']['filter']['maxResults'] ?? 0) > 0);
check('bearer token is the authentication scheme',
    ($r['body']['authenticationSchemes'][0]['type'] ?? '') === 'oauthbearertoken');

$r = scim('GET', '/ResourceTypes', $acme_token);
check('resource types list Users and Groups',
    count($r['body']['Resources'] ?? []) === 2
    && ($r['body']['schemas'][0] ?? '') === 'urn:ietf:params:scim:api:messages:2.0:ListResponse');

check('the schemas endpoint answers', (scim('GET', '/Schemas', $acme_token)['status']) === 200);

echo "\nCreating a user\n";

$r = scim('POST', '/Users', $acme_token, [
    'schemas'    => ['urn:ietf:params:scim:schemas:core:2.0:User'],
    'externalId' => 'acme-ext-1',
    'userName'   => 'alice@acme.test',
    'name'       => ['givenName' => 'Alice', 'familyName' => 'Anderson'],
    'emails'     => [['value' => 'alice@acme.test', 'type' => 'work', 'primary' => true]],
    'active'     => true,
]);

check('a create returns 201', $r['status'] === 201, $r['raw']);
check('with a Location header pointing at the new resource',
    str_contains((string) ($r['body']['meta']['location'] ?? ''), '/Users/'));
$alice_id = (string) ($r['body']['id'] ?? '');
check('the id is a UUID, not the GLPI user id',
    preg_match('/^[0-9a-f-]{36}$/', $alice_id) === 1, $alice_id);
check('externalId is echoed', ($r['body']['externalId'] ?? '') === 'acme-ext-1');
check('the user is active', ($r['body']['active'] ?? null) === true);

$link = Link::forScimId($acme_source->getID(), $alice_id);
$alice = $link?->user();
check('a GLPI user was created in the source\'s entity',
    $alice !== null && (int) $alice->fields['entities_id'] === $acme);
check('with an external auth type and no password',
    $alice !== null && (int) $alice->fields['authtype'] === Auth::EXTERNAL);
check('and the default profile in that entity',
    count(getAllDataFromTable(Profile_User::getTable(), [
        'users_id'    => $alice?->getID(),
        'entities_id' => $acme,
        'is_dynamic'  => 1,
    ])) === 1);

echo "\nReplaying a create\n";
$again = scim('POST', '/Users', $acme_token, [
    'externalId' => 'acme-ext-1',
    'userName'   => 'alice@acme.test',
    'active'     => true,
]);
check('a replayed create is 200, not 409 — connectors retry after timeouts',
    $again['status'] === 200, (string) $again['status']);
check('and does not make a second user', ($again['body']['id'] ?? '') === $alice_id);

echo "\nTenant isolation\n";

check('Beta cannot read Acme\'s user', scim('GET', '/Users/' . $alice_id, $beta_token)['status'] === 404);
check('Beta cannot replace Acme\'s user',
    scim('PUT', '/Users/' . $alice_id, $beta_token, ['userName' => 'hijacked'])['status'] === 404);
check('Beta cannot patch Acme\'s user',
    scim('PATCH', '/Users/' . $alice_id, $beta_token, [
        'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
    ])['status'] === 404);
check('Beta cannot delete Acme\'s user', scim('DELETE', '/Users/' . $alice_id, $beta_token)['status'] === 404);
check('Beta\'s user list is empty', (scim('GET', '/Users', $beta_token)['body']['totalResults'] ?? -1) === 0);
check('Acme\'s user list has exactly one', (scim('GET', '/Users', $acme_token)['body']['totalResults'] ?? -1) === 1);

echo "\nUsername collisions\n";

// Somebody who is not managed by this directory at all.
$outsider = new User();
$outsider_id = (int) $outsider->add(['name' => 'glpiid-outsider', 'entities_id' => 0]);

$r = scim('POST', '/Users', $acme_token, ['userName' => 'glpiid-outsider', 'active' => true]);
check('a directory cannot adopt a GLPI account it does not own', $r['status'] === 409, (string) $r['status']);
check('and says why, with the SCIM uniqueness code',
    ($r['body']['scimType'] ?? '') === 'uniqueness');
(new User())->delete(['id' => $outsider_id], true);

echo "\nFiltering\n";

$r = scim('GET', '/Users?filter=' . rawurlencode('userName eq "alice@acme.test"'), $acme_token);
check('a userName filter finds the user', ($r['body']['totalResults'] ?? 0) === 1);

$r = scim('GET', '/Users?filter=' . rawurlencode('userName eq "nobody@acme.test"'), $acme_token);
check('a filter that matches nothing returns an empty list, not an error',
    $r['status'] === 200 && ($r['body']['totalResults'] ?? -1) === 0);

$r = scim('GET', '/Users?filter=' . rawurlencode('externalId eq "acme-ext-1"'), $acme_token);
check('an externalId filter works too', ($r['body']['totalResults'] ?? 0) === 1);

$r = scim('GET', '/Users?filter=' . rawurlencode('title co "boss"'), $acme_token);
check('a filter this server cannot answer is refused, not answered emptily',
    $r['status'] === 400 && ($r['body']['scimType'] ?? '') === 'invalidFilter', $r['raw']);

$r = scim('GET', '/Users?filter=' . rawurlencode('userName eq "a" and active eq "true"'), $acme_token);
check('a compound filter is refused rather than half-understood',
    $r['status'] === 400 && ($r['body']['scimType'] ?? '') === 'invalidFilter');

echo "\nGroups and mapping\n";

// The mapping the whole feature exists for: a directory group named
// "Executive" becomes GLPI's VIP group.
$mapping = new Mapping();
$mapping->add([
    'plugin_glpiidentity_sources_id' => $acme_source->getID(),
    'claim'          => 'groups',
    'match_operator' => Mapping::OP_EQUALS,
    'match_value'    => 'Executive',
    'action'         => Mapping::ACTION_GROUP,
    'groups_id'      => $vip,
    'is_active'      => 1,
]);

$r = scim('POST', '/Groups', $acme_token, [
    'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    'externalId'  => 'acme-grp-exec',
    'displayName' => 'Executive',
    'members'     => [['value' => $alice_id]],
]);

check('a group create returns 201', $r['status'] === 201, $r['raw']);
check('with the member listed', count($r['body']['members'] ?? []) === 1);

$in_vip = static fn(): bool => count(getAllDataFromTable(Group_User::getTable(), [
    'users_id'  => $alice?->getID(),
    'groups_id' => $vip,
])) === 1;

check('the mapping put the user in the GLPI group', $in_vip());
// getAllDataFromTable keys its rows by id, not from zero.
$membership = getAllDataFromTable(Group_User::getTable(), [
    'users_id'  => $alice?->getID(),
    'groups_id' => $vip,
]);
check('and marked it dynamic, so it can be taken away again',
    ((int) (reset($membership)['is_dynamic'] ?? 0)) === 1);

check('the directory group is not itself a GLPI group',
    getAllDataFromTable(Group::getTable(), ['name' => 'Executive']) === []);

$r = scim('PATCH', '/Groups/acme-grp-exec', $acme_token, [
    'Operations' => [[
        'op'   => 'remove',
        'path' => 'members[value eq "' . $alice_id . '"]',
    ]],
]);
check('a member can be removed by value path', $r['status'] === 200, $r['raw']);
check('and the mapped GLPI group goes with them', !$in_vip());

$r = scim('PATCH', '/Groups/acme-grp-exec', $acme_token, [
    'Operations' => [[
        'op'    => 'add',
        'path'  => 'members',
        'value' => [['value' => $alice_id]],
    ]],
]);
check('and can be added back', $r['status'] === 200 && $in_vip());

// The isolation test that matters most for groups: Beta naming Acme's user.
$r = scim('POST', '/Groups', $beta_token, [
    'externalId'  => 'beta-grp-exec',
    'displayName' => 'Executive',
    'members'     => [['value' => $alice_id]],
]);
check('Beta creating a group cannot pull in Acme\'s user',
    $r['status'] === 201 && ($r['body']['members'] ?? []) === []);

check('Acme still sees its own group only',
    count(IdpGroup::forSource($acme_source->getID())) === 1);

echo "\nUser sees their groups\n";
$r = scim('GET', '/Users/' . $alice_id, $acme_token);
check('the user resource lists the directory group',
    ($r['body']['groups'][0]['display'] ?? '') === 'Executive', $r['raw']);

echo "\nDeprovisioning\n";

$r = scim('PATCH', '/Users/' . $alice_id, $acme_token, [
    'schemas'    => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
]);

check('the deactivation patch is accepted', $r['status'] === 200, $r['raw']);
check('and reports the user as inactive', ($r['body']['active'] ?? null) === false);

$alice->getFromDB($alice->getID());
check('the GLPI user is deactivated', (int) $alice->fields['is_active'] === 0);
check('and not deleted — their ticket history stays joined up',
    (int) $alice->fields['is_deleted'] === 0);

// Entra's other spelling of the same thing.
scim('PATCH', '/Users/' . $alice_id, $acme_token, [
    'Operations' => [['op' => 'Replace', 'value' => ['active' => 'True']]],
]);
$alice->getFromDB($alice->getID());
check('a capitalised op with a string boolean reactivates them',
    (int) $alice->fields['is_active'] === 1);

$r = scim('DELETE', '/Users/' . $alice_id, $acme_token);
check('DELETE returns 204 with no body', $r['status'] === 204 && trim($r['raw']) === '');
$alice->getFromDB($alice->getID());
check('and deactivates rather than destroying', (int) $alice->fields['is_active'] === 0);

echo "\nPaging\n";
$r = scim('GET', '/Users?startIndex=1&count=1', $acme_token);
check('a page reports its own index and size',
    ($r['body']['startIndex'] ?? 0) === 1 && ($r['body']['itemsPerPage'] ?? -1) === 1);
$r = scim('GET', '/Users?startIndex=99', $acme_token);
check('an index past the end is an empty page, not an error',
    $r['status'] === 200 && ($r['body']['itemsPerPage'] ?? -1) === 0);

echo "\nThe master switch\n";
Settings::save(['enabled' => '0']);
$r = scim('GET', '/Users', $acme_token);
check('everything answers 503 when federation is off', $r['status'] === 503);
check('503 rather than 401, so a connector retries instead of alerting',
    ($r['body']['status'] ?? '') === '503');
Settings::save(['enabled' => '1']);

echo "\nAudit trail\n";
$events = EventLog::recent(200, $acme_source->getID());
$kinds  = array_column($events, 'event');
check('the creation was recorded', in_array(EventLog::SCIM_CREATE, $kinds, true));
check('the deprovisioning was recorded', in_array(EventLog::SCIM_DEACTIVATE, $kinds, true));
check('the group sync was recorded', in_array(EventLog::GROUP_SYNC, $kinds, true));
check('the mapping decision was recorded', in_array(EventLog::MAPPED, $kinds, true));
check('a rejected token was recorded even though it matched no source',
    in_array(EventLog::SCIM_DENIED, array_column(EventLog::recent(200), 'event'), true));

$acme_source->getFromDB($acme_source->getID());
check('the source counts its requests', (int) $acme_source->fields['scim_requests'] > 10);

echo "\n" . ($failures === []
    ? "\033[32mall checks passed\033[0m\n"
    : "\033[31mFAILED\033[0m: " . implode('; ', $failures) . "\n");

exit($failures === [] ? 0 : 1);
