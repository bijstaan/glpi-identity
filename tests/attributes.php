<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Copying directory attributes into GLPI user fields.
 *
 * Three things are under test, and the second and third are the ones with teeth:
 *
 *  - **Flattening.** A SCIM payload is nested and a claims bag is flat, so an
 *    administrator has to be able to name an attribute the way their connector
 *    names it. Multi-valued attributes and schema extensions are where that
 *    stops being obvious.
 *  - **One field, one source of truth.** A static rule and a pass-through both
 *    writing one field is refused from both directions, so there is never a
 *    precedence question to answer at sync time.
 *  - **Absent is not empty.** A key missing from the bag leaves the field
 *    alone; a key present and empty clears it. Entra omits null attributes
 *    rather than sending them empty, so getting this backwards would wipe a
 *    field on every cycle that happened not to carry it.
 *
 * And the documented consequence of the pass-through: the directory overwrites
 * an edit made by hand, every time.
 *
 * Usage, inside the GLPI container:
 *   php tests/attributes.php
 */

require '/var/www/glpi/vendor/autoload.php';

(new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();

use GlpiPlugin\Glpiidentity\AttributeMap;
use GlpiPlugin\Glpiidentity\Mapper;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Scim\UserResource;
use GlpiPlugin\Glpiidentity\Source;

/** @var DBmysql $DB */
global $DB;

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

/** Refusals queue a message; drop it so the next check reads its own. */
function refusals(): array
{
    $out = $_SESSION['MESSAGE_AFTER_REDIRECT'][ERROR] ?? [];
    unset($_SESSION['MESSAGE_AFTER_REDIRECT']);

    return $out;
}

// ------------------------------------------------------------------ fixtures

$made_entity = [];
$made_source = [];
$made_user   = [];

register_shutdown_function(static function () use (&$made_entity, &$made_source, &$made_user): void {
    global $DB;

    foreach ($made_user as $id) {
        $DB->delete(Profile_User::getTable(), ['users_id' => $id]);
        (new User())->delete(['id' => $id], true);
    }
    foreach ($made_source as $id) {
        $DB->delete(Mapping::getTable(), ['plugin_glpiidentity_sources_id' => $id]);
        $DB->delete(AttributeMap::getTable(), ['plugin_glpiidentity_sources_id' => $id]);
        (new Source())->delete(['id' => $id], true);
    }
    foreach (array_reverse($made_entity) as $id) {
        (new Entity())->delete(['id' => $id], true);
    }
});

$entity        = new Entity();
$eid           = (int) $entity->add(['name' => 'glpiid-attr-tests', 'entities_id' => 0]);
$made_entity[] = $eid;

$source        = new Source();
$sid           = (int) $source->add([
    'name' => 'glpiid-attr-source', 'entities_id' => $eid, 'is_recursive' => 1,
    'is_active' => 1, 'issuer' => 'https://example.invalid', 'client_id' => 'test',
]);
$made_source[] = $sid;
$source->getFromDB($sid);

$user        = new User();
$uid         = (int) $user->add(['name' => 'glpiid-attr-probe', 'is_active' => 1, 'entities_id' => $eid]);
$made_user[] = $uid;
$user->getFromDB($uid);

$map = static function (string $field, string $scim, string $claim = '', int $active = 1) use ($sid) {
    return (new AttributeMap())->add([
        'plugin_glpiidentity_sources_id' => $sid,
        'field_name' => $field, 'scim_path' => $scim, 'claim' => $claim, 'is_active' => $active,
    ]);
};

// ------------------------------------------------------------- flattening

echo "\nFlattening a SCIM payload\n";

$flat = UserResource::attributes([
    'userName' => 'ada@example.com',
    'active'   => true,
    'title'    => 'Chief Engineer',
    'name'     => ['givenName' => 'Ada', 'familyName' => 'Lovelace'],
    'phoneNumbers' => [
        ['type' => 'work', 'value' => '+44 20 7946 0100', 'primary' => true],
        ['type' => 'mobile', 'value' => '+44 7700 900123'],
    ],
    'addresses' => [
        ['type' => 'work', 'locality' => 'London', 'country' => 'GB'],
    ],
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' => [
        'department'     => 'Engineering',
        'employeeNumber' => 'E-4711',
        'manager'        => ['value' => 'grace@example.com', 'displayName' => 'Grace Hopper'],
    ],
    // Read-only per RFC 7643, and not where group truth comes from here.
    'groups' => [['value' => 'abc', 'display' => 'All Staff']],
]);

$one = static fn(string $key): string => (string) ($flat[$key][0] ?? '');

check('a plain attribute keeps its name', $one('title') === 'Chief Engineer');
check('a nested one is dotted', $one('name.givenName') === 'Ada');
check('a boolean reads as a word', $one('active') === 'true', $one('active'));

check(
    'a multi-valued attribute is addressable by type',
    $one('phoneNumbers[type eq "work"].value') === '+44 20 7946 0100'
);
check(
    'and by primary',
    $one('phoneNumbers[primary eq true].value') === '+44 20 7946 0100'
);
check(
    'and collected under the bare path, in order',
    ($flat['phoneNumbers.value'] ?? []) === ['+44 20 7946 0100', '+44 7700 900123'],
    implode(', ', $flat['phoneNumbers.value'] ?? [])
);
check(
    'a sub-attribute other than value is addressable too',
    $one('addresses[type eq "work"].locality') === 'London'
);

check(
    'an extension is named by its full urn',
    $one('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department') === 'Engineering'
);
check(
    'a sub-attribute below an extension goes back to dots',
    $one('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.displayName') === 'Grace Hopper',
    'colon joins the extension to its own attributes, not to everything below them'
);

check(
    'a read-only groups attribute is dropped entirely',
    !isset($flat['groups']) && !isset($flat['groups.display']),
    'SCIM group truth is /Groups; an echoed attribute must not outrank it'
);

// --------------------------------------------------------- reading values

echo "\nWhat a map takes out of the bag\n";

check('a map is accepted', $map('phone', 'phoneNumbers[type eq "work"].value', 'phone_number') !== false);
check('a second field is fine', $map('registration_number', 'externalId') !== false);

$values = AttributeMap::valuesFrom($source, $flat);
check(
    'the SCIM path is read',
    ($values['phone'] ?? null) === '+44 20 7946 0100',
    json_encode($values)
);
check(
    'a field whose path is absent gets no entry at all',
    !array_key_exists('registration_number', $values),
    'absent must leave the field alone, not clear it'
);

$values = AttributeMap::valuesFrom($source, ['phone_number' => ['+1 555 0100']]);
check(
    'the same map is served by its claim at sign-in',
    ($values['phone'] ?? null) === '+1 555 0100'
);

$values = AttributeMap::valuesFrom($source, ['phoneNumbers[type eq "work"].value' => ['']]);
check(
    'present and empty does clear it',
    array_key_exists('phone', $values) && $values['phone'] === ''
);

// ---------------------------------------------------------- the overlap

echo "\nOne field, one source of truth\n";

check(
    'a second map on the same field is refused',
    $map('phone', 'phoneNumbers[type eq "mobile"].value') === false,
    implode(' ', refusals())
);

$rule = (new Mapping())->add([
    'plugin_glpiidentity_sources_id' => $sid,
    'claim' => 'groups', 'match_operator' => Mapping::OP_EQUALS, 'match_value' => 'Anyone',
    'action' => Mapping::ACTION_FIELD, 'field_name' => 'phone', 'field_value' => '0000',
    'is_active' => 1,
]);
check(
    'a static rule writing a mapped field is refused',
    $rule === false,
    implode(' ', refusals())
);

$rule = (new Mapping())->add([
    'plugin_glpiidentity_sources_id' => $sid,
    'claim' => 'groups', 'match_operator' => Mapping::OP_EQUALS, 'match_value' => 'Depot',
    'action' => Mapping::ACTION_FIELD, 'field_name' => 'locations_id', 'field_value' => 'Depot Warehouse',
    'is_active' => 1,
]);
check('a static rule on an unclaimed field is fine', $rule !== false, implode(' ', refusals()));

check(
    'and a map on the field that rule writes is refused, from the other side',
    $map('locations_id', 'addresses[type eq "work"].locality') === false,
    implode(' ', refusals())
);

// -------------------------------------------------------- end to end

echo "\nApplied to a real user\n";

Mapper::apply($source, $user, $flat);
$user->getFromDB($uid);
check(
    'the phone number is copied in',
    (string) $user->fields['phone'] === '+44 20 7946 0100',
    (string) $user->fields['phone']
);

// The documented behaviour, and the reason the class docblock warns about it:
// there is no is_dynamic marker on a field, so a hand edit is simply lost.
$user->update(['id' => $uid, 'phone' => '999 corrected by hand']);
Mapper::apply($source, $user, $flat);
$user->getFromDB($uid);
check(
    'a manual edit is overwritten on the next sync',
    (string) $user->fields['phone'] === '+44 20 7946 0100',
    (string) $user->fields['phone']
);

$user->update(['id' => $uid, 'phone' => 'still here']);
Mapper::apply($source, $user, ['something' => ['else']]);
$user->getFromDB($uid);
check(
    'but a run that carries no such attribute leaves it alone',
    (string) $user->fields['phone'] === 'still here',
    (string) $user->fields['phone']
);

echo "\n" . ($failures === []
    ? "\033[32mall checks passed\033[0m\n"
    : "\033[31mFAILED\033[0m: " . implode('; ', $failures) . "\n");

exit($failures === [] ? 0 : 1);
