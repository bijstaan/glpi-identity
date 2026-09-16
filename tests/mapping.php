<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Which entity a mapping rule grants its profile in.
 *
 * A source used to grant every profile in its own entity and nowhere else,
 * which meant one directory could not describe somebody whose role differs
 * across two parts of the tree — a support technician who works every customer's
 * queue but is an ordinary requester on the internal side is the case that
 * cannot be expressed that way. A rule now names the entity, bounded by the
 * source's own subtree.
 *
 * Both halves are tested here, and the second is the one that matters: that the
 * bound actually holds, from the wrong side. A rule belonging to a source in one
 * part of the tree must not be able to grant anything in another.
 *
 * Usage, inside the GLPI container:
 *   php tests/mapping.php
 */

require '/var/www/glpi/vendor/autoload.php';

(new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\Mapper;
use GlpiPlugin\Glpiidentity\Mapping;
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
        // Only this run's events. The other suites empty the table wholesale,
        // which throws away an audit trail that belongs to whoever owns the
        // instance the tests happen to be running on.
        $DB->delete(EventLog::TABLE, ['plugin_glpiidentity_sources_id' => $id]);
        (new Source())->delete(['id' => $id], true);
    }
    // Deepest first: GLPI refuses to purge an entity that still has children.
    foreach (array_reverse($made_entity) as $id) {
        (new Entity())->delete(['id' => $id], true);
    }
});

$entity = new Entity();
// A tree with the same shape as the case this exists for: a house side with two
// queues, and an external side, under one root the house source will own.
$house  = (int) $entity->add(['name' => 'glpiid-house', 'entities_id' => 0]);
$deskA  = (int) $entity->add(['name' => 'glpiid-desk-a', 'entities_id' => $house]);
$deskB  = (int) $entity->add(['name' => 'glpiid-desk-b', 'entities_id' => $house]);
$other  = (int) $entity->add(['name' => 'glpiid-elsewhere', 'entities_id' => 0]);
$made_entity = [$house, $deskA, $deskB, $other];

// Stock profiles, present in every GLPI: 1 Self-Service, 6 Technician, 2 Observer.
const P_SELFSERVICE = 1;
const P_TECHNICIAN  = 6;
const P_OBSERVER    = 2;

$source = new Source();
$sid    = (int) $source->add([
    'name' => 'glpiid-house-source', 'entities_id' => $house, 'is_recursive' => 1,
    'is_active' => 1, 'issuer' => 'https://example.invalid', 'client_id' => 'test',
]);
$made_source[] = $sid;
$source->getFromDB($sid);

$rule = static function (string $value, int $profile, int $entity, int $recursive) use ($sid): int|false {
    return (new Mapping())->add([
        'plugin_glpiidentity_sources_id' => $sid,
        'claim' => 'groups', 'match_operator' => Mapping::OP_EQUALS, 'match_value' => $value,
        'action' => Mapping::ACTION_PROFILE, 'profiles_id' => $profile,
        'target_entities_id' => $entity, 'is_dynamic_recursive' => $recursive, 'is_active' => 1,
    ]);
};

$user = new User();
$uid  = (int) $user->add(['name' => 'glpiid-mapping-probe', 'is_active' => 1, 'entities_id' => $house]);
$made_user[] = $uid;
$user->getFromDB($uid);

/** @return array<string,array{entity:int,recursive:int,dynamic:int}> "profile@entity" => row */
$grants = static function (int $uid): array {
    global $DB;
    $out = [];
    foreach ($DB->request([
        'FROM' => Profile_User::getTable(), 'WHERE' => ['users_id' => $uid],
    ]) as $row) {
        $out[$row['profiles_id'] . '@' . $row['entities_id']] = [
            'entity'    => (int) $row['entities_id'],
            'recursive' => (int) $row['is_recursive'],
            'dynamic'   => (int) $row['is_dynamic'],
        ];
    }

    return $out;
};

// ------------------------------------------------- the bound, from both sides

echo "\nScope of a rule\n";

check(
    'a rule may grant in the source\'s own entity',
    $rule('Everyone', P_SELFSERVICE, $house, 0) !== false
);
check(
    'a rule may grant in an entity beneath the source',
    $rule('DeskA', P_TECHNICIAN, $deskA, 0) !== false
);
// The one that matters. `$other` is a sibling of the source's entity, so a rule
// reaching it would be one directory placing its people in another's tree.
check(
    'a rule may NOT grant in an entity outside the source\'s subtree',
    $rule('Sneaky', P_TECHNICIAN, $other, 0) === false
);
check(
    'nothing was written for the refused rule',
    count(getAllDataFromTable(Mapping::getTable(), [
        'plugin_glpiidentity_sources_id' => $sid,
        'match_value'                    => 'Sneaky',
    ])) === 0
);

// ------------------------------------------------------- what actually lands

echo "\nApplying rules\n";

$DB->delete(Profile_User::getTable(), ['users_id' => $uid]);
Mapper::apply($source, $user, ['groups' => ['Everyone', 'DeskA']]);
$now = $grants($uid);

check(
    'two rules naming two entities produce two grants',
    count($now) === 2,
    implode(', ', array_keys($now))
);
check(
    'the requester seat landed in the source entity',
    isset($now[P_SELFSERVICE . '@' . $house]) && $now[P_SELFSERVICE . '@' . $house]['dynamic'] === 1
);
check(
    'the technician seat landed in the sub-entity the rule named',
    isset($now[P_TECHNICIAN . '@' . $deskA]) && $now[P_TECHNICIAN . '@' . $deskA]['dynamic'] === 1
);

// ------------------------------------------------------------ reconciliation

echo "\nReconciliation\n";

// A seat an administrator granted by hand, inside the source's subtree, where
// the withdraw loop now reaches. It must survive regardless.
(new Profile_User())->add([
    'users_id' => $uid, 'profiles_id' => P_OBSERVER, 'entities_id' => $deskB,
    'is_recursive' => 0, 'is_dynamic' => 0,
]);

Mapper::apply($source, $user, ['groups' => ['Everyone']]);
$now = $grants($uid);

check(
    'a grant whose rule stopped matching is withdrawn',
    !isset($now[P_TECHNICIAN . '@' . $deskA])
);
check(
    'a grant whose rule still matches is kept',
    isset($now[P_SELFSERVICE . '@' . $house])
);
check(
    'a hand-granted seat inside the subtree is left alone',
    isset($now[P_OBSERVER . '@' . $deskB]) && $now[P_OBSERVER . '@' . $deskB]['dynamic'] === 0
);

// Moving a rule to another entity must move the grant, not leave one behind.
$moved = getAllDataFromTable(Mapping::getTable(), [
    'plugin_glpiidentity_sources_id' => $sid, 'match_value' => 'Everyone',
]);
(new Mapping())->update(['id' => (int) reset($moved)['id'], 'target_entities_id' => $deskB]);
Mapper::apply($source, $user, ['groups' => ['Everyone']]);
$now = $grants($uid);

check(
    'repointing a rule moves the grant rather than duplicating it',
    !isset($now[P_SELFSERVICE . '@' . $house]) && isset($now[P_SELFSERVICE . '@' . $deskB]),
    implode(', ', array_keys($now))
);

// ------------------------------------------------- rules written before this

echo "\nRules written before the column existed\n";

// Simulated by writing 0 straight to the column, which is what an un-backfilled
// row would hold. 0 is the root entity, a real and very powerful place, so the
// engine must not treat it as "inherit" — the install hook's backfill is what
// gives such a row its meaning, and this asserts the column is read literally.
$legacy = $rule('Legacy', P_TECHNICIAN, $house, 0);
$DB->update(Mapping::getTable(), ['target_entities_id' => 0], ['id' => $legacy]);
$DB->delete(Profile_User::getTable(), ['users_id' => $uid]);
Mapper::apply($source, $user, ['groups' => ['Legacy']]);
$now = $grants($uid);

check(
    'a rule pointing outside the subtree is dropped, not applied to the root',
    !isset($now[P_TECHNICIAN . '@0']),
    implode(', ', array_keys($now)) ?: '(no grants)'
);

echo "\n" . ($failures === []
    ? "\033[32mAll mapping checks passed.\033[0m\n"
    : "\033[31m" . count($failures) . " failed:\033[0m " . implode(', ', $failures) . "\n");

exit($failures === [] ? 0 : 1);
