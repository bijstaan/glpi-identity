<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use Dropdown;
use Group_User;
use Profile_User;
use User;

/**
 * Turning what a directory said into where a person sits in GLPI.
 *
 * Two things here are worth knowing before reading the code.
 *
 * **Every matching rule applies.** This is not a first-match-wins list. Someone
 * in both "Executive" and "IT Staff" gets the VIP group *and* the Technician
 * profile, because that is what an administrator means when they write both
 * rules, and a list that stopped at the first match would silently drop the
 * second.
 *
 * **Only dynamic assignments are managed.** A profile or group added by hand by
 * an administrator is left alone for ever. Anything this plugin assigned is
 * marked `is_dynamic`, and on the next sign-in or SCIM update those are
 * recomputed from scratch — added, removed, or left, according to what the
 * directory says today. Without that split, either the plugin can never take a
 * profile away, or it takes away one somebody deliberately granted.
 */
final class Mapper
{
    /**
     * Work out where this person belongs, without changing anything yet.
     *
     * Separated from applying it so the settings page can show an administrator
     * what a set of rules *would* do to a given set of groups — which is the
     * only way to be confident about a mapping before real people arrive.
     *
     * The claims bag is whatever route produced it: claim names at sign-in,
     * flattened SCIM attribute paths on a provisioning request. Rules match on
     * it and attribute maps read values out of it, and neither needs to know
     * which of the two it is looking at.
     *
     * @param array<string,string[]> $claims claim name => every value it has
     * @return array{groups:int[],profiles:array<int,bool>,fields:array<string,string>,matched:string[]}
     */
    public static function plan(Source $source, array $claims): array
    {
        $plan = ['groups' => [], 'profiles' => [], 'fields' => [], 'matched' => []];

        foreach (Mapping::forSource($source->getID()) as $rule) {
            $values = $claims[$rule->fields['claim']] ?? [];
            if ($values === [] || !$rule->matches($values)) {
                continue;
            }

            $plan['matched'][] = $rule->describe();

            switch ((string) $rule->fields['action']) {
                case Mapping::ACTION_GROUP:
                    $plan['groups'][] = (int) $rule->fields['groups_id'];
                    break;

                case Mapping::ACTION_PROFILE:
                    $profiles_id = (int) $rule->fields['profiles_id'];
                    // Keyed by entity as well as profile: the same profile in
                    // two different entities is two different grants, which is
                    // the whole point of a rule being able to name one. A rule
                    // written before the column existed carries its source's
                    // entity, backfilled by the install hook.
                    $entities_id = $rule->targetEntity();
                    // OR, not overwrite: if any matching rule grants the profile
                    // recursively, it is recursive. The alternative — last rule
                    // wins — makes the outcome depend on rule order in a way
                    // nobody would predict from reading the list.
                    $plan['profiles'][$entities_id][$profiles_id] =
                        ($plan['profiles'][$entities_id][$profiles_id] ?? false)
                        || (int) $rule->fields['is_dynamic_recursive'] === 1;
                    break;

                case Mapping::ACTION_FIELD:
                    $plan['fields'][(string) $rule->fields['field_name']] = (string) $rule->fields['field_value'];
                    break;
            }
        }

        // Mirrored directory groups. Membership of a mirror is the directory's
        // membership, so it goes through the same dynamic sync as a mapped
        // group — which is also what stops the next sign-in or SCIM update
        // withdrawing it again as "no rule asked for this".
        if ((int) $source->fields['mirror_groups'] === 1) {
            $mirrored = IdpGroup::mirroredFor($source->getID(), $claims[$source->groupsClaim()] ?? []);
            foreach ($mirrored as $groups_id => $name) {
                $plan['groups'][]  = $groups_id;
                $plan['matched'][] = sprintf('member of directory group "%s" → mirrored GLPI group', $name);
            }
        }

        // Pass-through: fields copied from what the directory said about *this*
        // person, rather than set to a constant by a rule. A field cannot be
        // written by both — an attribute map naming a field a static rule
        // already sets is refused on save, and vice versa — so the union below
        // cannot silently disagree with itself. `+` rather than array_merge is
        // belt and braces: if a pair ever did coexist, the explicit rule is the
        // more specific statement and wins.
        $plan['fields'] += AttributeMap::valuesFrom($source, $claims);

        // The floor. Somebody who authenticates and then has no profile has a
        // GLPI that refuses every page, which reads as a broken login rather
        // than as a missing mapping.
        $fallback = (int) $source->fields['default_profiles_id'];
        if ($plan['profiles'] === [] && $fallback > 0) {
            $plan['profiles'][(int) $source->fields['entities_id']][$fallback] =
                (bool) $source->fields['is_recursive'];
        }

        $plan['groups'] = array_values(array_unique(array_filter($plan['groups'])));

        return $plan;
    }

    /**
     * Apply a plan to a user.
     *
     * @param array<string,string[]> $claims
     * @return string[] a description of what changed, for the event log
     */
    public static function apply(Source $source, User $user, array $claims): array
    {
        $plan    = self::plan($source, $claims);
        $changes = [];

        $changes = array_merge($changes, self::syncProfiles($source, $user, $plan['profiles']));
        $changes = array_merge($changes, self::syncGroups($user, $plan['groups']));
        $changes = array_merge($changes, self::setFields($source, $user, $plan['fields']));

        if ($plan['matched'] !== []) {
            EventLog::record(EventLog::MAPPED, $source, [
                'users_id' => $user->getID(),
                'detail'   => implode("\n", $plan['matched']) . "\n\n" . implode("\n", $changes),
            ]);
        }

        return $changes;
    }

    /**
     * Re-run every rule for every account a source manages.
     *
     * Rules otherwise reach a person only when the directory next mentions
     * them. That is fine for a rule changed on a busy directory and useless
     * for a quiet one — and it is the only way a group mirrored before
     * mirrors were given members gets filled without waiting for Entra to
     * re-send a membership it has no reason to re-send.
     *
     * Two limits, both because the only thing on record between sign-ins is
     * directory-group membership. Accounts that only ever signed in over SSO
     * have none recorded — their groups travel in the token — so recomputing
     * them would strip everything; they are skipped. And a rule on any other
     * claim (department, title) cannot be evaluated without the payload that
     * carried it, so a source with one is refused rather than half-applied.
     *
     * @return array{users:int,changed:int,refused:?string}
     */
    public static function applyToSource(Source $source): array
    {
        foreach (Mapping::forSource($source->getID()) as $rule) {
            if ((int) $rule->fields['is_active'] === 1 && (string) $rule->fields['claim'] !== $source->groupsClaim()) {
                return [
                    'users'   => 0,
                    'changed' => 0,
                    'refused' => sprintf(
                        __('Not applied: the rule on "%s" can only be evaluated when the directory sends '
                            . 'that attribute, so it will apply at each person\'s next sign-in or SCIM update.', 'glpiidentity'),
                        $rule->fields['claim']
                    ),
                ];
            }
        }

        $users   = 0;
        $changed = 0;

        foreach (Link::forSource($source->getID()) as $link) {
            // Nothing on record for someone SCIM never touched: their groups
            // arrive in the token, and "no groups" would be a lie.
            if (
                (int) $link->fields['is_scim_managed'] !== 1
                && IdpGroup::namesForUser($source->getID(), (int) $link->fields['users_id']) === []
            ) {
                continue;
            }

            $user = $link->user();
            if ($user === null || (int) $user->fields['is_deleted'] === 1) {
                continue;
            }

            $users++;
            if (self::apply($source, $user, Provisioning::claimsFor($source, (int) $user->getID())) !== []) {
                $changed++;
            }
        }

        return ['users' => $users, 'changed' => $changed, 'refused' => null];
    }

    /**
     * Bring the user's dynamic profile grants in line with the plan.
     *
     * Scoped to the source's **subtree** — its own entity and everything below
     * it. A rule may name which entity in there a profile lands in, which is
     * what lets one directory describe somebody who is a technician in one part
     * of the tree and an ordinary requester in another. It still cannot reach
     * outside that subtree: Mapping::scopeFor() bounds the choice on save, and
     * the loop below re-checks it rather than trusting the stored row, since a
     * source can be moved to a different entity after its rules were written.
     *
     * Reconciling across the whole subtree rather than a single entity rests on
     * one property: these rows all belong to *this* source, because a GLPI user
     * belongs to one source. Provisioning::createNew() refuses a username that
     * already exists anywhere, and an invitation is only ever claimed at
     * sign-in, which routes by email domain to exactly one source. If that ever
     * stops holding, the withdraw loop below would need to know which source
     * granted a row rather than inferring it.
     *
     * Only `is_dynamic` rows are touched either way, so anything an
     * administrator granted by hand survives all of this untouched.
     *
     * @param array<int,array<int,bool>> $wanted entities_id => [profiles_id => recursive]
     * @return string[]
     */
    private static function syncProfiles(Source $source, User $user, array $wanted): array
    {
        $scope   = Mapping::scopeFor($source->getID());
        $changes = [];

        if ($scope === []) {
            return $changes;
        }

        $existing = [];
        foreach (
            getAllDataFromTable(Profile_User::getTable(), [
                'users_id'    => $user->getID(),
                'entities_id' => $scope,
                'is_dynamic'  => 1,
            ]) as $row
        ) {
            $existing[(int) $row['entities_id']][(int) $row['profiles_id']] = $row;
        }

        $name = static fn(int $p, int $e): string => sprintf(
            '"%s" in "%s"',
            Dropdown::getDropdownName('glpi_profiles', $p),
            Dropdown::getDropdownName('glpi_entities', $e)
        );

        foreach ($wanted as $entities_id => $profiles) {
            if (!in_array($entities_id, $scope, true)) {
                // The source moved after the rule was written, and the rule now
                // points outside what it owns. Dropped rather than applied.
                continue;
            }

            foreach ($profiles as $profiles_id => $recursive) {
                if (isset($existing[$entities_id][$profiles_id])) {
                    $row = $existing[$entities_id][$profiles_id];
                    if ((bool) $row['is_recursive'] !== $recursive) {
                        (new Profile_User())->update([
                            'id'           => $row['id'],
                            'is_recursive' => $recursive ? 1 : 0,
                        ]);
                        $changes[] = 'recursion changed on ' . $name($profiles_id, $entities_id);
                    }
                    unset($existing[$entities_id][$profiles_id]);
                    continue;
                }

                (new Profile_User())->add([
                    'users_id'     => $user->getID(),
                    'profiles_id'  => $profiles_id,
                    'entities_id'  => $entities_id,
                    'is_recursive' => $recursive ? 1 : 0,
                    // The marker that makes this reversible. Without it the plugin
                    // could never withdraw a profile it granted.
                    'is_dynamic'   => 1,
                ]);
                $changes[] = 'granted ' . $name($profiles_id, $entities_id);
            }
        }

        // Whatever is left was granted by a rule that no longer matches, or that
        // now names a different entity.
        foreach ($existing as $entities_id => $profiles) {
            foreach ($profiles as $profiles_id => $row) {
                (new Profile_User())->delete(['id' => $row['id']], true);
                $changes[] = 'withdrew ' . $name($profiles_id, $entities_id);
            }
        }

        return $changes;
    }

    /**
     * The same treatment for groups.
     *
     * @param int[] $wanted
     * @return string[]
     */
    private static function syncGroups(User $user, array $wanted): array
    {
        $changes = [];

        $existing = [];
        foreach (
            getAllDataFromTable(Group_User::getTable(), [
                'users_id'   => $user->getID(),
                'is_dynamic' => 1,
            ]) as $row
        ) {
            $existing[(int) $row['groups_id']] = $row;
        }

        foreach ($wanted as $groups_id) {
            if (isset($existing[$groups_id])) {
                unset($existing[$groups_id]);
                continue;
            }

            // Already in it by hand. A second, dynamic row would be a duplicate
            // membership, and withdrawing it later would look like removing
            // somebody an administrator put there.
            if (
                countElementsInTable(Group_User::getTable(), [
                    'users_id'  => $user->getID(),
                    'groups_id' => $groups_id,
                ]) > 0
            ) {
                continue;
            }

            (new Group_User())->add([
                'users_id'   => $user->getID(),
                'groups_id'  => $groups_id,
                'is_dynamic' => 1,
            ]);
            $changes[] = sprintf('added to group "%s"', Dropdown::getDropdownName('glpi_groups', $groups_id));
        }

        foreach ($existing as $groups_id => $row) {
            (new Group_User())->delete(['id' => $row['id']], true);
            $changes[] = sprintf('removed from group "%s"', Dropdown::getDropdownName('glpi_groups', $groups_id));
        }

        return $changes;
    }

    /**
     * Set the descriptive fields a mapping asked for.
     *
     * Dropdown values are matched by name and created if absent — the GLPI
     * idiom, and what an administrator writing "London Office" expects. The
     * allowlist on {@see Mapping::assignableFields()} is what keeps this from
     * being a way to write to `authtype`.
     *
     * @param array<string,string> $fields
     * @return string[]
     */
    private static function setFields(Source $source, User $user, array $fields): array
    {
        if ($fields === []) {
            return [];
        }

        $allowed = Mapping::assignableFields();
        $update  = [];
        $changes = [];

        foreach ($fields as $name => $value) {
            if (!isset($allowed[$name])) {
                continue;
            }

            // A pointer to another user, resolved through this source's own
            // links. Checked before the dropdown branch, which creates what it
            // cannot find — the wrong behaviour entirely for a person.
            if (isset($allowed[$name]['reference'])) {
                if (trim($value) === '') {
                    // Said explicitly, so honoured: the directory is telling us
                    // this person has no supervisor any more.
                    if ((int) ($user->fields[$name] ?? 0) !== 0) {
                        $update[$name] = 0;
                        $changes[]     = sprintf('cleared %s', $name);
                    }

                    continue;
                }

                $resolved = Link::resolveUser($source, $value);

                if ($resolved === 0) {
                    // Nobody here yet. Connectors provision in no particular
                    // order, so a manager routinely arrives before — or after —
                    // the person they manage, and failing would make a
                    // transient ordering quirk permanent. The next sync fixes
                    // it, exactly as it does for a group member who has not
                    // been created yet.
                    $changes[] = sprintf('could not resolve %s from "%s"', $name, $value);
                    continue;
                }

                if ($resolved === (int) $user->getID()) {
                    // GLPI will store it, and then route the person's own
                    // approvals back to them. A directory that says somebody
                    // manages themselves is describing a vacancy.
                    $changes[] = sprintf('refused %s pointing at the user themselves', $name);
                    continue;
                }

                if ((int) ($user->fields[$name] ?? 0) !== $resolved) {
                    $update[$name] = $resolved;
                    $changes[]     = sprintf('set %s to user #%d', $name, $resolved);
                }

                continue;
            }

            $itemtype = $allowed[$name]['itemtype'];

            if ($itemtype !== null) {
                if (trim($value) === '') {
                    continue;
                }

                $resolved = Dropdown::importExternal(
                    $itemtype,
                    $value,
                    (int) $source->fields['entities_id']
                );

                if ($resolved > 0 && (int) ($user->fields[$name] ?? 0) !== $resolved) {
                    $update[$name] = $resolved;
                    $changes[]     = sprintf('set %s to "%s"', $name, $value);
                }

                continue;
            }

            if ((string) ($user->fields[$name] ?? '') !== $value) {
                $update[$name] = $value;
                $changes[]     = sprintf('set %s', $name);
            }
        }

        if ($update !== []) {
            $user->update(['id' => $user->getID()] + $update);
        }

        return $changes;
    }

    /**
     * Every claim value a mapping might match, as lists.
     *
     * Claims arrive as strings, arrays, or nested objects depending on the
     * provider and the claim; normalising once here means a rule never has to
     * care which, and means `matches()` has exactly one input shape to reason
     * about.
     *
     * @param array<string,mixed> $raw
     * @return array<string,string[]>
     */
    public static function normaliseClaims(array $raw): array
    {
        $out = [];

        foreach ($raw as $name => $value) {
            if (is_scalar($value)) {
                $out[$name] = [(string) $value];
                continue;
            }

            if (!is_array($value)) {
                continue;
            }

            $values = [];
            foreach ($value as $entry) {
                if (is_scalar($entry)) {
                    $values[] = (string) $entry;
                    continue;
                }

                // Group claims sometimes arrive as objects. SCIM uses
                // `display`/`value`; some IdPs use `name`. Take whichever is
                // there, preferring the human-readable one, because that is
                // what an administrator will have typed into the rule.
                if (is_array($entry)) {
                    foreach (['display', 'name', 'value'] as $key) {
                        if (isset($entry[$key]) && is_scalar($entry[$key])) {
                            $values[] = (string) $entry[$key];
                            break;
                        }
                    }
                }
            }

            if ($values !== []) {
                $out[$name] = $values;
            }
        }

        return $out;
    }
}
