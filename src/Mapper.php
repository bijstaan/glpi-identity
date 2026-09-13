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
                    // OR, not overwrite: if any matching rule grants the profile
                    // recursively, it is recursive. The alternative — last rule
                    // wins — makes the outcome depend on rule order in a way
                    // nobody would predict from reading the list.
                    $plan['profiles'][$profiles_id] =
                        ($plan['profiles'][$profiles_id] ?? false)
                        || (int) $rule->fields['is_dynamic_recursive'] === 1;
                    break;

                case Mapping::ACTION_FIELD:
                    $plan['fields'][(string) $rule->fields['field_name']] = (string) $rule->fields['field_value'];
                    break;
            }
        }

        // The floor. Somebody who authenticates and then has no profile has a
        // GLPI that refuses every page, which reads as a broken login rather
        // than as a missing mapping.
        $fallback = (int) $source->fields['default_profiles_id'];
        if ($plan['profiles'] === [] && $fallback > 0) {
            $plan['profiles'][$fallback] = (bool) $source->fields['is_recursive'];
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
     * Bring the user's dynamic profile grants in line with the plan.
     *
     * Scoped to the source's entity. A rule belonging to Acme can only ever
     * grant a profile *in Acme's entity* — the entity is not something a rule
     * can choose, because a rule that could choose it would be a way for one
     * organisation's directory to place a user in another's tree.
     *
     * @param array<int,bool> $wanted profiles_id => recursive
     * @return string[]
     */
    private static function syncProfiles(Source $source, User $user, array $wanted): array
    {
        $entities_id = (int) $source->fields['entities_id'];
        $changes     = [];

        $existing = [];
        foreach (
            getAllDataFromTable(Profile_User::getTable(), [
                'users_id'    => $user->getID(),
                'entities_id' => $entities_id,
                'is_dynamic'  => 1,
            ]) as $row
        ) {
            $existing[(int) $row['profiles_id']] = $row;
        }

        foreach ($wanted as $profiles_id => $recursive) {
            if (isset($existing[$profiles_id])) {
                if ((bool) $existing[$profiles_id]['is_recursive'] !== $recursive) {
                    (new Profile_User())->update([
                        'id'           => $existing[$profiles_id]['id'],
                        'is_recursive' => $recursive ? 1 : 0,
                    ]);
                    $changes[] = sprintf('profile %d recursion changed', $profiles_id);
                }
                unset($existing[$profiles_id]);
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
            $changes[] = sprintf(
                'granted profile "%s"',
                Dropdown::getDropdownName('glpi_profiles', $profiles_id)
            );
        }

        // Whatever is left was granted by a rule that no longer matches.
        foreach ($existing as $profiles_id => $row) {
            (new Profile_User())->delete(['id' => $row['id']], true);
            $changes[] = sprintf(
                'withdrew profile "%s"',
                Dropdown::getDropdownName('glpi_profiles', $profiles_id)
            );
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
