<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

use GlpiPlugin\Glpiidentity\IdpGroup;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Source;
use GlpiPlugin\Glpiidentity\Url;
use User;

/**
 * A directory group, as SCIM sees it.
 *
 * These are the organisation's groups, kept as the organisation's groups. What reaches
 * GLPI proper is decided by the mappings — that separation is the whole point
 * of the feature, and it is why a SCIM `Group` here does not create a GLPI
 * `Group` unless the source is explicitly told to mirror them.
 */
final class GroupResource
{
    /** @return array<string,mixed> */
    public static function toScim(Source $source, IdpGroup $group): array
    {
        $members = [];
        foreach ($group->memberIds() as $users_id) {
            $link = Link::forUser($source->getID(), $users_id);
            if ($link === null) {
                continue;
            }

            $user = new User();
            $members[] = array_filter([
                'value'   => (string) $link->fields['scim_id'],
                'display' => $user->getFromDB($users_id) ? $user->getFriendlyName() : null,
                '$ref'    => Url::absolute('front/scim.php/v2/Users/' . $link->fields['scim_id']),
            ], static fn($v): bool => $v !== null);
        }

        return array_filter([
            'schemas'     => [Response::SCHEMA_GROUP],
            // The directory's own id is the SCIM id for a group. Unlike users,
            // a group has no privacy dimension and connectors PATCH groups by
            // the id they gave us, so echoing it back avoids a translation that
            // buys nothing.
            'id'          => (string) $group->fields['external_id'],
            'displayName' => (string) $group->fields['name'],
            'members'     => $members ?: null,
            'meta'        => array_filter([
                'resourceType' => 'Group',
                'created'      => Response::timestamp($group->fields['date_creation'] ?? null),
                'lastModified' => Response::timestamp($group->fields['date_mod'] ?? null),
                'location'     => Url::absolute('front/scim.php/v2/Groups/' . rawurlencode((string) $group->fields['external_id'])),
            ]),
        ], static fn($v): bool => $v !== null);
    }

    /**
     * The GLPI user ids named in a `members` array.
     *
     * Members that resolve to nothing are dropped rather than refused. A
     * connector routinely sends a membership before it sends the member — Entra
     * does it whenever a group is assigned before its users have synced — and
     * failing the whole group for one unknown id turns a transient ordering
     * quirk into a permanently broken group.
     *
     * @param array<int,mixed> $members
     * @return array{ids:int[],unknown:int}
     */
    public static function resolveMembers(Source $source, array $members): array
    {
        $ids     = [];
        $unknown = 0;

        foreach ($members as $entry) {
            $scim_id = is_array($entry) ? (string) ($entry['value'] ?? '') : (string) $entry;
            if ($scim_id === '') {
                continue;
            }

            $link = Link::forScimId($source->getID(), $scim_id);
            if ($link === null) {
                $unknown++;
                continue;
            }

            $ids[] = (int) $link->fields['users_id'];
        }

        return ['ids' => array_values(array_unique($ids)), 'unknown' => $unknown];
    }

    /**
     * Mirror a directory group into a real GLPI group, when asked to.
     *
     * Off by default. A shared group tree filling up with a dozen organisations'
     * internal vocabulary helps nobody, and the mapping is the supported way to
     * decide which of a directory's groups deserves to exist in GLPI — which is
     * also why a group an "Add to GLPI group" rule already picks up is not
     * mirrored as well: the administrator has said where those people go.
     *
     * This only makes the group and remembers which one it is. Membership is
     * the mapper's job ({@see \GlpiPlugin\Glpiidentity\Mapper::plan()}), so it
     * follows the directory the same way a mapped group does — added, withdrawn
     * and marked dynamic — and it used to be missing entirely: the group was
     * created, forgotten, and never had anybody put in it.
     */
    public static function mirror(Source $source, IdpGroup $group): void
    {
        if ((int) $source->fields['mirror_groups'] !== 1) {
            return;
        }

        $name       = (string) $group->fields['name'];
        $glpi_group = new \Group();

        // Already mirrored: keep the name in step, since a rename in the
        // directory is the same group under a new name, not a new group.
        $current = (int) ($group->fields['groups_id'] ?? 0);
        if ($current > 0 && $glpi_group->getFromDB($current)) {
            if ((string) $glpi_group->fields['name'] !== $name) {
                $glpi_group->update(['id' => $current, 'name' => $name]);
            }

            return;
        }

        foreach (Mapping::forSource($source->getID()) as $rule) {
            if (
                (string) $rule->fields['action'] === Mapping::ACTION_GROUP
                && (string) $rule->fields['claim'] === $source->groupsClaim()
                && $rule->matches([$name])
            ) {
                return;
            }
        }

        $entities_id = (int) $source->fields['entities_id'];

        // One of the same name in the source's own entity is adopted rather than
        // duplicated — it is what this used to create, before it recorded which.
        if (!$glpi_group->getFromDBByCrit(['name' => $name, 'entities_id' => $entities_id])) {
            $glpi_group = new \Group();
            $made       = (int) $glpi_group->add([
                'name'         => $name,
                'entities_id'  => $entities_id,
                'is_recursive' => (int) $source->fields['is_recursive'],
                'is_usergroup' => 1,
                'comment'      => sprintf(
                    __('Mirrored from the %s directory.', 'glpiidentity'),
                    $source->fields['name']
                ),
            ]);
            if ($made <= 0) {
                return;
            }
        }

        $group->update(['id' => $group->getID(), 'groups_id' => (int) $glpi_group->getID()]);
        $group->fields['groups_id'] = (int) $glpi_group->getID();
    }
}
