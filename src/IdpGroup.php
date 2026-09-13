<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBTM;

/**
 * A group an organisation's directory has told us about.
 *
 * Deliberately not a GLPI group. An organisation's directory is theirs to organise,
 * and mirroring every group it mentions would fill one shared group tree with a
 * dozen organisations' internal vocabulary — "All Staff", "All Staff", "All
 * Staff" — none of which a technician wants to see in a dropdown.
 *
 * What these are for is the mapping. An administrator writing "Executive → VIP"
 * needs to know that Acme's directory really does call it Executive, and
 * picking from a list of what SCIM has actually sent beats typing a name and
 * finding out six weeks later that it was Executives.
 */
class IdpGroup extends CommonDBTM
{
    public static $rightname = 'plugin_glpiidentity_source';

    public static function getTypeName($nb = 0)
    {
        return _n('Directory group', 'Directory groups', $nb, 'glpiidentity');
    }

    public static function getIcon()
    {
        return 'ti ti-users-group';
    }

    /** Find or create the record for a directory group, by the directory's own id. */
    public static function upsert(int $sources_id, string $external_id, string $name): self
    {
        $group = new self();

        if (
            $group->getFromDBByCrit([
                'plugin_glpiidentity_sources_id' => $sources_id,
                'external_id'                    => $external_id,
            ])
        ) {
            if ($group->fields['name'] !== $name) {
                $group->update(['id' => $group->getID(), 'name' => $name]);
            }

            return $group;
        }

        $group->add([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'external_id'                    => $external_id,
            'name'                           => $name,
            'date_creation'                  => date('Y-m-d H:i:s'),
        ]);

        return $group;
    }

    /** @return self[] */
    public static function forSource(int $sources_id): array
    {
        $out = [];
        foreach (
            getAllDataFromTable(
                self::getTable(),
                ['plugin_glpiidentity_sources_id' => $sources_id],
                false,
                'name'
            ) as $row
        ) {
            $group         = new self();
            $group->fields = $row;
            $out[]         = $group;
        }

        return $out;
    }

    /**
     * The names of the directory groups a user is in, for one source.
     *
     * This is what the mapper matches against when the claims did not travel
     * with the request — a SCIM update names the user, not their groups, and
     * membership arrives separately on the /Groups endpoint.
     *
     * @return string[]
     */
    public static function namesForUser(int $sources_id, int $users_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $names = [];
        foreach (
            $DB->request([
                'SELECT'     => ['g.name'],
                'FROM'       => self::getTable() . ' AS g',
                'INNER JOIN' => [
                    IdpGroup_User::getTable() . ' AS m' => [
                        'ON' => [
                            'm' => 'plugin_glpiidentity_idpgroups_id',
                            'g' => 'id',
                        ],
                    ],
                ],
                'WHERE'      => [
                    'g.plugin_glpiidentity_sources_id' => $sources_id,
                    'm.users_id'                       => $users_id,
                ],
            ]) as $row
        ) {
            $names[] = (string) $row['name'];
        }

        return $names;
    }

    /** @return int[] GLPI user ids */
    public function memberIds(): array
    {
        $out = [];
        foreach (
            getAllDataFromTable(
                IdpGroup_User::getTable(),
                ['plugin_glpiidentity_idpgroups_id' => $this->getID()]
            ) as $row
        ) {
            $out[] = (int) $row['users_id'];
        }

        return $out;
    }

    /**
     * Replace this group's membership wholesale.
     *
     * A SCIM PUT on a group is a statement about the whole membership, so the
     * honest implementation is a replace and not a merge. PATCH is handled
     * separately, because that one really is incremental.
     *
     * @param int[] $users_ids
     */
    public function setMembers(array $users_ids): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $wanted  = array_values(array_unique(array_map('intval', $users_ids)));
        $current = $this->memberIds();

        foreach (array_diff($current, $wanted) as $gone) {
            $DB->delete(IdpGroup_User::getTable(), [
                'plugin_glpiidentity_idpgroups_id' => $this->getID(),
                'users_id'                         => $gone,
            ]);
        }

        foreach (array_diff($wanted, $current) as $added) {
            $this->addMember($added);
        }
    }

    public function addMember(int $users_id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        try {
            $DB->insert(IdpGroup_User::getTable(), [
                'plugin_glpiidentity_idpgroups_id' => $this->getID(),
                'users_id'                         => $users_id,
            ]);
        } catch (\Throwable $e) {
            // Unique key: already a member. A directory re-sending a membership
            // it already sent is the normal case, not an error.
        }
    }

    public function removeMember(int $users_id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->delete(IdpGroup_User::getTable(), [
            'plugin_glpiidentity_idpgroups_id' => $this->getID(),
            'users_id'                         => $users_id,
        ]);
    }

    public function cleanDBonPurge()
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->delete(IdpGroup_User::getTable(), ['plugin_glpiidentity_idpgroups_id' => $this->getID()]);
    }
}
