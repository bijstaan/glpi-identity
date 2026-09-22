<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBTM;
use Dropdown;

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

    /**
     * A groups claim with each known group id joined by that group's name.
     *
     * The ids stay: a rule written against an object id — the only stable
     * thing to write one against, if the directory renames groups — keeps
     * matching.
     *
     * @param string[] $values
     * @return string[]
     */
    public static function withNames(int $sources_id, array $values): array
    {
        if ($values === []) {
            return $values;
        }

        $names = [];
        foreach (
            getAllDataFromTable(self::getTable(), [
                'plugin_glpiidentity_sources_id' => $sources_id,
                'external_id'                    => array_values(array_unique($values)),
            ]) as $row
        ) {
            $names[] = (string) $row['name'];
        }

        return array_values(array_unique(array_merge($values, $names)));
    }

    /**
     * The mirrored GLPI groups for a set of directory-group names or ids.
     *
     * Matched on either, case-insensitively, for the same reason a rule is:
     * at sign-in the claim may carry ids, over SCIM it carries names.
     *
     * @param string[] $values
     * @return array<int,string> GLPI group id => directory group name
     */
    public static function mirroredFor(int $sources_id, array $values): array
    {
        if ($values === []) {
            return [];
        }

        $wanted = array_flip(array_map('mb_strtolower', $values));
        $out    = [];

        foreach (
            getAllDataFromTable(self::getTable(), [
                'plugin_glpiidentity_sources_id' => $sources_id,
                'groups_id'                      => ['>', 0],
            ]) as $row
        ) {
            if (
                isset($wanted[mb_strtolower((string) $row['name'])])
                || isset($wanted[mb_strtolower((string) $row['external_id'])])
            ) {
                $out[(int) $row['groups_id']] = (string) $row['name'];
            }
        }

        return $out;
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

    // --------------------------------------------------------------- the tab

    public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof Source || $item->isNewItem()) {
            return '';
        }

        return self::createTabEntry(self::getTypeName(2), count(self::forSource($item->getID())), $item::class);
    }

    public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof Source) {
            self::showForSource($item);
        }

        return true;
    }

    /**
     * What the directory has told us, and what each group currently does.
     *
     * The starting point for writing a rule: every group is one click from a
     * mapping with its name already filled in, and the "Rules" column shows at
     * a glance which groups nothing acts on yet.
     */
    private static function showForSource(Source $source): void
    {
        $e      = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $groups = self::forSource($source->getID());
        $can    = $source->canUpdateItem();
        $rules  = array_filter(
            Mapping::forSource($source->getID()),
            static fn(Mapping $r): bool => (int) $r->fields['is_active'] === 1
                && (string) $r->fields['claim'] === $source->groupsClaim()
        );

        echo "<div class='glpiidentity-mappings'>";

        if ($groups === []) {
            echo "<div class='alert alert-secondary'>"
               . __s('No directory groups yet. They appear here once the SCIM connector provisions '
                   . 'groups — in Entra ID, assign the groups to the enterprise application and '
                   . 'include them in the provisioning scope.', 'glpiidentity')
               . '</div></div>';

            return;
        }

        echo "<table class='table table-sm table-hover align-middle'><thead><tr>"
           . '<th>' . __s('Directory group', 'glpiidentity') . '</th>'
           . '<th>' . __s('Members', 'glpiidentity') . '</th>'
           . '<th>' . __s('Rules', 'glpiidentity') . '</th>'
           . '<th>' . __s('Mirrored as', 'glpiidentity') . '</th>'
           . '<th></th></tr></thead><tbody>';

        foreach ($groups as $group) {
            $name    = (string) $group->fields['name'];
            $members = $group->memberIds();
            $hits    = count(array_filter($rules, static fn(Mapping $r): bool => $r->matches([$name])));

            echo '<tr><td><strong>' . $e($name) . '</strong>'
               . "<div class='text-muted small'><code>" . $e($group->fields['external_id']) . '</code></div></td>';

            echo '<td>';
            if ($members === []) {
                echo "<span class='text-muted'>0</span>";
            } else {
                // A handful of names is what tells an administrator whether this
                // is the group they think it is.
                $names = [];
                foreach (array_slice($members, 0, 25) as $users_id) {
                    $names[] = $e(getUserName($users_id));
                }
                echo '<details><summary>' . count($members) . '</summary>'
                   . "<div class='small'>" . implode(', ', $names)
                   . (count($members) > 25 ? ' …' : '') . '</div></details>';
            }
            echo '</td>';

            echo '<td>' . ($hits > 0
                ? "<span class='badge bg-green-lt'>" . $hits . '</span>'
                : "<span class='text-muted'>" . __s('none', 'glpiidentity') . '</span>') . '</td>';

            $mirror = (int) ($group->fields['groups_id'] ?? 0);
            echo '<td>' . ($mirror > 0
                ? "<a href='" . $e(\Group::getFormURLWithID($mirror)) . "'>"
                    . $e(Dropdown::getDropdownName('glpi_groups', $mirror)) . '</a>'
                : "<span class='text-muted'>—</span>") . '</td>';

            echo "<td class='text-end text-nowrap'>";
            if ($can) {
                $base = Url::to('front/mapping.form.php') . '?plugin_glpiidentity_sources_id='
                    . (int) $source->getID() . '&match_value=' . rawurlencode($name);
                echo "<a class='btn btn-sm btn-outline-primary' href='" . $e($base . '&action=' . Mapping::ACTION_PROFILE)
                   . "'><i class='ti ti-id-badge-2 me-1'></i>" . __s('Grant a profile', 'glpiidentity') . '</a> ';
                echo "<a class='btn btn-sm btn-ghost-secondary' href='" . $e($base . '&action=' . Mapping::ACTION_GROUP)
                   . "'><i class='ti ti-users-plus me-1'></i>" . __s('Add to group', 'glpiidentity') . '</a>';
            }
            echo '</td></tr>';
        }

        echo '</tbody></table></div>';
    }

    public function cleanDBonPurge()
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->delete(IdpGroup_User::getTable(), ['plugin_glpiidentity_idpgroups_id' => $this->getID()]);
    }
}
