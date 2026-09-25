<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBChild;
use Dropdown;
use Group;
use Html;
use Profile;

/**
 * One rule turning something a directory said into something GLPI does.
 *
 * "If the `groups` claim contains Executive, put them in the VIP group." "If it
 * contains IT Staff, give them the Technician profile." "If `department` is
 * Field Services, set their location to the depot."
 *
 * Rules belong to a source rather than to the instance, which is the whole
 * design. GLPI has a perfectly good global authorisation-rules engine, and a
 * single global list is the wrong shape here: forty entities' rules in one
 * ordered list, where the isolation between them depends on every rule
 * remembering to test which directory it came from. Here the isolation is
 * structural — a rule cannot see a claim from a directory it does not belong
 * to, because it is never asked about one.
 */
class Mapping extends CommonDBChild
{
    public static string $itemtype = Source::class;
    public static string $items_id = 'plugin_glpiidentity_sources_id';

    public static string $rightname = 'plugin_glpiidentity_source';

    public bool $dohistory = true;

    public const ACTION_GROUP   = 'group';
    public const ACTION_PROFILE = 'profile';
    public const ACTION_FIELD   = 'field';

    public const OP_EQUALS   = 'equals';
    public const OP_CONTAINS = 'contains';
    public const OP_STARTS   = 'starts_with';
    public const OP_REGEX    = 'regex';

    public static function getTypeName($nb = 0)
    {
        return _n('Mapping', 'Mappings', $nb, 'glpiidentity');
    }

    public static function getIcon()
    {
        return 'ti ti-arrow-ramp-right';
    }

    /** @return array<string,string> */
    public static function actions(): array
    {
        return [
            self::ACTION_GROUP   => __('Add to GLPI group', 'glpiidentity'),
            self::ACTION_PROFILE => __('Grant GLPI profile', 'glpiidentity'),
            self::ACTION_FIELD   => __('Set user field', 'glpiidentity'),
        ];
    }

    /** @return array<string,string> */
    public static function operators(): array
    {
        return [
            self::OP_EQUALS   => __('is', 'glpiidentity'),
            self::OP_CONTAINS => __('contains', 'glpiidentity'),
            self::OP_STARTS   => __('starts with', 'glpiidentity'),
            self::OP_REGEX    => __('matches regex', 'glpiidentity'),
        ];
    }

    /**
     * The user fields a mapping may write, and what they are.
     *
     * An allowlist, not a denylist. The interesting fields on a GLPI user are
     * `authtype`, `password`, `is_active` and `profiles_id`, and a mapping
     * engine that can reach any column is a mapping engine that can hand a
     * directory the ability to disable an administrator or change how they
     * authenticate. Everything here is descriptive: worst case a rule writes a
     * wrong phone number.
     *
     * Three kinds, and the third is the one to be careful with:
     *
     *  - `itemtype` null — a plain column, written as text;
     *  - `itemtype` a dropdown class — matched by name, created if absent;
     *  - `reference` — a pointer to another *user*, resolved through this
     *    source's own links and never created.
     *
     * A reference deliberately does not travel as an `itemtype`. The dropdown
     * branch calls `Dropdown::importExternal()`, which creates the row when it
     * finds nothing — and a field that creates GLPI *users* out of whatever a
     * directory put in a manager attribute is a very different thing from one
     * that creates a Location called "London".
     *
     * @return array<string,array{label:string,itemtype:?class-string,reference?:class-string}>
     */
    public static function assignableFields(): array
    {
        return [
            'locations_id'        => ['label' => __('Location'), 'itemtype' => \Location::class],
            'usertitles_id'       => ['label' => __('Title'), 'itemtype' => \UserTitle::class],
            'usercategories_id'   => ['label' => __('Category'), 'itemtype' => \UserCategory::class],
            'registration_number' => ['label' => __('Administrative number'), 'itemtype' => null],
            'phone'               => ['label' => __('Phone'), 'itemtype' => null],
            'phone2'              => ['label' => __('Phone 2'), 'itemtype' => null],
            'mobile'              => ['label' => __('Mobile phone'), 'itemtype' => null],
            'comment'             => ['label' => __('Comments'), 'itemtype' => null],
            'users_id_supervisor' => [
                'label'     => __('Supervisor'),
                'itemtype'  => null,
                'reference' => \User::class,
            ],
        ];
    }

    /**
     * The entities a source's rules may grant a profile in: its own, and
     * everything beneath it.
     *
     * This is the boundary that keeps a rule's choice of entity safe. A rule can
     * place someone anywhere inside the subtree its source already owns — which
     * is the subtree that source's directory is already trusted with — and
     * nowhere else. Acme's rules still cannot reach Beta's tree, so the property
     * that made the entity un-choosable in the first place is intact; it is only
     * the granularity that changed.
     *
     * @return int[] entity ids, the source's own first
     */
    public static function scopeFor(int $sources_id): array
    {
        $source = new Source();
        if (!$source->getFromDB($sources_id)) {
            return [];
        }

        return array_values(getSonsOf('glpi_entities', (int) $source->fields['entities_id']));
    }

    /**
     * The GLPI groups a source's rules may add people to: those in its subtree,
     * and recursive ones above it that its entity already inherits.
     *
     * @return int[]
     */
    public static function groupsInScope(int $sources_id): array
    {
        $scope = self::scopeFor($sources_id);
        if ($scope === []) {
            return [];
        }

        $where = [['entities_id' => $scope]];
        $above = array_values(getAncestorsOf('glpi_entities', $scope[0]));
        if ($above !== []) {
            $where[] = ['entities_id' => $above, 'is_recursive' => 1];
        }

        return array_map(
            'intval',
            array_column(getAllDataFromTable(Group::getTable(), ['OR' => $where]), 'id')
        );
    }

    /** The entity this rule grants its profile in. */
    public function targetEntity(): int
    {
        return (int) ($this->fields['target_entities_id'] ?? 0);
    }

    /**
     * Does this rule fire, given what the directory said?
     *
     * `$values` is every value of the rule's claim — a groups claim is a list,
     * a department claim is one string, and both arrive here as an array so
     * that the rule does not have to care which.
     *
     * Equality is case-insensitive. Directory group names are compared by
     * people typing them into a form, and "executive" not matching "Executive"
     * is a support ticket rather than a security property.
     *
     * @param string[] $values
     */
    public function matches(array $values): bool
    {
        if (!$this->fields['is_active']) {
            return false;
        }

        $needle = (string) $this->fields['match_value'];
        if ($needle === '') {
            return false;
        }

        foreach ($values as $value) {
            $value = (string) $value;

            $hit = match ((string) $this->fields['match_operator']) {
                self::OP_CONTAINS => mb_stripos($value, $needle) !== false,
                self::OP_STARTS   => mb_stripos($value, $needle) === 0,
                // Delimited here rather than in the stored value, so an
                // administrator writes `^acme-.*-admins$` and not `/^…$/`, and
                // cannot accidentally enable a modifier by typing a delimiter.
                self::OP_REGEX    => @preg_match('#' . str_replace('#', '\\#', $needle) . '#u', $value) === 1,
                default           => mb_strtolower($value) === mb_strtolower($needle),
            };

            if ($hit) {
                return true;
            }
        }

        return false;
    }

    /** A one-line rendering, for the mapping list and the event log. */
    public function describe(): string
    {
        $operator = self::operators()[$this->fields['match_operator']] ?? $this->fields['match_operator'];

        $target = match ((string) $this->fields['action']) {
            self::ACTION_GROUP   => Dropdown::getDropdownName('glpi_groups', (int) $this->fields['groups_id']),
            // The entity belongs in the description: "grant Technician" means
            // something very different in the root entity than in one leaf of
            // it, and this string is what the event log records as the reason
            // somebody's access changed.
            self::ACTION_PROFILE => sprintf(
                '%s %s %s',
                Dropdown::getDropdownName('glpi_profiles', (int) $this->fields['profiles_id']),
                __('in', 'glpiidentity'),
                Dropdown::getDropdownName('glpi_entities', $this->targetEntity())
                    . ((int) $this->fields['is_dynamic_recursive'] === 1
                        ? ' ' . __('and below', 'glpiidentity') : '')
            ),
            default              => $this->fields['field_name'] . ' = ' . $this->fields['field_value'],
        };

        return sprintf(
            '%s %s "%s" → %s: %s',
            $this->fields['claim'],
            $operator,
            $this->fields['match_value'],
            self::actions()[$this->fields['action']] ?? $this->fields['action'],
            $target
        );
    }

    /**
     * The rules of a source, in the order they should be applied.
     *
     * @return self[]
     */
    public static function forSource(int $sources_id): array
    {
        $out = [];
        foreach (
            getAllDataFromTable(
                self::getTable(),
                ['plugin_glpiidentity_sources_id' => $sources_id, 'ORDER' => ['rank_order', 'id']]
            ) as $row
        ) {
            $rule         = new self();
            $rule->fields = $row;
            $out[]        = $rule;
        }

        return $out;
    }

    public function prepareInputForAdd($input)
    {
        return $this->validate($input, true);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->validate($input, false);
    }

    /**
     * Refuse a rule that cannot do anything, and one that could do too much.
     *
     * A rule with no target silently does nothing, which is worse than an
     * error: it looks configured. A rule naming a field outside the allowlist
     * is rejected outright rather than ignored, because ignoring it would leave
     * an administrator believing a mapping is in place.
     */
    private function validate(array $input, bool $adding): array|false
    {
        $action = (string) ($input['action'] ?? $this->fields['action'] ?? self::ACTION_GROUP);

        if (!array_key_exists($action, self::actions())) {
            return false;
        }

        if ($adding && !isset($input['rank_order'])) {
            $input['rank_order'] = self::nextRank((int) ($input['plugin_glpiidentity_sources_id'] ?? 0));
        }

        $refuse = static function (string $message): false {
            \Session::addMessageAfterRedirect(htmlescape($message), false, ERROR);

            return false;
        };

        // The form's "Match on: directory group" is a claim chosen for the
        // administrator, not a column: it is whatever claim the source carries
        // group membership in, which they should not have to know.
        if (($input['_match_on'] ?? '') === 'group') {
            $owner = new Source();
            if (
                $owner->getFromDB((int) ($input['plugin_glpiidentity_sources_id']
                    ?? $this->fields['plugin_glpiidentity_sources_id'] ?? 0))
            ) {
                $input['claim'] = $owner->groupsClaim();
            }
        }

        if (array_key_exists('claim', $input) && trim((string) $input['claim']) === '') {
            return $refuse(__('Say which claim or attribute this rule looks at.', 'glpiidentity'));
        }

        if ($action === self::ACTION_GROUP) {
            $target = (int) ($input['groups_id'] ?? $this->fields['groups_id'] ?? 0);
            if ($target <= 0) {
                return $refuse(__('Choose the GLPI group this rule should add the user to.', 'glpiidentity'));
            }

            // The same boundary as a profile's entity. The form only offers
            // groups a source's subtree can see; this is what stops a crafted
            // post naming another organisation's group.
            $sources_id = (int) ($input['plugin_glpiidentity_sources_id']
                ?? $this->fields['plugin_glpiidentity_sources_id'] ?? 0);
            if (!in_array($target, self::groupsInScope($sources_id), true)) {
                return $refuse(__('A rule can only add people to a group its source\'s entity can see.', 'glpiidentity'));
            }
        }

        if ($action === self::ACTION_PROFILE) {
            $target = (int) ($input['profiles_id'] ?? $this->fields['profiles_id'] ?? 0);
            if ($target <= 0) {
                return $refuse(__('Choose the GLPI profile this rule should grant.', 'glpiidentity'));
            }

            $sources_id = (int) ($input['plugin_glpiidentity_sources_id']
                ?? $this->fields['plugin_glpiidentity_sources_id'] ?? 0);
            $scope = self::scopeFor($sources_id);
            if ($scope === []) {
                return $refuse(__('This rule has no identity source.', 'glpiidentity'));
            }

            // Absent on an older form post, or on a rule written before the
            // column existed: the source's own entity is what that has always
            // meant, and is the narrowest thing it could mean.
            $entity = array_key_exists('target_entities_id', $input)
                ? (int) $input['target_entities_id']
                : (int) ($this->fields['target_entities_id'] ?? $scope[0]);

            // The check that makes a choosable entity safe. Without it a rule
            // could grant a profile in another organisation's tree, which is a
            // directory being handed the ability to place its people anywhere.
            if (!in_array($entity, $scope, true)) {
                return $refuse(__('A rule can only grant a profile in its source\'s entity '
                    . 'or one beneath it.', 'glpiidentity'));
            }

            $input['target_entities_id'] = $entity;
        }

        if ($action === self::ACTION_FIELD) {
            $field = (string) ($input['field_name'] ?? $this->fields['field_name'] ?? '');
            if (!array_key_exists($field, self::assignableFields())) {
                return $refuse(__('That user field cannot be set by a mapping.', 'glpiidentity'));
            }

            // The other half of the overlap refusal — see AttributeMap. A field
            // filled by pass-through already has a source of truth, and a rule
            // writing a constant into it would mean the value an administrator
            // sees depends on which ran last.
            $sources_id = (int) ($input['plugin_glpiidentity_sources_id']
                ?? $this->fields['plugin_glpiidentity_sources_id'] ?? 0);

            if (isset(AttributeMap::fieldsSetByMaps($sources_id)[$field])) {
                return $refuse(sprintf(
                    __('This source already fills "%s" from a directory attribute. Remove that '
                        . 'attribute map first, or choose another field.', 'glpiidentity'),
                    self::assignableFields()[$field]['label']
                ));
            }
        }

        if (isset($input['match_operator']) && $input['match_operator'] === self::OP_REGEX) {
            $pattern = (string) ($input['match_value'] ?? '');
            if (@preg_match('#' . str_replace('#', '\\#', $pattern) . '#u', '') === false) {
                return $refuse(__('That is not a valid regular expression.', 'glpiidentity'));
            }
        }

        return $input;
    }

    private static function nextRank(int $sources_id): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $row = $DB->request([
            'SELECT' => ['MAX' => 'rank_order AS top'],
            'FROM'   => self::getTable(),
            'WHERE'  => ['plugin_glpiidentity_sources_id' => $sources_id],
        ])->current();

        return (int) ($row['top'] ?? 0) + 1;
    }

    // --------------------------------------------------------------- the tab

    public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof Source || $item->isNewItem()) {
            return '';
        }

        return self::createTabEntry(
            self::getTypeName(2),
            count(self::forSource($item->getID())),
            $item::class
        );
    }

    public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof Source) {
            self::showForSource($item);
        }

        return true;
    }

    /**
     * The condition half of a rule, the way an administrator would say it.
     *
     * Nearly every rule is "in directory group X", and that is how people
     * think of it; the claim name is plumbing, shown only when a rule looks at
     * something other than group membership.
     */
    private function conditionHtml(Source $source, callable $e): string
    {
        $operator = (string) $this->fields['match_operator'];
        $verb     = $e(self::operators()[$operator] ?? $operator);
        $value    = '<strong>' . $e($this->fields['match_value']) . '</strong>';

        if ((string) $this->fields['claim'] === $source->groupsClaim()) {
            return $operator === self::OP_EQUALS
                ? __s('In directory group', 'glpiidentity') . ' ' . $value
                : __s('In a directory group that', 'glpiidentity') . ' ' . $verb . ' ' . $value;
        }

        return '<code>' . $e($this->fields['claim']) . '</code> ' . $verb . ' ' . $value;
    }

    /**
     * The outcome half.
     *
     * `getDropdownName()` returns the row as it is stored, markup and all —
     * GLPI 11 escapes on output, not on input — so a group name is
     * attacker-supplied text here: `group` UPDATE is a much more widely granted
     * right than this page needs, and a mirroring source creates groups
     * straight from a SCIM `displayName`. The badges are ours and stay outside
     * the escape.
     */
    private function outcomeHtml(callable $e): string
    {
        return match ((string) $this->fields['action']) {
            self::ACTION_GROUP   => __s('Add to GLPI group', 'glpiidentity') . ' <strong>'
                . $e(Dropdown::getDropdownName('glpi_groups', (int) $this->fields['groups_id'])) . '</strong>',
            self::ACTION_PROFILE => __s('Grant', 'glpiidentity') . ' <strong>'
                . $e(Dropdown::getDropdownName('glpi_profiles', (int) $this->fields['profiles_id'])) . '</strong> '
                . __s('in', 'glpiidentity') . ' '
                . $e(Dropdown::getDropdownName('glpi_entities', $this->targetEntity()))
                . ((int) $this->fields['is_dynamic_recursive'] === 1
                    ? ' <span class="badge bg-azure-lt">' . __s('and below', 'glpiidentity') . '</span>' : ''),
            default              => __s('Set', 'glpiidentity') . ' '
                . $e(self::assignableFields()[$this->fields['field_name']]['label'] ?? $this->fields['field_name'])
                . ' = <strong>' . $e($this->fields['field_value']) . '</strong>',
        };
    }

    private static function showForSource(Source $source): void
    {
        $e     = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $rules = self::forSource($source->getID());
        $can   = $source->canUpdateItem();
        $form  = Url::to('front/mapping.form.php');

        echo "<div class='glpiidentity-mappings'>";

        echo "<div class='d-flex flex-wrap align-items-start gap-2 mb-3'>";
        echo '<p class="text-muted mb-0 flex-grow-1">'
           . __s('Every matching rule applies, top to bottom — a user in two mapped groups gets both. '
               . 'Rules run whenever this directory signs somebody in or changes them over SCIM.', 'glpiidentity')
           . '</p>';

        if ($can) {
            echo "<a class='btn btn-primary' href='" . $e($form)
               . '?plugin_glpiidentity_sources_id=' . (int) $source->getID() . "'>"
               . "<i class='ti ti-plus me-1'></i>" . __s('Add a mapping', 'glpiidentity') . '</a>';

            // Rules otherwise only reach a person the next time the directory
            // mentions them, which for a quiet account can be weeks.
            if (Link::forSource($source->getID()) !== []) {
                echo "<form method='post' action='" . $e($form) . "' class='d-inline'>";
                echo Html::hidden('plugin_glpiidentity_sources_id', ['value' => (int) $source->getID()]);
                echo "<button type='submit' name='reapply' value='1' class='btn btn-outline-secondary' title='"
                   . __s('Recompute groups and profiles for every account this source manages, from the '
                       . 'directory groups on record.', 'glpiidentity') . "'>"
                   . "<i class='ti ti-refresh me-1'></i>" . __s('Apply to everyone now', 'glpiidentity')
                   . '</button>';
                Html::closeForm();
            }
        }
        echo '</div>';

        if ($rules === []) {
            echo "<div class='alert alert-secondary'>"
               . __s('No mappings yet. Without one, users from this source get only the default '
                   . 'profile set on the source itself.', 'glpiidentity')
               . '</div>';
            echo '</div>';

            return;
        }

        echo "<table class='table table-sm table-hover align-middle'><thead><tr>"
           . "<th class='w-1'>#</th>"
           . '<th>' . __s('When', 'glpiidentity') . '</th>'
           . '<th>' . __s('Then', 'glpiidentity') . '</th>'
           . '<th></th></tr></thead><tbody>';

        foreach ($rules as $rule) {
            $active = (int) $rule->fields['is_active'] === 1;

            echo '<tr' . ($active ? '' : " class='text-muted'") . '>';
            echo '<td>' . (int) $rule->fields['rank_order'] . '</td>';
            echo '<td>' . $rule->conditionHtml($source, $e) . '</td>';
            echo '<td>' . $rule->outcomeHtml($e)
               . ($active ? '' : ' <span class="badge bg-secondary-lt">' . __s('Inactive') . '</span>') . '</td>';
            echo '<td class="text-end">';
            if ($can) {
                echo "<a class='btn btn-sm btn-ghost-secondary' title='" . __s('Edit') . "' href='" . $e($form)
                   . '?id=' . (int) $rule->getID() . "'><i class='ti ti-edit'></i></a>";
            }
            echo '</td></tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
    }

    /**
     * The rule form, laid out as the sentence it builds.
     *
     * "When [the user is in directory group X], then [grant profile P in
     * entity E]". Only the fields the chosen action uses are shown, and a line
     * underneath reads the rule back in words — the whole form used to show
     * every action's fields at once, with a hint on each saying which action
     * it belonged to.
     *
     * Without JavaScript every row stays visible and the form still works: the
     * script only hides and summarises, it never decides what is posted.
     */
    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);

        $e      = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $rand   = mt_rand();
        $source = new Source();
        $source->getFromDB((int) $this->fields['plugin_glpiidentity_sources_id']);

        $claim    = (string) $this->fields['claim'];
        $on_group = $claim === $source->groupsClaim()
            // A new rule's empty claim is "groups"; on a source that calls it
            // something else, a new rule is still a group rule.
            || ($this->isNewItem() && $claim === 'groups');

        // Scope wrapper: this form is core-rendered, so without a plugin-owned
        // container the shipped dark-theme CSS could never reach its helper
        // text (see the dark section of the plugin stylesheet).
        echo "<div class='glpiidentity-scope' id='glpiidentity-mapping-$rand'>";
        $this->showFormHeader($options);

        echo "<tr class='tab_bg_1'><td>" . __s('Identity source', 'glpiidentity') . '</td><td>';
        echo $e($source->fields['name'] ?? '');
        echo Html::hidden('plugin_glpiidentity_sources_id', [
            'value' => (int) $this->fields['plugin_glpiidentity_sources_id'],
        ]);
        echo '</td><td>' . __s('Active') . '</td><td>';
        Dropdown::showYesNo('is_active', $this->fields['is_active']);
        echo '</td></tr>';

        // ------------------------------------------------------------- when
        echo "<tr class='tab_bg_2'><th colspan='4'><i class='ti ti-filter me-1'></i>"
           . __s('When', 'glpiidentity') . '</th></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Match on', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('_match_on', [
            'group' => __('Directory group membership', 'glpiidentity'),
            'claim' => __('Another claim or attribute', 'glpiidentity'),
        ], ['value' => $on_group ? 'group' : 'claim']);
        echo '</td><td data-glpiidentity-claim>' . __s('Claim', 'glpiidentity') . '</td><td data-glpiidentity-claim>';
        echo Html::input('claim', ['value' => $on_group ? $source->groupsClaim() : $claim, 'placeholder' => 'department']);
        echo "<div class='form-text'>"
           . __s('A sign-in claim, or a SCIM attribute such as department or title.', 'glpiidentity')
           . '</div></td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Condition', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('match_operator', self::operators(), [
            'value' => $this->fields['match_operator'],
        ]);
        echo '</td><td>' . __s('Value', 'glpiidentity') . '</td><td>';

        // The directory's own group names, so the value can be picked rather
        // than remembered — a datalist and not a select, because a contains
        // or regex rule, or a group not synced yet, still needs free text.
        $known = IdpGroup::forSource((int) $this->fields['plugin_glpiidentity_sources_id']);
        echo "<input type='text' class='form-control' name='match_value' autocomplete='off' required"
           . " list='glpiidentity-groups-$rand' value='" . $e($this->fields['match_value']) . "'>";
        echo "<datalist id='glpiidentity-groups-$rand'>";
        foreach ($known as $group) {
            echo "<option value='" . $e($group->fields['name']) . "'></option>";
        }
        echo '</datalist>';
        echo "<div class='form-text' data-glpiidentity-groupmode>"
           . ($known !== []
               ? sprintf(
                   __s('Start typing to pick from the %d groups this directory has sent.', 'glpiidentity'),
                   count($known)
               )
               : __s('No groups received from this directory yet — type the name exactly as the '
                   . 'directory spells it.', 'glpiidentity'))
           . '</div></td></tr>';

        // ------------------------------------------------------------- then
        echo "<tr class='tab_bg_2'><th colspan='4'><i class='ti ti-arrow-ramp-right me-1'></i>"
           . __s('Then', 'glpiidentity') . '</th></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Action', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('action', self::actions(), ['value' => $this->fields['action']]);
        echo '</td><td>' . __s('Order', 'glpiidentity') . '</td><td>';
        echo "<input type='number' min='0' class='form-control' name='rank_order' value='"
           . $e($this->fields['rank_order']) . "'>";
        echo "<div class='form-text'>"
           . __s('Only matters when two rules set the same user field: the later one wins.', 'glpiidentity')
           . '</div></td></tr>';

        echo "<tr class='tab_bg_1' data-glpiidentity-action='" . self::ACTION_GROUP . "'><td>"
           . Group::getTypeName(1) . "</td><td colspan='3'>";
        Group::dropdown([
            'name'        => 'groups_id',
            'value'       => $this->fields['groups_id'],
            'entity'      => (int) ($source->fields['entities_id'] ?? 0),
            'entity_sons' => true,
            'condition'   => ['is_usergroup' => 1],
        ]);
        echo '</td></tr>';

        // The entity the profile is granted in, limited to the source's own
        // subtree. Listing only those entities is the point: an administrator
        // cannot pick one belonging to another organisation, so the rule form
        // cannot express something the validator would then have to refuse.
        $scope   = self::scopeFor((int) $this->fields['plugin_glpiidentity_sources_id']);
        $default = $this->isNewItem() ? (int) ($source->fields['entities_id'] ?? 0) : $this->targetEntity();

        echo "<tr class='tab_bg_1' data-glpiidentity-action='" . self::ACTION_PROFILE . "'><td>"
           . Profile::getTypeName(1) . '</td><td>';
        Profile::dropdown(['name' => 'profiles_id', 'value' => $this->fields['profiles_id']]);
        echo '</td><td>' . __s('In entity', 'glpiidentity') . '</td><td>';
        \Entity::dropdown([
            'name'                => 'target_entities_id',
            'value'               => $default,
            'condition'           => ['id' => $scope ?: [-1]],
            'display_emptychoice' => false,
        ]);
        echo "<div class='mt-2'>" . Html::getCheckbox([
            'name'    => 'is_dynamic_recursive',
            'checked' => (int) $this->fields['is_dynamic_recursive'] === 1,
            'value'   => 1,
        ]) . ' ' . __s('and every entity below it', 'glpiidentity') . '</div>';
        echo "<div class='form-text'>"
           . __s('Any entity at or below this source\'s own. One source can grant different '
               . 'profiles in different parts of the tree — Technician in one department, '
               . 'Self-Service in the rest.', 'glpiidentity')
           . '</div></td></tr>';

        echo "<tr class='tab_bg_1' data-glpiidentity-action='" . self::ACTION_FIELD . "'><td>"
           . __s('User field', 'glpiidentity') . '</td><td>';
        $choices = ['' => Dropdown::EMPTY_VALUE];
        foreach (self::assignableFields() as $name => $meta) {
            $choices[$name] = $meta['label'];
        }
        Dropdown::showFromArray('field_name', $choices, ['value' => $this->fields['field_name']]);
        echo '</td><td>' . __s('Value', 'glpiidentity') . '</td><td>';
        echo Html::input('field_value', ['value' => $this->fields['field_value']]);
        echo "<div class='form-text'>"
           . __s('For a dropdown field the value is matched by name, and created if it does not '
               . 'exist yet.', 'glpiidentity')
           . '</div></td></tr>';

        echo "<tr class='tab_bg_1'><td colspan='4'>"
           . "<div class='alert alert-info mb-0 d-none' data-glpiidentity-summary></div></td></tr>";

        echo "<tr class='tab_bg_1'><td>" . __s('Comments') . "</td><td colspan='3'>";
        echo "<textarea class='form-control' name='comment' rows='2'>" . $e($this->fields['comment']) . '</textarea>';
        echo '</td></tr>';

        $this->showFormButtons($options);
        echo '</div>';

        echo Html::scriptBlock(self::formScript("glpiidentity-mapping-$rand"));

        return true;
    }

    /**
     * Show only the chosen action's fields, and read the rule back in words.
     *
     * jQuery rather than addEventListener: GLPI's selects are select2, which
     * announces a change through jQuery's trigger() — a native listener never
     * hears it. The summary is built with textContent, so a group or entity
     * name cannot become markup on its way into it.
     */
    private static function formScript(string $root_id): string
    {
        $strings = json_encode([
            'inGroup'    => __('When the user is in directory group %s,', 'glpiidentity'),
            'inGroupOp'  => __('When one of the user\'s directory groups %1$s %2$s,', 'glpiidentity'),
            'claimOp'    => __('When %1$s %2$s %3$s,', 'glpiidentity'),
            'group'      => __('add them to the GLPI group %s.', 'glpiidentity'),
            'profile'    => __('grant them %1$s in %2$s only.', 'glpiidentity'),
            'profileRec' => __('grant them %1$s in %2$s and every entity below it.', 'glpiidentity'),
            'field'      => __('set their %1$s to %2$s.', 'glpiidentity'),
            'blank'      => __('(not chosen yet)', 'glpiidentity'),
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE);

        $root = json_encode('#' . $root_id);

        return <<<JS
            (function ($) {
                const \$root = $($root);
                const t = $strings;
                const fmt = (s, ...args) => { let i = 0; return s.replace(/%(\\d+)\\\$s|%s/g, (_, n) => args[n ? n - 1 : i++]); };
                const q = (v) => (v && v.trim() !== '' && !/^-+$/.test(v.trim())) ? '“' + v.trim() + '”' : t.blank;
                const field = (name) => \$root.find('[name="' + name + '"]');
                const chosen = (name) => {
                    const \$f = field(name);
                    return \$f.is('select') ? \$f.find('option:selected').text() : String(\$f.val() || '');
                };

                function sync() {
                    const action = field('action').val();
                    const onGroup = field('_match_on').val() === 'group';

                    \$root.find('[data-glpiidentity-action]').each(function () {
                        $(this).toggle(this.dataset.glpiidentityAction === action);
                    });
                    \$root.find('[data-glpiidentity-claim]').toggle(!onGroup);
                    \$root.find('[data-glpiidentity-groupmode]').toggle(onGroup);

                    const op = field('match_operator').val();
                    const when = onGroup
                        ? (op === 'equals' ? fmt(t.inGroup, q(chosen('match_value')))
                            : fmt(t.inGroupOp, chosen('match_operator'), q(chosen('match_value'))))
                        : fmt(t.claimOp, q(chosen('claim')), chosen('match_operator'), q(chosen('match_value')));

                    let then = '';
                    if (action === 'group') {
                        then = fmt(t.group, q(chosen('groups_id')));
                    } else if (action === 'profile') {
                        const below = \$root.find('input[type=checkbox][name="is_dynamic_recursive"]').is(':checked');
                        then = fmt(below ? t.profileRec : t.profile, q(chosen('profiles_id')), q(chosen('target_entities_id')));
                    } else {
                        then = fmt(t.field, q(chosen('field_name')), q(chosen('field_value')));
                    }

                    const box = \$root.find('[data-glpiidentity-summary]');
                    box.text(when + ' ' + then).removeClass('d-none');
                }

                \$root.on('change input', 'select, input', sync);
                sync();
            })(jQuery);
            JS;
    }

    public function post_getEmpty()
    {
        // The table is created by the install hook rather than through GLPI's
        // migration API, so getEmpty() has no column defaults to read.
        $this->fields['is_active']            = 1;
        $this->fields['claim']                = 'groups';
        $this->fields['match_operator']       = self::OP_EQUALS;
        $this->fields['action']               = self::ACTION_GROUP;
        $this->fields['rank_order']           = 0;
        $this->fields['is_dynamic_recursive'] = 0;
        // Left at 0 rather than guessed: the form fills it from the source, and
        // validate() falls back to the source's own entity for anything that
        // reaches the database without passing through the form.
        $this->fields['target_entities_id']   = 0;
    }
}
