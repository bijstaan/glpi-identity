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
 * design. GLPI has a perfectly good global authorisation-rules engine, and for
 * an MSP a single global list is the wrong shape: forty customers' rules in one
 * ordered list, where the isolation between them depends on every rule
 * remembering to test which directory it came from. Here the isolation is
 * structural — a rule cannot see a claim from a directory it does not belong
 * to, because it is never asked about one.
 */
class Mapping extends CommonDBChild
{
    public static $itemtype = Source::class;
    public static $items_id = 'plugin_glpiidentity_sources_id';

    public static $rightname = 'plugin_glpiidentity_source';

    public $dohistory = true;

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
     * @return array<string,array{label:string,itemtype:?class-string}>
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
        ];
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
            self::ACTION_PROFILE => Dropdown::getDropdownName('glpi_profiles', (int) $this->fields['profiles_id']),
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
                ['plugin_glpiidentity_sources_id' => $sources_id],
                false,
                'rank_order, id'
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
            \Session::addMessageAfterRedirect(Html::entities_deep($message), false, ERROR);

            return false;
        };

        if ($action === self::ACTION_GROUP) {
            $target = (int) ($input['groups_id'] ?? $this->fields['groups_id'] ?? 0);
            if ($target <= 0) {
                return $refuse(__('Choose the GLPI group this rule should add the user to.', 'glpiidentity'));
            }
        }

        if ($action === self::ACTION_PROFILE) {
            $target = (int) ($input['profiles_id'] ?? $this->fields['profiles_id'] ?? 0);
            if ($target <= 0) {
                return $refuse(__('Choose the GLPI profile this rule should grant.', 'glpiidentity'));
            }
        }

        if ($action === self::ACTION_FIELD) {
            $field = (string) ($input['field_name'] ?? $this->fields['field_name'] ?? '');
            if (!array_key_exists($field, self::assignableFields())) {
                return $refuse(__('That user field cannot be set by a mapping.', 'glpiidentity'));
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

    private static function showForSource(Source $source): void
    {
        $e     = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $rules = self::forSource($source->getID());
        $can   = $source->canUpdateItem();

        echo "<div class='glpiidentity-mappings'>";

        echo '<p class="text-muted">'
           . __s('Rules are read top to bottom and every matching rule applies — this is not a '
               . 'first-match-wins list. A user who is in two mapped groups gets both.', 'glpiidentity')
           . '</p>';

        if ($rules === []) {
            echo "<div class='alert alert-secondary'>"
               . __s('No mappings yet. Without one, users from this source get only the default '
                   . 'profile set on the source itself.', 'glpiidentity')
               . '</div>';
        } else {
            echo "<table class='table table-sm'><thead><tr>"
               . '<th></th><th>' . __s('Claim', 'glpiidentity') . '</th>'
               . '<th>' . __s('Condition', 'glpiidentity') . '</th>'
               . '<th>' . __s('Then', 'glpiidentity') . '</th>'
               . '<th></th></tr></thead><tbody>';

            foreach ($rules as $rule) {
                // `getDropdownName()` returns the row as it is stored, markup and
                // all — GLPI 11 escapes on output, not on input — so a group name
                // is attacker-supplied text here: `group` UPDATE is a much more
                // widely granted right than this page needs, and a SCIM connector
                // creates groups straight from a `displayName` it was handed. The
                // badge is ours and stays outside the escape.
                $target = match ((string) $rule->fields['action']) {
                    self::ACTION_GROUP   => $e(Dropdown::getDropdownName('glpi_groups', (int) $rule->fields['groups_id'])),
                    self::ACTION_PROFILE => $e(Dropdown::getDropdownName('glpi_profiles', (int) $rule->fields['profiles_id']))
                        . ((int) $rule->fields['is_dynamic_recursive'] === 1
                            ? ' <span class="badge bg-azure-lt">' . __s('recursive') . '</span>' : ''),
                    default              => $e($rule->fields['field_name']) . ' = ' . $e($rule->fields['field_value']),
                };

                echo '<tr' . ((int) $rule->fields['is_active'] === 1 ? '' : " class='text-muted'") . '>';
                echo '<td>' . (int) $rule->fields['rank_order'] . '</td>';
                echo '<td><code>' . $e($rule->fields['claim']) . '</code></td>';
                echo '<td>' . $e(self::operators()[$rule->fields['match_operator']] ?? '')
                   . ' <strong>' . $e($rule->fields['match_value']) . '</strong></td>';
                echo '<td>' . $e(self::actions()[$rule->fields['action']] ?? '') . ': ' . $target . '</td>';
                echo '<td class="text-end">';
                if ($can) {
                    echo "<a class='btn btn-sm btn-ghost-secondary' href='" . $e(Url::to('front/mapping.form.php'))
                       . '?id=' . (int) $rule->getID() . "'><i class='ti ti-edit'></i></a>";
                }
                echo '</td></tr>';
            }

            echo '</tbody></table>';
        }

        if ($can) {
            echo "<a class='btn btn-primary' href='" . $e(Url::to('front/mapping.form.php'))
               . '?plugin_glpiidentity_sources_id=' . (int) $source->getID() . "'>"
               . "<i class='ti ti-plus me-1'></i>" . __s('Add a mapping', 'glpiidentity') . '</a>';
        }

        echo '</div>';
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);

        // Scope wrapper: this form is core-rendered, so without a plugin-owned
        // container the shipped dark-theme CSS could never reach its helper
        // text (see the dark section of the plugin stylesheet).
        echo "<div class='glpiidentity-scope'>";
        $this->showFormHeader($options);

        $e      = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $source = new Source();
        $source->getFromDB((int) $this->fields['plugin_glpiidentity_sources_id']);

        echo "<tr class='tab_bg_1'><td>" . __s('Identity source', 'glpiidentity') . '</td><td>';
        echo $e($source->fields['name'] ?? '');
        echo Html::hidden('plugin_glpiidentity_sources_id', [
            'value' => (int) $this->fields['plugin_glpiidentity_sources_id'],
        ]);
        echo '</td><td>' . __s('Active') . '</td><td>';
        Dropdown::showYesNo('is_active', $this->fields['is_active']);
        echo '</td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Claim', 'glpiidentity') . '</td><td>';
        echo Html::input('claim', ['value' => $this->fields['claim'], 'placeholder' => 'groups']);
        echo "<div class='form-text'>"
           . __s('The claim to look at. "groups" is what an IdP sends group membership in, and is '
               . 'also what SCIM group provisioning fills in.', 'glpiidentity')
           . '</div></td>';
        echo '<td>' . __s('Order', 'glpiidentity') . '</td><td>';
        echo "<input type='number' class='form-control' name='rank_order' value='"
           . $e($this->fields['rank_order']) . "'>";
        echo '</td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Condition', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('match_operator', self::operators(), [
            'value' => $this->fields['match_operator'],
        ]);
        echo '</td><td>' . __s('Value', 'glpiidentity') . '</td><td>';
        echo Html::input('match_value', ['value' => $this->fields['match_value'], 'size' => 40]);

        // The directory's own group names, so the value can be picked rather
        // than remembered. Only shown when there are some: an empty datalist is
        // a worse hint than none.
        $known = IdpGroup::forSource((int) $this->fields['plugin_glpiidentity_sources_id']);
        if ($known !== []) {
            echo "<div class='form-text'>" . __s('Seen from this directory: ', 'glpiidentity');
            $names = array_map(static fn(IdpGroup $g): string => (string) $g->fields['name'], $known);
            echo $e(implode(', ', array_slice($names, 0, 12)))
               . (count($names) > 12 ? ' …' : '');
            echo '</div>';
        }
        echo '</td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Then', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('action', self::actions(), ['value' => $this->fields['action']]);
        echo '</td><td colspan="2"></td></tr>';

        echo "<tr class='tab_bg_1'><td>" . Group::getTypeName(1) . '</td><td>';
        Group::dropdown([
            'name'   => 'groups_id',
            'value'  => $this->fields['groups_id'],
            'entity' => $source->fields['entities_id'] ?? 0,
            'condition' => ['is_usergroup' => 1],
        ]);
        echo "<div class='form-text'>" . __s('Used when the action is "Add to GLPI group".', 'glpiidentity')
           . '</div></td>';
        echo '<td>' . Profile::getTypeName(1) . '</td><td>';
        Profile::dropdown(['name' => 'profiles_id', 'value' => $this->fields['profiles_id']]);
        echo "<div class='form-text'>"
           . __s('Granted in the source\'s entity.', 'glpiidentity') . ' ';
        echo Html::getCheckbox([
            'name'    => 'is_dynamic_recursive',
            'checked' => (int) $this->fields['is_dynamic_recursive'] === 1,
            'value'   => 1,
        ]) . ' ' . __s('and its sub-entities', 'glpiidentity');
        echo '</div></td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('User field', 'glpiidentity') . '</td><td>';
        $choices = ['' => Dropdown::EMPTY_VALUE];
        foreach (self::assignableFields() as $name => $meta) {
            $choices[$name] = $meta['label'];
        }
        Dropdown::showFromArray('field_name', $choices, ['value' => $this->fields['field_name']]);
        echo '</td><td>' . __s('Value', 'glpiidentity') . '</td><td>';
        echo Html::input('field_value', ['value' => $this->fields['field_value'], 'size' => 30]);
        echo "<div class='form-text'>"
           . __s('For a dropdown field the value is matched by name, and created if it does not '
               . 'exist yet.', 'glpiidentity')
           . '</div></td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Comments') . "</td><td colspan='3'>";
        echo "<textarea class='form-control' name='comment' rows='2'>" . $e($this->fields['comment']) . '</textarea>';
        echo '</td></tr>';

        $this->showFormButtons($options);
        echo '</div>';

        return true;
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
    }
}
