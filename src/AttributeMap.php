<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBChild;
use Dropdown;
use Html;

/**
 * One GLPI user field, filled from whatever the directory said about *this*
 * person.
 *
 * A {@see Mapping} answers "who is this person" — group membership, coarse and
 * shared, the same answer for everyone in the group. It sets a field to a
 * constant, which is the right shape for a location or a category and the wrong
 * shape for a phone number: expressing those as rules would need one rule per
 * employee.
 *
 * This answers the other question, "what do we know about them", by copying a
 * value across. A row names a GLPI field and where its value comes from:
 *
 *   Phone           ← phoneNumbers[type eq "work"].value   (SCIM)
 *                   ← phone_number                         (an id token claim)
 *
 * Both sides may be filled in, and usually are — the same GLPI field is fed by
 * SCIM when a connector pushes an update and by the id token when the person
 * signs in, and the two vocabularies name it differently. Whichever key is
 * present in the bag for a given run is the one used.
 *
 * **One row per field.** A GLPI field has one source of truth, so the form
 * refuses a second row for a field this source already fills, and refuses a row
 * for a field a static {@see Mapping} on the same source already sets. That
 * removes the precedence question rather than answering it: two things writing
 * one field, with a documented winner, is a configuration nobody can read off
 * the screen.
 *
 * **Absent is not empty.** A key missing from the bag leaves the field alone; a
 * key present and empty clears it. This matters because connectors do not agree
 * on how to say "this person has no phone number" — Entra omits null attributes
 * entirely rather than sending them empty, so treating missing as "clear it"
 * would wipe a field every time a cycle happened not to carry it.
 *
 * **The directory wins.** A value copied here overwrites whatever is in GLPI,
 * on every sign-in and every SCIM update, including an edit an administrator
 * made by hand. That is the point of a pass-through and it is worth being
 * deliberate about: a field listed here should be one the directory owns.
 * Unlike a profile or a group grant there is no `is_dynamic` marker to tell the
 * two apart afterwards, so the only way to keep a field editable in GLPI is not
 * to map it.
 *
 * The allowlist is {@see Mapping::assignableFields()}, shared and unchanged —
 * it is what keeps any of this from reaching `authtype`, `password`,
 * `is_active` or `profiles_id`, and a second copy of it would be a second thing
 * to get wrong.
 */
class AttributeMap extends CommonDBChild
{
    public static $itemtype = Source::class;
    public static $items_id = 'plugin_glpiidentity_sources_id';

    public static $rightname = 'plugin_glpiidentity_source';

    public $dohistory = true;

    public static function getTypeName($nb = 0)
    {
        return _n('Attribute map', 'Attribute maps', $nb, 'glpiidentity');
    }

    public static function getIcon()
    {
        return 'ti ti-arrows-exchange';
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
                'field_name'
            ) as $row
        ) {
            $map         = new self();
            $map->fields = $row;
            $out[]       = $map;
        }

        return $out;
    }

    /**
     * The fields this source fills by pass-through, and what to put in them.
     *
     * Reads the same bag the rules match on, so a SCIM path and an id token
     * claim are looked up the same way: at SCIM time the bag is keyed by
     * flattened attribute paths, at sign-in by claim names, and a row that
     * names both is served by whichever run it is.
     *
     * A key that is absent produces no entry at all, which is what leaves the
     * field alone — see the class docblock on why that is not the same as
     * clearing it.
     *
     * @param array<string,string[]> $claims
     * @return array<string,string> field name => value to write
     */
    public static function valuesFrom(Source $source, array $claims): array
    {
        $out = [];

        foreach (self::forSource($source->getID()) as $map) {
            if ((int) $map->fields['is_active'] !== 1) {
                continue;
            }

            $field = (string) $map->fields['field_name'];
            if (!array_key_exists($field, Mapping::assignableFields())) {
                // A field that has since left the allowlist. Skipped rather
                // than written: setFields() would drop it anyway, and this way
                // the reason is here rather than two files away.
                continue;
            }

            foreach ([(string) $map->fields['scim_path'], (string) $map->fields['claim']] as $key) {
                if ($key === '' || !array_key_exists($key, $claims)) {
                    continue;
                }

                $values      = $claims[$key];
                $out[$field] = is_array($values) ? (string) ($values[0] ?? '') : (string) $values;

                // The first key that is present wins, and only one of the two
                // ever is: a SCIM run carries no claim names and a sign-in
                // carries no SCIM paths.
                continue 2;
            }
        }

        return $out;
    }

    /**
     * The fields a static mapping on this source already writes.
     *
     * Inactive rules count. A disabled rule is one someone can re-enable, and
     * discovering the clash at that point — silently, as a field that stops
     * following the directory — is exactly what refusing the overlap is for.
     *
     * @return array<string,true>
     */
    public static function fieldsSetByRules(int $sources_id, int $ignore_id = 0): array
    {
        $out = [];
        foreach (Mapping::forSource($sources_id) as $rule) {
            if ((string) $rule->fields['action'] !== Mapping::ACTION_FIELD) {
                continue;
            }
            if ((int) $rule->getID() === $ignore_id) {
                continue;
            }

            $field = (string) $rule->fields['field_name'];
            if ($field !== '') {
                $out[$field] = true;
            }
        }

        return $out;
    }

    /**
     * The fields a pass-through on this source already fills.
     *
     * @return array<string,true>
     */
    public static function fieldsSetByMaps(int $sources_id, int $ignore_id = 0): array
    {
        $out = [];
        foreach (self::forSource($sources_id) as $map) {
            if ((int) $map->getID() === $ignore_id) {
                continue;
            }

            $field = (string) $map->fields['field_name'];
            if ($field !== '') {
                $out[$field] = true;
            }
        }

        return $out;
    }

    public function prepareInputForAdd($input)
    {
        return $this->validate($input, 0);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->validate($input, (int) $this->getID());
    }

    /**
     * Refuse a row that cannot do anything, and one that fights another.
     *
     * @return array<string,mixed>|false
     */
    private function validate(array $input, int $self_id): array|false
    {
        $refuse = static function (string $message): false {
            \Session::addMessageAfterRedirect(Html::entities_deep($message), false, ERROR);

            return false;
        };

        $sources_id = (int) ($input['plugin_glpiidentity_sources_id']
            ?? $this->fields['plugin_glpiidentity_sources_id'] ?? 0);
        if ($sources_id <= 0) {
            return $refuse(__('This attribute map has no identity source.', 'glpiidentity'));
        }

        $field = (string) ($input['field_name'] ?? $this->fields['field_name'] ?? '');
        if (!array_key_exists($field, Mapping::assignableFields())) {
            return $refuse(__('That user field cannot be set from a directory attribute.', 'glpiidentity'));
        }

        // A row naming neither a SCIM path nor a claim looks configured and
        // does nothing, which is the failure this plugin refuses everywhere.
        $scim  = trim((string) ($input['scim_path'] ?? $this->fields['scim_path'] ?? ''));
        $claim = trim((string) ($input['claim'] ?? $this->fields['claim'] ?? ''));
        if ($scim === '' && $claim === '') {
            return $refuse(__('Give a SCIM attribute path, an id token claim, or both — '
                . 'otherwise there is nothing to copy.', 'glpiidentity'));
        }

        $label = Mapping::assignableFields()[$field]['label'];

        if (isset(self::fieldsSetByMaps($sources_id, $self_id)[$field])) {
            return $refuse(sprintf(
                __('This source already fills "%s" from a directory attribute. A field has one '
                    . 'source of truth; edit that map instead.', 'glpiidentity'),
                $label
            ));
        }

        // The overlap the two halves must never have. A static rule setting the
        // same field would mean a constant and a copied value both writing it,
        // and which one an administrator got would depend on order they cannot
        // see.
        if (isset(self::fieldsSetByRules($sources_id)[$field])) {
            return $refuse(sprintf(
                __('A mapping rule on this source already sets "%s" to a fixed value. Remove that '
                    . 'rule first, or choose another field.', 'glpiidentity'),
                $label
            ));
        }

        $input['scim_path'] = $scim;
        $input['claim']     = $claim;

        return $input;
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
        $e    = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $maps = self::forSource($source->getID());
        $can  = $source->canUpdateItem();

        echo "<div class='glpiidentity-attributemaps'>";

        echo '<p class="text-muted">'
           . __s('Each row copies one directory attribute into one GLPI field, for every user of '
               . 'this source. The value overwrites what is in GLPI, including an edit made by '
               . 'hand — map only fields the directory owns.', 'glpiidentity')
           . '</p>';

        if ($maps === []) {
            echo "<div class='alert alert-secondary'>"
               . __s('No attribute maps yet. Names, email addresses and the active flag are '
                   . 'provisioned anyway; this is for the rest.', 'glpiidentity')
               . '</div>';
        } else {
            $fields = Mapping::assignableFields();

            echo "<table class='table table-sm'><thead><tr>"
               . '<th>' . __s('GLPI field', 'glpiidentity') . '</th>'
               . '<th>' . __s('From SCIM', 'glpiidentity') . '</th>'
               . '<th>' . __s('From an id token claim', 'glpiidentity') . '</th>'
               . '<th></th></tr></thead><tbody>';

            foreach ($maps as $map) {
                $field = (string) $map->fields['field_name'];
                $none  = '<span class="text-muted">' . __s('—', 'glpiidentity') . '</span>';

                echo '<tr' . ((int) $map->fields['is_active'] === 1 ? '' : " class='text-muted'") . '>';
                echo '<td>' . $e($fields[$field]['label'] ?? $field) . '</td>';
                echo '<td>' . ((string) $map->fields['scim_path'] !== ''
                    ? '<code>' . $e($map->fields['scim_path']) . '</code>' : $none) . '</td>';
                echo '<td>' . ((string) $map->fields['claim'] !== ''
                    ? '<code>' . $e($map->fields['claim']) . '</code>' : $none) . '</td>';
                echo '<td class="text-end">';
                if ($can) {
                    echo "<a class='btn btn-sm btn-ghost-secondary' href='"
                       . $e(Url::to('front/attributemap.form.php'))
                       . '?id=' . (int) $map->getID() . "'><i class='ti ti-edit'></i></a>";
                }
                echo '</td></tr>';
            }

            echo '</tbody></table>';
        }

        if ($can) {
            echo "<a class='btn btn-primary' href='" . $e(Url::to('front/attributemap.form.php'))
               . '?plugin_glpiidentity_sources_id=' . (int) $source->getID() . "'>"
               . "<i class='ti ti-plus me-1'></i>" . __s('Add an attribute map', 'glpiidentity') . '</a>';
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

        // Only fields nothing else on this source already writes. Listing the
        // others and refusing them on save would be a form that can express
        // something the validator has to reject.
        $taken   = self::fieldsSetByRules((int) $this->fields['plugin_glpiidentity_sources_id'])
                 + self::fieldsSetByMaps(
                     (int) $this->fields['plugin_glpiidentity_sources_id'],
                     (int) $this->getID()
                 );
        $choices = ['' => Dropdown::EMPTY_VALUE];
        foreach (Mapping::assignableFields() as $name => $meta) {
            if (isset($taken[$name]) && $name !== (string) $this->fields['field_name']) {
                continue;
            }
            $choices[$name] = $meta['label'];
        }

        echo "<tr class='tab_bg_1'><td>" . __s('GLPI field', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('field_name', $choices, ['value' => $this->fields['field_name']]);
        echo "<div class='form-text'>"
           . __s('Fields already written by a mapping rule on this source are not listed: one '
               . 'field, one source of truth.', 'glpiidentity')
           . '</div></td><td colspan="2"></td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('SCIM attribute', 'glpiidentity') . '</td><td>';
        echo Html::input('scim_path', [
            'value'       => $this->fields['scim_path'],
            'size'        => 40,
            'placeholder' => 'phoneNumbers[type eq "work"].value',
        ]);
        echo "<div class='form-text'>"
           . __s('The attribute as the connector sends it. Multi-valued attributes are addressed '
               . 'by type, and an extension by its full urn.', 'glpiidentity')
           . '</div></td>';
        echo '<td>' . __s('Id token claim', 'glpiidentity') . '</td><td>';
        echo Html::input('claim', [
            'value'       => $this->fields['claim'],
            'size'        => 30,
            'placeholder' => 'phone_number',
        ]);
        echo "<div class='form-text'>"
           . __s('Used at sign-in, where the provider sends claims rather than SCIM attributes. '
               . 'Fill in either or both.', 'glpiidentity')
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
        $this->fields['is_active']  = 1;
        $this->fields['field_name'] = '';
        $this->fields['scim_path']  = '';
        $this->fields['claim']      = '';
    }
}
