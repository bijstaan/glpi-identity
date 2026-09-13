<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Instance-wide settings.
 *
 * Deliberately short. Almost every decision this plugin makes is per-organisation
 * and lives on the source; what is here is the handful that is genuinely about
 * the instance — chiefly the master switch and whether the local password form
 * survives.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;

Session::checkRight('plugin_glpiidentity_source', READ);

if (!empty($_POST['update'])) {
    // No explicit Session::checkCSRF: GLPI 11's CheckCsrfListener validated and
    // consumed the token before this page ran, so a second check always fails.
    Session::checkRight('plugin_glpiidentity_source', UPDATE);

    Settings::save([
        'enabled'              => !empty($_POST['enabled']) ? '1' : '0',
        'allow_local_login'    => !empty($_POST['allow_local_login']) ? '1' : '0',
        'event_retention_days' => (int) ($_POST['event_retention_days'] ?? 180),
        'scim_max_results'     => (int) ($_POST['scim_max_results'] ?? 200),
    ]);

    Session::addMessageAfterRedirect(__s('Settings saved.', 'glpiidentity'));
    Html::back();
}

Html::header(__('Identity', 'glpiidentity'), $_SERVER['PHP_SELF'], 'config', 'plugins');

$cfg = Settings::all();
$e   = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

$sources = Source::all();
$sso     = array_filter($sources, static fn(Source $s): bool => $s->ssoReady());
$scim    = array_filter($sources, static fn(Source $s): bool => $s->scimReady());

// Read-only visitors keep the page but lose the button.
//
// READ opens this page and UPDATE saves it, and the two are separately
// grantable — so a profile can legitimately arrive here unable to change
// anything. Rendering the form as though they could, and answering Save with an
// access-denied page, wastes the work they just did explaining nothing.
$can_edit = Session::haveRight('plugin_glpiidentity_source', UPDATE);

echo "<div class='container-fluid glpiidentity-config' style='max-width:960px'>";

if (!$can_edit) {
    echo "<div class='alert alert-info py-2'>"
       . __s('Read only: you can see these settings but not change them.', 'glpiidentity')
       . '</div>';
}
echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);

// ------------------------------------------------------------------- status
$ready = Settings::flag('enabled') && ($sso !== [] || $scim !== []);
echo "<div class='alert " . ($ready ? 'alert-success' : 'alert-secondary') . " d-flex align-items-center'>";
echo "<i class='ti " . ($ready ? 'ti-circle-check' : 'ti-circle-dashed') . " me-2 fs-3'></i><div>";
echo '<strong>' . ($ready
    ? sprintf(
        __s('%1$d source(s) can sign people in, %2$d can accept provisioning.', 'glpiidentity'),
        count($sso),
        count($scim)
    )
    : __s('Identity federation is not active.', 'glpiidentity')) . '</strong>';
echo "<div class='small'>"
   . __s('Each organisation is configured as its own identity source, with its own entity, '
       . 'its own credentials and its own group mappings.', 'glpiidentity')
   . '</div>';
echo '</div></div>';

// ------------------------------------------------------------------ general
echo "<div class='card mb-3'><div class='card-header d-flex align-items-center'>";
echo "<h3 class='card-title mb-0'>" . __s('General', 'glpiidentity') . '</h3>';
echo "<a class='btn btn-sm btn-outline-secondary ms-auto' href='" . $e(Source::getSearchURL(false)) . "'>"
   . "<i class='ti ti-id-badge-2 me-1'></i>" . __s('Identity sources', 'glpiidentity') . '</a>';
echo '</div><div class="card-body">';

echo "<label class='form-check'>";
echo "<input type='checkbox' class='form-check-input' name='enabled' value='1' "
   . (((int) $cfg['enabled']) === 1 ? "checked='checked'" : '') . '>';
echo "<span class='form-check-label'>" . __s('Enable federated identity', 'glpiidentity') . '</span></label>';
echo "<div class='form-text mb-3'>"
   . __s('The master switch. Off, no sign-on button is shown and every SCIM request is answered '
       . 'with 503 — a status connectors retry rather than treating as a credential problem.', 'glpiidentity')
   . '</div>';

echo "<label class='form-check'>";
echo "<input type='checkbox' class='form-check-input' name='allow_local_login' value='1' "
   . (((int) $cfg['allow_local_login']) === 1 ? "checked='checked'" : '') . '>';
echo "<span class='form-check-label'>" . __s('Keep the username and password form', 'glpiidentity') . '</span></label>';
echo "<div class='form-text mb-3'>"
   . __s('Off, GLPI\'s own login controls are taken off the login page, leaving only single '
       . 'sign-on — but only while at least one identity source can actually sign somebody in, so '
       . 'a broken provider cannot lock everyone out. ', 'glpiidentity')
   . '<strong>'
   . __s('This changes the login page, not what GLPI accepts.', 'glpiidentity')
   . '</strong> '
   . __s('A password still works for any account that has one, and index.php?local=1 always shows '
       . 'the form — which is deliberate, because the configuration that fixes a broken identity '
       . 'provider lives inside the instance that provider is the only way into. Accounts this '
       . 'plugin provisions have no password at all, so they cannot be signed in that way '
       . 'regardless.', 'glpiidentity')
   . '</div>';

echo "<div class='row'>";
echo "<div class='col-md-6 mb-3'><label class='form-label'>"
   . __s('Keep identity events for (days)', 'glpiidentity') . '</label>';
echo "<input type='number' min='0' max='3650' class='form-control' name='event_retention_days' value='"
   . $e($cfg['event_retention_days']) . "'>";
echo "<div class='form-text'>"
   . __s('Who signed in and what was provisioned. Zero keeps them for ever.', 'glpiidentity')
   . '</div></div>';

echo "<div class='col-md-6 mb-3'><label class='form-label'>"
   . __s('Maximum SCIM results per page', 'glpiidentity') . '</label>';
echo "<input type='number' min='10' max='1000' class='form-control' name='scim_max_results' value='"
   . $e($cfg['scim_max_results']) . "'>";
echo "<div class='form-text'>"
   . __s('Advertised in ServiceProviderConfig, so connectors page to it rather than discovering it '
       . 'by being truncated.', 'glpiidentity')
   . '</div></div>';
echo '</div>';

echo '</div></div>';

// ------------------------------------------------------------------ sources
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
   . __s('Sources', 'glpiidentity') . '</h3></div><div class="card-body">';

if ($sources === []) {
    echo "<div class='text-muted'>"
       . __s('No identity sources yet. Add one per organisation.', 'glpiidentity')
       . '</div>';
} else {
    echo "<table class='table table-sm'><thead><tr>"
       . '<th>' . __s('Name') . '</th><th>' . __s('Entity') . '</th>'
       . '<th>' . __s('Sign-on', 'glpiidentity') . '</th>'
       . '<th>' . __s('Provisioning', 'glpiidentity') . '</th>'
       . '<th>' . __s('Domains', 'glpiidentity') . '</th></tr></thead><tbody>';

    foreach ($sources as $source) {
        $badge = static fn(bool $on, string $label): string => $on
            ? "<span class='badge bg-green-lt'>" . $label . '</span>'
            : "<span class='badge bg-secondary-lt'>" . __s('off') . '</span>';

        echo '<tr>';
        echo "<td><a href='" . $e($source->getFormURLWithID($source->getID())) . "'>"
           . $e($source->fields['name']) . '</a>'
           . ((int) $source->fields['is_default'] === 1
               ? " <span class='badge bg-blue-lt'>" . __s('house', 'glpiidentity') . '</span>' : '')
           . '</td>';
        echo '<td>' . $e(Dropdown::getDropdownName('glpi_entities', (int) $source->fields['entities_id'])) . '</td>';
        echo '<td>' . $badge($source->ssoReady(), __s('ready', 'glpiidentity')) . '</td>';
        echo '<td>' . $badge($source->scimReady(), __s('ready', 'glpiidentity')) . '</td>';
        echo '<td><small>' . $e(implode(', ', $source->domains())) . '</small></td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
}

echo '</div></div>';

echo "<div class='text-end mb-4'>";
if ($can_edit) {
    echo "<button type='submit' name='update' value='1' class='btn btn-primary'>" . __s('Save') . '</button>';
}
echo '</div>';
echo '</form>';

// ------------------------------------------------------------------- events
echo "<div class='card mb-4'><div class='card-header'><h3 class='card-title'>"
   . __s('Recent identity events', 'glpiidentity') . '</h3></div><div class="card-body">';

$events = EventLog::recent(25);

if ($events === []) {
    echo "<div class='text-muted'>" . __s('Nothing yet.', 'glpiidentity') . '</div>';
} else {
    echo "<table class='table table-sm'><tbody>";
    foreach ($events as $event) {
        echo '<tr' . ((int) $event['is_error'] === 1 ? " class='text-danger'" : '') . '>';
        echo '<td><small>' . $e(Html::convDateTime($event['date_creation'])) . '</small></td>';
        echo '<td><code>' . $e($event['event']) . '</code></td>';
        echo '<td>' . $e($event['subject']) . '</td>';
        echo '<td><small>' . $e(mb_substr((string) $event['detail'], 0, 160)) . '</small></td>';
        echo '</tr>';
    }
    echo '</tbody></table>';
}

echo '</div></div>';
echo '</div>';

Html::footer();
