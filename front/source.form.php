<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * One identity source.
 *
 * Two buttons on this form do something rather than saving something —
 * refreshing the provider metadata, and issuing a SCIM token — and both take
 * UPDATE rather than READ, because both act on the credentials that make this
 * source work.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\Source;

Session::checkRight('plugin_glpiidentity_source', READ);

$source = new Source();

if (!empty($_POST['add'])) {
    $source->check(-1, CREATE, $_POST);
    $newid = $source->add($_POST);

    // Back to the form on a rejection: a refused add has already queued the
    // reason as a message, and redirecting to an id that does not exist renders
    // an error page that swallows it.
    if ($newid === false) {
        Html::back();
    }

    Html::redirect($source->getFormURLWithID($newid));
} elseif (!empty($_POST['update'])) {
    $source->check($_POST['id'], UPDATE);
    $source->update($_POST);
    Html::back();
} elseif (!empty($_POST['purge'])) {
    $source->check($_POST['id'], PURGE);
    $source->delete($_POST, true);
    $source->redirectToList();
} elseif (!empty($_POST['discover'])) {
    $source->check($_POST['id'], UPDATE);
    $source->getFromDB((int) $_POST['id']);
    $result = $source->discover();

    Session::addMessageAfterRedirect(
        htmlspecialchars($result['message']),
        false,
        $result['ok'] ? INFO : ERROR
    );
    Html::back();
} elseif (!empty($_POST['rotate_token'])) {
    $source->check($_POST['id'], UPDATE);
    $source->getFromDB((int) $_POST['id']);
    $token = $source->rotateScimToken();

    // The only time this value is ever displayed. Shown as a message rather
    // than stored anywhere, because storing it is precisely what the design
    // avoids.
    Session::addMessageAfterRedirect(
        sprintf(
            __s('New SCIM bearer token — copy it now, it will not be shown again: %s', 'glpiidentity'),
            '<code>' . htmlspecialchars($token) . '</code>'
        ),
        false,
        INFO
    );
    Html::back();
}

// GLPI derives the itemtype from the URL as `pluginglpiidentitysource`, which
// does not resolve to a namespaced plugin class — so forcetab is dropped and
// both GLPI's own tab links and every post-edit redirect land on the wrong tab.
// The same fix core applies in front/knowbaseitem.php.
if (isset($_GET['forcetab'])) {
    Session::setActiveTab(Source::class, $_GET['forcetab']);
}

Html::header(
    Source::getTypeName(1),
    $_SERVER['PHP_SELF'],
    'admin',
    Source::class
);

$source->display(['id' => (int) ($_GET['id'] ?? -1)]);

Html::footer();
