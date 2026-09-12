<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * One identity source.
 *
 * Several buttons on this page do something rather than saving something —
 * refreshing the provider metadata, issuing a SCIM token, and the three on the
 * links tab that decide which accounts this source owns. All of them take
 * UPDATE rather than READ, because all of them act on what makes this source
 * able to sign somebody in.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\Link;
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
} elseif (!empty($_POST['prelink']) || !empty($_POST['prelink_all'])) {
    $source->check($_POST['id'], UPDATE);
    $source->getFromDB((int) $_POST['id']);

    // The candidate list is recomputed rather than trusted from the page, and
    // the posted selection is filtered through it. What the browser sent is a
    // statement about what was linkable when the tab was drawn; the ids that
    // may be acted on are the ones that are linkable now, in this source's
    // entity. Without the intersection, this button would link any user id in
    // the instance, which is not what the page offered.
    $linkable = array_column(Link::candidates($source, 10000), 'id');

    $wanted = !empty($_POST['prelink_all'])
        ? $linkable
        : array_map('intval', (array) ($_POST['users'] ?? []));

    $linked = 0;
    foreach (array_intersect($wanted, $linkable) as $users_id) {
        if (Link::invite($source, (int) $users_id)) {
            $linked++;
        }
    }

    Session::addMessageAfterRedirect(
        htmlspecialchars(sprintf(
            _n(
                '%d account linked. It is adopted the first time somebody signs in through this '
                    . 'provider with an address it already holds.',
                '%d accounts linked. Each is adopted the first time somebody signs in through this '
                    . 'provider with an address it already holds.',
                $linked,
                'glpiidentity'
            ),
            $linked
        )),
        false,
        $linked > 0 ? INFO : WARNING
    );
    Html::back();
} elseif (!empty($_POST['reopen']) || !empty($_POST['unlink'])) {
    $source->check($_POST['id'], UPDATE);
    $source->getFromDB((int) $_POST['id']);

    $reopening = !empty($_POST['reopen']);
    $link      = new Link();

    // Scoped to the source the right was checked against. A link id belonging
    // to another customer's source must not be reachable through this one, and
    // an id in a form field is not evidence of anything.
    if (
        !$link->getFromDB((int) ($_POST['reopen'] ?? $_POST['unlink']))
        || (int) $link->fields['plugin_glpiidentity_sources_id'] !== $source->getID()
    ) {
        Session::addMessageAfterRedirect(
            htmlspecialchars(__('That link does not belong to this source.', 'glpiidentity')),
            false,
            ERROR
        );
        Html::back();
    }

    $done = $reopening ? $link->reopen() : $link->disown();

    Session::addMessageAfterRedirect(
        htmlspecialchars($reopening
            ? __('The link is open again. The next sign-in that matches a verified address on that '
               . 'account will claim it.', 'glpiidentity')
            : __('The link is gone. This source no longer owns that account, and signing in '
               . 'through it will be refused.', 'glpiidentity')),
        false,
        $done ? INFO : WARNING
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
