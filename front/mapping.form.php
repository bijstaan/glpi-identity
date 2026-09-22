<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * One mapping rule, belonging to a source.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\Mapper;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Source;

Session::checkRight('plugin_glpiidentity_source', READ);

$mapping = new Mapping();

$back = static function (int $sources_id): never {
    $source = new Source();
    Html::redirect(
        $source->getFormURLWithID($sources_id) . '&forcetab=' . urlencode(Mapping::class . '$1')
    );
};

if (!empty($_POST['add'])) {
    $mapping->check(-1, CREATE, $_POST);
    if ($mapping->add($_POST) === false) {
        Html::back();
    }
    $back((int) $_POST['plugin_glpiidentity_sources_id']);
} elseif (!empty($_POST['update'])) {
    $mapping->check($_POST['id'], UPDATE);
    $mapping->update($_POST);
    $back((int) $_POST['plugin_glpiidentity_sources_id']);
} elseif (!empty($_POST['reapply'])) {
    $source = new Source();
    $source->check((int) $_POST['plugin_glpiidentity_sources_id'], UPDATE);
    $result = Mapper::applyToSource($source);
    if ($result['refused'] !== null) {
        Session::addMessageAfterRedirect(htmlspecialchars($result['refused']), false, WARNING);
    } else {
        Session::addMessageAfterRedirect(sprintf(
            __s('Mappings applied to %1$d directory-managed account(s); %2$d changed.', 'glpiidentity'),
            $result['users'],
            $result['changed']
        ));
    }
    $back((int) $source->getID());
} elseif (!empty($_POST['purge'])) {
    $mapping->check($_POST['id'], PURGE);
    $sources_id = (int) $mapping->fields['plugin_glpiidentity_sources_id'];
    $mapping->delete($_POST, true);
    $back($sources_id);
}

Html::header(
    Mapping::getTypeName(1),
    $_SERVER['PHP_SELF'],
    'admin',
    Source::class
);

// A new rule may arrive pre-filled from the Directory groups tab's "Map" link.
$mapping->display(array_filter([
    'id'                             => (int) ($_GET['id'] ?? -1),
    'plugin_glpiidentity_sources_id' => (int) ($_GET['plugin_glpiidentity_sources_id'] ?? 0),
    'match_value'                    => isset($_GET['match_value']) ? (string) $_GET['match_value'] : null,
    'action'                         => isset($_GET['action']) && array_key_exists((string) $_GET['action'], Mapping::actions())
        ? (string) $_GET['action'] : null,
], static fn($v): bool => $v !== null));

Html::footer();
