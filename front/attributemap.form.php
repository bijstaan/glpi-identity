<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * One attribute map, belonging to a source.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\AttributeMap;
use GlpiPlugin\Glpiidentity\Source;

Session::checkRight('plugin_glpiidentity_source', READ);

$map = new AttributeMap();

$back = static function (int $sources_id): never {
    $source = new Source();
    Html::redirect(
        $source->getFormURLWithID($sources_id) . '&forcetab=' . urlencode(AttributeMap::class . '$1')
    );
};

if (!empty($_POST['add'])) {
    $map->check(-1, CREATE, $_POST);
    if ($map->add($_POST) === false) {
        // An overlap refusal lands here. Back to the form with the message,
        // rather than to the tab, so what was typed is still on screen.
        Html::back();
    }
    $back((int) $_POST['plugin_glpiidentity_sources_id']);
} elseif (!empty($_POST['update'])) {
    $map->check($_POST['id'], UPDATE);
    $map->update($_POST);
    $back((int) $_POST['plugin_glpiidentity_sources_id']);
} elseif (!empty($_POST['purge'])) {
    $map->check($_POST['id'], PURGE);
    $sources_id = (int) $map->fields['plugin_glpiidentity_sources_id'];
    $map->delete($_POST, true);
    $back($sources_id);
}

Html::header(
    AttributeMap::getTypeName(1),
    $_SERVER['PHP_SELF'],
    'admin',
    Source::class
);

$map->display([
    'id' => (int) ($_GET['id'] ?? -1),
    'plugin_glpiidentity_sources_id' => (int) ($_GET['plugin_glpiidentity_sources_id'] ?? 0),
]);

Html::footer();
