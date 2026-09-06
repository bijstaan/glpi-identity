<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The identity sources — one per customer directory.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\Source;

Session::checkRight('plugin_glpiidentity_source', READ);

Html::header(
    Source::getTypeName(2),
    $_SERVER['PHP_SELF'],
    'admin',
    Source::class
);

Search::show(Source::class);

Html::footer();
