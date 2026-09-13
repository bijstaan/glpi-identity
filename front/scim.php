<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The SCIM 2.0 endpoint.
 *
 * Reached as `/plugins/glpiidentity/front/scim.php/v2/...`, which is the base
 * URL an administrator pastes into an organisation's provisioning configuration.
 *
 * This script runs with GLPI's session check turned off — see the firewall
 * strategy registered in setup.php — because the caller is a directory holding
 * a bearer token and will never have a cookie. It authenticates before it does
 * anything else, and there is no path through {@see Server} that reaches data
 * without having resolved that token to exactly one source first.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\Scim\Request;
use GlpiPlugin\Glpiidentity\Scim\Response;
use GlpiPlugin\Glpiidentity\Scim\Server;

// No session is started, and none should be: a bearer-token API that set a
// cookie would be handing a session to every directory that talked to it, and
// GLPI's CSRF machinery would then have opinions about requests that have no
// browser behind them.
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

try {
    (new Server())->handle(Request::fromGlobals())->send();
} catch (\Throwable $e) {
    // The last resort. Anything escaping the server's own handler still has to
    // leave as SCIM, because a connector shown an HTML stack trace reports that
    // the URL is not a SCIM endpoint.
    trigger_error('glpiidentity: unhandled SCIM failure: ' . $e->getMessage(), E_USER_WARNING);
    Response::error(500, 'The request could not be processed.')->send();
}
