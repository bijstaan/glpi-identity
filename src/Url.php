<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

/**
 * URLs for the plugin's own resources.
 *
 * GLPI 11 deprecated Plugin::getWebDir in favour of the plain `/plugins/` path,
 * but that path still has to be prefixed with root_doc so an installation in a
 * subdirectory works. Files under `public/` are served without that segment.
 */
final class Url
{
    public const KEY = 'glpiidentity';

    /** Root-relative, WITHOUT root_doc — what Html::css()/script() expect. */
    public static function path(string $path): string
    {
        return '/plugins/' . self::KEY . '/' . ltrim($path, '/');
    }

    /** Absolute, including root_doc — for anything fetched from JavaScript. */
    public static function to(string $path): string
    {
        global $CFG_GLPI;

        return rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . self::path($path);
    }

    /**
     * The path a request carried *after* one of this plugin's scripts.
     *
     * `$_SERVER['PATH_INFO']` is the obvious way to get this and is empty in
     * GLPI 11: every request goes through Symfony's front controller, so
     * SCRIPT_NAME is `/index.php` and the legacy script is `require`d without
     * PHP ever computing a path info. The information is still there — in
     * REQUEST_URI — it just has to be taken rather than asked for.
     *
     * PATH_INFO is still preferred when a server does set it, so a deployment
     * that reaches these scripts some other way keeps working.
     */
    public static function pathAfter(string $script): string
    {
        $explicit = (string) ($_SERVER['PATH_INFO'] ?? '');
        if ($explicit !== '') {
            return $explicit;
        }

        $uri = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
        $marker = '/front/' . ltrim($script, '/');

        $at = strpos($uri, $marker);
        if ($at === false) {
            return '';
        }

        return substr($uri, $at + strlen($marker));
    }

    /**
     * Fully-qualified, for a URL that leaves the browser and comes back.
     *
     * The OIDC redirect URI and the SCIM base URL are both registered in
     * somebody else's console, so they have to be absolute and they have to be
     * *exactly* what we will present later — an IdP compares the redirect URI
     * character for character. Built from GLPI's configured url_base rather
     * than from the incoming request, because the incoming request is
     * attacker-controlled and a redirect URI taken from it is an open redirect
     * waiting to be reported.
     */
    public static function absolute(string $path): string
    {
        global $CFG_GLPI;

        return rtrim((string) ($CFG_GLPI['url_base'] ?? ''), '/') . self::path($path);
    }
}
