<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use Config;

/**
 * Plugin-wide configuration.
 *
 * Almost everything about this plugin is per-source, because almost everything
 * about it is per-organisation. What lives here is the small set of decisions that
 * are genuinely about the instance rather than about one organisation.
 */
final class Settings
{
    public const DEFAULTS = [
        // The master switch. Off on install: a plugin that started accepting
        // SCIM writes the moment it was enabled would be a nasty surprise.
        'enabled' => 0,

        // Keep GLPI's username-and-password form on the login page.
        //
        // On by default, and worth leaving on longer than feels necessary. The
        // configuration that fixes a broken identity provider lives inside the
        // instance the identity provider is the only way into.
        'allow_local_login' => 1,

        // Days of identity events to keep. These record who signed in and what
        // was provisioned, which is exactly the sort of log that is useless if
        // it is too short and a liability if it is kept for ever.
        'event_retention_days' => 180,

        // Ceiling on a SCIM list response, whatever the client asked for.
        'scim_max_results' => 200,
    ];

    /** @return array<string,mixed> */
    public static function all(): array
    {
        $stored = Config::getConfigurationValues(
            PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT,
            array_keys(self::DEFAULTS)
        );

        $out = [];
        foreach (self::DEFAULTS as $key => $default) {
            $value     = $stored[$key] ?? null;
            $out[$key] = ($value === null || $value === '')
                ? $default
                : (is_int($default) ? (int) $value : (string) $value);
        }

        $out['scim_max_results']     = max(10, min(1000, (int) $out['scim_max_results']));
        $out['event_retention_days'] = max(0, (int) $out['event_retention_days']);

        return $out;
    }

    public static function get(string $key): mixed
    {
        return self::all()[$key] ?? (self::DEFAULTS[$key] ?? null);
    }

    public static function flag(string $key): bool
    {
        return ((int) self::get($key)) === 1;
    }

    /** @param array<string,mixed> $values */
    public static function save(array $values): void
    {
        $filtered = array_intersect_key($values, self::DEFAULTS);
        if ($filtered !== []) {
            Config::setConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT, $filtered);
        }
    }

    /** Shown in place of a stored secret. Posting it back means "unchanged". */
    public const SECRET_PLACEHOLDER = '••••••••';
}
