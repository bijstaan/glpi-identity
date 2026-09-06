<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

use GlpiPlugin\Glpiidentity\IdpGroup;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Source;
use GlpiPlugin\Glpiidentity\Url;
use User;
use UserEmail;

/**
 * A GLPI user, as SCIM sees it — and back again.
 *
 * The translation is small; the care is in what is *not* translated. A SCIM
 * User has fifty attributes and this exposes eight, because every one exposed
 * is one a customer's connector can overwrite, and the useful ones are few:
 * who they are, whether they still work there, and what to call them.
 */
final class UserResource
{
    /** @return array<string,mixed> */
    public static function toScim(Source $source, Link $link, User $user): array
    {
        $emails = [];
        foreach (
            getAllDataFromTable(UserEmail::getTable(), ['users_id' => $user->getID()]) as $row
        ) {
            $emails[] = array_filter([
                'value'   => (string) $row['email'],
                'type'    => 'work',
                'primary' => (bool) $row['is_default'] ?: null,
            ], static fn($v): bool => $v !== null);
        }

        $groups = [];
        foreach (IdpGroup::forSource($source->getID()) as $group) {
            if (in_array((int) $user->getID(), $group->memberIds(), true)) {
                $groups[] = [
                    'value'   => (string) $group->fields['external_id'],
                    'display' => (string) $group->fields['name'],
                    // Read-only per the spec: membership is changed on the
                    // group, not on the user, and a connector that is told
                    // otherwise will try.
                    'type'    => 'direct',
                ];
            }
        }

        $given  = (string) $user->fields['firstname'];
        $family = (string) $user->fields['realname'];

        return array_filter([
            'schemas'    => [Response::SCHEMA_USER],
            'id'         => (string) $link->fields['scim_id'],
            'externalId' => ((string) $link->fields['external_id']) ?: null,
            'userName'   => (string) $user->fields['name'],
            'name'       => array_filter([
                'givenName'  => $given ?: null,
                'familyName' => $family ?: null,
                'formatted'  => trim($given . ' ' . $family) ?: null,
            ]) ?: null,
            'displayName' => $user->getFriendlyName() ?: null,
            'emails'      => $emails ?: null,
            'active'      => (bool) $user->fields['is_active'] && !$user->fields['is_deleted'],
            'groups'      => $groups ?: null,
            'meta'        => array_filter([
                'resourceType' => 'User',
                'created'      => Response::timestamp($link->fields['date_creation'] ?? null),
                'lastModified' => Response::timestamp($user->fields['date_mod'] ?? null),
                'location'     => Url::absolute('front/scim.php/v2/Users/' . $link->fields['scim_id']),
            ]),
        ], static fn($v): bool => $v !== null);
    }

    /**
     * A SCIM payload, reduced to what provisioning needs.
     *
     * Tolerant on the way in, deliberately: connectors put the primary address
     * in different places, send `name` as an object or not at all, and disagree
     * about whether `active` is a boolean or the string "True".
     *
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public static function fromScim(array $payload): array
    {
        $person = [
            'userName'   => trim((string) ($payload['userName'] ?? '')),
            'externalId' => trim((string) ($payload['externalId'] ?? '')),
            'firstname'  => trim((string) ($payload['name']['givenName'] ?? '')),
            'lastname'   => trim((string) ($payload['name']['familyName'] ?? '')),
            'email'      => self::primaryEmail($payload),
        ];

        if (array_key_exists('active', $payload)) {
            $person['active'] = self::toBool($payload['active']);
        }

        return $person;
    }

    /**
     * The address to treat as theirs.
     *
     * Prefer the one flagged primary, then the first work address, then simply
     * the first — and fall back to `userName` when it is an address, which is
     * what Entra sends for accounts with no mailbox.
     *
     * @param array<string,mixed> $payload
     */
    private static function primaryEmail(array $payload): string
    {
        $emails = $payload['emails'] ?? [];

        if (is_array($emails)) {
            foreach ([true, false] as $want_primary) {
                foreach ($emails as $entry) {
                    if (!is_array($entry) || !isset($entry['value'])) {
                        continue;
                    }
                    if ($want_primary && !self::toBool($entry['primary'] ?? false)) {
                        continue;
                    }

                    return trim((string) $entry['value']);
                }
            }
        }

        $username = trim((string) ($payload['userName'] ?? ''));

        return filter_var($username, FILTER_VALIDATE_EMAIL) ? $username : '';
    }

    /** "True", "1", true and 1 all mean the same thing to a connector author. */
    public static function toBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_string($value)) {
            return in_array(strtolower(trim($value)), ['true', '1', 'yes'], true);
        }

        return (bool) $value;
    }

    /**
     * Every link this source owns, with its user loaded.
     *
     * Deliberately joined rather than looped: a customer with four thousand
     * people is not unusual, and a connector's first act is to list all of them.
     *
     * @return array<int,array{link:Link,user:User}>
     */
    public static function allFor(Source $source): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];

        foreach (
            $DB->request([
                'SELECT'     => ['l.*', 'u.id AS glpi_users_id'],
                'FROM'       => Link::getTable() . ' AS l',
                'INNER JOIN' => [
                    User::getTable() . ' AS u' => ['ON' => ['u' => 'id', 'l' => 'users_id']],
                ],
                'WHERE'      => ['l.plugin_glpiidentity_sources_id' => $source->getID()],
                'ORDER'      => 'l.id',
            ]) as $row
        ) {
            $user = new User();
            if (!$user->getFromDB((int) $row['users_id'])) {
                continue;
            }

            $link         = new Link();
            $link->fields = array_diff_key($row, ['glpi_users_id' => null]);

            $out[] = ['link' => $link, 'user' => $user];
        }

        return $out;
    }
}
