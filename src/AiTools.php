<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use GlpiPlugin\Glpiai\Tool;
use User;

/**
 * Sign-in and provisioning, offered to glpi-ai's assistant as tools.
 *
 * "They can't log in" is the single most common ticket a service desk
 * takes, and it is the one where a model was previously reduced to advice.
 * Every fact that answers it is in this plugin: which identity provider the
 * person belongs to, whether they were ever provisioned, whether the last
 * attempt was refused and why, and whether a whole organisation's SSO stopped
 * working at 09:04.
 *
 * Three tools, and they are the three shapes the question comes in:
 *
 *  - **`identity_status`** for one person — are they linked, are they active,
 *    what happened the last few times they tried.
 *  - **`identity_events`** for the estate — what has been failing, which is
 *    the difference between one person's password and an organisation's whole
 *    tenant being down.
 *  - **`identity_sources`** for the configuration behind both: which
 *    organisations have an identity provider at all, whether its discovery still
 *    resolves, when its directory last pushed anything, and how many people
 *    are attached to it. It is the tool that separates "this person's account
 *    is wrong" from "this organisation's connector stopped three weeks ago and
 *    nobody noticed" — and the second is invisible from a single user's
 *    record, which is where everybody looks first.
 *
 * **Read only, and this is the plugin where that matters most.** These tools
 * sit next to code that creates accounts, disables them and maps them into
 * profiles. A model that could provision would be a model that could grant
 * itself — or anybody — access to your GLPI, and no wording in a
 * description makes that safe. Deprovisioning is worse: it locks a real person
 * out of the system they raise tickets in.
 *
 * Both are gated on this plugin's own `plugin_glpiidentity_source` right,
 * which is the same gate its pages use. A first-line profile that does not
 * hold it does not get these tools at all — which is the correct answer, since
 * the event log carries denial reasons and IP addresses.
 */
final class AiTools
{
    /** Events returned by one call. */
    private const MAX_EVENTS = 25;

    /** Sign-in attempts shown against one person. */
    private const MAX_PER_USER = 8;

    /** @return Tool[] */
    public static function all(): array
    {
        return [self::status(), self::events(), self::sources()];
    }

    // -------------------------------------------------------------- one person

    private static function sources(): Tool
    {
        return new Tool(
            name: 'identity_sources',
            description: 'The identity providers configured here and the health of each: which '
                . 'entity they belong to, whether sign-in and SCIM provisioning are switched '
                . 'on, when discovery last succeeded or what error it is stuck on, when the '
                . 'directory last pushed a change, how many accounts are attached, and how many '
                . 'are waiting for their owner to sign in for the first time. Use it when more '
                . 'than one person at the same entity cannot log in, when nobody there has '
                . 'been provisioned lately, and before telling somebody to reset a password — a '
                . 'connector that stopped three weeks ago is not a password problem.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'sources_id' => [
                        'type'        => 'integer',
                        'description' => 'One provider, in detail.',
                    ],
                    'entities_id' => [
                        'type'        => 'integer',
                        'description' => 'Only providers belonging to this entity.',
                    ],
                ],
            ],
            handler: [self::class, 'runSources'],
            right: Source::$rightname,
            source: 'glpiidentity',
            pinned: false
        );
    }

    /**
     * @param array<string,mixed> $arguments
     * @return array<string,mixed>
     */
    public static function runSources(array $arguments = [], mixed $context = null): array
    {
        $one         = (int) ($arguments['sources_id'] ?? 0);
        $entities_id = array_key_exists('entities_id', $arguments)
            ? (int) $arguments['entities_id']
            : null;

        $rows = [];

        foreach (Source::all() as $source) {
            $id = (int) $source->fields['id'];

            if ($one > 0 && $id !== $one) {
                continue;
            }

            // Per row, and against the session rather than against the
            // argument: a source is an entity's, and the argument narrows what
            // is asked for without ever widening what may be seen.
            if (!\Session::haveAccessToEntity(
                (int) $source->fields['entities_id'],
                (bool) $source->fields['is_recursive']
            )) {
                continue;
            }

            if ($entities_id !== null && (int) $source->fields['entities_id'] !== $entities_id) {
                continue;
            }

            $rows[] = self::describeSource($source);
        }

        if ($rows === []) {
            return [
                'sources' => [],
                'note'    => $one > 0
                    ? 'No such identity provider, or it is not one you can see.'
                    : 'No identity provider is configured for you to see. Everybody here signs '
                        . 'in with a GLPI password, so a sign-in problem is a GLPI account '
                        . 'problem.',
            ];
        }

        $broken = array_filter($rows, static fn(array $r): bool => isset($r['discovery_error']));

        return [
            'sources' => $rows,
            'note'    => $broken !== []
                ? sprintf(
                    '%d provider(s) have a discovery error. Nobody on those can sign in with '
                    . 'SSO until it clears, however correct their password is.',
                    count($broken)
                )
                : 'A provider with SSO off is configured but not in use; one with SCIM off is '
                    . 'not being kept in step with its directory, so accounts there are '
                    . 'maintained by hand.',
        ];
    }

    /** @return array<string,mixed> */
    private static function describeSource(Source $source): array
    {
        $id    = (int) $source->fields['id'];
        $links = Link::forSource($id);

        $signed_in = 0;
        foreach ($links as $link) {
            if ((string) $link->fields['subject'] !== '') {
                $signed_in++;
            }
        }

        $denials = 0;
        foreach (EventLog::recent(self::MAX_EVENTS * 4, $id) as $event) {
            if (in_array(
                (string) $event['event'],
                [EventLog::SSO_DENIED, EventLog::SCIM_DENIED],
                true
            )) {
                $denials++;
            }
        }

        return array_filter([
            'id'       => $id,
            'name'     => (string) $source->fields['name'],
            'entity'   => (string) \Dropdown::getDropdownName(
                'glpi_entities',
                (int) $source->fields['entities_id']
            ),
            'active'   => (bool) $source->fields['is_active'],
            'sso'      => (bool) $source->fields['sso_enabled'],
            'scim'     => (bool) $source->fields['scim_enabled'],
            'issuer'   => (string) ($source->fields['issuer'] ?? ''),
            'discovery_last_ok' => (string) ($source->fields['date_lastdiscovery'] ?? '') ?: null,
            // Only when there is one. An empty string here would read as "the
            // error is blank" rather than as "nothing is wrong".
            'discovery_error'   => trim((string) ($source->fields['discovery_error'] ?? '')) ?: null,
            'scim_last_seen'    => (string) ($source->fields['date_lastscim'] ?? '') ?: null,
            'accounts'          => count($links),
            'never_signed_in'   => count($links) - $signed_in,
            'recent_denials'    => $denials ?: null,
            'provisions_on_first_login' => (bool) ($source->fields['jit_provision'] ?? 0),
        ], static fn($v): bool => $v !== null && $v !== '');
    }

    private static function status(): Tool
    {
        return new Tool(
            name: 'identity_status',
            description: 'Why one person can or cannot sign in: which identity provider they '
                . 'belong to, whether their account is linked and active, when they last signed '
                . 'in, and what happened on their recent attempts including the reason for any '
                . 'refusal. Reach for this before suggesting a password reset — an account that '
                . 'was never provisioned, was deactivated by the organisation\'s own directory, or '
                . 'is being refused by a mapping rule looks identical to a forgotten password '
                . 'from the outside.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'users_id' => [
                        'type'        => 'integer',
                        'description' => 'The GLPI user id, as read_user or a ticket gives it.',
                    ],
                    'query'    => [
                        'type'        => 'string',
                        'description' => 'A login or email address, when there is no id to hand.',
                    ],
                ],
            ],
            handler: [self::class, 'runStatus'],
            right: Source::$rightname,
            source: 'glpiidentity',
            // Found rather than declared: "they cannot sign in" is a whole
            // ticket rather than a passing question, so the model has every
            // reason to go looking, and most conversations are not about
            // logging in.
            pinned: false
        );
    }

    /**
     * @param array<string,mixed> $arguments
     * @return array<string,mixed>
     */
    public static function runStatus(array $arguments = [], mixed $context = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $user = self::person($arguments);
        if ($user === null) {
            return ['error' => 'No such person is visible to you. Give users_id, or a login or '
                . 'email address that matches one.'];
        }

        $users_id = (int) $user->getID();

        $links = [];
        foreach (Link::allForUser($users_id) as $link) {
            $source = new Source();
            $sources_id = (int) ($link->fields['plugin_glpiidentity_sources_id'] ?? 0);

            $links[] = array_filter([
                'provider'    => $source->getFromDB($sources_id) ? (string) $source->fields['name'] : '',
                'subject'     => (string) ($link->fields['subject'] ?? ''),
                'external_id' => (string) ($link->fields['external_id'] ?? ''),
                'scim_id'     => (string) ($link->fields['scim_id'] ?? ''),
                'linked_on'   => (string) ($link->fields['date_creation'] ?? ''),
            ], static fn($v): bool => $v !== '');
        }

        $events = [];
        foreach (
            $DB->request([
                'FROM'  => EventLog::TABLE,
                'WHERE' => ['users_id' => $users_id],
                'ORDER' => 'id DESC',
                'LIMIT' => self::MAX_PER_USER,
            ]) as $row
        ) {
            $events[] = array_filter([
                'when'   => (string) $row['date_creation'],
                'event'  => (string) $row['event'],
                'failed' => (bool) $row['is_error'],
                'detail' => mb_substr(trim((string) ($row['detail'] ?? '')), 0, 300),
            ], static fn($v): bool => $v !== null && $v !== '' && $v !== false);
        }

        return array_filter([
            'user' => [
                'id'         => $users_id,
                'login'      => (string) $user->fields['name'],
                // The first thing to check and the easiest to miss: a GLPI
                // account that is switched off refuses every sign-in no matter
                // how healthy the identity provider is.
                'is_active'  => (bool) $user->fields['is_active'],
                'last_login' => (string) ($user->fields['last_login'] ?? ''),
            ],
            'identities' => $links,
            'recent'     => $events,
            'note'       => self::diagnose($user, $links, $events),
        ], static fn($v): bool => $v !== null && $v !== []);
    }

    /**
     * The one-line reading of the three facts above.
     *
     * Written here rather than left to the model because the combination is
     * what means something, and getting it wrong sends somebody to reset a
     * password on an account that is disabled.
     *
     * @param array<int,array<string,mixed>> $links
     * @param array<int,array<string,mixed>> $events
     */
    private static function diagnose(User $user, array $links, array $events): string
    {
        if (!(bool) $user->fields['is_active']) {
            return 'Their GLPI account is disabled. Nothing about the identity provider will '
                 . 'change that, and re-enabling it is a decision, not a fix.';
        }

        if ($links === []) {
            return 'They have no identity link, so they have never signed in through a provider '
                 . 'here — either they were never provisioned, or they sign in with a local '
                 . 'password.';
        }

        $last = $events[0] ?? null;
        if (is_array($last) && !empty($last['failed'])) {
            return sprintf(
                'Their most recent attempt failed (%s). The detail on it is the actual reason; '
                . 'read it before suggesting anything.',
                (string) $last['event']
            );
        }

        return 'Linked and active, and the last recorded attempt did not fail. If they still '
             . 'cannot get in, the problem is more likely their side of the provider than this '
             . 'one.';
    }

    // --------------------------------------------------------------- the estate

    private static function events(): Tool
    {
        return new Tool(
            name: 'identity_events',
            description: 'Recent sign-in and provisioning activity across the identity '
                . 'providers: successful logins, refusals with their reason, accounts created or '
                . 'deactivated by an organisation\'s directory, and group syncs. Use it when more than '
                . 'one person cannot get in — a run of refusals at the same minute is a tenant '
                . 'problem and not eleven forgotten passwords — and after an organisation changes '
                . 'something at their end.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'errors_only' => [
                        'type'        => 'boolean',
                        'description' => 'Only refusals and failures. Defaults to true, which is '
                            . 'almost always what the question is.',
                    ],
                    'limit'       => [
                        'type'        => 'integer',
                        'description' => 'Events to return, 1-25. Defaults to 15.',
                    ],
                ],
            ],
            handler: [self::class, 'runEvents'],
            right: Source::$rightname,
            source: 'glpiidentity',
            pinned: false
        );
    }

    /**
     * @param array<string,mixed> $arguments
     * @return array<string,mixed>
     */
    public static function runEvents(array $arguments = [], mixed $context = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $errors_only = ($arguments['errors_only'] ?? true) !== false;
        $limit       = max(1, min(self::MAX_EVENTS, (int) ($arguments['limit'] ?? 15)));

        $where = $errors_only ? ['is_error' => 1] : [];

        $sources = [];
        $out     = [];

        foreach (
            $DB->request([
                'FROM'  => EventLog::TABLE,
                'WHERE' => $where,
                'ORDER' => 'id DESC',
                'LIMIT' => $limit,
            ]) as $row
        ) {
            $sources_id = (int) $row['plugin_glpiidentity_sources_id'];

            if (!array_key_exists($sources_id, $sources)) {
                $source              = new Source();
                $sources[$sources_id] = $source->getFromDB($sources_id)
                    ? (string) $source->fields['name']
                    : '';
            }

            $out[] = array_filter([
                'when'     => (string) $row['date_creation'],
                'event'    => (string) $row['event'],
                'failed'   => (bool) $row['is_error'],
                'provider' => $sources[$sources_id],
                // The subject rather than the GLPI user, because the
                // interesting failures are the ones where no GLPI user exists
                // yet — a provisioning refusal has a subject and no account.
                'subject'  => mb_substr((string) ($row['subject'] ?? ''), 0, 120),
                'detail'   => mb_substr(trim((string) ($row['detail'] ?? '')), 0, 300),
            ], static fn($v): bool => $v !== null && $v !== '' && $v !== false);
        }

        return [
            'count'  => count($out),
            'events' => $out,
            'note'   => $out === []
                ? ($errors_only
                    ? 'Nothing has failed recently. Ask again with errors_only false to see what '
                      . 'has been happening at all.'
                    : 'Nothing has been recorded. Either no provider is configured here, or '
                      . 'nobody has signed in through one.')
                : 'Several failures at the same minute point at the provider or a mapping rule '
                  . 'rather than at the people.',
        ];
    }

    // --------------------------------------------------------------- shared

    /** @param array<string,mixed> $arguments */
    private static function person(array $arguments): ?User
    {
        $users_id = (int) ($arguments['users_id'] ?? 0);
        $user     = new User();

        if ($users_id > 0) {
            return $user->getFromDB($users_id) && $user->can($users_id, READ) ? $user : null;
        }

        $query = trim((string) ($arguments['query'] ?? ''));
        if ($query === '') {
            return null;
        }

        // Login first, then email. Both are exact: this is a lookup for a
        // person somebody already named, not a search, and a fuzzy match here
        // would answer about the wrong account with total confidence.
        if ($user->getFromDBbyName($query)) {
            return $user->can((int) $user->getID(), READ) ? $user : null;
        }

        $found = $user->getFromDBbyEmail($query);

        return $found && $user->can((int) $user->getID(), READ) ? $user : null;
    }
}
