<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use Auth;
use User;
use UserEmail;

/**
 * Creating, updating and retiring GLPI users on a directory's behalf.
 *
 * The one rule that governs everything here: **never take over an account this
 * source does not already own.** A directory saying "I have a user called
 * jsmith" is not evidence that the existing GLPI user jsmith is theirs — it may
 * be another organisation's person, or an administrator. So a username that is
 * already taken by somebody outside this source is a conflict reported back to
 * the connector, not an account silently adopted.
 *
 * That is the difference between multi-tenant provisioning and a privilege
 * escalation with a REST API in front of it.
 */
final class Provisioning
{
    /**
     * A conflict, so the SCIM layer can answer 409 and the OIDC layer can
     * refuse the sign-in, from one piece of logic that decides it.
     */
    public const CONFLICT = 'conflict';

    /**
     * Create or update a GLPI user from a directory's description of them.
     *
     * @param array{userName:string,externalId?:string,email?:string,firstname?:string,lastname?:string,active?:bool,subject?:string} $person
     * @return array{link:?Link,created:bool,error:?string}
     */
    public static function upsert(Source $source, array $person): array
    {
        $username = trim((string) ($person['userName'] ?? ''));
        if ($username === '') {
            return ['link' => null, 'created' => false, 'error' => 'userName is required.'];
        }

        $link = self::locate($source, $person);

        if ($link !== null) {
            $user = $link->user();
            if ($user === null) {
                // The link outlived the user it pointed at — a purge, most
                // likely. Drop the stale link and provision afresh rather than
                // failing for ever on a row nobody can see.
                $link->delete(['id' => $link->getID()], true);
                $link = null;
            }
        }

        if ($link !== null) {
            return self::updateExisting($source, $link, $person);
        }

        return self::createNew($source, $person, $username);
    }

    /**
     * Find this person's existing link, by the strongest evidence available.
     *
     * Order matters, and email is deliberately absent from it. The directory's
     * own identifiers are stable and unambiguous; an address is neither, and a
     * lookup by address is how one organisation's directory ends up owning another
     * organisation's account.
     */
    private static function locate(Source $source, array $person): ?Link
    {
        $sources_id = $source->getID();

        foreach (
            [
                Link::forExternalId($sources_id, (string) ($person['externalId'] ?? '')),
                Link::forSubject($sources_id, (string) ($person['subject'] ?? '')),
            ] as $candidate
        ) {
            if ($candidate !== null) {
                return $candidate;
            }
        }

        // Last resort: a GLPI user with this login that this source already
        // owns. Scoped through the link table, so a login belonging to another
        // source or to nobody is not a match.
        $user = new User();
        if ($user->getFromDBbyName((string) ($person['userName'] ?? ''))) {
            return Link::forUser($sources_id, (int) $user->getID());
        }

        return null;
    }

    /** @return array{link:?Link,created:bool,error:?string} */
    private static function createNew(Source $source, array $person, string $username): array
    {
        // The collision check that makes this safe to expose to an outside directory.
        $existing = new User();
        if ($existing->getFromDBbyName($username)) {
            EventLog::record(EventLog::SCIM_DENIED, $source, [
                'error'   => true,
                'subject' => $username,
                'detail'  => 'A GLPI user with this login already exists and does not belong to this source.',
            ]);

            return [
                'link'    => null,
                'created' => false,
                'error'   => self::CONFLICT,
            ];
        }

        $user   = new User();
        $fields = [
            'name'        => $username,
            'entities_id' => (int) $source->fields['entities_id'],
            // Authenticated elsewhere, and with no password of their own: a
            // provisioned account that could also be signed into with a
            // password would be a way around the directory that provisioned it.
            'authtype'    => Auth::EXTERNAL,
            'auths_id'    => 0,
            'is_active'   => ($person['active'] ?? true) ? 1 : 0,
            'firstname'   => (string) ($person['firstname'] ?? ''),
            'realname'    => (string) ($person['lastname'] ?? ''),
            '_no_history' => false,
        ];

        $users_id = (int) $user->add($fields);
        if ($users_id <= 0) {
            return ['link' => null, 'created' => false, 'error' => 'GLPI refused to create the user.'];
        }

        $user->getFromDB($users_id);
        self::syncEmail($user, (string) ($person['email'] ?? ''));

        $link = Link::attach($source->getID(), $users_id, [
            'external_id'     => (string) ($person['externalId'] ?? ''),
            'subject'         => (string) ($person['subject'] ?? ''),
            'is_scim_managed' => !empty($person['externalId']) ? 1 : 0,
        ]);

        EventLog::record(EventLog::SCIM_CREATE, $source, [
            'users_id' => $users_id,
            'subject'  => $username,
            'detail'   => 'Created from the directory.',
        ]);

        return ['link' => $link, 'created' => true, 'error' => null];
    }

    /** @return array{link:?Link,created:bool,error:?string} */
    private static function updateExisting(Source $source, Link $link, array $person): array
    {
        $user = $link->user();
        if ($user === null) {
            return ['link' => null, 'created' => false, 'error' => 'The linked user has gone.'];
        }

        $update = [];

        // The login can change — people marry, companies rebrand — but only to
        // one nobody else is using, and never onto an account owned elsewhere.
        $username = trim((string) ($person['userName'] ?? ''));
        if ($username !== '' && $username !== (string) $user->fields['name']) {
            $clash = new User();
            if ($clash->getFromDBbyName($username) && (int) $clash->getID() !== (int) $user->getID()) {
                return ['link' => null, 'created' => false, 'error' => self::CONFLICT];
            }
            $update['name'] = $username;
        }

        foreach (
            [
                'firstname' => (string) ($person['firstname'] ?? ''),
                'realname'  => (string) ($person['lastname'] ?? ''),
            ] as $field => $value
        ) {
            // An absent name in the payload means "not mentioned", not "clear
            // it". A connector that only sends changed attributes would
            // otherwise blank out everything it did not repeat.
            if ($value !== '' && $value !== (string) $user->fields[$field]) {
                $update[$field] = $value;
            }
        }

        if (array_key_exists('active', $person)) {
            $active = $person['active'] ? 1 : 0;
            if ((int) $user->fields['is_active'] !== $active) {
                $update['is_active'] = $active;
            }
        }

        if ($update !== []) {
            $user->update(['id' => $user->getID()] + $update);
            $user->getFromDB($user->getID());
        }

        if (!empty($person['email'])) {
            self::syncEmail($user, (string) $person['email']);
        }

        $link->update([
            'id'          => $link->getID(),
            'external_id' => (string) ($person['externalId'] ?? $link->fields['external_id']),
            'subject'     => (string) ($person['subject'] ?? $link->fields['subject']),
        ]);

        if ($update !== []) {
            EventLog::record(EventLog::SCIM_UPDATE, $source, [
                'users_id' => $user->getID(),
                'subject'  => (string) $user->fields['name'],
                'detail'   => 'Updated: ' . implode(', ', array_keys($update)),
            ]);
        }

        return ['link' => $link, 'created' => false, 'error' => null];
    }

    /**
     * Keep the primary address in step, without disturbing the others.
     *
     * GLPI users hold several addresses and one of them is primary. A directory
     * knows about one; overwriting the whole list with it would throw away an
     * alias somebody added by hand, so only the primary is touched.
     */
    private static function syncEmail(User $user, string $email): void
    {
        $email = trim($email);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return;
        }

        $rows    = getAllDataFromTable(UserEmail::getTable(), ['users_id' => $user->getID()]);
        $primary = null;

        foreach ($rows as $row) {
            if (strcasecmp((string) $row['email'], $email) === 0) {
                // Already present. Make sure it is the primary one and stop.
                if (!$row['is_default']) {
                    (new UserEmail())->update(['id' => $row['id'], 'is_default' => 1]);
                }

                return;
            }

            if ($row['is_default']) {
                $primary = $row;
            }
        }

        if ($primary !== null) {
            (new UserEmail())->update(['id' => $primary['id'], 'email' => $email]);

            return;
        }

        (new UserEmail())->add([
            'users_id'   => $user->getID(),
            'email'      => $email,
            'is_default' => 1,
        ]);
    }

    /**
     * Retire an account the directory no longer wants.
     *
     * Never a purge, whichever action is configured. A GLPI user is referenced
     * by every ticket they ever raised or solved, and purging one takes those
     * references with it — the reporting equivalent of deleting history to
     * close an account.
     */
    public static function deprovision(Source $source, Link $link): bool
    {
        $user = $link->user();
        if ($user === null) {
            return false;
        }

        if ((string) $source->fields['deprovision_action'] === Source::DEPROVISION_DELETE) {
            // GLPI's `delete` is the bin, not the shredder — recoverable, and
            // the user disappears from pickers meanwhile.
            $user->delete(['id' => $user->getID()]);
        } else {
            $user->update(['id' => $user->getID(), 'is_active' => 0]);
        }

        EventLog::record(EventLog::SCIM_DEACTIVATE, $source, [
            'users_id' => $user->getID(),
            'subject'  => (string) $user->fields['name'],
            'detail'   => 'Deprovisioned (' . $source->fields['deprovision_action'] . ').',
        ]);

        return true;
    }

    /**
     * Everything a mapping might match on, for a user of this source.
     *
     * Claims that arrived with the request win; where there are none — a SCIM
     * update names the user, not their groups — the directory groups recorded
     * from the /Groups endpoint stand in. That is what makes group mapping work
     * for Google Workspace, which sends no groups claim at sign-in at all.
     *
     * @param array<string,string[]> $claims
     * @return array<string,string[]>
     */
    public static function claimsFor(Source $source, int $users_id, array $claims = []): array
    {
        $groups_claim = (string) ($source->fields['claim_groups'] ?: 'groups');

        if (($claims[$groups_claim] ?? []) === []) {
            $known = IdpGroup::namesForUser($source->getID(), $users_id);
            if ($known !== []) {
                $claims[$groups_claim] = $known;
            }
        }

        return $claims;
    }
}
