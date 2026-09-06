<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use Auth;
use Session;
use User;

/**
 * Turning verified claims into a signed-in GLPI session.
 *
 * The verification is done by the time anything here runs — {@see Oidc\Flow}
 * has checked the signature, issuer, audience and nonce, and what arrives is a
 * set of claims we are entitled to believe. What is left is the part that is
 * specific to running several organisations in one GLPI: deciding *which*
 * account these claims are about, and refusing to guess.
 */
final class SignIn
{
    /** @return array{ok:bool,message:string,users_id:int} */
    public static function complete(Source $source, array $claims): array
    {
        $subject = (string) ($claims['sub'] ?? '');
        $login   = self::claim($claims, (string) $source->fields['claim_login']);
        $email   = self::claim($claims, (string) $source->fields['claim_email']);

        // Entra sends `preferred_username` for work accounts and nothing at all
        // for some guest ones; an address is a reasonable second choice, and a
        // subject is a terrible username but a correct last resort.
        $username = $login !== '' ? $login : ($email !== '' ? $email : $subject);

        if ($username === '') {
            return self::refuse($source, $subject, 'The provider sent no username, email or subject.');
        }

        $link = Link::forSubject($source->getID(), $subject);

        if ($link === null) {
            $link = self::adopt($source, $username, $subject);
        }

        if ($link === null) {
            if ((int) $source->fields['jit_provision'] !== 1) {
                return self::refuse(
                    $source,
                    $username,
                    'No GLPI account is linked to this source and creating one on sign-in is switched off.'
                );
            }

            $result = Provisioning::upsert($source, [
                'userName'  => $username,
                'subject'   => $subject,
                'email'     => $email,
                'firstname' => self::claim($claims, (string) $source->fields['claim_firstname']),
                'lastname'  => self::claim($claims, (string) $source->fields['claim_lastname']),
                'active'    => true,
            ]);

            if ($result['error'] === Provisioning::CONFLICT) {
                // The important refusal. Somebody else in GLPI already answers
                // to this name, and adopting them would hand this directory an
                // account it does not own — possibly an administrator's.
                return self::refuse(
                    $source,
                    $username,
                    'A GLPI account with this username already exists and belongs to someone else.'
                );
            }

            if ($result['link'] === null) {
                return self::refuse($source, $username, (string) $result['error']);
            }

            $link = $result['link'];

            EventLog::record(EventLog::SSO_PROVISION, $source, [
                'users_id' => (int) $link->fields['users_id'],
                'subject'  => $username,
                'detail'   => 'Account created on first sign-in.',
            ]);
        }

        $user = $link->user();
        if ($user === null) {
            return self::refuse($source, $username, 'The linked GLPI account has gone.');
        }

        // Claims may have moved on since the account was made: a surname, an
        // address, a directory that now sends a different display name.
        Provisioning::upsert($source, [
            'userName'  => (string) $user->fields['name'],
            'subject'   => $subject,
            'email'     => $email,
            'firstname' => self::claim($claims, (string) $source->fields['claim_firstname']),
            'lastname'  => self::claim($claims, (string) $source->fields['claim_lastname']),
        ]);
        $user->getFromDB($user->getID());

        Mapper::apply(
            $source,
            $user,
            Provisioning::claimsFor(
                $source,
                (int) $user->getID(),
                Mapper::normaliseClaims($claims)
            )
        );
        $user->getFromDB($user->getID());

        if (!$user->fields['is_active'] || $user->fields['is_deleted']) {
            // Deprovisioned upstream, or disabled here. Refusing at this point
            // rather than letting Session::init do it silently is what turns
            // "GLPI just logs me straight back out" into an answer.
            return self::refuse($source, $username, 'This GLPI account is deactivated.');
        }

        $link->touchLogin();

        return self::establish($source, $user, $link);
    }

    /**
     * Adopt an account this source already owns, found by username.
     *
     * Only reachable for a user that already has a link to *this* source: a
     * person whose subject changed because the directory was rebuilt, which
     * happens on tenant migrations. An account with no link, or a link to
     * another source, is never adopted here.
     */
    private static function adopt(Source $source, string $username, string $subject): ?Link
    {
        $user = new User();
        if (!$user->getFromDBbyName($username)) {
            return null;
        }

        $link = Link::forUser($source->getID(), (int) $user->getID());
        if ($link === null) {
            return null;
        }

        if ((string) $link->fields['subject'] !== $subject && $subject !== '') {
            $link->update(['id' => $link->getID(), 'subject' => $subject]);

            EventLog::record(EventLog::SSO_LOGIN, $source, [
                'users_id' => (int) $user->getID(),
                'subject'  => $username,
                'detail'   => 'The provider issued a new subject for an account this source owns; relinked.',
            ]);
        }

        return $link;
    }

    /**
     * Hand the session to GLPI.
     *
     * `Session::init()` is the same call `Auth::login()` makes once a password
     * has checked out: it regenerates the session id, reloads the user, applies
     * their preferences and enforces the active/date window. Doing it this way
     * rather than through GLPI's EXTERNAL auth mode is deliberate — that mode
     * trusts a request header instance-wide, which is a much larger promise
     * than "this one token verified".
     *
     * Everything around that call is about one failure: a session GLPI will
     * accept now and refuse on the next click. See {@see purgeStaleMarkers()}
     * and {@see sessionIsUsable()} for the two ways that happens.
     *
     * @return array{ok:bool,message:string,users_id:int}
     */
    private static function establish(Source $source, User $user, Link $link): array
    {
        self::purgeStaleMarkers();

        $auth                = new Auth();
        $auth->user          = $user;
        $auth->auth_succeded = true;
        $auth->extauth       = 1;
        $auth->user_present  = true;

        Session::init($auth);

        $unusable = self::sessionIsUsable((int) $user->getID());
        if ($unusable !== null) {
            // Do not leave a half-built session behind. A browser holding a
            // cookie for a session GLPI refuses to validate is the worst
            // outcome available: every page becomes an error, and the only fix
            // a user can find is clearing their cookies.
            Session::destroy();

            return self::refuse($source, (string) $user->fields['name'], $unusable);
        }

        EventLog::record(EventLog::SSO_LOGIN, $source, [
            'users_id' => (int) $user->getID(),
            'subject'  => (string) $user->fields['name'],
            'detail'   => 'Signed in.',
        ]);

        return ['ok' => true, 'message' => '', 'users_id' => (int) $user->getID()];
    }

    /**
     * Remove session keys that would poison the session we are about to build.
     *
     * `glpi_remote_user` is the one that matters, and it is worth spelling out
     * because the failure it causes is baffling from the outside.
     *
     * GLPI sets that key when somebody authenticates through its built-in
     * EXTERNAL mode — the one that trusts a web-server variable like
     * REMOTE_USER. From then on, {@see \Session::checkValidSessionId()} demands
     * that `$_SERVER[<the configured SSO variable>]` still equals it, **on
     * every request**. And `Session::init()` deliberately *preserves* the key
     * across the session regeneration it performs.
     *
     * So a browser that once held such a session carries the key forward
     * through every subsequent sign-in. The sign-in itself succeeds; the next
     * page throws SessionExpiredException; the user is bounced to the login
     * page; signing in again does the same thing. Clearing cookies is the only
     * fix they can find, which is exactly the bug this guards against.
     *
     * A session established here is not a remote-user session, so the key is
     * not merely stale — it is untrue. It is removed *before* Session::init()
     * runs, because init() copies it into the values it will restore.
     */
    private static function purgeStaleMarkers(): void
    {
        foreach (
            [
                // Not how this user authenticated. See above.
                'glpi_remote_user',
                // Left by GLPI's CAS client. Present, it makes Session::init()
                // record the session as CAS-authenticated instead of ours.
                'phpCAS',
                // A half-finished password-expiry flow from a previous
                // password login, which would otherwise send an SSO user to a
                // change-password form for a password they do not have.
                'glpi_password_expired',
            ] as $key
        ) {
            unset($_SESSION[$key]);
        }
    }

    /**
     * Will GLPI still accept this session on the *next* request?
     *
     * Session::init() populates a session and returns nothing; it is
     * checkValidSessionId() on the following request that decides whether the
     * session is real. The two ways that check fails after a successful
     * sign-in are both worth catching here, while there is still a person
     * looking at a page we can explain something on:
     *
     *  - **no profile or no active entity.** GLPI sets the user id and stops.
     *    Every page then throws, and the symptom — signed in, immediately
     *    signed out — reads as a broken plugin rather than as an account with
     *    no rights.
     *  - **valid_id out of step with the session id**, which would mean the
     *    regeneration did not take.
     *
     * @return string|null the reason it is not usable, or null if it is
     */
    private static function sessionIsUsable(int $users_id): ?string
    {
        if ((int) ($_SESSION['glpiID'] ?? 0) !== $users_id) {
            return 'GLPI refused the session — the account may be inactive or outside its valid dates.';
        }

        if (($_SESSION['valid_id'] ?? null) !== session_id()) {
            return 'The session id could not be established. Check that the web server can write sessions.';
        }

        if (($_SESSION['glpiactiveprofile']['id'] ?? null) === null) {
            return 'This account has no profile in any entity. Set a default profile on the identity '
                . 'source, or add a mapping that grants one.';
        }

        if (($_SESSION['glpiactive_entity'] ?? null) === null) {
            return 'This account has a profile but no entity it applies to.';
        }

        return null;
    }

    /** @return array{ok:bool,message:string,users_id:int} */
    private static function refuse(Source $source, string $subject, string $reason): array
    {
        EventLog::record(EventLog::SSO_DENIED, $source, [
            'error'   => true,
            'subject' => $subject,
            'detail'  => $reason,
        ]);

        return ['ok' => false, 'message' => $reason, 'users_id' => 0];
    }

    /**
     * One claim, as a string.
     *
     * Claims are not reliably scalar: `email` is occasionally a list, and a
     * name claim is occasionally an object. Taking the first usable value is
     * more useful than being strict, because the alternative is refusing a
     * sign-in over a formatting difference.
     */
    private static function claim(array $claims, string $name): string
    {
        if ($name === '' || !isset($claims[$name])) {
            return '';
        }

        $value = $claims[$name];

        if (is_scalar($value)) {
            return trim((string) $value);
        }

        if (is_array($value)) {
            foreach ($value as $entry) {
                if (is_scalar($entry) && trim((string) $entry) !== '') {
                    return trim((string) $entry);
                }
            }
        }

        return '';
    }
}
