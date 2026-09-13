<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBTM;
use Ramsey\Uuid\Uuid;
use User;

/**
 * The fact that a GLPI user came from a particular identity source.
 *
 * This is the load-bearing table, and the reason is worth stating plainly:
 * **identity is not email**. Addresses change on marriage and rebrand, get
 * reused when someone leaves, and are claimed by whoever controls the domain
 * today. An OIDC `sub` and a SCIM resource id are opaque, stable, and issued by
 * the directory that actually knows who the person is.
 *
 * So both halves of the plugin resolve through here. SSO matches on
 * (source, subject); SCIM matches on (source, external id) or its own resource
 * id. Neither ever looks a user up by email alone — an email match across
 * sources is how one organisation's directory ends up owning another's
 * account, and it would look like an ordinary successful login.
 */
class Link extends CommonDBTM
{
    public static $rightname = 'plugin_glpiidentity_source';

    public static function getTypeName($nb = 0)
    {
        return _n('Identity link', 'Identity links', $nb, 'glpiidentity');
    }

    /** The link for a GLPI user under one source, or null. */
    public static function forUser(int $sources_id, int $users_id): ?self
    {
        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'users_id'                       => $users_id,
        ]);
    }

    /** The link for an OIDC subject under one source, or null. */
    public static function forSubject(int $sources_id, string $subject): ?self
    {
        if ($subject === '') {
            return null;
        }

        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'subject'                        => $subject,
        ]);
    }

    /** The link for a directory's own id under one source, or null. */
    public static function forExternalId(int $sources_id, string $external_id): ?self
    {
        if ($external_id === '') {
            return null;
        }

        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'external_id'                    => $external_id,
        ]);
    }

    /**
     * The link for a SCIM resource id — scoped to the calling source.
     *
     * The scoping is the access control, not the unguessability of the id: a
     * caller asking for a resource id that is not theirs must get a 404, not
     * somebody else's user.
     */
    public static function forScimId(int $sources_id, string $scim_id): ?self
    {
        if ($scim_id === '') {
            return null;
        }

        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'scim_id'                        => $scim_id,
        ]);
    }

    /**
     * Every link a source holds, oldest first.
     *
     * @return self[]
     */
    public static function forSource(int $sources_id): array
    {
        $out = [];
        foreach (
            getAllDataFromTable(
                self::getTable(),
                ['plugin_glpiidentity_sources_id' => $sources_id],
                false,
                'id'
            ) as $row
        ) {
            $link         = new self();
            $link->fields = $row;
            $out[]        = $link;
        }

        return $out;
    }

    /**
     * The links of a source that nobody has signed into yet.
     *
     * Two things produce one: a SCIM connector creating an account before its
     * owner has ever logged in, and an administrator inviting an account that
     * was already in GLPI ({@see invite()}). Both mean the same thing — this
     * source is entitled to take this account over, once somebody turns up who
     * can prove they own an address it already holds.
     *
     * @return self[]
     */
    public static function invitations(int $sources_id): array
    {
        return array_values(array_filter(
            self::forSource($sources_id),
            static fn(self $link): bool => (string) $link->fields['subject'] === ''
        ));
    }

    /**
     * The most recent sign-in a user has made through *any* source.
     *
     * Asked by the idle-disable task, and the reason it asks is a consultant
     * who works for two of the organisations you support: one GLPI user with a link
     * to each directory, and one of those directories not having seen them
     * lately says nothing about whether they still use GLPI.
     *
     * @return string a MySQL datetime, or '' if they have never signed in
     */
    public static function lastLoginAnywhere(int $users_id): string
    {
        $latest = '';
        foreach (self::allForUser($users_id) as $link) {
            $seen = (string) ($link->fields['date_lastlogin'] ?? '');
            if ($seen > $latest) {
                $latest = $seen;
            }
        }

        return $latest;
    }

    /**
     * Invite a source to adopt a GLPI account that already exists.
     *
     * The problem this solves shows up on the first day of any migration: a
     * GLPI instance is already full of the contacts it has been raising
     * tickets for, created by hand or by an inbound mail collector, and the
     * first time one of them signs in through their provider the
     * plugin quite correctly refuses — a directory does not get to adopt an
     * account it has never owned, because that is how provisioning a user
     * called `admin` becomes a privilege escalation.
     *
     * An invitation is an administrator saying, per account, that this
     * particular directory *is* the owner of this particular person. It is
     * still not a grant: {@see SignIn::adopt()} binds it only when somebody
     * signs in who can prove they hold an address the account already has, and
     * a link that has been bound once is never rebound. So the pair of them
     * are two different people's decisions, which is the point.
     */
    public static function invite(Source $source, int $users_id): bool
    {
        $user = new User();
        if (!$user->getFromDB($users_id) || (int) $user->fields['is_deleted'] === 1) {
            return false;
        }

        if (self::forUser($source->getID(), $users_id) !== null) {
            // Already linked, bound or not. Not an error: an administrator
            // pressing the button twice means the same thing both times.
            return false;
        }

        self::attach($source->getID(), $users_id);

        EventLog::record(EventLog::LINK_INVITED, $source, [
            'users_id' => $users_id,
            'subject'  => (string) $user->fields['name'],
            'detail'   => 'Existing GLPI account invited to be adopted by this source on first sign-in.',
        ]);

        return true;
    }

    /**
     * Hand a bound link back, so the next sign-in can claim it.
     *
     * The refusal in {@see SignIn::adopt()} — "this account is already linked
     * to a different subject at this provider" — tells an administrator to
     * clear the link, and this is that. It comes up for real reasons: a tenant
     * migration reissues every subject, a rebuilt IdP does the same, and a
     * person who was deleted and recreated in the directory is a new subject
     * for the same human being.
     *
     * The link itself stays, so the account is still this source's to adopt and
     * still has to be claimed by somebody presenting an address it already
     * holds. Clearing the subject reopens the question of *who*; it does not
     * answer it.
     */
    public function reopen(): bool
    {
        if ((string) $this->fields['subject'] === '') {
            return false;
        }

        $was  = (string) $this->fields['subject'];
        $user = $this->user();

        $this->update(['id' => $this->getID(), 'subject' => '']);

        EventLog::record(EventLog::LINK_CLEARED, $this->source(), [
            'users_id' => (int) $this->fields['users_id'],
            'subject'  => $user === null ? '' : (string) $user->fields['name'],
            'detail'   => 'Link reopened by an administrator; the subject it was bound to (' . $was
                . ') will be replaced by the next sign-in that matches a verified address.',
        ]);

        return true;
    }

    /**
     * Disown an account entirely.
     *
     * The GLPI user stays — deleting a source's link is a statement about who
     * owns an account, not about whether the person exists, and they are named
     * on every ticket they ever raised. What goes is this source's claim to
     * them: sign-in through it is refused afterwards, the way it would be for
     * any account the source never owned.
     */
    public function disown(): bool
    {
        $user   = $this->user();
        $source = $this->source();

        if (!$this->delete(['id' => $this->getID()], true)) {
            return false;
        }

        EventLog::record(EventLog::LINK_CLEARED, $source, [
            'users_id' => (int) $this->fields['users_id'],
            'subject'  => $user === null ? '' : (string) $user->fields['name'],
            'detail'   => 'Link removed by an administrator; this source no longer owns the account.',
        ]);

        return true;
    }

    /**
     * GLPI accounts this source could be invited to adopt.
     *
     * Scoped to the entity the source places people in, because that is where
     * its people are: an organisation's contacts sit in that organisation's
     * entity whatever else is true of them. Accounts with no email address at all are
     * left out — adoption needs an address to match against, so listing them
     * would be offering something that could never work.
     *
     * @return array<int,array{id:int,name:string,fullname:string,emails:string[]}>
     */
    public static function candidates(Source $source, int $limit = 200): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $entities = [(int) $source->fields['entities_id']];
        if ((int) $source->fields['is_recursive'] === 1) {
            $entities = array_merge($entities, getSonsOf('glpi_entities', (int) $source->fields['entities_id']));
        }

        $rows = [];
        foreach (
            $DB->request([
                'SELECT'     => ['u.id', 'u.name', 'u.firstname', 'u.realname'],
                'DISTINCT'   => true,
                'FROM'       => 'glpi_users AS u',
                'INNER JOIN' => [
                    'glpi_profiles_users AS pu' => ['ON' => ['pu' => 'users_id', 'u' => 'id']],
                    'glpi_useremails AS ue'     => ['ON' => ['ue' => 'users_id', 'u' => 'id']],
                ],
                'LEFT JOIN'  => [
                    self::getTable() . ' AS l' => [
                        'ON' => [
                            'l' => 'users_id',
                            'u' => 'id',
                            ['AND' => ['l.plugin_glpiidentity_sources_id' => $source->getID()]],
                        ],
                    ],
                ],
                'WHERE'      => [
                    'u.is_deleted'   => 0,
                    'pu.entities_id' => array_values(array_unique($entities)),
                    'l.id'           => null,
                ],
                'ORDER'      => 'u.name',
                'LIMIT'      => $limit,
            ]) as $row
        ) {
            $rows[(int) $row['id']] = [
                'id'       => (int) $row['id'],
                'name'     => (string) $row['name'],
                'fullname' => trim((string) $row['firstname'] . ' ' . (string) $row['realname']),
                'emails'   => [],
            ];
        }

        if ($rows === []) {
            return [];
        }

        foreach (
            $DB->request([
                'SELECT' => ['users_id', 'email'],
                'FROM'   => \UserEmail::getTable(),
                'WHERE'  => ['users_id' => array_keys($rows)],
            ]) as $row
        ) {
            $rows[(int) $row['users_id']]['emails'][] = (string) $row['email'];
        }

        return array_values($rows);
    }

    /** @param array<string,mixed> $criteria */
    private static function findOne(array $criteria): ?self
    {
        $link = new self();

        return $link->getFromDBByCrit($criteria) ? $link : null;
    }

    /**
     * Link a user to a source, or return the link that already exists.
     *
     * Named `attach` rather than `create` because the second call for the same
     * pair is the normal case, not an error: every sign-in and every SCIM
     * update comes through here.
     */
    public static function attach(int $sources_id, int $users_id, array $fields = []): self
    {
        $existing = self::forUser($sources_id, $users_id);

        if ($existing !== null) {
            if ($fields !== []) {
                $existing->update(['id' => $existing->getID()] + $fields);
            }

            return $existing;
        }

        $link = new self();
        $link->add([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'users_id'                       => $users_id,
            'scim_id'                        => Uuid::uuid4()->toString(),
            'date_creation'                  => date('Y-m-d H:i:s'),
        ] + $fields);

        return $link;
    }

    public function user(): ?User
    {
        $user = new User();

        return $user->getFromDB((int) $this->fields['users_id']) ? $user : null;
    }

    public function source(): ?Source
    {
        $source = new Source();

        return $source->getFromDB((int) $this->fields['plugin_glpiidentity_sources_id']) ? $source : null;
    }

    public function touchLogin(): void
    {
        $this->update(['id' => $this->getID(), 'date_lastlogin' => date('Y-m-d H:i:s')]);
    }

    // --------------------------------------------------------------- the tab

    public static function getIcon()
    {
        return 'ti ti-link';
    }

    public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof Source || $item->isNewItem()) {
            return '';
        }

        return self::createTabEntry(
            self::getTypeName(2),
            count(self::forSource($item->getID())),
            $item::class
        );
    }

    public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof Source) {
            self::showForSource($item);
        }

        return true;
    }

    /**
     * The links this source holds, and the accounts it could be given.
     *
     * One form for the whole tab, with the action chosen by which button was
     * pressed. Two of the three buttons take a list of accounts and the third
     * takes one link, so they cannot share a name — but they can share a form,
     * and a second form nested in the first would be dropped by the parser.
     */
    private static function showForSource(Source $source): void
    {
        $e     = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $links = self::forSource($source->getID());
        $can   = $source->canUpdateItem();

        echo "<div class='glpiidentity-links'>";

        if ($can) {
            echo "<form method='post' action='" . $e(Url::to('front/source.form.php')) . "'>";
            echo \Html::hidden('id', ['value' => $source->getID()]);
        }

        echo '<p class="text-muted">'
           . __s('A link is the record that a GLPI account belongs to this source. Sign-in and '
               . 'provisioning both resolve through one, which is what stops a directory reaching '
               . 'an account it does not own — nothing here is ever matched on an email address '
               . 'alone.', 'glpiidentity')
           . '</p>';

        if ($links === []) {
            echo "<div class='alert alert-secondary'>"
               . __s('No accounts are linked to this source yet.', 'glpiidentity')
               . '</div>';
        } else {
            echo "<table class='table table-sm'><thead><tr>"
               . '<th>' . \User::getTypeName(1) . '</th>'
               . '<th>' . __s('Bound to', 'glpiidentity') . '</th>'
               . '<th>' . __s('Last sign-in', 'glpiidentity') . '</th>'
               . '<th></th></tr></thead><tbody>';

            foreach ($links as $link) {
                $user = $link->user();

                echo '<tr>';
                echo '<td>' . ($user === null
                    ? "<span class='text-muted'>" . __s('Deleted account', 'glpiidentity') . '</span>'
                    : $user->getLink()) . '</td>';

                if ((string) $link->fields['subject'] !== '') {
                    echo '<td><code class="text-break"><small>' . $e($link->fields['subject']) . '</small></code></td>';
                } else {
                    // The state that matters on this page: a link with nothing
                    // bound to it is an offer, not a fact.
                    echo '<td><span class="badge bg-azure-lt">'
                       . __s('Awaiting first sign-in', 'glpiidentity') . '</span></td>';
                }

                echo '<td><small>' . ((string) ($link->fields['date_lastlogin'] ?? '') === ''
                    ? "<span class='text-muted'>" . __s('Never', 'glpiidentity') . '</span>'
                    : $e(\Html::convDateTime($link->fields['date_lastlogin']))) . '</small></td>';

                echo '<td class="text-end">';
                if ($can) {
                    if ((string) $link->fields['subject'] !== '') {
                        echo "<button type='submit' name='reopen' value='" . (int) $link->getID() . "' "
                           . "class='btn btn-sm btn-ghost-secondary' title='"
                           . __s('Let the next sign-in claim this account again', 'glpiidentity') . "'>"
                           . "<i class='ti ti-refresh-dot'></i></button>";
                    }

                    echo "<button type='submit' name='unlink' value='" . (int) $link->getID() . "' "
                       . "class='btn btn-sm btn-ghost-danger' title='"
                       . __s('This source no longer owns this account', 'glpiidentity') . "'>"
                       . "<i class='ti ti-unlink'></i></button>";
                }
                echo '</td></tr>';
            }

            echo '</tbody></table>';
        }

        if ($can) {
            self::showCandidates($source, $e);
            \Html::closeForm();
        }

        echo '</div>';
    }

    /**
     * The accounts an administrator can hand to this source.
     *
     * Listed rather than swept up in one go on purpose. "Link everyone" is the
     * button somebody wants at four o'clock on a migration day, and the list
     * above it is what stops them discovering afterwards that it also linked
     * the account their own service desk logs in with.
     */
    private static function showCandidates(Source $source, callable $e): void
    {
        $candidates = self::candidates($source);

        echo "<h4 class='mt-4'>" . __s('Link accounts that already exist', 'glpiidentity') . '</h4>';

        echo '<p class="text-muted">'
           . sprintf(
               __s('Accounts in %s with an email address, that no link here owns yet. Linking one '
                 . 'does not grant anything by itself: the account is taken over the first time '
                 . 'somebody signs in through this provider with an address the account already '
                 . 'holds, and never afterwards. Without it, their first sign-in is refused '
                 . 'because a GLPI account with that username already exists.', 'glpiidentity'),
               '<strong>' . $e(\Dropdown::getDropdownName('glpi_entities', (int) $source->fields['entities_id'])) . '</strong>'
           )
           . '</p>';

        if ($candidates === []) {
            echo "<div class='alert alert-secondary'>"
               . __s('Nothing to link — every account here is either linked already or has no '
                   . 'email address to be matched on.', 'glpiidentity')
               . '</div>';

            return;
        }

        echo "<table class='table table-sm'><thead><tr>"
           . '<th></th>'
           . '<th>' . __s('Login') . '</th>'
           . '<th>' . __s('Name') . '</th>'
           . '<th>' . _n('Email', 'Emails', 2) . '</th>'
           . '</tr></thead><tbody>';

        foreach ($candidates as $candidate) {
            echo '<tr>';
            echo "<td><input type='checkbox' class='form-check-input' name='users[]' value='"
               . (int) $candidate['id'] . "'></td>";
            echo '<td>' . $e($candidate['name']) . '</td>';
            echo '<td>' . $e($candidate['fullname']) . '</td>';
            echo '<td><small>' . $e(implode(', ', $candidate['emails'])) . '</small></td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        echo "<button type='submit' name='prelink' value='1' class='btn btn-primary me-2'>"
           . "<i class='ti ti-link me-1'></i>" . __s('Link the selected accounts', 'glpiidentity') . '</button>';

        echo "<button type='submit' name='prelink_all' value='1' class='btn btn-outline-secondary'>"
           . sprintf(__s('Link all %d listed', 'glpiidentity'), count($candidates)) . '</button>';

        if (count($candidates) >= 200) {
            echo "<div class='form-text'>"
               . __s('Only the first 200 are listed; link these and the rest will appear.', 'glpiidentity')
               . '</div>';
        }
    }

    /**
     * Every link a GLPI user has, across sources.
     *
     * More than one is legitimate and worth surfacing: a consultant who is a
     * user of two organisations' directories is one person in GLPI with two
     * accounts upstream, and an administrator debugging why their profile keeps
     * changing needs to see both.
     *
     * @return self[]
     */
    public static function allForUser(int $users_id): array
    {
        $out = [];
        foreach (getAllDataFromTable(self::getTable(), ['users_id' => $users_id]) as $row) {
            $link         = new self();
            $link->fields = $row;
            $out[]        = $link;
        }

        return $out;
    }
}
