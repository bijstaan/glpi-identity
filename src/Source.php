<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBTM;
use CronTask;
use Dropdown;
use GLPIKey;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\TransferException;
use Html;
use Profile;

/**
 * One organisation's identity configuration.
 *
 * A source is the whole of what you need to know about one organisation's
 * directory: how their people sign in (OpenID Connect), how their accounts
 * arrive (SCIM), and which entity all of it belongs to. It is one record rather
 * than three because that is how the work actually arrives — somebody onboards
 * Acme, and Acme has an identity provider.
 *
 * Everything downstream is scoped through this object. A SCIM request resolves
 * to a source before it resolves to anything else; a sign-in resolves to a
 * source before a user is looked up. That is what stops one organisation's
 * directory from reaching another's people, and it is a property of
 * the structure rather than of remembering to check.
 */
class Source extends CommonDBTM
{
    public static string $rightname = 'plugin_glpiidentity_source';

    public bool $dohistory = true;

    public const DEPROVISION_DISABLE = 'disable';
    public const DEPROVISION_DELETE  = 'delete';

    public static function getTypeName($nb = 0)
    {
        return _n('Identity source', 'Identity sources', $nb, 'glpiidentity');
    }

    public static function getIcon()
    {
        return 'ti ti-id-badge-2';
    }

    public function isEntityAssign()
    {
        return true;
    }

    public function maybeRecursive()
    {
        return true;
    }

    public static function canView(): bool
    {
        return (bool) \Session::haveRight(self::$rightname, READ);
    }

    public static function canCreate(): bool
    {
        return (bool) \Session::haveRight(self::$rightname, CREATE);
    }

    public static function getMenuContent()
    {
        if (!self::canView()) {
            return false;
        }

        return [
            'title' => self::getTypeName(2),
            'page'  => self::getSearchURL(false),
            'icon'  => self::getIcon(),
            'links' => [
                'search' => self::getSearchURL(false),
                'add'    => self::getFormURL(false),
            ],
        ];
    }

    public function post_getEmpty()
    {
        // Defaults live here because the tables are created by the install hook
        // rather than through GLPI's migration API, so getEmpty() has no column
        // defaults to read and every field would render blank.
        $this->fields['is_active']          = 0;
        $this->fields['is_recursive']       = 1;
        $this->fields['sso_enabled']        = 0;
        $this->fields['scim_enabled']       = 0;
        $this->fields['jit_provision']      = 1;
        $this->fields['scopes']             = 'openid profile email';
        $this->fields['claim_login']        = 'preferred_username';
        $this->fields['claim_email']        = 'email';
        $this->fields['claim_firstname']    = 'given_name';
        $this->fields['claim_lastname']     = 'family_name';
        $this->fields['claim_groups']       = 'groups';
        $this->fields['deprovision_action'] = self::DEPROVISION_DISABLE;
        $this->fields['idle_disable_days']  = 0;
        $this->fields['mirror_groups']      = 0;
    }

    // ------------------------------------------------------------- resolution

    /**
     * The source a bearer token belongs to.
     *
     * Looked up by hash, so nothing here has to decrypt anything and a database
     * that leaks yields no working token. `hash_equals` is not needed on top:
     * the comparison happens in the index, on a value the caller cannot vary
     * one byte at a time to learn anything — the hash of a wrong guess is not
     * closer to the right hash than any other.
     */
    public static function byScimToken(string $token): ?self
    {
        if ($token === '') {
            return null;
        }

        $source = new self();
        $found  = $source->getFromDBByCrit([
            'scim_token_hash' => hash('sha256', $token),
            'is_active'       => 1,
            'scim_enabled'    => 1,
        ]);

        return $found ? $source : null;
    }

    /**
     * The source that claims an email address's domain.
     *
     * This is home-realm discovery, and it is why `email_domains` is validated
     * as globally unique on save: two organisations claiming the same domain is not
     * an ambiguity to resolve at sign-in time with a tie-break, it is a
     * misconfiguration that would route one organisation's people into
     * another's entity.
     */
    public static function forEmail(string $email): ?self
    {
        $at = strrpos($email, '@');
        if ($at === false) {
            return null;
        }

        return self::forDomain(mb_strtolower(substr($email, $at + 1)));
    }

    public static function forDomain(string $domain): ?self
    {
        $domain = mb_strtolower(trim($domain));
        if ($domain === '') {
            return null;
        }

        foreach (self::activeSso() as $source) {
            if (in_array($domain, $source->domains(), true)) {
                return $source;
            }
        }

        return null;
    }

    /**
     * The house identity provider, used when no domain matches.
     *
     * There is at most one, enforced on save. "Several defaults" has no meaning
     * and the failure would be an arbitrary choice made silently.
     */
    public static function houseDefault(): ?self
    {
        foreach (self::activeSso() as $source) {
            if ((int) $source->fields['is_default'] === 1) {
                return $source;
            }
        }

        return null;
    }

    /** @return self[] */
    public static function activeSso(): array
    {
        return self::listWhere(['is_active' => 1, 'sso_enabled' => 1]);
    }

    /** @return self[] */
    public static function all(): array
    {
        return self::listWhere([]);
    }

    /** @return self[] */
    private static function listWhere(array $criteria): array
    {
        $out = [];
        foreach (getAllDataFromTable(self::getTable(), ['ORDER' => 'name'] + $criteria) as $row) {
            $source         = new self();
            $source->fields = $row;
            $out[]          = $source;
        }

        return $out;
    }

    /** @return string[] lowercase domains this source claims */
    public function domains(): array
    {
        $raw = (string) ($this->fields['email_domains'] ?? '');

        return array_values(array_filter(array_map(
            static fn(string $d): string => mb_strtolower(trim($d, " \t\n\r\0\x0B.@")),
            preg_split('/[\s,;]+/', $raw) ?: []
        )));
    }

    // ---------------------------------------------------------------- secrets

    /**
     * The claim directory-group membership travels in.
     *
     * One place for the fallback, because the mapper, the mirror and the
     * mapping form all have to agree on it: a rule on "groups" when the source
     * says "roles" is a rule that never fires.
     */
    public function groupsClaim(): string
    {
        return (string) ($this->fields['claim_groups'] ?? '') ?: 'groups';
    }

    public function clientSecret(): string
    {
        $raw = (string) ($this->fields['client_secret'] ?? '');
        if ($raw === '') {
            return '';
        }

        // A secret that will not decrypt reads as absent rather than being
        // passed through: GLPI's key can be regenerated, and sending ciphertext
        // to a token endpoint produces an opaque `invalid_client` instead of an
        // obvious "not configured".
        $plain = (new GLPIKey())->decrypt($raw);

        return is_string($plain) ? $plain : '';
    }

    /**
     * Mint a new SCIM bearer token, store its hash, and return it once.
     *
     * The only time the token exists in a form anyone can use it. If it is lost
     * it is regenerated, which also revokes the old one — the two things an
     * administrator wants from a credential they cannot look up.
     */
    public function rotateScimToken(): string
    {
        $token = 'scim_' . bin2hex(random_bytes(24));

        $this->update([
            'id'              => $this->getID(),
            'scim_token_hash' => hash('sha256', $token),
            // Enough to tell two tokens apart in a list, not enough to be one.
            'scim_token_hint' => substr($token, 0, 12),
        ]);

        EventLog::record('scim_token_rotated', $this, ['detail' => 'A new SCIM bearer token was issued.']);

        return $token;
    }

    public function hasScimToken(): bool
    {
        return (string) ($this->fields['scim_token_hash'] ?? '') !== '';
    }

    /** The base URL an organisation's IdP should be pointed at. */
    public function scimBaseUrl(): string
    {
        return Url::absolute('front/scim.php/v2');
    }

    /** The redirect URI to register in the IdP's application. Identical for every source. */
    public static function redirectUri(): string
    {
        return Url::absolute('front/sso.php/callback');
    }

    // -------------------------------------------------------------- discovery

    /**
     * The OIDC endpoints, from the last successful discovery.
     *
     * @return array<string,string>
     */
    public function endpoints(): array
    {
        $decoded = json_decode((string) ($this->fields['endpoints'] ?? ''), true);

        return is_array($decoded) ? $decoded : [];
    }

    public function endpoint(string $name): string
    {
        return (string) ($this->endpoints()[$name] ?? '');
    }

    /**
     * Fetch the provider's metadata document and remember it.
     *
     * Discovery is deliberate rather than lazy. Fetching it on the sign-in that
     * needs it would put their IdP on the critical path of a page load
     * twice — once for metadata, once for the token — and a slow provider would
     * look like a slow GLPI. A daily cron and a button cover it, and a stale
     * document is almost always still correct: issuers change endpoints about
     * as often as they change name.
     *
     * @return array{ok:bool,message:string}
     */
    public function discover(): array
    {
        $url = $this->discoveryUrl();
        if ($url === '') {
            return ['ok' => false, 'message' => __('Set the issuer first.', 'glpiidentity')];
        }

        try {
            $response = (new HttpClient())->get($url, [
                'timeout'     => 15,
                'http_errors' => false,
                'headers'     => ['Accept' => 'application/json'],
            ]);
        } catch (TransferException $e) {
            return $this->recordDiscoveryFailure($e->getMessage());
        }

        if ($response->getStatusCode() >= 400) {
            return $this->recordDiscoveryFailure(
                sprintf('HTTP %d from %s', $response->getStatusCode(), $url)
            );
        }

        $document = json_decode((string) $response->getBody(), true);
        if (!is_array($document)) {
            return $this->recordDiscoveryFailure('The metadata document was not JSON.');
        }

        // The issuer in the document is authoritative, and is what every id
        // token will be checked against. Taking it from here rather than from
        // what was typed is the difference between a typo being a one-off
        // failure and a permanent mismatch nobody can explain.
        $keep = [
            'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri',
            'userinfo_endpoint', 'end_session_endpoint',
        ];

        $endpoints = [];
        foreach ($keep as $key) {
            if (isset($document[$key]) && is_string($document[$key])) {
                $endpoints[$key] = $document[$key];
            }
        }

        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
            if (($endpoints[$required] ?? '') === '') {
                return $this->recordDiscoveryFailure(
                    sprintf('The metadata document has no %s.', $required)
                );
            }
        }

        $this->update([
            'id'                 => $this->getID(),
            'endpoints'          => json_encode($endpoints, JSON_UNESCAPED_SLASHES),
            'issuer'             => $endpoints['issuer'],
            'date_lastdiscovery' => date('Y-m-d H:i:s'),
            'discovery_error'    => '',
        ]);

        return ['ok' => true, 'message' => __('Provider metadata refreshed.', 'glpiidentity')];
    }

    private function discoveryUrl(): string
    {
        $explicit = trim((string) ($this->fields['discovery_url'] ?? ''));
        if ($explicit !== '') {
            return $explicit;
        }

        $issuer = trim((string) ($this->fields['issuer'] ?? ''));

        return $issuer === '' ? '' : rtrim($issuer, '/') . '/.well-known/openid-configuration';
    }

    /** @return array{ok:bool,message:string} */
    private function recordDiscoveryFailure(string $message): array
    {
        $this->update([
            'id'              => $this->getID(),
            'discovery_error' => mb_substr($message, 0, 500),
        ]);

        EventLog::record('discovery_failed', $this, ['error' => true, 'detail' => $message]);

        return ['ok' => false, 'message' => $message];
    }

    public function ssoReady(): bool
    {
        return (int) $this->fields['is_active'] === 1
            && (int) $this->fields['sso_enabled'] === 1
            && $this->fields['client_id'] !== ''
            && $this->clientSecret() !== ''
            && $this->endpoint('authorization_endpoint') !== ''
            && $this->endpoint('token_endpoint') !== ''
            && $this->endpoint('jwks_uri') !== '';
    }

    public function scimReady(): bool
    {
        return (int) $this->fields['is_active'] === 1
            && (int) $this->fields['scim_enabled'] === 1
            && $this->hasScimToken();
    }

    /**
     * The name to put on a login-page button, or '' for no button at all.
     *
     * Empty is the default and means the login page shows only the email box —
     * which already routes everyone, including staff, because an address at no
     * claimed domain falls back to the house provider. Filling this in is how
     * you opt into a one-click path for people who sign in many times a day.
     */
    public function buttonLabel(): string
    {
        return trim((string) ($this->fields['button_label'] ?? ''));
    }

    // --------------------------------------------------------------- the cron

    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'discovery'   => ['description' => __('Refresh identity provider metadata', 'glpiidentity')],
            'idledisable' => ['description' => __('Deactivate accounts that have stopped signing in', 'glpiidentity')],
            default       => [],
        };
    }

    public static function cronDiscovery(CronTask $task): int
    {
        $changed = 0;

        foreach (self::activeSso() as $source) {
            $before = $source->fields['endpoints'];
            $result = $source->discover();

            $task->addVolume(1);
            $task->log(sprintf('%s: %s', $source->fields['name'], $result['message']));

            if ($source->fields['endpoints'] !== $before) {
                $changed++;
            }
        }

        return $changed > 0 ? 1 : 0;
    }

    /**
     * Deactivate accounts that have stopped signing in.
     *
     * The gap this fills: {@see Provisioning::deprovision()} only ever runs
     * from a SCIM request, so a source whose organisation has no connector never
     * hears that somebody has left. Their account stays active for ever. That
     * matters less than it sounds while the provider still refuses them — and
     * a great deal when the account is a licence, a name in every picker and a
     * mailbox that still gets notifications.
     *
     * Three deliberate limits, each of which is the difference between a
     * useful task and one an administrator has to turn off again:
     *
     *  - **Only links that have been used.** A link with no last login is an
     *    invitation nobody has taken up, and a contact who has been in GLPI for
     *    six years should not be deactivated because an invitation written last
     *    month went unanswered.
     *  - **Every link the user holds, not just this one.** A consultant who
     *    signs in through a second organisation's directory is not idle, and
     *    disabling them because this one has not seen them lately would be a
     *    lockout with no cause.
     *  - **Deactivate, never bin**, whatever `deprovision_action` says. "Has
     *    not signed in lately" is a weaker claim than "the directory says they
     *    are gone", and it is a claim this plugin is making on its own rather
     *    than repeating.
     */
    public static function cronIdleDisable(CronTask $task): int
    {
        $disabled = 0;

        foreach (self::listWhere(['is_active' => 1]) as $source) {
            $days = (int) ($source->fields['idle_disable_days'] ?? 0);
            if ($days <= 0) {
                continue;
            }

            $cutoff = date('Y-m-d H:i:s', time() - ($days * DAY_TIMESTAMP));

            foreach (Link::forSource($source->getID()) as $link) {
                if ((string) ($link->fields['date_lastlogin'] ?? '') === '') {
                    continue;
                }

                if (Link::lastLoginAnywhere((int) $link->fields['users_id']) >= $cutoff) {
                    continue;
                }

                $user = $link->user();
                if (
                    $user === null
                    || (int) $user->fields['is_active'] !== 1
                    || (int) $user->fields['is_deleted'] === 1
                ) {
                    continue;
                }

                $user->update(['id' => $user->getID(), 'is_active' => 0]);

                EventLog::record(EventLog::IDLE_DISABLE, $source, [
                    'users_id' => (int) $user->getID(),
                    'subject'  => (string) $user->fields['name'],
                    'detail'   => sprintf(
                        'Deactivated after %d days without a sign-in (last was %s).',
                        $days,
                        (string) $link->fields['date_lastlogin']
                    ),
                ]);

                $task->addVolume(1);
                $disabled++;
            }
        }

        return $disabled > 0 ? 1 : 0;
    }

    // ------------------------------------------------------------- validation

    public function prepareInputForAdd($input)
    {
        return $this->validate($input);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->validate($input);
    }

    /**
     * The checks that stop one organisation's configuration from reaching another's.
     *
     * Domain uniqueness and the single default are both refusals rather than
     * warnings, because both failures are silent: sign-in would keep working,
     * for the wrong organisation.
     */
    private function validate(array $input): array|false
    {
        $refuse = static function (string $message): false {
            \Session::addMessageAfterRedirect(htmlescape($message), false, ERROR);

            return false;
        };

        $id = (int) ($input['id'] ?? $this->fields['id'] ?? 0);

        if (array_key_exists('client_secret', $input)) {
            $posted = trim((string) $input['client_secret']);

            if ($posted === Settings::SECRET_PLACEHOLDER) {
                unset($input['client_secret']);
            } elseif ($posted === '') {
                $input['client_secret'] = '';
            } else {
                $input['client_secret'] = (new GLPIKey())->encrypt($posted);
            }
        }

        if (array_key_exists('email_domains', $input)) {
            $probe                 = new self();
            $probe->fields         = ['email_domains' => $input['email_domains']];
            $claimed               = $probe->domains();
            $input['email_domains'] = implode(', ', $claimed);

            foreach (self::all() as $other) {
                if ((int) $other->getID() === $id) {
                    continue;
                }

                $clash = array_intersect($claimed, $other->domains());
                if ($clash !== []) {
                    return $refuse(sprintf(
                        __('The domain %1$s is already claimed by the source "%2$s".', 'glpiidentity'),
                        implode(', ', $clash),
                        $other->fields['name']
                    ));
                }
            }
        }

        if ((int) ($input['is_default'] ?? 0) === 1) {
            foreach (self::all() as $other) {
                if ((int) $other->getID() !== $id && (int) $other->fields['is_default'] === 1) {
                    return $refuse(sprintf(
                        __('"%s" is already the default identity provider. There can only be one.', 'glpiidentity'),
                        $other->fields['name']
                    ));
                }
            }
        }

        if (isset($input['issuer'])) {
            $issuer = rtrim(trim((string) $input['issuer']), '/');

            // Read from the database, not from $this->fields. GLPI copies the
            // input into $this->fields before prepareInputForAdd() runs, so on
            // an add the "stored" value is the posted one and any comparison
            // against it is a value compared with itself — which silently
            // disabled this check entirely.
            $stored = '';
            if ($id > 0) {
                $current = new self();
                if ($current->getFromDB($id)) {
                    $stored = rtrim((string) $current->fields['issuer'], '/');
                }
            }

            // https, and no exception for loopback. Unlike an internal API, an
            // issuer URL is where a browser is sent to type a password.
            //
            // Applied only when the value actually changes. discover() writes
            // the issuer back from the provider's own metadata document on
            // every refresh, and re-checking a value that is already stored
            // would make that write fail silently — leaving the endpoints
            // unrefreshed and no error anywhere.
            if ($issuer !== '' && $issuer !== $stored && !str_starts_with(strtolower($issuer), 'https://')) {
                return $refuse(__('An issuer URL must use https.', 'glpiidentity'));
            }

            $input['issuer'] = $issuer;
        }

        if (isset($input['discovery_url'])) {
            $url = trim((string) $input['discovery_url']);

            // The same rule as the issuer, for a stronger reason: every
            // endpoint the sign-in uses comes out of the document this URL
            // returns, so whoever can answer it decides where a browser is sent
            // to type a password. No exception for loopback, and no comparison
            // with the stored value — unlike the issuer, nothing writes this
            // field back, so re-checking it costs nothing.
            if ($url !== '' && !str_starts_with(strtolower($url), 'https://')) {
                return $refuse(__('A metadata URL must use https.', 'glpiidentity'));
            }

            $input['discovery_url'] = $url;
        }

        if (isset($input['idle_disable_days'])) {
            $input['idle_disable_days'] = max(0, (int) $input['idle_disable_days']);
        }

        if (
            isset($input['deprovision_action'])
            && !in_array($input['deprovision_action'], [self::DEPROVISION_DISABLE, self::DEPROVISION_DELETE], true)
        ) {
            return $refuse(__('Unknown deprovisioning action.', 'glpiidentity'));
        }

        return $input;
    }

    /**
     * Rediscover when the issuer changes.
     *
     * Otherwise an administrator corrects a typo, saves, and the plugin keeps
     * using the endpoints belonging to the URL they just replaced.
     */
    public function post_updateItem($history = true)
    {
        // Guarded against re-entry: discover() writes the endpoints and the
        // issuer, which lands back here. Without the flag the second pass is
        // harmless but pointless — a second HTTP fetch on every save.
        if ($this->rediscovering) {
            return;
        }

        if (in_array('issuer', $this->updates, true) || in_array('discovery_url', $this->updates, true)) {
            $this->rediscovering = true;

            try {
                $this->discover();
            } finally {
                $this->rediscovering = false;
            }
        }
    }

    /** Re-entry guard for the discovery triggered by saving a new issuer. */
    private bool $rediscovering = false;

    public function cleanDBonPurge()
    {
        /** @var \DBmysql $DB */
        global $DB;

        // The links go, the GLPI users stay. Deleting a source is an
        // administrative act about a configuration; deleting the people it
        // provisioned is not implied by it, and would take their ticket history
        // with them.
        // Memberships first: they are keyed by group, not by source, so once
        // the groups are gone nothing can find them any more.
        $DB->delete(IdpGroup_User::getTable(), [
            'plugin_glpiidentity_idpgroups_id' => new \Glpi\DBAL\QuerySubQuery([
                'SELECT' => 'id',
                'FROM'   => IdpGroup::getTable(),
                'WHERE'  => ['plugin_glpiidentity_sources_id' => $this->getID()],
            ]),
        ]);

        foreach ([Mapping::getTable(), Link::getTable(), IdpGroup::getTable()] as $table) {
            $DB->delete($table, ['plugin_glpiidentity_sources_id' => $this->getID()]);
        }
    }

    // --------------------------------------------------------------- the form

    public function rawSearchOptions()
    {
        return [
            ['id' => 'common', 'name' => self::getTypeName(2)],
            [
                'id'            => '1',
                'table'         => self::getTable(),
                'field'         => 'name',
                'name'          => __('Name'),
                'datatype'      => 'itemlink',
                'massiveaction' => false,
            ],
            [
                'id'       => '2',
                'table'    => self::getTable(),
                'field'    => 'is_active',
                'name'     => __('Active'),
                'datatype' => 'bool',
            ],
            [
                'id'       => '3',
                'table'    => self::getTable(),
                'field'    => 'sso_enabled',
                'name'     => __('Single sign-on', 'glpiidentity'),
                'datatype' => 'bool',
            ],
            [
                'id'       => '4',
                'table'    => self::getTable(),
                'field'    => 'scim_enabled',
                'name'     => __('SCIM provisioning', 'glpiidentity'),
                'datatype' => 'bool',
            ],
            [
                'id'       => '5',
                'table'    => self::getTable(),
                'field'    => 'issuer',
                'name'     => __('Issuer', 'glpiidentity'),
                'datatype' => 'string',
            ],
            [
                'id'       => '6',
                'table'    => self::getTable(),
                'field'    => 'email_domains',
                'name'     => __('Email domains', 'glpiidentity'),
                'datatype' => 'text',
            ],
            [
                'id'       => '80',
                'table'    => 'glpi_entities',
                'field'    => 'completename',
                'name'     => \Entity::getTypeName(1),
                'datatype' => 'dropdown',
            ],
        ];
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);

        // Scope wrapper: this form is core-rendered, so without a plugin-owned
        // container the shipped dark-theme CSS could never reach its helper
        // text (see the dark section of the plugin stylesheet).
        echo "<div class='glpiidentity-scope'>";
        $this->showFormHeader($options);

        $e   = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $row = static fn(): string => "<tr class='tab_bg_1'>";
        $new = $this->isNewID($ID);

        echo $row() . '<td>' . __s('Name') . " <span class='text-red'>*</span></td><td>";
        echo Html::input('name', ['value' => $this->fields['name'], 'required' => 'required']);
        echo "<div class='form-text'>" . __s('The entity this directory belongs to.', 'glpiidentity') . '</div>';
        echo '</td><td>' . __s('Active') . '</td><td>';
        Dropdown::showYesNo('is_active', $this->fields['is_active']);
        echo "<div class='form-text'>"
           . __s('Off means neither sign-in nor provisioning works for this source.', 'glpiidentity')
           . '</div></td></tr>';

        echo $row() . '<td>' . __s('Comments') . "</td><td colspan='3'>";
        echo "<textarea class='form-control' name='comment' rows='2'>" . $e($this->fields['comment']) . '</textarea>';
        echo '</td></tr>';

        $this->showSsoSection($e, $row, $new);
        $this->showScimSection($e, $row, $new);
        $this->showPlacementSection($e, $row);

        $this->showFormButtons($options);
        echo '</div>';

        return true;
    }

    private function showSsoSection(callable $e, callable $row, bool $new): void
    {
        echo "<tr class='tab_bg_2'><th colspan='4'>"
           . "<i class='ti ti-login me-1'></i>" . __s('Single sign-on (OpenID Connect)', 'glpiidentity')
           . '</th></tr>';

        echo $row() . '<td>' . __s('Enabled') . '</td><td>';
        Dropdown::showYesNo('sso_enabled', $this->fields['sso_enabled']);
        echo '</td><td>' . __s('House provider', 'glpiidentity') . '</td><td>';
        Dropdown::showYesNo('is_default', $this->fields['is_default']);
        echo "<div class='form-text'>"
           . __s('Used when a sign-in address matches no configured domain. Typically your own '
               . 'tenant, for your technicians. Only one source can be this.', 'glpiidentity')
           . '</div></td></tr>';

        echo $row() . '<td>' . __s('Issuer', 'glpiidentity') . "</td><td colspan='3'>";
        echo Html::input('issuer', [
            'value'       => $this->fields['issuer'],
            'size'        => 80,
            'placeholder' => 'https://login.microsoftonline.com/<tenant-id>/v2.0',
        ]);
        echo "<div class='form-text'>"
           . __s('The metadata document is read from {issuer}/.well-known/openid-configuration, and '
               . 'the endpoints come from there — you do not fill them in by hand.', 'glpiidentity')
           . '</div></td></tr>';

        echo $row() . '<td>' . __s('Metadata URL', 'glpiidentity') . "</td><td colspan='3'>";
        echo Html::input('discovery_url', [
            'value'       => $this->fields['discovery_url'],
            'size'        => 80,
            'placeholder' => __('Only for a provider that publishes it somewhere else', 'glpiidentity'),
        ]);
        echo "<div class='form-text'>"
           . __s('Leave this empty for a provider that publishes its metadata under the issuer, '
               . 'which is nearly all of them. Azure AD B2C is the exception you will actually '
               . 'meet: its document lives under the user flow rather than under the issuer, at '
               . 'https://tenant.b2clogin.com/tenant.onmicrosoft.com/B2C_1_signin/v2.0/.well-known/openid-configuration. '
               . 'Whatever is read here is authoritative — the issuer field above is overwritten '
               . 'with the one the document declares, which is the value tokens are checked '
               . 'against.', 'glpiidentity')
           . '</div></td></tr>';

        echo $row() . '<td>' . __s('Client ID', 'glpiidentity') . '</td><td>';
        echo Html::input('client_id', ['value' => $this->fields['client_id'], 'size' => 40]);
        echo '</td><td>' . __s('Client secret', 'glpiidentity') . '</td><td>';
        echo "<input type='password' class='form-control' name='client_secret' autocomplete='new-password' value='"
           . ($this->clientSecret() !== '' ? $e(Settings::SECRET_PLACEHOLDER) : '') . "'>";
        echo "<div class='form-text'>" . __s('Stored encrypted with GLPI\'s key.', 'glpiidentity') . '</div>';
        echo '</td></tr>';

        echo $row() . '<td>' . __s('Email domains', 'glpiidentity') . '</td><td>';
        echo Html::input('email_domains', [
            'value'       => $this->fields['email_domains'],
            'size'        => 40,
            'placeholder' => 'acme.com, acme.co.uk',
        ]);
        echo "<div class='form-text'>"
           . __s('Someone typing an address at one of these domains is sent to this provider. A '
               . 'domain can only be claimed by one source.', 'glpiidentity')
           . '</div></td>';
        echo '<td>' . __s('Scopes', 'glpiidentity') . '</td><td>';
        echo Html::input('scopes', ['value' => $this->fields['scopes'], 'size' => 30]);
        echo '</td></tr>';

        echo $row() . '<td>' . __s('Create users on first sign-in', 'glpiidentity') . '</td><td>';
        Dropdown::showYesNo('jit_provision', $this->fields['jit_provision']);
        echo "<div class='form-text'>"
           . __s('On, someone the directory knows about can sign in without having been provisioned '
               . 'first. Off, only accounts SCIM has already created can sign in.', 'glpiidentity')
           . '</div></td>';
        echo '<td>' . __s('Button label', 'glpiidentity') . '</td><td>';
        echo Html::input('button_label', [
            'value'       => $this->fields['button_label'],
            // A worked example, not the format string it is substituted into:
            // a placeholder reading "Sign in with %s" is a leaked sprintf.
            'placeholder' => __('leave empty', 'glpiidentity'),
        ]);
        echo "<div class='form-text'>"
           . __s('Empty — the default — means the login page shows only the email box, which already '
               . 'routes your own staff: an address matching no claimed domain comes here. Fill this '
               . 'in to add a one-click button as well, shown as "Sign in with …". Only the house '
               . 'provider gets one, because a button naming an organisation would put their name on a '
               . 'public page.', 'glpiidentity')
           . '</div>';
        echo '</td></tr>';

        echo "<tr class='tab_bg_1'><td>" . __s('Claims', 'glpiidentity') . "</td><td colspan='3'>";
        echo "<div class='row'>";
        foreach (
            [
                'claim_login'     => __s('Username', 'glpiidentity'),
                'claim_email'     => __s('Email', 'glpiidentity'),
                'claim_firstname' => __s('First name'),
                'claim_lastname'  => __s('Surname'),
                'claim_groups'    => __s('Groups'),
            ] as $field => $label
        ) {
            echo "<div class='col-md-4 mb-2'><label class='form-label'>$label</label>";
            echo Html::input($field, ['value' => $this->fields[$field]]);
            echo '</div>';
        }
        echo '</div>';
        echo "<div class='form-text'>"
           . __s('Which claim carries what. The defaults are right for Entra ID and Okta; Google '
               . 'sends no groups claim at all, so group mapping there needs SCIM.', 'glpiidentity')
           . '</div></td></tr>';

        if (!$new) {
            echo $row() . '<td>' . __s('Provider metadata', 'glpiidentity') . "</td><td colspan='3'>";
            echo "<button type='submit' name='discover' value='1' class='btn btn-sm btn-outline-secondary me-2'>"
               . "<i class='ti ti-refresh me-1'></i>" . __s('Refresh metadata', 'glpiidentity') . '</button>';

            if (!empty($this->fields['discovery_error'])) {
                echo "<div class='alert alert-danger py-2 mt-2'>" . $e($this->fields['discovery_error']) . '</div>';
            } elseif ($this->endpoints() !== []) {
                echo "<div class='small text-muted mt-2'>"
                   . sprintf(
                       __s('Read %s.', 'glpiidentity'),
                       $e(Html::convDateTime($this->fields['date_lastdiscovery']))
                   )
                   . '</div>';
                echo "<table class='table table-sm mt-1'>";
                foreach ($this->endpoints() as $name => $value) {
                    echo '<tr><td><code>' . $e($name) . '</code></td><td class="text-break"><small>'
                       . $e($value) . '</small></td></tr>';
                }
                echo '</table>';
            } else {
                echo "<div class='text-muted mt-2'>"
                   . __s('Not read yet. Save the issuer, then press Refresh metadata.', 'glpiidentity')
                   . '</div>';
            }

            echo "<div class='alert alert-info py-2 mt-2'>"
               . __s('Redirect URI to register in the provider:', 'glpiidentity')
               . ' <code>' . $e(self::redirectUri()) . '</code></div>';

            echo '</td></tr>';
        }
    }

    private function showScimSection(callable $e, callable $row, bool $new): void
    {
        echo "<tr class='tab_bg_2'><th colspan='4'>"
           . "<i class='ti ti-refresh-dot me-1'></i>" . __s('Provisioning (SCIM 2.0)', 'glpiidentity')
           . '</th></tr>';

        echo $row() . '<td>' . __s('Enabled') . '</td><td>';
        Dropdown::showYesNo('scim_enabled', $this->fields['scim_enabled']);
        echo '</td><td>' . __s('When a user is deprovisioned', 'glpiidentity') . '</td><td>';
        Dropdown::showFromArray('deprovision_action', [
            self::DEPROVISION_DISABLE => __('Deactivate the GLPI user', 'glpiidentity'),
            self::DEPROVISION_DELETE  => __('Move the GLPI user to the bin', 'glpiidentity'),
        ], ['value' => $this->fields['deprovision_action']]);
        echo "<div class='form-text'>"
           . __s('Never purged either way. A deleted user takes their ticket history out of every '
               . 'report that joins on them.', 'glpiidentity')
           . '</div></td></tr>';

        echo $row() . '<td>' . __s('Deactivate after (days idle)', 'glpiidentity') . "</td><td colspan='3'>";
        echo Html::input('idle_disable_days', [
            'type'  => 'number',
            'min'   => '0',
            'max'   => '3650',
            'value' => $this->fields['idle_disable_days'],
            'style' => 'max-width: 8rem',
        ]);
        echo "<div class='form-text'>"
           . __s('0 — the default — deactivates nobody. Set it for a source whose organisation has no '
               . 'SCIM connector, because without one nothing will ever tell this GLPI that '
               . 'somebody has left. Only accounts that have actually signed in are considered, '
               . 'somebody still signing in through another source is left alone, and the account '
               . 'is deactivated rather than binned whatever the setting above says.', 'glpiidentity')
           . '</div></td></tr>';

        if ($new) {
            echo $row() . "<td colspan='4'>"
               . __s('Save the source to generate its SCIM endpoint and token.', 'glpiidentity')
               . '</td></tr>';

            return;
        }

        echo $row() . '<td>' . __s('Endpoint', 'glpiidentity') . "</td><td colspan='3'>";
        echo '<code class="text-break">' . $e($this->scimBaseUrl()) . '</code>';
        echo "<div class='form-text'>"
           . __s('The Tenant URL to paste into the provisioning configuration on the provider\'s side.', 'glpiidentity')
           . '</div></td></tr>';

        echo $row() . '<td>' . __s('Bearer token', 'glpiidentity') . "</td><td colspan='3'>";
        echo "<button type='submit' name='rotate_token' value='1' class='btn btn-sm btn-outline-secondary me-2'>"
           . "<i class='ti ti-key me-1'></i>"
           . ($this->hasScimToken()
               ? __s('Generate a new token', 'glpiidentity')
               : __s('Generate a token', 'glpiidentity'))
           . '</button>';

        if ($this->hasScimToken()) {
            echo '<code>' . $e($this->fields['scim_token_hint']) . '…</code>';
            echo "<div class='form-text'>"
               . __s('Only the hash is stored, so the token cannot be shown again. Generating a new '
                   . 'one immediately revokes the old one.', 'glpiidentity')
               . '</div>';
        } else {
            echo "<span class='text-muted'>" . __s('None yet.', 'glpiidentity') . '</span>';
        }

        if (!empty($this->fields['date_lastscim'])) {
            echo "<div class='small text-muted mt-1'>"
               . sprintf(
                   __s('Last request %1$s · %2$d in total.', 'glpiidentity'),
                   $e(Html::convDateTime($this->fields['date_lastscim'])),
                   (int) $this->fields['scim_requests']
               )
               . '</div>';
        }

        echo '</td></tr>';
    }

    private function showPlacementSection(callable $e, callable $row): void
    {
        echo "<tr class='tab_bg_2'><th colspan='4'>"
           . "<i class='ti ti-user-check me-1'></i>" . __s('Placement', 'glpiidentity')
           . '</th></tr>';

        echo $row() . '<td>' . __s('Default profile', 'glpiidentity') . '</td><td>';
        Profile::dropdown([
            'name'  => 'default_profiles_id',
            'value' => $this->fields['default_profiles_id'],
        ]);
        echo "<div class='form-text'>"
           . __s('Granted in this source\'s entity to anyone no mapping gives a profile to. Without '
               . 'it, a user with no matching mapping can authenticate and then cannot use GLPI, '
               . 'which reads as a broken login.', 'glpiidentity')
           . '</div></td>';

        echo '<td>' . __s('Mirror unmapped groups', 'glpiidentity') . '</td><td>';
        Dropdown::showYesNo('mirror_groups', $this->fields['mirror_groups']);
        echo "<div class='form-text'>"
           . __s('On, a directory group that no "Add to GLPI group" mapping picks up becomes a GLPI '
               . 'group of the same name in this entity, and its members follow the directory. Off '
               . '— the default — the directory\'s group names stay on the Directory groups tab and '
               . 'only mapped ones reach GLPI.', 'glpiidentity')
           . '</div></td></tr>';
    }
}
