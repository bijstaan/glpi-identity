<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Oidc;

use Glpi\Security\ReAuth\ReAuthStrategyInterface;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;
use GlpiPlugin\Glpiidentity\Url;
use Symfony\Component\HttpFoundation\Request;

/**
 * GLPI 12's "sudo mode" for people who sign in through an identity provider.
 *
 * Before an administrator touches something sensitive (a user, a group, a
 * profile), GLPI asks them to prove it is still them, using the strongest
 * strategy available to the account. Core offers GLPI TOTP, a local password
 * and LDAP, and when none of those applies it falls back to a *Confirm* button
 * that always succeeds. An account that only ever signs in through SSO has no
 * password and no LDAP bind, so without this class every such administrator
 * would pass sudo mode by clicking a button.
 *
 * This strategy sends them back to their provider instead, asking for a fresh
 * authentication (`prompt=login`, `max_age=0`). The provider's own MFA applies,
 * and the answer only counts if it is for the same linked account and was
 * authenticated after the request left. The work is done in front/sso.php;
 * {@see getVerifyUrl()} points the prompt there, which is the extension point
 * core documents for verification by an external service.
 *
 * Priority 75: above a local password and LDAP (50), since an SSO-linked
 * account's real credential is at the provider, and below GLPI's own TOTP
 * (100), which an administrator who configured it clearly meant to use.
 */
final class ReAuthStrategy implements ReAuthStrategyInterface
{
    /** Never reached: the prompt posts to front/sso.php, not /ReAuth/Verify. */
    public function verify(int $users_id, Request $request): bool
    {
        return false;
    }

    public function getVerifyUrl(): string
    {
        return Url::to('front/sso.php/reauth');
    }

    public function getVerifyHttpMethod(): string
    {
        return 'GET';
    }

    public function isAvailable(int $users_id, int $entities_id = 0): bool
    {
        return Settings::flag('enabled') && self::sourceFor($users_id) !== null;
    }

    public function getLabel(): string
    {
        $source = self::sourceFor((int) ($_SESSION['glpiID'] ?? 0));

        return $source === null
            ? __('Single sign-on', 'glpiidentity')
            : sprintf(__('Sign in again with %s', 'glpiidentity'), (string) $source->fields['name']);
    }

    public function getPromptTemplate(): string
    {
        return '@glpiidentity/reauth_prompt.html.twig';
    }

    public function getPriority(): int
    {
        return 75;
    }

    /**
     * The source this user can re-authenticate against, if any.
     *
     * Only a link that has been bound to a subject counts. An invited or
     * SCIM-provisioned account that has never signed in has no subject yet,
     * and there would be nothing to compare the provider's answer with.
     */
    public static function sourceFor(int $users_id): ?Source
    {
        if ($users_id <= 0) {
            return null;
        }

        foreach (Link::allForUser($users_id) as $link) {
            if ((string) $link->fields['subject'] === '') {
                continue;
            }
            $source = new Source();
            if ($source->getFromDB((int) $link->fields['plugin_glpiidentity_sources_id']) && $source->ssoReady()) {
                return $source;
            }
        }

        return null;
    }
}
