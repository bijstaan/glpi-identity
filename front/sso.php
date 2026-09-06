<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The two halves of an OpenID Connect sign-in.
 *
 *   /front/sso.php/start     — work out which provider, and go there
 *   /front/sso.php/callback  — verify what came back, and establish the session
 *
 * Runs with GLPI's session check turned off, because this is where somebody
 * arrives who does not have a session yet. It starts one — the state, nonce and
 * PKCE verifier have to survive the round trip to the provider — but grants
 * nothing until the callback has verified a token.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\Mapper;
use GlpiPlugin\Glpiidentity\Oidc\Flow;
use GlpiPlugin\Glpiidentity\Oidc\OidcException;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\SignIn;
use GlpiPlugin\Glpiidentity\Source;

Session::start();

$path   = trim(GlpiPlugin\Glpiidentity\Url::pathAfter('sso.php'), '/');
$action = $path === '' ? 'start' : $path;

/**
 * Back to the login page with something to read.
 *
 * The message shown is deliberately vague where the detail would help an
 * attacker and specific where it would help a person: "we could not sign you
 * in" for anything to do with verification, and the real reason for the two
 * cases a user can act on — a deactivated account, and an unknown domain.
 */
$bounce = static function (string $message): never {
    Session::addMessageAfterRedirect(Html::entities_deep($message), false, ERROR);
    Html::redirect((string) ($CFG_GLPI['root_doc'] ?? '') . '/index.php');
};

if (!Settings::flag('enabled')) {
    $bounce(__('Single sign-on is not enabled on this GLPI instance.', 'glpiidentity'));
}

// --------------------------------------------------------------------- start

if ($action === 'start') {
    $source = null;

    if (!empty($_GET['source'])) {
        $candidate = new Source();
        if ($candidate->getFromDB((int) $_GET['source']) && $candidate->ssoReady()) {
            // Only a provider offered on the login page can be started by id.
            // Otherwise the id is a way to enumerate which sources exist.
            if ((int) $candidate->fields['is_default'] === 1 || $candidate->domains() !== []) {
                $source = $candidate;
            }
        }
    } elseif (!empty($_GET['email'])) {
        $source = Source::forEmail((string) $_GET['email']) ?? Source::houseDefault();
    }

    if ($source === null || !$source->ssoReady()) {
        // The same answer whether the domain is unknown or the source is
        // misconfigured: an address that gets a different response is an
        // address an outsider can use to map the customer list.
        EventLog::record(EventLog::SSO_DENIED, null, [
            'error'   => true,
            'subject' => (string) ($_GET['email'] ?? ''),
            'detail'  => 'No usable identity source for this sign-in request.',
        ]);

        $bounce(__('We could not find a single sign-on provider for that address.', 'glpiidentity'));
    }

    Html::redirect(Flow::begin($source));
}

// ------------------------------------------------------------------ callback

if ($action !== 'callback') {
    $bounce(__('Unknown sign-on endpoint.', 'glpiidentity'));
}

$pending = Flow::pending();
if ($pending === null) {
    $bounce(__('That sign-in took too long. Please try again.', 'glpiidentity'));
}

// Consumed whatever happens next: a state that survives a failed attempt is a
// state that can be replayed.
Flow::forget();

$source = new Source();
if (!$source->getFromDB((int) $pending['sources_id']) || !$source->ssoReady()) {
    $bounce(__('That identity source is no longer available.', 'glpiidentity'));
}

// The provider reporting a refusal — consent declined, or the account blocked.
if (!empty($_GET['error'])) {
    EventLog::record(EventLog::SSO_DENIED, $source, [
        'error'  => true,
        'detail' => sprintf(
            '%s: %s',
            (string) $_GET['error'],
            (string) ($_GET['error_description'] ?? '')
        ),
    ]);

    $bounce(__('The identity provider did not complete the sign-in.', 'glpiidentity'));
}

$state = (string) ($_GET['state'] ?? '');
if ($state === '' || !hash_equals((string) $pending['state'], $state)) {
    // Constant-time, and a hard stop. A mismatched state is either a bug or a
    // login-CSRF attempt, and the two are indistinguishable from here.
    EventLog::record(EventLog::SSO_DENIED, $source, [
        'error'  => true,
        'detail' => 'The callback state did not match the one issued.',
    ]);

    $bounce(__('We could not sign you in. Please try again.', 'glpiidentity'));
}

$code = (string) ($_GET['code'] ?? '');
if ($code === '') {
    $bounce(__('We could not sign you in. Please try again.', 'glpiidentity'));
}

try {
    $tokens = Flow::exchange($source, $code, (string) $pending['verifier']);
    $claims = Flow::verify($source, (string) $tokens['id_token'], (string) $pending['nonce']);

    // Ask userinfo only for what is missing. The groups claim is the usual
    // gap — several providers keep it out of the id token entirely.
    $groups_claim = (string) $source->fields['claim_groups'];
    if ($groups_claim !== '' && !isset($claims[$groups_claim])) {
        $claims = Flow::userinfo($source, (string) ($tokens['access_token'] ?? '')) + $claims;
    }
} catch (OidcException $e) {
    EventLog::record(EventLog::SSO_DENIED, $source, ['error' => true, 'detail' => $e->getMessage()]);

    $bounce(__('We could not sign you in. Please try again.', 'glpiidentity'));
}

$result = SignIn::complete($source, $claims);

if (!$result['ok']) {
    // SignIn has already logged the detail; what reaches the user is the
    // subset that is theirs to act on.
    $bounce(
        str_contains($result['message'], 'deactivated')
            ? __('That account is deactivated. Contact your IT support.', 'glpiidentity')
            : __('We could not sign you in. Please contact your IT support.', 'glpiidentity')
    );
}

Html::redirect((string) ($CFG_GLPI['root_doc'] ?? '') . '/index.php');
