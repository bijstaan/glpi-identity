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

use Glpi\Application\View\TemplateRenderer;
use Glpi\Security\ReAuth\ReAuthManager;
use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Mapper;
use GlpiPlugin\Glpiidentity\Oidc\Flow;
use GlpiPlugin\Glpiidentity\Oidc\OidcException;
use GlpiPlugin\Glpiidentity\Oidc\ReAuthStrategy;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\SignIn;
use GlpiPlugin\Glpiidentity\Source;
use Symfony\Component\HttpFoundation\Response;

/** @var array $CFG_GLPI */
global $CFG_GLPI;

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
$home   = (string) ($CFG_GLPI['root_doc'] ?? '') . '/index.php';
$prompt = (string) ($CFG_GLPI['root_doc'] ?? '') . '/ReAuth/Prompt';

/**
 * Hand the browser back to GLPI with a page of our own, never a 302.
 *
 * The callback is a cross-site navigation from the identity provider, and
 * GLPI's session cookie is `SameSite=Strict`. A redirect keeps the request in
 * that cross-site chain, so the browser withholds the Strict cookie from the
 * page it lands on: the session built here is never sent back, GLPI starts a
 * fresh one, and the person is on the login page having signed in
 * successfully — with any bounce message lost with it, and nothing in any log.
 * Verified in Chromium. A navigation started by a same-origin page is not
 * cross-site, so the cookie goes with it.
 *
 * A meta refresh rather than script: nothing for a Content-Security-Policy to
 * block, and the link is there for a browser that ignores both.
 */
$land = static function (string $url): Response {
    $href = htmlescape($url);

    return new Response(
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        . '<meta http-equiv="refresh" content="0;url=' . $href . '">'
        . '<meta name="robots" content="noindex">'
        . '<title>' . __s('Signing you in…', 'glpiidentity') . '</title></head>'
        . '<body><p><a href="' . $href . '">' . __s('Continue', 'glpiidentity') . '</a></p></body></html>',
        Response::HTTP_OK,
        [
            'Content-Type'  => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store',
        ]
    );
};

// By reference: a failed sudo-mode confirmation goes back to GLPI's prompt, not
// the home page, and the callback only learns which it is once it has read the
// pending record.
$bounce = static function (string $message) use ($land, &$home): Response {
    if (session_status() === PHP_SESSION_ACTIVE) {
        Session::addMessageAfterRedirect(htmlescape($message), false, ERROR);
    }

    return $land($home);
};

if (!Settings::flag('enabled')) {
    return $bounce(__('Single sign-on is not enabled on this GLPI instance.', 'glpiidentity'));
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
        // address an outsider can use to map the list of organisations.
        EventLog::record(EventLog::SSO_DENIED, null, [
            'error'   => true,
            'subject' => (string) ($_GET['email'] ?? ''),
            'detail'  => 'No usable identity source for this sign-in request.',
        ]);

        return $bounce(__('We could not find a single sign-on provider for that address.', 'glpiidentity'));
    }

    Html::redirect(Flow::begin($source));
}

// ----------------------------------------------------------------- sudo mode

// GLPI's re-authentication prompt submits here (see Oidc\ReAuthStrategy). The
// person is signed in and arrived from a GLPI page, so the session is present.
if ($action === 'reauth') {
    $users_id = (int) Session::getLoginUserID();
    $source   = ReAuthStrategy::sourceFor($users_id);
    if ($source === null) {
        Html::redirect($prompt);
    }

    Html::redirect(Flow::begin($source, '', $users_id));
}

// Second half of a confirmation. The callback verified the provider's answer
// but could not see the session (Strict cookie, cross-site request); this
// request came from our own landing page, so it can.
if ($action === 'reauth-done') {
    $confirmed = Flow::pending();
    Flow::forget();

    $users_id = (int) Session::getLoginUserID();
    if ($users_id <= 0 || (int) ($confirmed['reauth_confirmed'] ?? 0) !== $users_id) {
        Html::redirect($prompt);
    }

    $manager = ReAuthManager::getInstance();
    $manager->authenticate();

    // Exactly what core's ReAuthController does after a password: resubmit the
    // request that asked for sudo mode, POST data included.
    return new Response(TemplateRenderer::getInstance()->render('pages/redirect_post.html.twig', [
        'http_method' => $manager->getRequestedMethod(),
        'url'         => $manager->getRequestedURL(),
        'replay_data' => $manager->getReplayData(),
    ]));
}

// ------------------------------------------------------------------ callback

if ($action !== 'callback') {
    return $bounce(__('Unknown sign-on endpoint.', 'glpiidentity'));
}

$pending = Flow::pending();
if ($pending === null || !isset($pending['state'])) {
    return $bounce(__('That sign-in took too long. Please try again.', 'glpiidentity'));
}

// Consumed whatever happens next: a state that survives a failed attempt is a
// state that can be replayed.
Flow::forget();

$reauth_for = (int) ($pending['reauth_users_id'] ?? 0);
if ($reauth_for > 0) {
    $home = $prompt;

    // The person is signed in, but their session cookie is SameSite=Strict and
    // this is a cross-site request, so it did not come with it. GLPI's kernel
    // has therefore started a *blank* session for this request, and queued its
    // cookie, which would replace theirs and sign them out, whatever the
    // outcome here. Drop both. Nothing in a confirmation needs this session:
    // the result goes to sso.php/reauth-done, which has the real one.
    if (!isset($_COOKIE[session_name()]) && session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
        header_remove('Set-Cookie');
        // header_remove() took the pending-record deletion with it.
        Flow::forget();
    }
}

$source = new Source();
if (!$source->getFromDB((int) $pending['sources_id']) || !$source->ssoReady()) {
    return $bounce(__('That identity source is no longer available.', 'glpiidentity'));
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

    return $bounce(__('The identity provider did not complete the sign-in.', 'glpiidentity'));
}

$state = (string) ($_GET['state'] ?? '');
if ($state === '' || !hash_equals((string) $pending['state'], $state)) {
    // Constant-time, and a hard stop. A mismatched state is either a bug or a
    // login-CSRF attempt, and the two are indistinguishable from here.
    EventLog::record(EventLog::SSO_DENIED, $source, [
        'error'  => true,
        'detail' => 'The callback state did not match the one issued.',
    ]);

    return $bounce(__('We could not sign you in. Please try again.', 'glpiidentity'));
}

$code = (string) ($_GET['code'] ?? '');
if ($code === '') {
    return $bounce(__('We could not sign you in. Please try again.', 'glpiidentity'));
}

try {
    $tokens = Flow::exchange($source, $code, (string) $pending['verifier']);
    $claims = Flow::verify($source, (string) $tokens['id_token'], (string) $pending['nonce']);

    // Ask userinfo only for what is missing. The groups claim is the usual
    // gap — several providers keep it out of the id token entirely.
    //
    // The union is written this way round on purpose: `+` keeps the left
    // operand on collision, so the verified id token has to be on the left. A
    // userinfo response is an ordinary JSON body with no signature over it, and
    // it must be able to add the claim we came for without being able to
    // restate `sub`, the login claim or the address. OIDC Core §5.3.2 asks for
    // the subject check as well, and it is the check that makes the rest of the
    // response safe to read at all.
    $groups_claim = (string) $source->fields['claim_groups'];
    if ($groups_claim !== '' && !isset($claims[$groups_claim])) {
        $extra = Flow::userinfo($source, (string) ($tokens['access_token'] ?? ''));

        if (($extra['sub'] ?? null) === ($claims['sub'] ?? null)) {
            $claims += $extra;
        } elseif ($extra !== []) {
            EventLog::record(EventLog::SSO_DENIED, $source, [
                'error'  => true,
                'detail' => 'The userinfo response was for a different subject than the id token; ignored.',
            ]);
        }
    }
} catch (OidcException $e) {
    EventLog::record(EventLog::SSO_DENIED, $source, ['error' => true, 'detail' => $e->getMessage()]);

    return $bounce(__('We could not sign you in. Please try again.', 'glpiidentity'));
}

if ($reauth_for > 0) {
    // A sudo-mode confirmation, not a sign-in: nothing about the account is
    // created, adopted or updated. It passes only if the provider vouched for
    // the *same* linked account, and authenticated it after we asked.
    $link = Link::forSubject($source->getID(), (string) ($claims['sub'] ?? ''));

    if ($link === null || (int) $link->fields['users_id'] !== $reauth_for) {
        EventLog::record(EventLog::SSO_DENIED, $source, [
            'error'    => true,
            'users_id' => $reauth_for,
            'detail'   => 'Re-authentication answered for a different account than the one signed in.',
        ]);

        return $bounce(__('That was a different account. Sign in again as yourself to continue.', 'glpiidentity'));
    }

    if (!Flow::authenticatedSince($claims, (int) ($pending['started'] ?? 0))) {
        EventLog::record(EventLog::SSO_DENIED, $source, [
            'error'    => true,
            'users_id' => $reauth_for,
            'detail'   => 'Re-authentication refused: the provider did not report a fresh sign-in (auth_time).',
        ]);

        return $bounce(__('Your sign-in could not be confirmed. Please try again.', 'glpiidentity'));
    }

    Flow::rememberReauth($reauth_for, (int) $source->getID());

    EventLog::record(EventLog::SSO_LOGIN, $source, [
        'users_id' => $reauth_for,
        'detail'   => 'Re-authenticated for a sensitive action.',
    ]);

    return $land(GlpiPlugin\Glpiidentity\Url::to('front/sso.php/reauth-done'));
}

$result = SignIn::complete($source, $claims);

if (!$result['ok']) {
    // SignIn has already logged the detail; what reaches the user is the
    // subset that is theirs to act on.
    return $bounce(
        str_contains($result['message'], 'deactivated')
            ? __('That account is deactivated. Contact your IT support.', 'glpiidentity')
            : __('We could not sign you in. Please contact your IT support.', 'glpiidentity')
    );
}

return $land($home);
