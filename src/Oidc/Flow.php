<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Glpi\Cache\CacheManager;
use GLPIKey;
use GlpiPlugin\Glpiidentity\Source;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\TransferException;

/**
 * The authorisation-code flow, with the checks that make it an authentication.
 *
 * OAuth2 answers "may this application act for someone"; OIDC turns that into
 * "and here is who". The difference is entirely in the verification, and each
 * of the checks below exists because skipping it is a known, named attack:
 *
 *  - **signature**, against the provider's published keys — without it the id
 *    token is a claim anybody can make;
 *  - **issuer**, against the discovered metadata — without it a token from one
 *    tenant is accepted by another;
 *  - **audience**, against our client id — without it a token minted for a
 *    different application is accepted here;
 *  - **nonce**, against the value we generated — without it a token captured
 *    from an earlier sign-in can be replayed;
 *  - **state**, against the value we generated — without it the callback can be
 *    forged, logging a victim into an attacker's account.
 *
 * PKCE is used as well, which the spec makes optional for confidential clients
 * and which costs one hash.
 */
final class Flow
{
    /**
     * Where the pending sign-in is kept, and why it is not the GLPI session.
     *
     * GLPI issues its session cookie with `SameSite=Strict`, which is a good
     * setting and is fatal here: the callback is a cross-site top-level
     * navigation from the identity provider, and a Strict cookie is not sent on
     * one. The session that holds the state and nonce would simply not be there,
     * and every sign-in would fail with "that took too long".
     *
     * So the pending record travels in a cookie of this plugin's own, marked
     * `SameSite=Lax` — which permits exactly this case, a top-level GET — and
     * encrypted with GLPI's key. Encryption rather than a signature because the
     * nonce and PKCE verifier are in it and neither should be readable; GLPI's
     * key uses authenticated encryption, so integrity comes with it and a
     * forged cookie is rejected rather than parsed.
     */
    private const COOKIE = 'glpiidentity_sso';

    /** Tolerance for clock drift when checking token times. */
    private const LEEWAY = 60;

    /**
     * Ten minutes: long enough for a password, a second factor and a consent
     * screen; short enough that a stale tab is not a valid callback tomorrow.
     */
    private const LIFETIME = 600;

    /**
     * Begin a sign-in: remember what we will need to verify, and say where to go.
     */
    public static function begin(Source $source, string $return_to = ''): string
    {
        $state    = bin2hex(random_bytes(16));
        $nonce    = bin2hex(random_bytes(16));
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        self::remember([
            'sources_id' => $source->getID(),
            'state'      => $state,
            'nonce'      => $nonce,
            'verifier'   => $verifier,
            'expires'    => time() + self::LIFETIME,
        ]);

        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $parameters = [
            'response_type'         => 'code',
            'client_id'             => (string) $source->fields['client_id'],
            'redirect_uri'          => Source::redirectUri(),
            'scope'                 => (string) $source->fields['scopes'],
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => $challenge,
            'code_challenge_method' => 'S256',
        ];

        $endpoint = $source->endpoint('authorization_endpoint');

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($parameters);
    }

    /** @param array<string,mixed> $pending */
    private static function remember(array $pending): void
    {
        $sealed = (new GLPIKey())->encrypt(json_encode($pending, JSON_THROW_ON_ERROR));

        setcookie(self::COOKIE, $sealed, self::cookieOptions(time() + self::LIFETIME));
    }

    /**
     * The attributes this plugin's cookie is written with, in one place.
     *
     * Both writes have to agree. A cookie is identified by name, domain, path
     * *and* whether it is Secure, so a deletion that omits `secure` does not
     * reliably replace the Secure cookie it is trying to clear — the browser
     * may keep the original and go on presenting the pending sign-in for the
     * rest of its ten minutes. {@see forget()} and {@see remember()} therefore
     * share this.
     *
     * `secure` is decided from url_base, which is what {@see Url::absolute()}
     * builds the redirect URI from and so is the scheme the browser will
     * actually be on. The live request's own scheme is consulted as well,
     * because an installation whose url_base is unset or stale would otherwise
     * write this cookie in the clear over a real TLS connection. Trusting the
     * request here is safe in the direction that matters: the only thing a
     * forged value can do is turn Secure *on*, which costs a sign-in over
     * plaintext rather than leaking one. Forwarded headers are deliberately not
     * read — a TLS-terminating proxy is already covered by url_base.
     *
     * @return array<string,mixed>
     */
    private static function cookieOptions(int $expires): array
    {
        global $CFG_GLPI;

        $on = strtolower((string) ($_SERVER['HTTPS'] ?? ''));

        $https = str_starts_with(strtolower((string) ($CFG_GLPI['url_base'] ?? '')), 'https://')
            || ($on !== '' && $on !== 'off')
            || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;

        return [
            'expires'  => $expires,
            'path'     => rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . '/',
            'secure'   => $https,
            'httponly' => true,
            // The whole point. Strict would not survive the return trip.
            'samesite' => 'Lax',
        ];
    }

    /** @return array<string,mixed>|null the pending sign-in, if there is one */
    public static function pending(): ?array
    {
        $sealed = (string) ($_COOKIE[self::COOKIE] ?? '');
        if ($sealed === '') {
            return null;
        }

        $plain = (new GLPIKey())->decrypt($sealed);
        if (!is_string($plain) || $plain === '') {
            // Undecryptable: a forgery, or a cookie written before GLPI's key
            // was rotated. Cleared rather than merely ignored — a cookie that
            // can never be read again should not be presented on every
            // subsequent request for the next ten minutes.
            self::forget();

            return null;
        }

        $pending = json_decode($plain, true);
        if (!is_array($pending) || (int) ($pending['expires'] ?? 0) < time()) {
            self::forget();

            return null;
        }

        return $pending;
    }

    public static function forget(): void
    {
        unset($_COOKIE[self::COOKIE]);

        setcookie(self::COOKIE, '', self::cookieOptions(time() - 3600));
    }

    /**
     * Swap the authorisation code for tokens.
     *
     * @return array<string,mixed>
     * @throws OidcException
     */
    public static function exchange(Source $source, string $code, string $verifier): array
    {
        try {
            $response = (new HttpClient())->post($source->endpoint('token_endpoint'), [
                'form_params' => [
                    'grant_type'    => 'authorization_code',
                    'code'          => $code,
                    'redirect_uri'  => Source::redirectUri(),
                    'client_id'     => (string) $source->fields['client_id'],
                    'client_secret' => $source->clientSecret(),
                    'code_verifier' => $verifier,
                ],
                'timeout'     => 20,
                'http_errors' => false,
                'headers'     => ['Accept' => 'application/json'],
            ]);
        } catch (TransferException $e) {
            throw new OidcException('Could not reach the identity provider: ' . $e->getMessage());
        }

        $body    = (string) $response->getBody();
        $decoded = json_decode($body, true);

        if (!is_array($decoded)) {
            throw new OidcException('The identity provider returned an unreadable token response.');
        }

        if ($response->getStatusCode() >= 400 || isset($decoded['error'])) {
            // The provider's own error, because `invalid_client` and
            // `invalid_grant` mean completely different things to whoever has
            // to fix it.
            throw new OidcException(sprintf(
                'The identity provider refused the token request: %s %s',
                (string) ($decoded['error'] ?? $response->getStatusCode()),
                (string) ($decoded['error_description'] ?? '')
            ));
        }

        if (empty($decoded['id_token'])) {
            throw new OidcException('The token response carried no id_token — check that the "openid" scope is requested.');
        }

        return $decoded;
    }

    /**
     * Verify an id token and return its claims.
     *
     * @return array<string,mixed>
     * @throws OidcException
     */
    public static function verify(Source $source, string $id_token, string $nonce): array
    {
        JWT::$leeway = self::LEEWAY;

        try {
            $claims = (array) JWT::decode($id_token, self::keys($source));
        } catch (\Throwable $e) {
            // Covers a bad signature, an expired token and an unknown key
            // alike. The distinction is not useful to the person signing in,
            // and spelling it out to a caller is a small oracle.
            throw new OidcException('The identity token did not verify: ' . $e->getMessage());
        }

        $issuer = (string) ($claims['iss'] ?? '');
        if ($issuer === '' || rtrim($issuer, '/') !== rtrim($source->endpoint('issuer'), '/')) {
            throw new OidcException('The identity token came from a different issuer than this source.');
        }

        $audience = $claims['aud'] ?? '';
        $accepted = is_array($audience) ? array_map('strval', $audience) : [(string) $audience];
        if (!in_array((string) $source->fields['client_id'], $accepted, true)) {
            throw new OidcException('The identity token was issued for a different application.');
        }

        if ((string) ($claims['nonce'] ?? '') !== $nonce) {
            throw new OidcException('The identity token did not carry the expected nonce.');
        }

        if ((string) ($claims['sub'] ?? '') === '') {
            throw new OidcException('The identity token carried no subject.');
        }

        return $claims;
    }

    /**
     * The provider's signing keys, cached.
     *
     * Cached because a JWKS fetch on every sign-in puts the provider on the
     * critical path twice, and only briefly — providers rotate keys, and a key
     * set held for a day is a sign-in outage on the day they do. Fifteen
     * minutes is short enough to ride out a rotation and long enough to matter.
     *
     * @return array<string,\Firebase\JWT\Key>
     * @throws OidcException
     */
    private static function keys(Source $source): array
    {
        $uri   = $source->endpoint('jwks_uri');
        $key   = 'jwks_' . hash('sha256', $uri);
        $cache = (new CacheManager())->getCacheInstance('plugin:glpiidentity');

        $document = $cache->get($key);

        if (!is_array($document)) {
            try {
                $response = (new HttpClient())->get($uri, [
                    'timeout'     => 15,
                    'http_errors' => false,
                    'headers'     => ['Accept' => 'application/json'],
                ]);
            } catch (TransferException $e) {
                throw new OidcException('Could not fetch the provider signing keys: ' . $e->getMessage());
            }

            if ($response->getStatusCode() >= 400) {
                throw new OidcException(sprintf('The provider key set returned HTTP %d.', $response->getStatusCode()));
            }

            $document = json_decode((string) $response->getBody(), true);
            if (!is_array($document) || empty($document['keys'])) {
                throw new OidcException('The provider key set was not a JWKS document.');
            }

            $cache->set($key, $document, 900);
        }

        try {
            // The default algorithm covers key entries that omit `alg`, which
            // Entra's do. Without it those keys are skipped and every sign-in
            // fails with "kid not found", which reads like a rotation problem.
            return JWK::parseKeySet($document, 'RS256');
        } catch (\Throwable $e) {
            throw new OidcException('The provider key set could not be parsed: ' . $e->getMessage());
        }
    }

    /**
     * The userinfo endpoint, for claims the id token did not carry.
     *
     * Worth asking only when something is missing. Entra, for instance, omits
     * `groups` from the id token once a user is in more than about 150 of them
     * and sends an overage claim instead; other providers keep the id token
     * minimal on principle.
     *
     * @return array<string,mixed>
     */
    public static function userinfo(Source $source, string $access_token): array
    {
        $endpoint = $source->endpoint('userinfo_endpoint');
        if ($endpoint === '' || $access_token === '') {
            return [];
        }

        try {
            $response = (new HttpClient())->get($endpoint, [
                'headers'     => [
                    'Authorization' => 'Bearer ' . $access_token,
                    'Accept'        => 'application/json',
                ],
                'timeout'     => 15,
                'http_errors' => false,
            ]);
        } catch (TransferException $e) {
            // Not fatal: the id token already established who this is, and
            // userinfo is only ever filling in detail.
            return [];
        }

        if ($response->getStatusCode() >= 400) {
            return [];
        }

        $decoded = json_decode((string) $response->getBody(), true);

        return is_array($decoded) ? $decoded : [];
    }
}
