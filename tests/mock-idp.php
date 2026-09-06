<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * A stand-in OpenID Connect provider.
 *
 * Enough of one to exercise the whole sign-in: discovery, an authorisation
 * endpoint that redirects straight back, a token endpoint that mints a real
 * RS256 id token, a JWKS document that verifies it, and userinfo.
 *
 * It signs properly rather than stubbing the verification out, because
 * verification is the part worth testing — a mock that returned an unsigned
 * token would let every one of {@see Oidc\Flow}'s checks rot unnoticed.
 *
 * The signing key is generated once and cached on disk: `php -S` handles each
 * request in a fresh process, so a key made per request would never match the
 * JWKS the client fetched a moment earlier.
 *
 * Behaviours selected by query parameter, for the unhappy paths:
 *   ?claims=nogroups    omit the groups claim from the id token
 *   ?bad=signature      sign with a different key
 *   ?bad=issuer         claim a different issuer
 *   ?bad=audience       issue for a different client
 *   ?bad=nonce          echo the wrong nonce
 *
 * Run inside the GLPI container:
 *   php -S 127.0.0.1:9097 tests/mock-idp.php
 */

require '/var/www/glpi/vendor/autoload.php';

use Firebase\JWT\JWT;

const BASE     = 'http://127.0.0.1:9097';
const CLIENT   = 'glpi-test-client';
const KEY_FILE = '/tmp/glpiidentity-idp-key.pem';
const ALT_FILE = '/tmp/glpiidentity-idp-alt.pem';
const STATE    = '/tmp/glpiidentity-idp-state.json';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

/** The signing key, made once and kept. */
function keypair(string $file): array
{
    if (!file_exists($file)) {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $pem);
        file_put_contents($file, $pem);
    }

    $pem     = (string) file_get_contents($file);
    $private = openssl_pkey_get_private($pem);
    $details = openssl_pkey_get_details($private);

    return ['private' => $pem, 'n' => $details['rsa']['n'], 'e' => $details['rsa']['e']];
}

function b64u(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function json_out(array $payload): never
{
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

// ------------------------------------------------------------------ metadata

if (str_contains($path, '/.well-known/openid-configuration')) {
    json_out([
        'issuer'                 => BASE,
        'authorization_endpoint' => BASE . '/authorize',
        'token_endpoint'         => BASE . '/token',
        'jwks_uri'               => BASE . '/jwks',
        'userinfo_endpoint'      => BASE . '/userinfo',
        'response_types_supported' => ['code'],
        'subject_types_supported'  => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
    ]);
}

if ($path === '/jwks') {
    $key = keypair(KEY_FILE);

    json_out([
        'keys' => [[
            'kty' => 'RSA',
            'use' => 'sig',
            'kid' => 'mock-key-1',
            // Deliberately no `alg`. Entra's JWKS omits it too, and a client
            // that cannot cope skips the key and fails every sign-in with
            // "kid not found" — which reads like a key rotation problem.
            'n'   => b64u($key['n']),
            'e'   => b64u($key['e']),
        ]],
    ]);
}

// ------------------------------------------------------------- authorisation

if ($path === '/authorize') {
    // No login screen: the point of this endpoint here is the redirect back,
    // carrying the code and echoing the state.
    $redirect = (string) ($_GET['redirect_uri'] ?? '');
    $state    = (string) ($_GET['state'] ?? '');

    file_put_contents(STATE, json_encode([
        'nonce'          => (string) ($_GET['nonce'] ?? ''),
        'code_challenge' => (string) ($_GET['code_challenge'] ?? ''),
        'scope'          => (string) ($_GET['scope'] ?? ''),
        'client_id'      => (string) ($_GET['client_id'] ?? ''),
        'redirect_uri'   => $redirect,
        // Carried through so a test can ask for a broken token later.
        'bad'            => (string) ($_GET['bad'] ?? ''),
        'claims'         => (string) ($_GET['claims'] ?? ''),
    ]));

    $separator = str_contains($redirect, '?') ? '&' : '?';
    header('Location: ' . $redirect . $separator . http_build_query([
        'code'  => 'mock-authorization-code',
        'state' => $state,
    ]));
    http_response_code(302);
    exit;
}

// -------------------------------------------------------------------- tokens

if ($path === '/token') {
    $pending = json_decode((string) @file_get_contents(STATE), true) ?: [];
    $posted  = [];
    parse_str((string) file_get_contents('php://input'), $posted);

    // Assert the client did its half properly, because a mock that accepts
    // anything cannot fail a client that sends nothing.
    if (($posted['grant_type'] ?? '') !== 'authorization_code') {
        json_out(['error' => 'unsupported_grant_type']);
    }

    if (($posted['client_id'] ?? '') !== CLIENT || ($posted['client_secret'] ?? '') === '') {
        json_out(['error' => 'invalid_client', 'error_description' => 'Wrong client id or missing secret.']);
    }

    // PKCE: the verifier must hash to the challenge sent at /authorize.
    $verifier  = (string) ($posted['code_verifier'] ?? '');
    $challenge = b64u(hash('sha256', $verifier, true));
    if ($verifier === '' || $challenge !== ($pending['code_challenge'] ?? '')) {
        json_out(['error' => 'invalid_grant', 'error_description' => 'PKCE verification failed.']);
    }

    $bad = (string) ($pending['bad'] ?? '');

    $claims = [
        'iss'                => $bad === 'issuer' ? 'https://somewhere.else/' : BASE,
        'aud'                => $bad === 'audience' ? 'a-different-client' : CLIENT,
        'sub'                => 'mock-subject-0001',
        'nonce'              => $bad === 'nonce' ? 'not-the-nonce' : (string) ($pending['nonce'] ?? ''),
        'iat'                => time(),
        'exp'                => time() + 300,
        'preferred_username' => 'alice@acme.test',
        'email'              => 'alice@acme.test',
        'given_name'         => 'Alice',
        'family_name'        => 'Anderson',
    ];

    if (($pending['claims'] ?? '') !== 'nogroups') {
        $claims['groups'] = ['Executive', 'All Staff'];
    }

    $key = keypair($bad === 'signature' ? ALT_FILE : KEY_FILE);

    json_out([
        'token_type'   => 'Bearer',
        'expires_in'   => 300,
        'access_token' => 'mock-access-token',
        'id_token'     => JWT::encode($claims, $key['private'], 'RS256', 'mock-key-1'),
    ]);
}

// ------------------------------------------------------------------ userinfo

if ($path === '/userinfo') {
    if (!preg_match('/^Bearer\s+\S+/i', (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? ''))) {
        http_response_code(401);
        json_out(['error' => 'invalid_token']);
    }

    // The groups an id token left out. This is the shape Entra uses when a
    // user is in too many groups for the token to carry them.
    json_out([
        'sub'    => 'mock-subject-0001',
        'email'  => 'alice@acme.test',
        'groups' => ['Executive', 'All Staff'],
    ]);
}

http_response_code(404);
json_out(['error' => 'not_found', 'path' => $path]);
