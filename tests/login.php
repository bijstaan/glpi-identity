<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * What the login page offers, and when it offers nothing.
 *
 * The block renders inside GLPI's own login form and, when local login is
 * switched off, takes that form off the page. So "what does this emit" is a
 * question about whether an administrator can still get in, not only about
 * whether a control looks right.
 *
 * The regression under test: the email box used to require that some source had
 * claimed a domain. A house provider is reached *without* one — an address at no
 * claimed domain falls back to it — so the commonest single-organisation setup
 * there is (one house provider, no domains claimed, because there is nobody else
 * to route to) rendered a heading over an empty box. With local login also off,
 * that page then removed GLPI's password form and offered no way in at all bar
 * the `?local=1` link.
 *
 * Usage, inside the GLPI container:
 *   php tests/login.php
 */

require '/var/www/glpi/vendor/autoload.php';

(new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();

use GlpiPlugin\Glpiidentity\LoginButtons;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;

if (!(new Auth())->login('glpi', 'glpi', true)) {
    fwrite(STDERR, "could not log in as glpi/glpi\n");
    exit(1);
}

(new Plugin())->init(true);

$failures = [];

function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    echo ($ok ? "  \033[32mPASS\033[0m  " : "  \033[31mFAIL\033[0m  ") . $name
       . ($detail !== '' ? " :: $detail" : '') . "\n";
    if (!$ok) {
        $failures[] = $name;
    }
}

// ------------------------------------------------------------------ fixtures

/**
 * A source that is never saved.
 *
 * canRoute() reads two fields and nothing else, and persisting these would mean
 * creating a second house provider — which prepareInput refuses outright when
 * the instance already has one. An unsaved object states the case exactly and
 * cannot disturb a configured instance.
 */
$src = static function (string $domains, int $is_default): Source {
    $source                 = new Source();
    $source->fields         = ['email_domains' => $domains, 'is_default' => $is_default];

    return $source;
};

// Restore whatever this instance had. These are real settings on a real
// install; the suite is not entitled to leave them changed.
$before = Settings::all();

register_shutdown_function(static function () use ($before): void {
    Settings::save([
        'enabled'           => (string) $before['enabled'],
        'allow_local_login' => (string) $before['allow_local_login'],
    ]);
});

// ------------------------------------------------------------- what routes

echo "\nWhether the box has somewhere to send people\n";

check(
    'a house provider alone is a route, with no domain claimed',
    LoginButtons::canRoute([$src('', 1)])
);

check(
    'a claimed domain is a route, with no house provider',
    LoginButtons::canRoute([$src('example.com', 0)])
);

check(
    'both together is still a route',
    LoginButtons::canRoute([$src('example.com', 1)])
);

check(
    'one house provider among several sources is enough',
    LoginButtons::canRoute([$src('', 0), $src('', 1), $src('', 0)])
);

check(
    'neither is not a route',
    !LoginButtons::canRoute([$src('', 0)])
);

check(
    'no ready source at all is not a route',
    !LoginButtons::canRoute([])
);

// --------------------------------------------------------------- the markup

echo "\nThe rendered block\n";

Settings::save(['enabled' => '0']);
check(
    'nothing is emitted while the master switch is off',
    LoginButtons::render() === ''
);

Settings::save(['enabled' => '1']);

$ready  = array_values(array_filter(Source::activeSso(), static fn(Source $s): bool => $s->ssoReady()));
$routes = LoginButtons::canRoute($ready);
$html   = LoginButtons::render();

echo '  ' . count($ready) . " ready source(s) on this instance; "
   . ($routes ? "they offer a route\n" : "they offer no route\n");

if ($routes) {
    check(
        'the email box is rendered whenever a route exists',
        str_contains($html, "id='glpiidentity-email'"),
        'the box is the only control for anyone without a button'
    );
    check(
        'and its Continue button with it',
        str_contains($html, "id='glpiidentity-continue'")
    );
} else {
    check(
        'a block with no route emits nothing at all',
        $html === '',
        'a heading over an empty box is worse than no block'
    );
}

// ------------------------------------------------- the form it can take away

echo "\nRemoving GLPI's own login form\n";

// The dangerous combination: local login off, and nothing this plugin renders
// can sign anybody in. Whatever else happens, the page must not lose the
// password form on the way.
Settings::save(['allow_local_login' => '0']);
$html = LoginButtons::render();

check(
    'the password form is only removed when there is a route to replace it',
    $routes || $html === '',
    'no route and no password form is a page nobody can sign in on'
);

check(
    'the escape hatch is offered whenever local login is hidden',
    $html === '' || str_contains($html, 'local=1'),
    'the link to ?local=1 is the way back in'
);

check(
    'with a route and local login off, the form is removed',
    !$routes || str_contains($html, 'if (true) {'),
    'that is the single-sign-on-only page working as intended'
);

Settings::save(['allow_local_login' => '1']);
$html = LoginButtons::render();

check(
    'nothing is removed while local login is on',
    $html === '' || str_contains($html, 'if (false) {'),
    'the removal is compiled out, not merely skipped at runtime'
);

echo "\n" . ($failures === []
    ? "\033[32mall checks passed\033[0m\n"
    : "\033[31mFAILED\033[0m: " . implode('; ', $failures) . "\n");

exit($failures === [] ? 0 : 1);
