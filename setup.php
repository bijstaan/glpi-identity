<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */
/**
 * GLPI Identity — OpenID Connect sign-in and SCIM provisioning, per entity.
 *
 * A GLPI instance can hold several organisations' people. This plugin lets each
 * of them bring their own identity provider: their users sign in with their own
 * IdP, are provisioned into their own entity by their own SCIM connector, and
 * are placed into GLPI groups and profiles by rules written against the groups
 * and claims their IdP actually sends.
 *
 * The unit of configuration is an {@see Source} — one organisation's identity
 * setup — because that is the boundary that matters: a mistake in Acme's
 * mapping must not be able to give an Acme user rights in Beta's entity.
 *
 * OIDC only, no SAML. GLPI already ships league/oauth2-client and
 * firebase/php-jwt, so OIDC costs no new dependency, and every IdP you are
 * likely to meet — Entra, Okta, Google, Auth0, Keycloak, JumpCloud — speaks
 * it. SAML would mean vendoring an XML-signature library into a GLPI install,
 * and XML signature verification is the one place where a subtle mistake is a
 * silent authentication bypass rather than an error.
 */

use Glpi\Http\Firewall;
use Glpi\Http\SessionManager;
use Glpi\Plugin\Hooks;
use GlpiPlugin\Glpiidentity\IdpGroup;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\AttributeMap;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Source;

define('PLUGIN_GLPIIDENTITY_VERSION', '0.3.0');
define('PLUGIN_GLPIIDENTITY_MIN_GLPI', '11.0');

define('PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT', 'plugin:glpiidentity');

function plugin_init_glpiidentity()
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['glpiidentity'] = true;

    // The plugin's rights, on Administration > Profiles.
    //
    // Core stores a plugin's rights and saves them back with its own, but
    // renders a form for its rights only — so without this tab the ones below
    // are enforced everywhere and grantable nowhere but SQL.
    Plugin::registerClass(\GlpiPlugin\Glpiidentity\Profile::class, ['addtabon' => ['Profile']]);

    // Setup > Plugins links the settings page. No menu_toadd for it: a second
    // link to the same page is what makes the Setup menu unreadable once
    // several plugins each add one.
    $PLUGIN_HOOKS['config_page']['glpiidentity'] = 'front/config.php';

    $PLUGIN_HOOKS['menu_toadd']['glpiidentity'] = [
        // The sources are an item list, which the Plugins page does not reach.
        'admin' => Source::class,
    ];

    Plugin::registerClass(Source::class);

    // `addtabon` is what actually attaches the tab. Registering the class
    // without it declares the type to GLPI and leaves getTabNameForItem()
    // never being called — the tab simply does not appear, with no error.
    Plugin::registerClass(Mapping::class, ['addtabon' => [Source::class]]);
    Plugin::registerClass(AttributeMap::class, ['addtabon' => [Source::class]]);
    Plugin::registerClass(IdpGroup::class, ['addtabon' => [Source::class]]);
    Plugin::registerClass(Link::class, ['addtabon' => [Source::class]]);

    /**
     * Two paths that must run without a GLPI session, for opposite reasons.
     *
     * `front/scim.php` is called by an organisation's identity provider, which has a
     * bearer token and no cookie and never will. `front/sso.php` is where a
     * browser lands *before* it has a session — that is the whole point of it.
     *
     * Both authenticate; neither authenticates the way GLPI's firewall expects,
     * so the check is turned off for these two scripts specifically and done
     * inside them. The patterns are anchored and name the exact scripts, so a
     * file added to this plugin later does not inherit the exemption.
     */
    Firewall::addPluginStrategyForLegacyScripts(
        'glpiidentity',
        '#^/front/scim\.php(/|$)#',
        Firewall::STRATEGY_NO_CHECK
    );
    Firewall::addPluginStrategyForLegacyScripts(
        'glpiidentity',
        '#^/front/sso\.php(/|$)#',
        Firewall::STRATEGY_NO_CHECK
    );

    /**
     * SCIM is stateless as well as unauthenticated-by-GLPI's-reckoning.
     *
     * Two separate things, and both are needed. The firewall strategy above
     * stops GLPI redirecting the request to the login page; this stops it
     * starting a session and — the part that actually bites — stops the CSRF
     * listener rejecting every POST, PUT, PATCH and DELETE, which is all of
     * them that matter.
     *
     * `sso.php` is deliberately *not* stateless: the OAuth state, nonce and
     * PKCE verifier have to survive the round trip to the provider, and a
     * session is where they live. It is GET-only, so CSRF never applies to it.
     */
    SessionManager::registerPluginStatelessPath('glpiidentity', '#^/front/scim\.php(/|$)#');

    // The OIDC client secret has to be reversible — it is sent to the token
    // endpoint — so it is encrypted with GLPI's key, and naming the column here
    // is what makes `glpi:security:changekey` re-encrypt it. The SCIM bearer
    // token is not here because it is not stored: only its hash is.
    $PLUGIN_HOOKS[Hooks::SECURED_FIELDS]['glpiidentity'] = [
        Source::getTable() . '.client_secret',
    ];

    $PLUGIN_HOOKS[Hooks::ADD_CSS]['glpiidentity'] = 'css/identity.css';

    // The sign-in buttons on GLPI's own login page.
    $PLUGIN_HOOKS[Hooks::DISPLAY_LOGIN]['glpiidentity'] = 'plugin_glpiidentity_display_login';

    // Offered to glpi-ai's assistant as tools. Registered unconditionally:
    // only glpi-ai reads this hook, so an instance without it pays one array
    // assignment and never loads the class — while guarding on
    // Plugin::isPluginActive('glpiai') would run a database lookup on every
    // request to avoid exactly that.
    $PLUGIN_HOOKS['glpiai_tools']['glpiidentity'] = [\GlpiPlugin\Glpiidentity\AiTools::class, 'all'];
}

function plugin_version_glpiidentity()
{
    return [
        'name'         => 'GLPI Identity',
        'version'      => PLUGIN_GLPIIDENTITY_VERSION,
        'author'       => 'Bijstaan',
        'license'      => 'GPL-3.0-or-later',
        'homepage'     => 'https://github.com/bijstaan/glpi-identity',
        'requirements' => ['glpi' => ['min' => PLUGIN_GLPIIDENTITY_MIN_GLPI]],
    ];
}

function plugin_glpiidentity_check_prerequisites()
{
    // Both ship with GLPI 11; checked rather than assumed, because the failure
    // without them is a fatal error inside a login attempt.
    foreach (
        [
            'Firebase\JWT\JWT'                  => 'firebase/php-jwt',
            'League\OAuth2\Client\Provider\GenericProvider' => 'league/oauth2-client',
        ] as $class => $package
    ) {
        if (!class_exists($class)) {
            echo sprintf('This plugin needs %s, which is not available in this GLPI install.', $package);

            return false;
        }
    }

    return true;
}

function plugin_glpiidentity_check_config($verbose = false)
{
    return true;
}
