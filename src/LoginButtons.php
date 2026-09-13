<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

/**
 * What this plugin adds to GLPI's own login page.
 *
 * An email box, and — only if somebody has explicitly asked for one — a button
 * for the house provider.
 *
 * The box alone is enough for everyone, which is why it is the default and the
 * button is not. An address at a claimed domain goes to that organisation's
 * provider; an address at no claimed domain falls back to the house provider.
 * A technician typing their own work address therefore arrives exactly where a
 * "Sign in with us" button would have sent them, so the button is a second
 * route to the same place — and it puts a second primary action next to GLPI's
 * own Sign in, which reads as a choice rather than as a shortcut.
 *
 * It remains available where staff sign in many times a day and would rather
 * click than type: filling in a source's **Button label** turns it on, and only
 * the house provider may have one. A button naming another *organisation* would
 * put that organisation's name on a public page, which is the disclosure the
 * email box exists to avoid.
 *
 * When **Keep the username and password form** is switched off, this also
 * takes GLPI's own login controls off the page — see {@see hideLocalForm()}
 * for what that does and, more importantly, what it does not.
 *
 * The email box is home-realm discovery. Someone at another organisation does
 * not know which of a dozen identity providers is theirs and should not be shown
 * a list of every organisation configured here — that list is itself a
 * disclosure, a directory of who they all are. Typing an address is the smallest
 * question that routes them correctly, and it discloses nothing: an address
 * that matches no configured domain is answered exactly like one that does.
 *
 * ---
 *
 * Two constraints of the login page shape every line of the markup below, and
 * both were learned by getting them wrong.
 *
 * **This renders *inside* GLPI's login `<form>`.** The hook's output lands in a
 * sibling column of the username and password fields, within the same form
 * element. So:
 *
 *  - a `<form>` here is a *nested* form, which the HTML parser silently drops —
 *    leaving its controls behind as part of GLPI's form;
 *  - a `<button>` with no explicit type defaults to `submit`, so pressing it
 *    submits GLPI's login form with empty credentials;
 *  - a `required` input here blocks GLPI's own password login entirely, because
 *    the browser refuses to submit a form with an unfilled required field.
 *
 * Nothing below is a form, every button says `type="button"`, no control is
 * required, and no control carries a `name` — so none of it can be submitted,
 * validated, or posted as part of somebody's password login.
 *
 * **Plugin CSS and JavaScript are not loaded on the login page.** GLPI only
 * serves plugin assets to authenticated pages, so `identity.css` is never
 * fetched here. The styling and behaviour are therefore inline: unusual, and
 * the only thing that actually works.
 */
final class LoginButtons
{
    public static function render(): string
    {
        if (!Settings::flag('enabled')) {
            return '';
        }

        $ready = array_values(array_filter(
            Source::activeSso(),
            static fn(Source $source): bool => $source->ssoReady()
        ));

        if ($ready === []) {
            return '';
        }

        $e     = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $house = null;
        foreach ($ready as $source) {
            // Only the house provider, and only when a label has been written
            // for it. An empty label — the default — means no button.
            if ((int) $source->fields['is_default'] === 1 && $source->buttonLabel() !== '') {
                $house = $source;
                break;
            }
        }

        // Anyone other than the house provider is reached by domain. If nobody
        // has claimed a domain, the box would be a dead end, so it is not shown.
        $has_domains = false;
        foreach ($ready as $source) {
            if ($source->domains() !== []) {
                $has_domains = true;
                break;
            }
        }

        $html = self::styles();
        $html .= "<div class='glpiidentity-sso'>";
        $html .= "<div class='glpiidentity-title'>" . __s('Single sign-on', 'glpiidentity') . '</div>';

        if ($house !== null) {
            // An anchor, not a button: it is a navigation, and an anchor cannot
            // accidentally submit the form this markup sits inside.
            $html .= "<a class='btn btn-primary w-100 glpiidentity-house' href='"
                . $e(Url::to('front/sso.php/start?source=' . (int) $house->getID())) . "'>"
                . "<i class='ti ti-login me-2'></i>"
                . $e(sprintf(__('Sign in with %s', 'glpiidentity'), $house->buttonLabel()))
                . '</a>';
        }

        if ($house !== null && $has_domains) {
            $html .= "<div class='glpiidentity-or'><span>" . __s('or', 'glpiidentity') . '</span></div>';
        }

        if ($has_domains) {
            $html .= "<label class='form-label' for='glpiidentity-email'>"
                . __s('Use your organisation account', 'glpiidentity') . '</label>';
            $html .= "<div class='input-group'>";
            // No name, no required — see the class docblock.
            $html .= "<input type='email' id='glpiidentity-email' class='form-control' "
                . "autocomplete='email' spellcheck='false' "
                . "placeholder='" . __s('you@example.com', 'glpiidentity') . "'>";
            $html .= "<button type='button' class='btn btn-outline-primary' id='glpiidentity-continue' "
                . "aria-label='" . __s('Continue', 'glpiidentity') . "'>"
                . "<i class='ti ti-arrow-right'></i></button>";
            $html .= '</div>';
            $html .= "<div class='form-text glpiidentity-hint'>"
                . __s('We will take you to your organisation to sign in.', 'glpiidentity')
                . '</div>';
            $html .= "<div class='glpiidentity-problem' role='alert' hidden></div>";
        }

        if (!self::localLoginVisible()) {
            $html .= "<div class='glpiidentity-localhint'>"
                . "<a href='" . $e(self::localLoginUrl()) . "'>"
                . __s('Sign in with a GLPI account', 'glpiidentity') . '</a></div>';
        }

        $html .= '</div>';

        $html .= self::behaviour($has_domains, !self::localLoginVisible());

        return $html;
    }

    /**
     * Should GLPI's own username and password form be on the page?
     *
     * Two ways it stays: the setting says so, or somebody asked for it with
     * `?local=1`. The second is the escape hatch, and it is not a bypass — the
     * form it reveals still requires valid credentials. It exists because the
     * configuration that fixes a broken identity provider lives inside the
     * instance that provider is the only way into, and an administrator who
     * cannot reach the password form has no way back in at all.
     */
    private static function localLoginVisible(): bool
    {
        return Settings::flag('allow_local_login') || !empty($_GET['local']);
    }

    private static function localLoginUrl(): string
    {
        global $CFG_GLPI;

        return rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . '/index.php?local=1';
    }

    /**
     * The block's own styling.
     *
     * A left rule rather than a horizontal "or" above everything: the hook
     * renders in a column *beside* the password fields, so the separation
     * between the two ways of signing in is vertical. Below the breakpoint
     * where the columns stack, it becomes a rule above instead.
     */
    private static function styles(): string
    {
        return <<<'CSS'
<style>
.glpiidentity-sso {
    width: 19rem;
    max-width: 100%;
    /* The parent column is text-center, which leaves labels floating. */
    text-align: left;
    padding-left: 1.5rem;
    border-left: 1px solid var(--tblr-border-color, #dee2e6);
}
@media (max-width: 767.98px) {
    /* GLPI puts this in a shrink-wrapping `col-auto`, so the block cannot widen
       to match the form above it once the columns stack. Degrades to a narrower
       centred block where :has() is unsupported, which is merely less tidy. */
    .col-auto:has(> .glpiidentity-sso) {
        width: 100%;
    }
    .glpiidentity-sso {
        width: 100%;
        margin-top: 1.5rem;
        padding-left: 0;
        padding-top: 1.5rem;
        border-left: 0;
        border-top: 1px solid var(--tblr-border-color, #dee2e6);
    }
}
.glpiidentity-title {
    font-size: 1.25rem;
    font-weight: 600;
    text-align: center;
    /* Sits level with GLPI's own "Login to your account", which carries a
       little more space above it than a bare heading would. */
    margin-top: 1rem;
    margin-bottom: 2rem;
}
.glpiidentity-house {
    display: flex;
    align-items: center;
    justify-content: center;
}
.glpiidentity-or {
    display: flex;
    align-items: center;
    gap: .75rem;
    margin: 1rem 0;
    color: var(--tblr-secondary, #6c757d);
    font-size: .8125rem;
}
.glpiidentity-or::before,
.glpiidentity-or::after {
    content: "";
    flex: 1;
    border-top: 1px solid var(--tblr-border-color, #dee2e6);
}
.glpiidentity-hint { margin-top: .5rem; }
.glpiidentity-problem {
    margin-top: .5rem;
    font-size: .875rem;
    color: var(--tblr-danger, #d63939);
}
.glpiidentity-localhint {
    margin-top: 2rem;
    font-size: .8125rem;
    text-align: center;
}
.glpiidentity-localhint a { color: var(--tblr-secondary, #6c757d); }
/* With GLPI's own form gone this is the only content, so it stops being a
   column beside something and becomes the page. */
.glpiidentity-sso.glpiidentity-alone {
    border-left: 0;
    padding-left: 0;
    margin: 0 auto;
}
</style>
CSS;
    }

    /**
     * Continue, Enter, and — when asked — taking GLPI's own form off the page.
     *
     * Continue and Enter both have to intercept: a click on any button inside
     * GLPI's form would otherwise submit it, and Enter in a text field submits
     * the form it belongs to — which is GLPI's, with an empty username and
     * password. That is the behaviour this replaces, and it produced a login
     * page that complained about missing credentials when somebody typed their
     * email.
     */
    private static function behaviour(bool $has_domains, bool $hide_local): string
    {
        $endpoint = json_encode(Url::to('front/sso.php/start'), JSON_UNESCAPED_SLASHES);
        $prompt   = json_encode(__('Enter your work email address.', 'glpiidentity'));
        $hide     = $hide_local ? 'true' : 'false';
        $wire     = $has_domains ? 'true' : 'false';

        return <<<JS
<script>
(function () {
    var endpoint = {$endpoint};
    var field    = document.getElementById('glpiidentity-email');
    var button   = document.getElementById('glpiidentity-continue');
    var problem  = document.querySelector('.glpiidentity-problem');
    var block    = document.querySelector('.glpiidentity-sso');

    if ({$hide}) {
        hideLocalForm();
    }

    if ({$wire} && field && button) {
        button.addEventListener('click', go);

        field.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                go(event);
            }
        });

        field.addEventListener('input', function () {
            if (problem) {
                problem.hidden = true;
            }
        });
    }

    function go(event) {
        // Always: this runs inside GLPI's login form, and the default action of
        // both a button press and an Enter key is to submit it.
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }

        var email = (field.value || '').trim();

        if (email === '' || email.indexOf('@') < 1) {
            if (problem) {
                problem.textContent = {$prompt};
                problem.hidden = false;
            }
            field.focus();
            return;
        }

        if (problem) {
            problem.hidden = true;
        }

        window.location = endpoint + '?email=' + encodeURIComponent(email);
    }

    /**
     * Remove GLPI's login controls, rather than hiding them.
     *
     * Hidden is not enough: a hidden password field is still filled by a
     * browser's autofill and still submitted, so "only SSO" would mean a
     * password travelling on a page that claims not to ask for one. Removing
     * the whole column takes the username, password, login-source, remember-me
     * and submit button with it in one go.
     *
     * This only ever runs as part of markup that is emitted for a *ready*
     * identity source. That ordering is the safety property: if no source can
     * sign anybody in, none of this is on the page, and GLPI's own form is left
     * exactly where it was.
     */
    function hideLocalForm() {
        var row = block && block.closest('.row');
        var name = document.getElementById('login_name');

        if (!row || !name) {
            return;
        }

        var column = name;
        while (column.parentElement && column.parentElement !== row) {
            column = column.parentElement;
        }

        if (column.parentElement === row) {
            column.parentNode.removeChild(column);
            if (block) {
                block.classList.add('glpiidentity-alone');
            }
        }
    }
})();
</script>
JS;
    }
}
