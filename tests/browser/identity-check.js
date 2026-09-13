// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// The glpiidentity admin surface, and the login page it changes.
//
// The PHP suites cover the protocol — SCIM over real HTTP, OIDC against a
// provider that signs properly. What is left is the part only a browser
// reaches: whether an administrator can actually configure a customer, whether
// the SCIM token is shown once and then never again, and whether the sign-in
// block appears on GLPI's own login page for a source that is ready and stays
// away for one that is not.
//
// It also captures the screenshots used in docs/.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const { openDark, audit } = require('./dark');
const { fullPage } = require('./shot');

const BASE = 'http://localhost:8081';
const SHOTS = process.env.SHOT_DIR || '.';
const DARK_SHOTS = path.join(SHOTS, 'dark');
const IDP = 'http://127.0.0.1:9097';

const fail = [];
function check(name, cond, detail) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ' :: ' + detail : ''}`);
  if (!cond) fail.push(name);
}

async function login(browser) {
  const ctx = await browser.newContext({ viewport: { width: 1500, height: 1200 } });
  const page = await ctx.newPage();
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.fill('#login_name', 'glpi');
  await page.fill('input[type=password]', 'glpi');
  await page.click('button[type=submit]');
  await page.waitForLoadState('networkidle');
  if (await page.locator('#login_name').count()) throw new Error('login failed');
  return page;
}

const save = async (page, button = 'update') => {
  await page.click(`button[name=${button}]`);
  await page.waitForLoadState('networkidle');
};

(async () => {
  const browser = await chromium.launch();
  const page = await login(browser);

  const problems = [];
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('response', (r) => {
    if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`);
  });

  // --------------------------------------------------------------- settings

  await page.goto(`${BASE}/plugins/glpiidentity/front/config.php`, { waitUntil: 'networkidle' });
  let body = await page.evaluate(() => document.body.innerText);

  check('the settings page renders', /Enable federated identity/.test(body));
  check('the password form is kept by default',
    await page.locator('input[name=allow_local_login]').isChecked());
  // "Off as installed" is a claim about install defaults, not about the state
  // this suite runs in — the login-page fixtures have to enable federation for
  // there to be anything on that page to test. It is asserted in tests/scim.php,
  // where the defaults can be read honestly.

  await page.check('input[name=enabled]');
  await save(page);
  check('the master switch round-trips', await page.locator('input[name=enabled]').isChecked());

  await fullPage(page, `${SHOTS}/identity-01-settings.png`);

  // ----------------------------------------------------------- a new source

  await page.goto(`${BASE}/plugins/glpiidentity/front/source.form.php`, { waitUntil: 'networkidle' });
  check('the new-source form renders', (await page.locator('input[name=name]').count()) === 1);
  check('SCIM is not offered before the source exists',
    /Save the source to generate/i.test(await page.evaluate(() => document.body.innerText)));

  await page.fill('input[name=name]', 'Acme Corporation');
  await page.fill('input[name=issuer]', 'http://insecure.example');
  await page.click('button[name=add]');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(500);
  check('an http issuer is refused rather than accepted quietly',
    (await page.locator('.toast').filter({ hasText: /error/i }).count()) > 0
     || /must use https/i.test(await page.evaluate(() => document.body.innerText)));

  await page.goto(`${BASE}/plugins/glpiidentity/front/source.form.php`, { waitUntil: 'networkidle' });
  await page.fill('input[name=name]', 'Acme Corporation');
  await page.fill('input[name=issuer]', 'https://login.microsoftonline.com/acme-tenant-id/v2.0');
  await page.fill('input[name=client_id]', '4f3c1e88-0b6d-4a2f-9c31-7ad9e2b41c55');
  await page.fill('input[name=client_secret]', 'a-real-client-secret');
  await page.fill('input[name=email_domains]', 'acme.com, acme.co.uk');
  await page.selectOption('select[name=sso_enabled]', '1');
  await page.selectOption('select[name=scim_enabled]', '1');
  await page.selectOption('select[name=is_active]', '1');
  await page.click('button[name=add]');
  await page.waitForLoadState('networkidle');

  check('a source with an https issuer is accepted',
    /Acme Corporation/.test(await page.evaluate(() => document.body.innerText)));

  const sourceUrl = page.url();
  check('and lands on its own form', /source\.form\.php\?id=\d+/.test(sourceUrl), sourceUrl);

  const shown = await page.locator('input[name=client_secret]').inputValue();
  check('the client secret is never rendered back', shown !== 'a-real-client-secret', shown);
  check('a placeholder stands in for it', /[•*]/.test(shown));

  body = await page.evaluate(() => document.body.innerText);
  check('the redirect URI to register is shown', /sso\.php\/callback/.test(body));
  check('the SCIM endpoint is shown', /scim\.php\/v2/.test(body));
  check('and there is no token yet', /None yet/i.test(body));

  await fullPage(page, `${SHOTS}/identity-02-source.png`);

  await page.goto(`${BASE}/plugins/glpiidentity/front/source.php`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  check('the source appears in the list under Administration',
    /Acme Corporation/.test(await page.evaluate(() => document.body.innerText)));
  await fullPage(page, `${SHOTS}/identity-03-list.png`);

  await page.goto(sourceUrl, { waitUntil: 'networkidle' });

  // ------------------------------------------------------------- the token

  await page.click('button[name=rotate_token]');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(500);

  const toast = await page.evaluate(() =>
    [...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' '));
  const token = (toast.match(/scim_[0-9a-f]{48}/) || [])[0];
  check('a token is generated and shown once', !!token, toast.slice(0, 80));

  await page.reload({ waitUntil: 'networkidle' });
  body = await page.evaluate(() => document.body.innerText);
  check('and is not shown again after a reload', !token || !body.includes(token));
  check('only a hint of it remains', /scim_[0-9a-f]{6,}…/.test(body), body.match(/scim_\S+/)?.[0]);

  // ------------------------------------------------------------- discovery

  await page.click('button[name=discover]');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(500);
  check('refreshing metadata against an unreachable issuer reports the failure',
    /alert-danger|could not|error/i.test(await page.evaluate(() => document.body.innerText)));

  // -------------------------------------------------------------- mappings

  await page.goto(`${sourceUrl}&forcetab=${encodeURIComponent('GlpiPlugin\\Glpiidentity\\Mapping$1')}`,
    { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  body = await page.evaluate(() => document.body.innerText);
  check('the mappings tab explains the empty case', /No mappings yet/i.test(body), body.slice(0, 120));
  check('and says that every matching rule applies', /every matching rule applies/i.test(body));

  await page.click('a[href*="mapping.form.php"]');
  await page.waitForLoadState('networkidle');
  check('the mapping form opens', (await page.locator('select[name=action]').count()) === 1);

  await page.fill('input[name=match_value]', 'Executive');
  await page.selectOption('select[name=action]', 'group');
  await page.click('button[name=add]');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(400);
  check('a rule with no target is refused rather than saved as a no-op',
    /Choose the GLPI group/i.test(await page.evaluate(() => document.body.innerText)));

  await fullPage(page, `${SHOTS}/identity-04-mapping.png`);

  // ------------------------------------------------------------ login page
  //
  // This block renders *inside* GLPI's own login form, which is a minefield:
  // a nested <form> is dropped by the parser, a button without an explicit
  // type submits the login form, and a `required` field blocks GLPI's own
  // password login outright. All three of those shipped once. Each has a check
  // here, asserted on where the browser is actually sent.

  const anon = await browser.newContext({ viewport: { width: 1400, height: 1000 } });
  const guest = await anon.newPage();

  const navigations = [];
  guest.on('request', (r) => {
    if (r.isNavigationRequest()) navigations.push(r.method() + ' ' + r.url().replace(BASE, ''));
  });

  const atLogin = async () => {
    await guest.goto(`${BASE}/index.php`, { waitUntil: 'networkidle' });
    navigations.length = 0;
  };

  await atLogin();

  check('the sign-in block renders for a ready source',
    (await guest.locator('.glpiidentity-sso').count()) === 1);

  // The two login captures the README uses. They were taken by hand once and
  // then went stale — they still showed GLPI's own logo and "GLPI internal
  // database" on a whitelabelled instance — so they are taken here, in the very
  // states this section already puts the page into.
  await fullPage(guest, `${SHOTS}/identity-05-login.png`);
  // The default is the email box and nothing else. The house provider is
  // reachable through it — an address matching no customer domain falls back
  // there — so a button would be a second route to the same place.
  check('no provider button by default',
    (await guest.locator('.glpiidentity-house').count()) === 0);
  check('customers are not listed by name',
    !/Contoso/.test(await guest.evaluate(() => document.body.innerText)));
  check('nor is the house provider',
    !/Bijstaan/.test(await guest.evaluate(() => document.body.innerText)));

  check('nothing it renders can be submitted with the login form', await guest.evaluate(() => {
    const block = document.querySelector('.glpiidentity-sso');
    if (!block) return false;
    const controls = [...block.querySelectorAll('input, button, select, textarea')];
    return controls.every((c) =>
      (c.tagName !== 'BUTTON' || c.type === 'button')
      && !c.required
      && !c.name);
  }));

  await guest.fill('#glpiidentity-email', 'someone@contoso.example');
  await guest.click('#glpiidentity-continue').catch(() => {});
  await guest.waitForTimeout(800);
  check('Continue starts a sign-in rather than submitting the login form',
    navigations.some((n) => n.includes('sso.php/start?email=someone%40contoso.example'))
    && !navigations.some((n) => n.includes('login.php')),
    navigations.join(' | '));

  await atLogin();
  await guest.fill('#glpiidentity-email', 'someone@contoso.example');
  await guest.press('#glpiidentity-email', 'Enter').catch(() => {});
  await guest.waitForTimeout(800);
  check('and so does pressing Enter in the address field',
    navigations.some((n) => n.includes('sso.php/start?email=')) 
    && !navigations.some((n) => n.includes('login.php')),
    navigations.join(' | '));

  await atLogin();
  await guest.click('#glpiidentity-continue').catch(() => {});
  await guest.waitForTimeout(400);
  check('an empty address asks for one instead of navigating',
    navigations.length === 0
    && /Enter your work email/i.test(await guest.locator('.glpiidentity-problem').innerText()),
    navigations.join(' | '));

  // Opting in. Done through the admin UI in the signed-in context, because
  // that is how an administrator would do it, and then re-checked as a guest.
  await page.goto(`${BASE}/plugins/glpiidentity/front/source.php`, { waitUntil: 'networkidle' });
  const house = page.locator('a[href*="source.form.php?id="]').filter({ hasText: 'Bijstaan' }).first();
  check('the house source is in the list', (await house.count()) === 1);

  if (await house.count()) {
    // Navigate by href rather than clicking: the list is GLPI's search table,
    // whose row links are JS-driven and do not always settle by networkidle.
    //
    // forcetab is required rather than tidy. GLPI remembers the last tab a user
    // was on *per itemtype*, and this suite visited the Mappings tab earlier —
    // so a bare form URL lands there, where the field being set does not exist.
    const houseUrl = BASE + (await house.getAttribute('href'))
      + '&forcetab=' + encodeURIComponent('GlpiPlugin\\Glpiidentity\\Source$main');
    await page.goto(houseUrl, { waitUntil: 'networkidle' });
    await page.waitForSelector('input[name=button_label]', { timeout: 15000 });
    await page.fill('input[name=button_label]', 'Bijstaan');
    await save(page);
    check('the button label saves', (await page.locator('input[name=button_label]').inputValue()) === 'Bijstaan');

    await atLogin();
    check('a labelled house provider gets a button',
      (await guest.locator('.glpiidentity-house').count()) === 1);

    await guest.click('.glpiidentity-house').catch(() => {});
    await guest.waitForTimeout(800);
    check('and it starts a sign-in for that source',
      navigations.some((n) => n.includes('sso.php/start?source=')), navigations.join(' | '));

    // Back to the default, so the suite leaves the state it assumes.
    await page.goto(houseUrl, { waitUntil: 'networkidle' });
    await page.fill('input[name=button_label]', '');
    await save(page);
    await atLogin();
    check('clearing the label removes the button again',
      (await guest.locator('.glpiidentity-house').count()) === 0);
  }

  // The worst of the three, because it breaks people who are not using SSO at
  // all: an injected required field makes the browser refuse to submit.
  await atLogin();
  await guest.fill('#login_name', 'glpi');
  await guest.fill('input[type=password]', 'glpi');
  await guest.click('button[type=submit]:has-text("Sign in")');
  await guest.waitForTimeout(1200);
  check('GLPI\'s own password login still works',
    (await guest.evaluate(() => !document.querySelector('#login_name'))),
    guest.url());

  // ------------------------------------------- turning the password form off

  // The check above signed this context in, so /index.php would now redirect
  // to the interface rather than showing a login page at all.
  await anon.clearCookies();

  const loginPageHas = async (selector, query = '') => {
    await guest.goto(`${BASE}/index.php${query}`, { waitUntil: 'networkidle' });
    await guest.waitForTimeout(400);
    return (await guest.locator(selector).count()) > 0;
  };

  const setLocalLogin = async (on) => {
    await page.goto(`${BASE}/plugins/glpiidentity/front/config.php`, { waitUntil: 'networkidle' });
    if (on) {
      await page.check('input[name=allow_local_login]');
    } else {
      await page.uncheck('input[name=allow_local_login]');
    }
    await save(page);
  };

  const setFederation = async (on) => {
    await page.goto(`${BASE}/plugins/glpiidentity/front/config.php`, { waitUntil: 'networkidle' });
    if (on) {
      await page.check('input[name=enabled]');
    } else {
      await page.uncheck('input[name=enabled]');
    }
    await save(page);
  };

  check('the password form is there while local login is allowed',
    await loginPageHas('#login_name'));

  await setLocalLogin(false);

  check('turning it off takes GLPI\'s login controls off the page',
    !(await loginPageHas('#login_name')));
  check('and the password field with them — hidden is not enough, autofill fills hidden fields',
    !(await loginPageHas('input[name=login_password]')));
  check('single sign-on is still offered', await loginPageHas('.glpiidentity-sso'));
  check('with a way back to a local account', await loginPageHas('.glpiidentity-localhint'));

  await guest.goto(`${BASE}/index.php`, { waitUntil: 'networkidle' });
  await fullPage(guest, `${SHOTS}/identity-06-login-sso-only.png`);

  check('the escape hatch shows the form again',
    await loginPageHas('#login_name', '?local=1'));

  // The property that makes this safe to switch off at all: hiding the local
  // form is emitted only as part of markup rendered for a *ready* source. Turn
  // single sign-on off entirely and the password form must come back, or an
  // administrator has locked themselves out of the instance that holds the
  // configuration they need to fix.
  await setFederation(false);
  check('with federation off, the password form returns even though local login is off',
    await loginPageHas('#login_name'));
  check('and nothing of this plugin is on the page',
    !(await loginPageHas('.glpiidentity-sso')));

  await setFederation(true);
  await setLocalLogin(true);
  check('and it is restored once both are back on', await loginPageHas('#login_name'));

  await guest.goto(`${BASE}/index.php`, { waitUntil: 'networkidle' });
  await anon.close();

  check('no server errors or JavaScript errors', problems.length === 0, problems.join(' | '));

  console.log('\nThe source and mapping are left for identity-setup.sh to clear.');


  // --- The dark palette --------------------------------------------------
  //
  // The settings page and the source form are this plugin's own markup, so
  // nothing in GLPI's dark stylesheet covers them. The login page is checked
  // separately below because it is rendered for somebody with no session at
  // all, and so cannot be visited as the dark account.
  fs.mkdirSync(DARK_SHOTS, { recursive: true });
  console.log('\nswitching to the dark palette...');

  const dark = await openDark(browser, { plugin: 'glpiidentity' });

  for (const [url, name, shot] of [
    [`${BASE}/plugins/glpiidentity/front/config.php`, 'the settings page', 'identity-dark-01-settings.png'],
    [`${BASE}/plugins/glpiidentity/front/source.php`, 'the source list', 'identity-dark-02-list.png'],
  ]) {
    await dark.goto(url, { waitUntil: 'networkidle' });
    await dark.waitForTimeout(400);
    const bad = await audit(dark, 'glpiidentity-');
    check(`[dark] ${name}: no near-white panel carrying dark-body text`,
      bad.whiteBg.length === 0, JSON.stringify(bad.whiteBg));
    check(`[dark] ${name}: muted text meets 4.5:1`,
      bad.lowContrast.length === 0, JSON.stringify(bad.lowContrast));
    await fullPage(dark, `${DARK_SHOTS}/${shot}`);
  }

  check('[dark] no page errors', dark.__darkErrors.length === 0, dark.__darkErrors.join(' | '));

  await browser.close();
  console.log(`\n${fail.length ? `FAILED: ${fail.join(', ')}` : 'all checks passed'}`);
  process.exit(fail.length ? 1 : 0);
})().catch((e) => {
  console.error('ERROR', e);
  process.exit(1);
});
