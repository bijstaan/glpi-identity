<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\IdpGroup;
use GlpiPlugin\Glpiidentity\IdpGroup_User;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Mapping;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;

/**
 * Install: six tables, one right, and the settings defaults.
 *
 * The shape is worth reading before the SQL. A **source** is one organisation's
 * identity configuration. A **link** is the fact that a particular GLPI user
 * came from that source, and is what makes the whole thing safe to run for
 * several organisations at once: SCIM and SSO both resolve through it rather than
 * by matching on an email address, which changes, is reused, and is not owned
 * by the person who has it.
 *
 * **idpgroups** are the groups an organisation's IdP has told us about. They are
 * deliberately not GLPI groups: an organisation's directory is theirs to name, and
 * turning every group it mentions into a GLPI group would fill the group tree
 * with a dozen organisations' internal vocabulary. Mappings translate.
 */
function plugin_glpiidentity_install()
{
    /** @var DBmysql $DB */
    global $DB;

    $charset = 'utf8mb4';
    $collate = 'utf8mb4_unicode_ci';

    if (!$DB->tableExists(Source::getTable())) {
        $DB->doQuery(
            "CREATE TABLE `" . Source::getTable() . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 0,
                `name` VARCHAR(190) NOT NULL,
                `is_active` TINYINT NOT NULL DEFAULT 0,
                `comment` TEXT NULL,

                -- OpenID Connect
                `sso_enabled` TINYINT NOT NULL DEFAULT 0,
                `is_default` TINYINT NOT NULL DEFAULT 0,
                `issuer` VARCHAR(500) NOT NULL DEFAULT '',
                `discovery_url` VARCHAR(500) NOT NULL DEFAULT '',
                `endpoints` TEXT NULL,
                `date_lastdiscovery` TIMESTAMP NULL DEFAULT NULL,
                `discovery_error` VARCHAR(500) NULL,
                `client_id` VARCHAR(255) NOT NULL DEFAULT '',
                `client_secret` TEXT NULL,
                `scopes` VARCHAR(255) NOT NULL DEFAULT 'openid profile email',
                `claim_login` VARCHAR(100) NOT NULL DEFAULT 'preferred_username',
                `claim_email` VARCHAR(100) NOT NULL DEFAULT 'email',
                `claim_firstname` VARCHAR(100) NOT NULL DEFAULT 'given_name',
                `claim_lastname` VARCHAR(100) NOT NULL DEFAULT 'family_name',
                `claim_groups` VARCHAR(100) NOT NULL DEFAULT 'groups',
                `email_domains` TEXT NULL,
                `jit_provision` TINYINT NOT NULL DEFAULT 1,
                `button_label` VARCHAR(100) NOT NULL DEFAULT '',

                -- SCIM 2.0
                `scim_enabled` TINYINT NOT NULL DEFAULT 0,
                -- The bearer token is stored as a hash and never as itself. It
                -- is shown once, when it is generated, and after that a lost
                -- token is regenerated rather than looked up: a table that
                -- cannot yield a working credential is one less thing a
                -- database backup has to be treated as.
                `scim_token_hash` CHAR(64) NOT NULL DEFAULT '',
                `scim_token_hint` VARCHAR(16) NOT NULL DEFAULT '',
                `deprovision_action` VARCHAR(20) NOT NULL DEFAULT 'disable',
                -- 0 means never. The fallback for a source with no SCIM
                -- connector, which otherwise never hears that anyone has left.
                `idle_disable_days` INT UNSIGNED NOT NULL DEFAULT 0,
                `date_lastscim` TIMESTAMP NULL DEFAULT NULL,
                `scim_requests` INT UNSIGNED NOT NULL DEFAULT 0,

                -- Placement
                `default_profiles_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `mirror_groups` TINYINT NOT NULL DEFAULT 0,

                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `name` (`entities_id`,`name`),
                KEY `entities_id` (`entities_id`,`is_recursive`),
                KEY `is_active` (`is_active`),
                KEY `scim_token_hash` (`scim_token_hash`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists(Mapping::getTable())) {
        // `rank` and `match` are reserved words in MariaDB, hence the suffixes.
        $DB->doQuery(
            "CREATE TABLE `" . Mapping::getTable() . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiidentity_sources_id` INT UNSIGNED NOT NULL,
                `rank_order` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `claim` VARCHAR(190) NOT NULL DEFAULT 'groups',
                `match_operator` VARCHAR(20) NOT NULL DEFAULT 'equals',
                `match_value` VARCHAR(255) NOT NULL DEFAULT '',
                `action` VARCHAR(20) NOT NULL DEFAULT 'group',
                `groups_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `profiles_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_dynamic_recursive` TINYINT NOT NULL DEFAULT 0,
                `field_name` VARCHAR(100) NOT NULL DEFAULT '',
                `field_value` VARCHAR(255) NOT NULL DEFAULT '',
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `source` (`plugin_glpiidentity_sources_id`,`rank_order`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists(IdpGroup::getTable())) {
        $DB->doQuery(
            "CREATE TABLE `" . IdpGroup::getTable() . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiidentity_sources_id` INT UNSIGNED NOT NULL,
                `external_id` VARCHAR(255) NOT NULL,
                `name` VARCHAR(255) NOT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `external` (`plugin_glpiidentity_sources_id`,`external_id`),
                KEY `name` (`name`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists(IdpGroup_User::getTable())) {
        $DB->doQuery(
            "CREATE TABLE `" . IdpGroup_User::getTable() . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiidentity_idpgroups_id` INT UNSIGNED NOT NULL,
                `users_id` INT UNSIGNED NOT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `membership` (`plugin_glpiidentity_idpgroups_id`,`users_id`),
                KEY `users_id` (`users_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists(Link::getTable())) {
        // scim_id is a UUID rather than the GLPI user id. Every SCIM query is
        // already scoped to the calling source, so the id is not the control —
        // but an unguessable id means a mistake in that scoping is not also an
        // information leak about how many users another organisation has.
        $DB->doQuery(
            "CREATE TABLE `" . Link::getTable() . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiidentity_sources_id` INT UNSIGNED NOT NULL,
                `users_id` INT UNSIGNED NOT NULL,
                `scim_id` CHAR(36) NOT NULL,
                `subject` VARCHAR(255) NOT NULL DEFAULT '',
                `external_id` VARCHAR(255) NOT NULL DEFAULT '',
                `is_scim_managed` TINYINT NOT NULL DEFAULT 0,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                `date_lastlogin` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `scim_id` (`scim_id`),
                UNIQUE KEY `source_user` (`plugin_glpiidentity_sources_id`,`users_id`),
                KEY `subject` (`plugin_glpiidentity_sources_id`,`subject`(190)),
                KEY `external_id` (`plugin_glpiidentity_sources_id`,`external_id`(190)),
                KEY `users_id` (`users_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists(EventLog::TABLE)) {
        $DB->doQuery(
            "CREATE TABLE `" . EventLog::TABLE . "` (
                `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiidentity_sources_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `users_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `event` VARCHAR(40) NOT NULL,
                `is_error` TINYINT NOT NULL DEFAULT 0,
                `subject` VARCHAR(255) NOT NULL DEFAULT '',
                `detail` TEXT NULL,
                `ip` VARCHAR(45) NOT NULL DEFAULT '',
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `reporting` (`date_creation`,`event`),
                KEY `source` (`plugin_glpiidentity_sources_id`),
                KEY `users_id` (`users_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Columns added after a table already existed somewhere. The install hook
    // runs on upgrade too, and the CREATE TABLE above is skipped once the table
    // is there — so a new column that only appears in the CREATE is a column
    // that only ever appears on a fresh install.
    if (!$DB->fieldExists(Source::getTable(), 'idle_disable_days')) {
        $DB->doQuery(
            "ALTER TABLE `" . Source::getTable() . "`
                ADD `idle_disable_days` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `deprovision_action`"
        );
    }

    CronTask::register(
        Source::class,
        'discovery',
        DAY_TIMESTAMP,
        [
            'state'         => CronTask::STATE_WAITING,
            'mode'          => CronTask::MODE_EXTERNAL,
            'allowmode'     => CronTask::MODE_EXTERNAL,
            'logs_lifetime' => 30,
            'comment'       => 'Refresh each identity provider\'s OpenID Connect metadata',
        ]
    );

    // Registered as `idledisable` because CronTask builds the callable as
    // `<itemtype>::cron<name>` — the method is cronIdleDisable(), and PHP
    // method names are case-insensitive.
    CronTask::register(
        Source::class,
        'idledisable',
        DAY_TIMESTAMP,
        [
            'state'         => CronTask::STATE_WAITING,
            'mode'          => CronTask::MODE_EXTERNAL,
            'allowmode'     => CronTask::MODE_EXTERNAL,
            'logs_lifetime' => 30,
            'comment'       => 'Deactivate accounts that have stopped signing in, on sources that set a limit',
        ]
    );

    CronTask::register(
        EventLog::class,
        'prune',
        DAY_TIMESTAMP,
        [
            'state'         => CronTask::STATE_WAITING,
            'mode'          => CronTask::MODE_EXTERNAL,
            'allowmode'     => CronTask::MODE_EXTERNAL,
            'logs_lifetime' => 30,
            'comment'       => 'Drop identity events past the retention window',
        ]
    );

    plugin_glpiidentity_install_rights();

    Config::setConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT, Settings::DEFAULTS);

    return true;
}

/**
 * One right, over the identity sources.
 *
 * Whoever holds it can read an organisation's client id, rotate their SCIM token and
 * decide which of their groups becomes which GLPI profile — which is to say,
 * can grant themselves anything. It is granted to profiles that can already
 * administer configuration, because those profiles could do the same thing the
 * long way round anyway.
 */
function plugin_glpiidentity_install_rights()
{
    /** @var DBmysql $DB */
    global $DB;

    $right = 'plugin_glpiidentity_source';

    $exists = false;
    foreach (
        $DB->request([
            'SELECT' => ['name'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => ['name' => $right],
            'LIMIT'  => 1,
        ]) as $row
    ) {
        $exists = true;
    }

    // addProfileRights() inserts unconditionally, and the install hook runs on
    // upgrade too — calling it for an existing right aborts the upgrade on a
    // duplicate key.
    if (!$exists) {
        ProfileRight::addProfileRights([$right]);
    }

    $targets = [];
    foreach (
        $DB->request([
            'SELECT' => ['profiles_id'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => ['name' => 'config', 'rights' => ['&', UPDATE]],
        ]) as $row
    ) {
        $targets[] = (int) $row['profiles_id'];
    }

    if (isset($_SESSION['glpiactiveprofile']['id'])) {
        $targets[] = (int) $_SESSION['glpiactiveprofile']['id'];
    }

    foreach (array_unique($targets) as $profiles_id) {
        ProfileRight::updateProfileRights($profiles_id, [$right => ALLSTANDARDRIGHT]);
    }
}

function plugin_glpiidentity_uninstall()
{
    /** @var DBmysql $DB */
    global $DB;

    // Order matters only for readability; there are no foreign keys, because
    // GLPI does not use them and a plugin that did would be the only thing in
    // the database that broke on a partial restore.
    foreach (
        [
            EventLog::TABLE,
            Link::getTable(),
            IdpGroup_User::getTable(),
            IdpGroup::getTable(),
            Mapping::getTable(),
            Source::getTable(),
        ] as $table
    ) {
        if ($DB->tableExists($table)) {
            $DB->doQuery("DROP TABLE `$table`");
        }
    }

    CronTask::unregister('glpiidentity');

    ProfileRight::deleteProfileRights(['plugin_glpiidentity_source']);

    Config::deleteConfigurationValues(PLUGIN_GLPIIDENTITY_CONFIG_CONTEXT, array_keys(Settings::DEFAULTS));

    return true;
}

/**
 * The sign-in buttons on GLPI's own login page.
 *
 * Rendered by the plugin rather than replacing the login page, so an
 * administrator whose IdP is misconfigured can still sign in with a local
 * password — which is the difference between a bad afternoon and being locked
 * out of the instance that holds the configuration you need to fix.
 */
function plugin_glpiidentity_display_login()
{
    echo GlpiPlugin\Glpiidentity\LoginButtons::render();
}
