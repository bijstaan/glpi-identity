<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBTM;
use CronTask;

/**
 * Who signed in, what was provisioned, and what was refused.
 *
 * The question this exists to answer is not "did it work" — that is visible
 * from whether people can log in. It is the one asked afterwards: why does this
 * user have that profile, when did that account stop working, and did anything
 * from Acme's directory ever touch Beta's entity. None of that is answerable
 * from GLPI's own history, which records the change and not the reason.
 *
 * Refusals are recorded as loudly as successes. A rejected SCIM token or an
 * unknown issuer is the interesting event, not the boring one.
 */
class EventLog extends CommonDBTM
{
    public const TABLE = 'glpi_plugin_glpiidentity_events';

    public static $rightname = 'plugin_glpiidentity_source';

    // Sign-in
    public const SSO_LOGIN     = 'sso_login';
    public const SSO_DENIED    = 'sso_denied';
    public const SSO_PROVISION = 'sso_provision';

    // Provisioning
    public const SCIM_CREATE     = 'scim_create';
    public const SCIM_UPDATE     = 'scim_update';
    public const SCIM_DEACTIVATE = 'scim_deactivate';
    public const SCIM_DENIED     = 'scim_denied';
    public const GROUP_SYNC      = 'group_sync';

    // Placement
    public const MAPPED = 'mapped';

    public static function getTable($classname = null)
    {
        return self::TABLE;
    }

    public static function getTypeName($nb = 0)
    {
        return _n('Identity event', 'Identity events', $nb, 'glpiidentity');
    }

    /**
     * Record something that happened.
     *
     * Swallows its own failures. A log table that is missing or full must not
     * be the reason a customer's staff cannot sign in.
     */
    public static function record(
        string $event,
        ?Source $source = null,
        array $context = []
    ): void {
        try {
            /** @var \DBmysql $DB */
            global $DB;

            $DB->insert(self::TABLE, [
                'plugin_glpiidentity_sources_id' => $source?->getID() ?: 0,
                'entities_id'   => (int) ($context['entities_id'] ?? $source?->fields['entities_id'] ?? 0),
                'users_id'      => (int) ($context['users_id'] ?? 0),
                'event'         => $event,
                'is_error'      => !empty($context['error']) ? 1 : 0,
                // The subject, not the email: an email is the person's, a
                // subject is the account's, and only one of them is stable.
                'subject'       => mb_substr((string) ($context['subject'] ?? ''), 0, 255),
                'detail'        => isset($context['detail'])
                    ? mb_substr((string) $context['detail'], 0, 60000)
                    : null,
                'ip'            => mb_substr(self::clientIp(), 0, 45),
                'date_creation' => date('Y-m-d H:i:s'),
            ]);
        } catch (\Throwable $e) {
            trigger_error('glpiidentity: could not record event: ' . $e->getMessage(), E_USER_WARNING);
        }
    }

    /**
     * The caller's address as GLPI sees it.
     *
     * Deliberately not reading X-Forwarded-For. Behind a proxy that address is
     * the useful one and behind nothing it is whatever the caller decided to
     * send, and this log is consulted precisely when somebody is doing
     * something they should not be. GLPI has no trusted-proxy configuration to
     * key that decision off, so the honest value is the connecting address.
     */
    private static function clientIp(): string
    {
        return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    /**
     * Recent events, most recent first.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function recent(int $limit = 100, ?int $sources_id = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $where = [];
        if ($sources_id !== null) {
            $where['plugin_glpiidentity_sources_id'] = $sources_id;
        }

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => $where,
                'ORDER' => 'id DESC',
                'LIMIT' => $limit,
            ]) as $row
        ) {
            $out[] = $row;
        }

        return $out;
    }

    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'prune'  => ['description' => __('Drop identity events past the retention window', 'glpiidentity')],
            default  => [],
        };
    }

    public static function cronPrune(CronTask $task): int
    {
        $days = (int) Settings::get('event_retention_days');
        if ($days <= 0) {
            return 0;
        }

        /** @var \DBmysql $DB */
        global $DB;

        $DB->delete(self::TABLE, [
            'date_creation' => ['<', date('Y-m-d H:i:s', time() - ($days * 86400))],
        ]);

        $removed = $DB->affectedRows();
        $task->addVolume($removed);

        return $removed > 0 ? 1 : 0;
    }
}
