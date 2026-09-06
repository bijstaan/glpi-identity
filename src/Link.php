<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBTM;
use Ramsey\Uuid\Uuid;
use User;

/**
 * The fact that a GLPI user came from a particular identity source.
 *
 * This is the load-bearing table, and the reason is worth stating plainly:
 * **identity is not email**. Addresses change on marriage and rebrand, get
 * reused when someone leaves, and are claimed by whoever controls the domain
 * today. An OIDC `sub` and a SCIM resource id are opaque, stable, and issued by
 * the directory that actually knows who the person is.
 *
 * So both halves of the plugin resolve through here. SSO matches on
 * (source, subject); SCIM matches on (source, external id) or its own resource
 * id. Neither ever looks a user up by email alone — an email match across
 * sources is how one customer's directory ends up owning another customer's
 * account, and it would look like an ordinary successful login.
 */
class Link extends CommonDBTM
{
    public static $rightname = 'plugin_glpiidentity_source';

    public static function getTypeName($nb = 0)
    {
        return _n('Identity link', 'Identity links', $nb, 'glpiidentity');
    }

    /** The link for a GLPI user under one source, or null. */
    public static function forUser(int $sources_id, int $users_id): ?self
    {
        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'users_id'                       => $users_id,
        ]);
    }

    /** The link for an OIDC subject under one source, or null. */
    public static function forSubject(int $sources_id, string $subject): ?self
    {
        if ($subject === '') {
            return null;
        }

        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'subject'                        => $subject,
        ]);
    }

    /** The link for a directory's own id under one source, or null. */
    public static function forExternalId(int $sources_id, string $external_id): ?self
    {
        if ($external_id === '') {
            return null;
        }

        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'external_id'                    => $external_id,
        ]);
    }

    /**
     * The link for a SCIM resource id — scoped to the calling source.
     *
     * The scoping is the access control, not the unguessability of the id: a
     * customer asking for a resource id that is not theirs must get a 404, not
     * somebody else's user.
     */
    public static function forScimId(int $sources_id, string $scim_id): ?self
    {
        if ($scim_id === '') {
            return null;
        }

        return self::findOne([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'scim_id'                        => $scim_id,
        ]);
    }

    /** @param array<string,mixed> $criteria */
    private static function findOne(array $criteria): ?self
    {
        $link = new self();

        return $link->getFromDBByCrit($criteria) ? $link : null;
    }

    /**
     * Link a user to a source, or return the link that already exists.
     *
     * Named `attach` rather than `create` because the second call for the same
     * pair is the normal case, not an error: every sign-in and every SCIM
     * update comes through here.
     */
    public static function attach(int $sources_id, int $users_id, array $fields = []): self
    {
        $existing = self::forUser($sources_id, $users_id);

        if ($existing !== null) {
            if ($fields !== []) {
                $existing->update(['id' => $existing->getID()] + $fields);
            }

            return $existing;
        }

        $link = new self();
        $link->add([
            'plugin_glpiidentity_sources_id' => $sources_id,
            'users_id'                       => $users_id,
            'scim_id'                        => Uuid::uuid4()->toString(),
            'date_creation'                  => date('Y-m-d H:i:s'),
        ] + $fields);

        return $link;
    }

    public function user(): ?User
    {
        $user = new User();

        return $user->getFromDB((int) $this->fields['users_id']) ? $user : null;
    }

    public function source(): ?Source
    {
        $source = new Source();

        return $source->getFromDB((int) $this->fields['plugin_glpiidentity_sources_id']) ? $source : null;
    }

    public function touchLogin(): void
    {
        $this->update(['id' => $this->getID(), 'date_lastlogin' => date('Y-m-d H:i:s')]);
    }

    /**
     * Every link a GLPI user has, across sources.
     *
     * More than one is legitimate and worth surfacing: a consultant who is a
     * user of two customers' directories is one person in GLPI with two
     * accounts upstream, and an administrator debugging why their profile keeps
     * changing needs to see both.
     *
     * @return self[]
     */
    public static function allForUser(int $users_id): array
    {
        $out = [];
        foreach (getAllDataFromTable(self::getTable(), ['users_id' => $users_id]) as $row) {
            $link         = new self();
            $link->fields = $row;
            $out[]        = $link;
        }

        return $out;
    }
}
