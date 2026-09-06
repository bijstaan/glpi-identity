<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity;

use CommonDBRelation;

/**
 * Membership of a directory group.
 *
 * A join table rather than a JSON column on the group, because the question
 * asked most often runs the other way — "which of Acme's groups is this user
 * in" — and that is a query rather than a scan of every group's member list.
 */
class IdpGroup_User extends CommonDBRelation
{
    public static $itemtype_1 = IdpGroup::class;
    public static $items_id_1 = 'plugin_glpiidentity_idpgroups_id';

    public static $itemtype_2 = 'User';
    public static $items_id_2 = 'users_id';

    public static $rightname = 'plugin_glpiidentity_source';

    public static function getTypeName($nb = 0)
    {
        return _n('Directory group membership', 'Directory group memberships', $nb, 'glpiidentity');
    }
}
