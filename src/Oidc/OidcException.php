<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Oidc;

/**
 * A sign-in that cannot proceed.
 *
 * Carries a message written for whoever configured the source rather than for
 * the person signing in — "the token was issued for a different application" is
 * useless to an employee and is the entire answer for an administrator. The
 * sign-in page shows a generic refusal; this message goes to the event log.
 */
final class OidcException extends \RuntimeException
{
}
