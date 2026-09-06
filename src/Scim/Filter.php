<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

/**
 * The part of SCIM's filter grammar that provisioning connectors actually send.
 *
 * SCIM defines a full expression language — grouping, `and`/`or`/`not`, value
 * paths like `emails[type eq "work"]`, a dozen operators. Implementing it
 * properly is a parser, and implementing it *badly* is worse than not
 * implementing it, because a filter that is silently misread returns the wrong
 * user and the connector cheerfully overwrites them.
 *
 * So this handles exactly one comparison — which is what Entra, Okta, Google
 * and OneLogin all send, because they are all asking the same question: "do you
 * already have this person?" — and refuses everything else with `invalidFilter`
 * rather than guessing. A connector that gets an honest 400 falls back to
 * listing; one that gets a wrong answer does not.
 */
final class Filter
{
    public const EQ = 'eq';
    public const SW = 'sw';
    public const CO = 'co';

    private function __construct(
        public readonly string $attribute,
        public readonly string $operator,
        public readonly string $value
    ) {
    }

    /**
     * Parse a filter, or explain why not.
     *
     * @return array{filter:?self,error:?string}
     */
    public static function parse(?string $raw): array
    {
        $raw = trim((string) $raw);

        if ($raw === '') {
            return ['filter' => null, 'error' => null];
        }

        // attribute op "value" — attribute may be dotted (`name.givenName`) or
        // schema-qualified, and the value may contain escaped quotes.
        $pattern = '/^\s*(?<attr>[A-Za-z][\w:.$-]*)\s+(?<op>eq|sw|co)\s+"(?<value>(?:[^"\\\\]|\\\\.)*)"\s*$/i';

        if (preg_match($pattern, $raw, $m) !== 1) {
            return [
                'filter' => null,
                'error'  => 'Only a single "attribute eq \\"value\\"" comparison is supported.',
            ];
        }

        return [
            'filter' => new self(
                self::normaliseAttribute($m['attr']),
                strtolower($m['op']),
                stripcslashes($m['value'])
            ),
            'error'  => null,
        ];
    }

    /**
     * Reduce an attribute path to the name this server reasons about.
     *
     * Connectors qualify attributes inconsistently — `userName`,
     * `urn:ietf:params:scim:schemas:core:2.0:User:userName`, and Okta's
     * `profile.userName` all mean the same thing. Comparison is
     * case-insensitive because SCIM says attribute names are.
     */
    private static function normaliseAttribute(string $attribute): string
    {
        $tail = $attribute;

        // Strip a schema URN prefix: everything up to the last colon.
        $colon = strrpos($tail, ':');
        if ($colon !== false) {
            $tail = substr($tail, $colon + 1);
        }

        // `profile.userName` → `userName`, but keep `name.givenName` intact:
        // only a leading `profile.` is noise.
        if (str_starts_with(strtolower($tail), 'profile.')) {
            $tail = substr($tail, 8);
        }

        return strtolower($tail);
    }

    /** Does a candidate value satisfy this comparison? */
    public function test(?string $candidate): bool
    {
        $candidate = (string) $candidate;

        return match ($this->operator) {
            self::SW => mb_stripos($candidate, $this->value) === 0,
            self::CO => $this->value === '' || mb_stripos($candidate, $this->value) !== false,
            default  => mb_strtolower($candidate) === mb_strtolower($this->value),
        };
    }

    public function isOn(string ...$attributes): bool
    {
        foreach ($attributes as $attribute) {
            if ($this->attribute === strtolower($attribute)) {
                return true;
            }
        }

        return false;
    }
}
