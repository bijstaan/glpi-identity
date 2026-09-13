<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

/**
 * One SCIM request, taken apart.
 *
 * Built from the superglobals in one place so the rest of the server is
 * testable without a web server: the constructor takes everything explicitly
 * and {@see fromGlobals()} is the only thing that reads PHP's environment.
 */
final class Request
{
    public function __construct(
        public readonly string $method,
        /** Path segments after the `/v2` base — `['Users', '<id>']`. */
        public readonly array $segments,
        /** @var array<string,mixed> */
        public readonly array $query = [],
        /** @var array<string,mixed> */
        public readonly array $body = [],
        public readonly string $bearer = '',
        public readonly string $raw = ''
    ) {
    }

    public static function fromGlobals(): self
    {
        // `.../front/scim.php/v2/Users` → `/v2/Users`. Taken from REQUEST_URI
        // rather than PATH_INFO, which GLPI 11 never sets — see Url::pathAfter.
        // The `/v2` is dropped here rather than matched later: it is a constant
        // of the base URL, not a routing decision.
        $path = \GlpiPlugin\Glpiidentity\Url::pathAfter('scim.php');
        $segments = array_values(array_filter(explode('/', $path), static fn(string $s): bool => $s !== ''));
        if (($segments[0] ?? '') === 'v2') {
            array_shift($segments);
        }

        $raw     = (string) file_get_contents('php://input');
        $decoded = json_decode($raw, true);

        return new self(
            strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
            $segments,
            $_GET,
            is_array($decoded) ? $decoded : [],
            self::bearerFromHeaders(),
            $raw
        );
    }

    /**
     * The bearer token, from wherever the web server put it.
     *
     * `Authorization` is stripped by some Apache configurations before it
     * reaches PHP, which is why `REDIRECT_HTTP_AUTHORIZATION` exists and why
     * every library that has ever read a bearer token checks all three. A
     * plugin that checked only the first works in development and fails on one
     * organisation's server for reasons nobody can reproduce.
     */
    private static function bearerFromHeaders(): string
    {
        $candidates = [
            $_SERVER['HTTP_AUTHORIZATION'] ?? null,
            $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null,
        ];

        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'Authorization') === 0) {
                    $candidates[] = $value;
                }
            }
        }

        foreach ($candidates as $header) {
            if (is_string($header) && preg_match('/^Bearer\s+(.+)$/i', trim($header), $m) === 1) {
                return trim($m[1]);
            }
        }

        return '';
    }

    public function resource(): string
    {
        return $this->segments[0] ?? '';
    }

    public function id(): string
    {
        return $this->segments[1] ?? '';
    }

    public function isCollection(): bool
    {
        return count($this->segments) === 1;
    }

    public function filter(): ?string
    {
        $filter = $this->query['filter'] ?? null;

        return is_string($filter) ? $filter : null;
    }

    /** SCIM pages from 1, not 0. Getting this wrong drops the first user, silently. */
    public function startIndex(): int
    {
        return max(1, (int) ($this->query['startIndex'] ?? 1));
    }

    public function count(int $ceiling): int
    {
        $requested = $this->query['count'] ?? null;

        if ($requested === null || !is_numeric($requested)) {
            return $ceiling;
        }

        return max(0, min($ceiling, (int) $requested));
    }
}
