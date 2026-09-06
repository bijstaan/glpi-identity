<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

/**
 * The shapes SCIM insists on.
 *
 * Provisioning connectors are strict and unhelpful in equal measure: Entra
 * reports "the endpoint returned an unexpected response" for a missing
 * `schemas` array, a wrong content type, and a 500 alike. So the envelopes live
 * in one place, get built the same way every time, and are covered by tests
 * that assert the bytes rather than the behaviour.
 */
final class Response
{
    /** RFC 7644 defines this media type; several connectors reject `application/json`. */
    public const CONTENT_TYPE = 'application/scim+json;charset=UTF-8';

    public const SCHEMA_LIST  = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
    public const SCHEMA_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';
    public const SCHEMA_PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    public const SCHEMA_USER  = 'urn:ietf:params:scim:schemas:core:2.0:User';
    public const SCHEMA_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';

    public function __construct(
        public readonly int $status,
        public readonly ?array $body = null,
        /** @var array<string,string> */
        public readonly array $headers = []
    ) {
    }

    public static function ok(array $body): self
    {
        return new self(200, $body);
    }

    public static function created(array $body, string $location): self
    {
        return new self(201, $body, ['Location' => $location]);
    }

    /** A successful delete carries no body, and a body would be a protocol error. */
    public static function noContent(): self
    {
        return new self(204);
    }

    /**
     * A list, paged the way SCIM pages: 1-based, and by *index* not by cursor.
     *
     * @param array<int,array<string,mixed>> $resources the page, already sliced
     */
    public static function list(array $resources, int $total, int $start_index): self
    {
        return self::ok([
            'schemas'      => [self::SCHEMA_LIST],
            'totalResults' => $total,
            'startIndex'   => $start_index,
            'itemsPerPage' => count($resources),
            // Capitalised. Lowercase `resources` is silently ignored by every
            // connector, which then reports that the directory is empty.
            'Resources'    => array_values($resources),
        ]);
    }

    /**
     * An error, in the envelope SCIM defines.
     *
     * `scimType` is optional and worth sending: it is the difference between a
     * connector logging "400 Bad Request" and logging "the filter was not
     * understood", and the person reading that log is not us.
     */
    public static function error(int $status, string $detail, ?string $scim_type = null): self
    {
        $body = [
            'schemas' => [self::SCHEMA_ERROR],
            // A string, not an integer. The spec says so and connectors check.
            'status'  => (string) $status,
            'detail'  => $detail,
        ];

        if ($scim_type !== null) {
            $body['scimType'] = $scim_type;
        }

        return new self($status, $body);
    }

    public static function notFound(string $what = 'Resource not found.'): self
    {
        return self::error(404, $what);
    }

    public static function unauthorized(): self
    {
        // The challenge header is what tells a connector its token was the
        // problem rather than the URL.
        return new self(
            401,
            [
                'schemas' => [self::SCHEMA_ERROR],
                'status'  => '401',
                'detail'  => 'A valid bearer token is required.',
            ],
            ['WWW-Authenticate' => 'Bearer realm="GLPI SCIM"']
        );
    }

    /** A duplicate userName — SCIM has a specific code for it, and connectors act on it. */
    public static function conflict(string $detail): self
    {
        return self::error(409, $detail, 'uniqueness');
    }

    public static function badRequest(string $detail, string $scim_type = 'invalidValue'): self
    {
        return self::error(400, $detail, $scim_type);
    }

    /** An xsd:dateTime, which is what `meta` timestamps must be. */
    public static function timestamp(?string $sql): ?string
    {
        if ($sql === null || $sql === '' || str_starts_with($sql, '0000')) {
            return null;
        }

        $time = strtotime($sql);

        return $time === false ? null : gmdate('Y-m-d\TH:i:s\Z', $time);
    }

    public function send(): void
    {
        http_response_code($this->status);
        header('Content-Type: ' . self::CONTENT_TYPE);

        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }

        if ($this->body !== null) {
            echo json_encode($this->body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
    }
}
