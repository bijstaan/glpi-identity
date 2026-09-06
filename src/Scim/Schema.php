<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

use GlpiPlugin\Glpiidentity\Settings;

/**
 * The documents a connector reads before it does anything else.
 *
 * These are not decoration. A provisioning connector fetches
 * ServiceProviderConfig on setup and adapts to it — it will not send a PATCH to
 * a server that says it cannot patch, and it will not try to sort. Declaring
 * unsupported features honestly is therefore how the unsupported parts stop
 * being a problem, and claiming one that is not implemented is how a customer's
 * sync fails in a way nobody can reproduce.
 */
final class Schema
{
    /** @return array<string,mixed> */
    public static function serviceProviderConfig(): array
    {
        return [
            'schemas'          => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'documentationUri' => 'https://github.com/bijstaan/glpi-identity',
            'patch'            => ['supported' => true],
            // Bulk is a genuine no: it exists to reduce round trips for very
            // large directories and it multiplies the blast radius of every
            // bug in here by the size of the batch.
            'bulk'             => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter'           => [
                'supported'  => true,
                'maxResults' => (int) Settings::get('scim_max_results'),
            ],
            // GLPI is not where these passwords live, and a SCIM endpoint that
            // offered to set one would be inviting a directory to write a
            // credential that could then be used to bypass it.
            'changePassword'   => ['supported' => false],
            'sort'             => ['supported' => false],
            'etag'             => ['supported' => false],
            'authenticationSchemes' => [[
                'type'        => 'oauthbearertoken',
                'name'        => 'OAuth Bearer Token',
                'description' => 'A per-source bearer token, issued from the identity source in GLPI.',
                'primary'     => true,
            ]],
            'meta' => ['resourceType' => 'ServiceProviderConfig'],
        ];
    }

    /** @return array<int,array<string,mixed>> */
    public static function resourceTypes(): array
    {
        return [
            [
                'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
                'id'          => 'User',
                'name'        => 'User',
                'endpoint'    => '/Users',
                'description' => 'A person, provisioned into this GLPI entity.',
                'schema'      => Response::SCHEMA_USER,
                'meta'        => ['resourceType' => 'ResourceType'],
            ],
            [
                'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
                'id'          => 'Group',
                'name'        => 'Group',
                'endpoint'    => '/Groups',
                'description' => 'A group from the directory, which GLPI mappings translate.',
                'schema'      => Response::SCHEMA_GROUP,
                'meta'        => ['resourceType' => 'ResourceType'],
            ],
        ];
    }

    /**
     * The attributes this server actually carries.
     *
     * Trimmed to what is implemented rather than copied from the RFC. A
     * connector that reads `title` here and then finds it silently dropped has
     * been misled by us, not by the standard.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function definitions(): array
    {
        return [
            [
                'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
                'id'          => Response::SCHEMA_USER,
                'name'        => 'User',
                'description' => 'SCIM core User, as implemented by GLPI Identity.',
                'attributes'  => [
                    self::attribute('userName', 'string', required: true, uniqueness: 'server'),
                    self::complex('name', [
                        self::attribute('givenName', 'string'),
                        self::attribute('familyName', 'string'),
                        self::attribute('formatted', 'string', mutability: 'readOnly'),
                    ]),
                    self::attribute('displayName', 'string', mutability: 'readOnly'),
                    self::complex('emails', [
                        self::attribute('value', 'string'),
                        self::attribute('type', 'string'),
                        self::attribute('primary', 'boolean'),
                    ], multi: true),
                    self::attribute('active', 'boolean'),
                    self::complex('groups', [
                        self::attribute('value', 'string', mutability: 'readOnly'),
                        self::attribute('display', 'string', mutability: 'readOnly'),
                    ], multi: true, mutability: 'readOnly'),
                ],
                'meta' => ['resourceType' => 'Schema'],
            ],
            [
                'schemas'     => ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
                'id'          => Response::SCHEMA_GROUP,
                'name'        => 'Group',
                'description' => 'SCIM core Group, as implemented by GLPI Identity.',
                'attributes'  => [
                    self::attribute('displayName', 'string', required: true),
                    self::complex('members', [
                        self::attribute('value', 'string'),
                        self::attribute('display', 'string', mutability: 'immutable'),
                    ], multi: true),
                ],
                'meta' => ['resourceType' => 'Schema'],
            ],
        ];
    }

    /** @return array<string,mixed> */
    private static function attribute(
        string $name,
        string $type,
        bool $required = false,
        bool $multi = false,
        string $mutability = 'readWrite',
        string $uniqueness = 'none'
    ): array {
        return [
            'name'          => $name,
            'type'          => $type,
            'multiValued'   => $multi,
            'required'      => $required,
            'caseExact'     => false,
            'mutability'    => $mutability,
            'returned'      => 'default',
            'uniqueness'    => $uniqueness,
        ];
    }

    /**
     * @param array<int,array<string,mixed>> $sub
     * @return array<string,mixed>
     */
    private static function complex(
        string $name,
        array $sub,
        bool $multi = false,
        string $mutability = 'readWrite'
    ): array {
        return self::attribute($name, 'complex', multi: $multi, mutability: $mutability)
            + ['subAttributes' => $sub];
    }
}
