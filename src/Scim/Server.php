<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiidentity\Scim;

use GlpiPlugin\Glpiidentity\EventLog;
use GlpiPlugin\Glpiidentity\IdpGroup;
use GlpiPlugin\Glpiidentity\Link;
use GlpiPlugin\Glpiidentity\Mapper;
use GlpiPlugin\Glpiidentity\Provisioning;
use GlpiPlugin\Glpiidentity\Settings;
use GlpiPlugin\Glpiidentity\Source;
use User;

/**
 * SCIM 2.0, for one customer at a time.
 *
 * Every request authenticates to exactly one {@see Source} before anything else
 * happens, and every query the handlers make is scoped through that source's
 * links. There is no code path here that can see a user another source
 * provisioned — not because each handler remembers to filter, but because the
 * only way to reach a user is through a link, and links belong to a source.
 *
 * What is implemented is what connectors use: Users and Groups, create, read,
 * replace, patch and delete, one filter comparison, and index paging. Bulk,
 * sort, ETags and the `/Me` alias are declared unsupported in
 * ServiceProviderConfig rather than half-built, because a connector reads that
 * document and adapts, and a half-built feature is one it will trust.
 */
final class Server
{
    public function handle(Request $request): Response
    {
        if (!Settings::flag('enabled')) {
            // 503 rather than 401: the credentials may be perfect. A connector
            // seeing 503 retries; one seeing 401 raises a quarantine alert at
            // the customer.
            return Response::error(503, 'Identity provisioning is switched off on this GLPI instance.');
        }

        $source = Source::byScimToken($request->bearer);
        if ($source === null) {
            EventLog::record(EventLog::SCIM_DENIED, null, [
                'error'  => true,
                'detail' => $request->bearer === ''
                    ? 'No bearer token was presented.'
                    : 'The bearer token presented matched no active source.',
            ]);

            return Response::unauthorized();
        }

        $this->recordUse($source);

        try {
            return $this->route($request, $source);
        } catch (\Throwable $e) {
            // A connector needs a SCIM error envelope even for an internal
            // fault; an HTML error page is reported as "the endpoint is not a
            // SCIM endpoint", which sends the customer looking in the wrong
            // place entirely.
            trigger_error('glpiidentity: SCIM request failed: ' . $e->getMessage(), E_USER_WARNING);

            EventLog::record(EventLog::SCIM_DENIED, $source, [
                'error'  => true,
                'detail' => $e->getMessage(),
            ]);

            return Response::error(500, 'The request could not be processed.');
        }
    }

    private function route(Request $request, Source $source): Response
    {
        return match ($request->resource()) {
            'ServiceProviderConfig' => Response::ok(Schema::serviceProviderConfig()),
            'ResourceTypes'         => $this->resourceTypes($request),
            'Schemas'               => $this->schemas($request),
            'Users'                 => $this->users($request, $source),
            'Groups'                => $this->groups($request, $source),
            default                 => Response::notFound('Unknown SCIM endpoint.'),
        };
    }

    private function recordUse(Source $source): void
    {
        $source->update([
            'id'            => $source->getID(),
            'date_lastscim' => date('Y-m-d H:i:s'),
            'scim_requests' => (int) $source->fields['scim_requests'] + 1,
        ]);
    }

    // --------------------------------------------------------------- metadata

    private function resourceTypes(Request $request): Response
    {
        $types = Schema::resourceTypes();

        if (!$request->isCollection()) {
            foreach ($types as $type) {
                if ($type['id'] === $request->id()) {
                    return Response::ok($type);
                }
            }

            return Response::notFound();
        }

        return Response::list($types, count($types), 1);
    }

    private function schemas(Request $request): Response
    {
        $schemas = Schema::definitions();

        if (!$request->isCollection()) {
            foreach ($schemas as $schema) {
                if ($schema['id'] === $request->id()) {
                    return Response::ok($schema);
                }
            }

            return Response::notFound();
        }

        return Response::list($schemas, count($schemas), 1);
    }

    // ------------------------------------------------------------------ users

    private function users(Request $request, Source $source): Response
    {
        return match ($request->method) {
            'GET'    => $request->isCollection()
                ? $this->listUsers($request, $source)
                : $this->readUser($request, $source),
            'POST'   => $this->createUser($request, $source),
            'PUT'    => $this->replaceUser($request, $source),
            'PATCH'  => $this->patchUser($request, $source),
            'DELETE' => $this->deleteUser($request, $source),
            default  => Response::error(405, 'Method not allowed on this resource.'),
        };
    }

    private function listUsers(Request $request, Source $source): Response
    {
        ['filter' => $filter, 'error' => $error] = Filter::parse($request->filter());
        if ($error !== null) {
            return Response::badRequest($error, 'invalidFilter');
        }

        $matched = [];
        foreach (UserResource::allFor($source) as $entry) {
            /** @var Link $link */
            $link = $entry['link'];
            /** @var User $user */
            $user = $entry['user'];

            if ($filter !== null) {
                $candidate = match (true) {
                    $filter->isOn('userName')   => (string) $user->fields['name'],
                    $filter->isOn('externalId') => (string) $link->fields['external_id'],
                    $filter->isOn('id')         => (string) $link->fields['scim_id'],
                    $filter->isOn('displayName') => $user->getFriendlyName(),
                    $filter->isOn('active')     => $user->fields['is_active'] ? 'true' : 'false',
                    default                     => null,
                };

                // A filter on an attribute this server does not carry is not an
                // empty result — it is a question that was not understood, and
                // saying so stops a connector concluding the directory is empty
                // and provisioning everyone a second time.
                if ($candidate === null) {
                    return Response::badRequest(
                        sprintf('Filtering on "%s" is not supported.', $filter->attribute),
                        'invalidFilter'
                    );
                }

                if (!$filter->test($candidate)) {
                    continue;
                }
            }

            $matched[] = UserResource::toScim($source, $link, $user);
        }

        return $this->page($matched, $request);
    }

    private function readUser(Request $request, Source $source): Response
    {
        $link = Link::forScimId($source->getID(), $request->id());
        if ($link === null) {
            return Response::notFound('No such user.');
        }

        $user = $link->user();
        if ($user === null) {
            return Response::notFound('No such user.');
        }

        return Response::ok(UserResource::toScim($source, $link, $user));
    }

    private function createUser(Request $request, Source $source): Response
    {
        $person = UserResource::fromScim($request->body);

        if ($person['userName'] === '') {
            return Response::badRequest('userName is required.', 'invalidValue');
        }

        $result = Provisioning::upsert($source, $person);

        if ($result['error'] === Provisioning::CONFLICT) {
            return Response::conflict(
                'A GLPI user with this userName already exists and is not managed by this directory.'
            );
        }

        if ($result['link'] === null) {
            return Response::badRequest((string) $result['error']);
        }

        $this->applyMappings($source, $result['link']);

        $user = $result['link']->user();
        $body = UserResource::toScim($source, $result['link'], $user);

        // 201 on create, 200 on "you asked to create someone who exists". The
        // spec prefers 409 for the latter, but connectors replay creates after
        // a timeout, and answering 409 to a replay makes a transient network
        // fault permanent.
        return $result['created']
            ? Response::created($body, (string) $body['meta']['location'])
            : Response::ok($body);
    }

    private function replaceUser(Request $request, Source $source): Response
    {
        $link = Link::forScimId($source->getID(), $request->id());
        if ($link === null) {
            return Response::notFound('No such user.');
        }

        $person = UserResource::fromScim($request->body);
        // PUT is a statement about the whole resource, so an omitted `active`
        // means active — unlike PATCH, where an omitted attribute means
        // "unchanged".
        $person['active'] ??= true;

        $result = Provisioning::upsert($source, $person + [
            'externalId' => (string) $link->fields['external_id'],
        ]);

        if ($result['error'] === Provisioning::CONFLICT) {
            return Response::conflict('That userName belongs to another account.');
        }

        if ($result['link'] === null) {
            return Response::badRequest((string) $result['error']);
        }

        $this->applyMappings($source, $result['link']);

        return Response::ok(UserResource::toScim($source, $result['link'], $result['link']->user()));
    }

    /**
     * PATCH, which in practice means one operation: deactivation.
     *
     * Entra and Okta both express "this person has left" as a patch setting
     * `active` to false, and it is the single most important message this
     * server receives — it is the one that takes a departed employee's access
     * away. The rest of the patch grammar is supported where it is simple and
     * refused where it is not.
     */
    private function patchUser(Request $request, Source $source): Response
    {
        $link = Link::forScimId($source->getID(), $request->id());
        if ($link === null) {
            return Response::notFound('No such user.');
        }

        $operations = $request->body['Operations'] ?? $request->body['operations'] ?? null;
        if (!is_array($operations)) {
            return Response::badRequest('A PatchOp needs an Operations array.', 'invalidSyntax');
        }

        $person  = [];
        $refused = null;

        foreach ($operations as $operation) {
            if (!is_array($operation)) {
                continue;
            }

            $op    = strtolower((string) ($operation['op'] ?? ''));
            $path  = strtolower(trim((string) ($operation['path'] ?? '')));
            $value = $operation['value'] ?? null;

            if ($op === 'remove' && $path === 'active') {
                $person['active'] = false;
                continue;
            }

            if (!in_array($op, ['add', 'replace'], true)) {
                $refused = sprintf('Unsupported patch operation "%s".', $op);
                continue;
            }

            // Two shapes are legal: a path plus a scalar, or no path and an
            // object of attributes. Entra sends the first, Okta the second.
            $attributes = $path === '' && is_array($value)
                ? $value
                : [$path => $value];

            foreach ($attributes as $attribute => $attribute_value) {
                $known = self::patchAttribute((string) $attribute, $attribute_value, $person);
                if (!$known) {
                    $refused = sprintf('Unsupported patch path "%s".', $attribute);
                }
            }
        }

        if ($person === []) {
            return $refused !== null
                ? Response::badRequest($refused, 'invalidPath')
                : Response::ok(UserResource::toScim($source, $link, $link->user()));
        }

        // Deactivation is a retirement, not a field update: which of the two it
        // is comes from the source's own policy, and the user may need to be
        // moved to the bin rather than merely flagged.
        if (($person['active'] ?? true) === false) {
            Provisioning::deprovision($source, $link);
            $link->getFromDB($link->getID());

            $user = $link->user();

            return $user === null
                ? Response::noContent()
                : Response::ok(UserResource::toScim($source, $link, $user));
        }

        $person['userName'] ??= (string) ($link->user()?->fields['name'] ?? '');
        $result = Provisioning::upsert($source, $person);

        if ($result['link'] === null) {
            return Response::badRequest((string) $result['error']);
        }

        $this->applyMappings($source, $result['link']);

        return Response::ok(UserResource::toScim($source, $result['link'], $result['link']->user()));
    }

    /**
     * Fold one patched attribute into the person being built.
     *
     * @param array<string,mixed> $person
     * @return bool whether the path was one we act on
     */
    private static function patchAttribute(string $path, mixed $value, array &$person): bool
    {
        switch (strtolower($path)) {
            case 'active':
                $person['active'] = UserResource::toBool($value);

                return true;

            case 'username':
                $person['userName'] = trim((string) $value);

                return true;

            case 'externalid':
                $person['externalId'] = trim((string) $value);

                return true;

            case 'name.givenname':
                $person['firstname'] = trim((string) $value);

                return true;

            case 'name.familyname':
                $person['lastname'] = trim((string) $value);

                return true;

            case 'name':
                if (!is_array($value)) {
                    return false;
                }
                $person['firstname'] = trim((string) ($value['givenName'] ?? ''));
                $person['lastname']  = trim((string) ($value['familyName'] ?? ''));

                return true;

            case 'emails':
                if (!is_array($value)) {
                    return false;
                }
                $person['email'] = UserResource::fromScim(['emails' => $value])['email'];

                return true;

            case 'displayname':
                // Derived from the name parts here, so it is accepted and
                // ignored rather than refused: a connector that gets an error
                // for displayName treats the whole patch as having failed.
                return true;

            default:
                return false;
        }
    }

    private function deleteUser(Request $request, Source $source): Response
    {
        $link = Link::forScimId($source->getID(), $request->id());
        if ($link === null) {
            return Response::notFound('No such user.');
        }

        Provisioning::deprovision($source, $link);

        return Response::noContent();
    }

    // ----------------------------------------------------------------- groups

    private function groups(Request $request, Source $source): Response
    {
        return match ($request->method) {
            'GET'    => $request->isCollection()
                ? $this->listGroups($request, $source)
                : $this->readGroup($request, $source),
            'POST'   => $this->createGroup($request, $source),
            'PUT'    => $this->replaceGroup($request, $source),
            'PATCH'  => $this->patchGroup($request, $source),
            'DELETE' => $this->deleteGroup($request, $source),
            default  => Response::error(405, 'Method not allowed on this resource.'),
        };
    }

    private function listGroups(Request $request, Source $source): Response
    {
        ['filter' => $filter, 'error' => $error] = Filter::parse($request->filter());
        if ($error !== null) {
            return Response::badRequest($error, 'invalidFilter');
        }

        $matched = [];
        foreach (IdpGroup::forSource($source->getID()) as $group) {
            if ($filter !== null) {
                $candidate = match (true) {
                    $filter->isOn('displayName') => (string) $group->fields['name'],
                    $filter->isOn('id', 'externalId') => (string) $group->fields['external_id'],
                    default => null,
                };

                if ($candidate === null) {
                    return Response::badRequest(
                        sprintf('Filtering on "%s" is not supported.', $filter->attribute),
                        'invalidFilter'
                    );
                }

                if (!$filter->test($candidate)) {
                    continue;
                }
            }

            $matched[] = GroupResource::toScim($source, $group);
        }

        return $this->page($matched, $request);
    }

    private function readGroup(Request $request, Source $source): Response
    {
        $group = $this->findGroup($source, $request->id());

        return $group === null
            ? Response::notFound('No such group.')
            : Response::ok(GroupResource::toScim($source, $group));
    }

    private function createGroup(Request $request, Source $source): Response
    {
        $name = trim((string) ($request->body['displayName'] ?? ''));
        if ($name === '') {
            return Response::badRequest('displayName is required.', 'invalidValue');
        }

        // The directory's own id where it gave one; the name otherwise. Some
        // connectors omit externalId on groups and then address them by
        // displayName, and a group with no stable id at all cannot be patched.
        $external_id = trim((string) ($request->body['externalId'] ?? $request->body['id'] ?? $name));

        $group = IdpGroup::upsert($source->getID(), $external_id, $name);
        GroupResource::mirror($source, $group);

        $members = GroupResource::resolveMembers($source, (array) ($request->body['members'] ?? []));
        $group->setMembers($members['ids']);

        $this->afterGroupChange($source, $group, $members['unknown'], []);

        $body = GroupResource::toScim($source, $group);

        return Response::created($body, (string) $body['meta']['location']);
    }

    private function replaceGroup(Request $request, Source $source): Response
    {
        $group = $this->findGroup($source, $request->id());
        if ($group === null) {
            return Response::notFound('No such group.');
        }

        $name = trim((string) ($request->body['displayName'] ?? ''));
        if ($name !== '' && $name !== (string) $group->fields['name']) {
            $group->update(['id' => $group->getID(), 'name' => $name]);
        }

        $before = $group->memberIds();

        $members = GroupResource::resolveMembers($source, (array) ($request->body['members'] ?? []));
        $group->setMembers($members['ids']);

        $this->afterGroupChange($source, $group, $members['unknown'], $before);

        return Response::ok(GroupResource::toScim($source, $group));
    }

    /**
     * Group PATCH — where membership actually changes.
     *
     * This is the endpoint that carries "Alice joined Executive", and therefore
     * the one that carries most of what group mapping acts on. The awkward part
     * is `remove` with a value path — `members[value eq "..."]` — which is a
     * fragment of the filter grammar appearing in a place the filter parser
     * never sees.
     */
    private function patchGroup(Request $request, Source $source): Response
    {
        $group = $this->findGroup($source, $request->id());
        if ($group === null) {
            return Response::notFound('No such group.');
        }

        $operations = $request->body['Operations'] ?? $request->body['operations'] ?? null;
        if (!is_array($operations)) {
            return Response::badRequest('A PatchOp needs an Operations array.', 'invalidSyntax');
        }

        // Who was in the group before anything changed. Needed because the
        // interesting case is somebody *leaving*: their mappings have to be
        // recomputed too, and by the time the patch is applied they are no
        // longer among the members to iterate over.
        $before  = $group->memberIds();
        $unknown = 0;

        foreach ($operations as $operation) {
            if (!is_array($operation)) {
                continue;
            }

            $op   = strtolower((string) ($operation['op'] ?? ''));
            $path = trim((string) ($operation['path'] ?? ''));

            if (stripos($path, 'displayname') === 0) {
                $name = trim((string) ($operation['value'] ?? ''));
                if ($name !== '') {
                    $group->update(['id' => $group->getID(), 'name' => $name]);
                }
                continue;
            }

            if (stripos($path, 'members') !== 0 && $path !== '') {
                continue;
            }

            // `members[value eq "abc"]` names its target in the path; a plain
            // `members` path carries it in the value.
            $targets = [];
            if (preg_match('/\[\s*value\s+eq\s+"([^"]+)"\s*\]/i', $path, $m) === 1) {
                $targets[] = ['value' => $m[1]];
            } else {
                $value = $operation['value'] ?? [];
                $targets = is_array($value) ? $value : [];
            }

            $resolved = GroupResource::resolveMembers($source, $targets);
            $unknown += $resolved['unknown'];

            match ($op) {
                'add'     => array_map([$group, 'addMember'], $resolved['ids']),
                'remove'  => array_map([$group, 'removeMember'], $resolved['ids']),
                // A replace on `members` is a whole-membership statement.
                'replace' => $group->setMembers($resolved['ids']),
                default   => null,
            };
        }

        $this->afterGroupChange($source, $group, $unknown, $before);

        return Response::ok(GroupResource::toScim($source, $group));
    }

    private function deleteGroup(Request $request, Source $source): Response
    {
        $group = $this->findGroup($source, $request->id());
        if ($group === null) {
            return Response::notFound('No such group.');
        }

        $members = $group->memberIds();
        $group->delete(['id' => $group->getID()], true);

        // The people are still people; only the group is gone. Their mappings
        // are recomputed so a GLPI group granted by the group that just
        // disappeared goes away with it.
        foreach ($members as $users_id) {
            $link = Link::forUser($source->getID(), $users_id);
            if ($link !== null) {
                $this->applyMappings($source, $link);
            }
        }

        EventLog::record(EventLog::GROUP_SYNC, $source, [
            'subject' => (string) $group->fields['name'],
            'detail'  => 'Directory group deleted.',
        ]);

        return Response::noContent();
    }

    private function findGroup(Source $source, string $id): ?IdpGroup
    {
        if ($id === '') {
            return null;
        }

        $group = new IdpGroup();
        $found = $group->getFromDBByCrit([
            'plugin_glpiidentity_sources_id' => $source->getID(),
            'external_id'                    => $id,
        ]);

        return $found ? $group : null;
    }

    /**
     * Re-apply mappings to everyone a group change touched.
     *
     * Group membership is the input to most mappings, so a change that did not
     * trigger this would leave the mapping correct in configuration and wrong
     * in fact until the person next signed in.
     *
     * Both sides of the change, not just the current members. Somebody who has
     * just been removed from Executive is precisely the person whose VIP group
     * needs taking away, and they are no longer in the list of who to look at.
     *
     * @param int[] $before who was in the group before the change
     */
    private function afterGroupChange(Source $source, IdpGroup $group, int $unknown, array $before): void
    {
        $touched = array_unique(array_merge($before, $group->memberIds()));

        foreach ($touched as $users_id) {
            $link = Link::forUser($source->getID(), $users_id);
            if ($link !== null) {
                $this->applyMappings($source, $link);
            }
        }

        EventLog::record(EventLog::GROUP_SYNC, $source, [
            'subject' => (string) $group->fields['name'],
            'detail'  => sprintf(
                '%d member(s)%s.',
                count($group->memberIds()),
                $unknown > 0 ? sprintf(', %d unknown member(s) ignored', $unknown) : ''
            ),
        ]);
    }

    // ------------------------------------------------------------------ shared

    private function applyMappings(Source $source, Link $link): void
    {
        $user = $link->user();
        if ($user === null) {
            return;
        }

        Mapper::apply($source, $user, Provisioning::claimsFor($source, (int) $user->getID()));
    }

    /**
     * One page of a list, indexed the way SCIM indexes.
     *
     * @param array<int,array<string,mixed>> $resources
     */
    private function page(array $resources, Request $request): Response
    {
        $total = count($resources);
        $start = $request->startIndex();
        $count = $request->count((int) Settings::get('scim_max_results'));

        return Response::list(
            array_slice($resources, $start - 1, $count),
            $total,
            $start
        );
    }
}
