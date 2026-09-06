#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bijstaan
# Put glpiidentity back to as-installed, and start the mock identity provider
# that the OIDC suite needs.
#
#   ./identity-setup.sh start   # or stop, or reset
set -eu

CONTAINER=${CONTAINER:-glpi-glpi-1}
MOCK=/var/www/glpi/plugins/glpiidentity/tests/mock-idp.php

reset_config() {
  docker exec "$CONTAINER" php -r '
    require "/var/www/glpi/vendor/autoload.php";
    (new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();
    (new Auth())->login("glpi", "glpi", true);
    (new Plugin())->init(true);
    global $DB;

    // Sources first: purging one clears its mappings, links and directory
    // groups, which is the behaviour worth exercising here as well as relying
    // on.
    foreach (getAllDataFromTable("glpi_plugin_glpiidentity_sources") as $row) {
        (new GlpiPlugin\Glpiidentity\Source())->delete(["id" => $row["id"]], true);
    }
    $DB->delete("glpi_plugin_glpiidentity_events", [1]);

    $ctx = "plugin:glpiidentity";
    Config::deleteConfigurationValues($ctx, array_keys(GlpiPlugin\Glpiidentity\Settings::DEFAULTS));
    Config::setConfigurationValues($ctx, GlpiPlugin\Glpiidentity\Settings::DEFAULTS);

    echo "glpiidentity reset to as-installed\n";
  '
}

case "${1:-start}" in
  reset)
    reset_config
    ;;
  start)
    reset_config
    docker exec "$CONTAINER" pkill -f '[m]ock-idp.php' >/dev/null 2>&1 || true
    # A fresh signing key each run; the plugin caches JWKS for fifteen minutes,
    # so the cache is dropped too or the old key set outlives the mock.
    docker exec "$CONTAINER" sh -c 'rm -f /tmp/glpiidentity-idp-*.pem /tmp/glpiidentity-idp-state.json'
    docker exec -d "$CONTAINER" php -S 127.0.0.1:9097 "$MOCK"
    sleep 1
    docker exec "$CONTAINER" sh -c \
      'curl -s http://127.0.0.1:9097/.well-known/openid-configuration' \
      | grep -q authorization_endpoint || { echo "the mock IdP did not come up" >&2; exit 1; }
    # Two sources the login page can actually offer: a house provider and one
    # reached by email domain. The login block only renders for a source that
    # is *ready*, so without these there is nothing on that page to test.
    docker exec "$CONTAINER" php -r '
      require "/var/www/glpi/vendor/autoload.php";
      (new Glpi\Kernel\Kernel(Glpi\Application\Environment::PRODUCTION->value))->boot();
      (new Auth())->login("glpi", "glpi", true);
      (new Plugin())->init(true);
      global $DB;

      GlpiPlugin\Glpiidentity\Settings::save(["enabled" => "1"]);

      $make = function (string $name, string $domains, int $default) use ($DB) {
          $source = new GlpiPlugin\Glpiidentity\Source();
          $id = (int) $source->add([
              "name" => $name, "entities_id" => 0, "is_active" => 1, "sso_enabled" => 1,
              "issuer" => "https://placeholder.invalid", "client_id" => "glpi-test-client",
              "client_secret" => "secret", "email_domains" => $domains,
              "is_default" => $default, "jit_provision" => 1, "default_profiles_id" => 1,
          ]);
          // The mock speaks http on loopback, which the https rule refuses for a
          // good reason; written straight to the table so the rule stays under
          // test rather than being relaxed for the convenience of a fixture.
          $DB->update(GlpiPlugin\Glpiidentity\Source::getTable(), [
              "issuer" => "http://127.0.0.1:9097",
              "discovery_url" => "http://127.0.0.1:9097/.well-known/openid-configuration",
          ], ["id" => $id]);
          $source->getFromDB($id);
          $source->discover();
      };

      $make("Bijstaan", "", 1);
      $make("Contoso", "contoso.example", 0);
      echo "login fixtures ready\n";
    '
    echo "mock identity provider listening on 127.0.0.1:9097 inside $CONTAINER"
    ;;
  stop)
    docker exec "$CONTAINER" pkill -f '[m]ock-idp.php' >/dev/null 2>&1 || true
    reset_config
    echo "mock identity provider stopped"
    ;;
  *)
    echo "usage: $0 [start|stop|reset]" >&2
    exit 2
    ;;
esac
