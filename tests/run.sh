#!/bin/sh
# Both suites, with the mock identity provider running behind them.
#
# Run inside the GLPI container, from the plugin directory:
#   docker compose -p glpi exec glpi sh -c 'cd /var/www/glpi/plugins/glpiidentity && tests/run.sh'
#
# mapping.php needs nothing at all. scim.php needs the plugin active — it drives
# the real HTTP endpoint. oidc.php additionally needs the mock provider, which
# this starts.
# Each suite restores the configuration and purges the fixtures it creates.
set -e

cd "$(dirname "$0")/.."

# A fresh signing key each run, so a stale one cannot make a broken JWKS fetch
# look like a working one.
rm -f /tmp/glpiidentity-idp-*.pem /tmp/glpiidentity-idp-state.json

php -S 127.0.0.1:9097 tests/mock-idp.php >/tmp/glpiidentity-idp.log 2>&1 &
idp=$!
trap 'kill $idp 2>/dev/null' EXIT
sleep 1

status=0
# Needs neither the mock provider nor the web server - it drives the mapping
# engine directly - so it runs first and fails fast.
php tests/mapping.php || status=1
php tests/scim.php || status=1
php tests/oidc.php || status=1

exit $status
