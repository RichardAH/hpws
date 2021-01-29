#!/bin/bash
# This script must be run from hpws repo root. eg: ./test/client-test.sh
# Requires docker.

make hpws echo-client || { echo "Build failed. Make sure you are running this script from hpws repo root."; exit 1; }

# Pull latest autobahn docker image if not exists.
docker image inspect crossbario/autobahn-testsuite >/dev/null 2>&1 || \
    docker pull crossbario/autobahn-testsuite || \
    { echo "Check whether docker is installed properly."; exit 1; }

# Generate tls key files inside autobahn mount.
if [ -f ${PWD}/test/autobahn/key.pem -a -f ${PWD}/test/autobahn/cert.pem ]; then
    :
else
    rm ${PWD}/test/autobahn/key.pem ${PWD}/test/autobahn/cert.pem > /dev/null 2>&1
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout ${PWD}/test/autobahn/key.pem -out ${PWD}/test/autobahn/cert.pem -subj "/C=AU/ST=ACT/L=AU/O=abahn/CN=abahn"
fi

# Clear existing reports.
sudo rm -r ${PWD}/test/autobahn/client-reports >/dev/null 2>&1

# Run the autobahn test server (runs in background with -d flag).
docker run -d --rm -v "${PWD}/test/autobahn:/autobahn" --name hpws-autobahn-client-tester -p 9001:443 \
    crossbario/autobahn-testsuite /usr/local/bin/wstest --mode fuzzingserver --spec /autobahn/client-tests.json --webport 0

sigint_handler()
{
    docker stop hpws-autobahn-client-tester
}
trap sigint_handler SIGINT

# Run hpws echo client. (give some time for autobahn container to initialize in background)
sleep 1
./echo-client

docker stop hpws-autobahn-client-tester >/dev/null 2>&1

echo "test report generated at ${PWD}/test/autobahn/client-reports/index.html"
