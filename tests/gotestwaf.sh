#!/bin/bash

# running script full path
SCRIPT_PATH=$(dirname $(realpath $0))

docker run --rm --network="host" --add-host "${1}:172.17.0.1" -v ${SCRIPT_PATH}/reports:/app/reports \
    wallarm/gotestwaf --url="https://$1" --wafName="Karna" --noEmailReport --includePayloads --skipWAFIdentification