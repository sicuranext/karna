#!/bin/bash

docker compose exec kong /usr/local/openresty/bin/resty /usr/local/kong/custom-plugins/karna/ka-regression-tests/004_bodyparser_cookie.lua | egrep -v '(\[C\]|\.\.\.|_G|stack|init_worker)'

