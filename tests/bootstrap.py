import requests
import json
import time

test_service_id = False
test_service_plugin_id = False
test_service_just_created = False

resp = requests.get('http://localhost:8001/services')
data = json.loads(resp.text)
if "data" in data:
    for service in data["data"]:
        if "name" in service:
            if service["name"] == "karna_example.com":
                test_service_id = service["id"]
                break

if not test_service_id:
    resp = requests.post(
        'http://localhost:8001/services',
        json={
            "name": "karna_example.com",
            "retries": 5,
            "protocol": "https",
            "host": "httpbin.org",
            "port": 443,
            "path": "/anything",
            "connect_timeout": 6000,
            "write_timeout": 6000,
            "read_timeout": 6000,
            "enabled": True
        }
    )

    if resp.status_code == 201:
        test_service_id = json.loads(resp.text)["id"]
    
        # add a default route
        resp = requests.post(
            f'http://localhost:8001/services/{test_service_id}/routes',
            json={
                "hosts": [
                    "karna-test"
                ],
                "strip_path": True,
                "preserve_host": False
            }
        )

        test_service_just_created = True

print(f'test_service_id: {test_service_id}')

resp = requests.get(
    f'http://localhost:8001/services/{test_service_id}/plugins'
)
data = json.loads(resp.text)
if "data" in data:
    for plugin in data["data"]:
        if "name" in plugin:
            if plugin["name"] == "karna":
                test_service_plugin_id = plugin["id"]
                break

if not test_service_plugin_id:
    resp = requests.post(
        f'http://localhost:8001/services/{test_service_id}/plugins',
        json={
            "name": "karna",
        }
    )

    if resp.status_code == 201:
        test_service_plugin_id = json.loads(resp.text)["id"]

print(f'test_service_plugin_id: {test_service_plugin_id}')

if test_service_just_created:
    time.sleep(2)

