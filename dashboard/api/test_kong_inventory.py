import unittest
from unittest.mock import AsyncMock, patch

import httpx

import app


class KongInventoryPaginationTests(unittest.IsolatedAsyncioTestCase):
    async def test_follows_all_same_origin_cursor_pages(self):
        requested = []

        def handler(request):
            requested.append(str(request.url))
            if request.url.params.get("offset") == "page-2":
                return httpx.Response(200, json={"data": [{"id": "second"}]})
            return httpx.Response(200, json={
                "data": [{"id": "first"}],
                "next": "/plugins?offset=page-2&size=1000",
            })

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            rows = await app._fetch_kong_pages(client, "https://kong.example.test:8444", "plugins")

        self.assertEqual([row["id"] for row in rows], ["first", "second"])
        self.assertEqual(len(requested), 2)

    async def test_rejects_cross_origin_pagination_cursor(self):
        def handler(_request):
            return httpx.Response(200, json={
                "data": [],
                "next": "https://attacker.example.test/plugins?offset=stolen",
            })

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with self.assertRaisesRegex(ValueError, "changed origin"):
                await app._fetch_kong_pages(client, "https://kong.example.test", "plugins")

    def test_groups_crs_inventory_by_normalized_path(self):
        groups = app._crs_inventory_groups([
            {"id": "one", "name": "karna", "config": {"crs_plugins_path": "/plugins"}},
            {"id": "two", "name": "karna", "config": {"crs_plugins_path": "/plugins/"}},
            {"id": "three", "name": "karna", "config": {}},
            {"id": "ignored", "name": "other", "config": {"crs_plugins_path": "/plugins"}},
        ])

        self.assertEqual(set(groups), {"/plugins/", "/opt/coreruleset-plugins/"})
        self.assertEqual([plugin["id"] for plugin in groups["/plugins/"]], ["one", "two"])

    async def test_repeated_forced_refresh_is_coalesced_for_a_short_interval(self):
        cached = {"connected": True, "services": []}
        previous = dict(app._kong_inventory_cache)
        app._kong_inventory_cache.update({
            "ts": app.time.monotonic(),
            "key": "https://kong.example.test",
            "data": cached,
            "task": None,
            "generation": 0,
        })
        try:
            with patch.object(app, "_kong_admin_url", return_value="https://kong.example.test"), \
                    patch.object(app, "_load_kong_inventory", new=AsyncMock()) as load:
                result = await app._refresh_kong_inventory(force=True)
            self.assertIs(result, cached)
            load.assert_not_awaited()
        finally:
            app._kong_inventory_cache.clear()
            app._kong_inventory_cache.update(previous)


if __name__ == "__main__":
    unittest.main()
