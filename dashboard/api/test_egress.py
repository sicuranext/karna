"""The outbound guard refuses link-local / metadata destinations, resolves once, pins the address."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import unittest
from unittest import mock

import httpx

import egress
import kong_connection


def _info(*ips):
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]


class BlockedTests(unittest.TestCase):
    def test_metadata_and_link_local_are_blocked(self):
        for ip in ("169.254.169.254", "169.254.0.1", "::ffff:169.254.169.254", "fe80::1",
                   "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "224.0.0.1"):
            self.assertTrue(egress.blocked(ipaddress.ip_address(ip)), ip)

    def test_private_loopback_and_public_are_allowed(self):
        for ip in ("10.0.0.1", "172.17.0.1", "192.168.1.10", "127.0.0.1", "::1", "8.8.8.8", "2001:db8::1"):
            self.assertFalse(egress.blocked(ipaddress.ip_address(ip)), ip)

    def test_kong_connection_rejects_metadata_literals(self):
        with self.assertRaises(ValueError):
            kong_connection.validate({"protocol": "http", "host": "169.254.169.254", "port": 80})
        self.assertEqual(kong_connection.validate({"protocol": "http", "host": "10.1.2.3", "port": 8001})["host"], "10.1.2.3")


class TransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.seen = []

        def handler(request):
            self.seen.append(request)
            return httpx.Response(200, json={"ok": True})

        self.client = httpx.AsyncClient(transport=egress.GuardedTransport(httpx.MockTransport(handler)))

    async def asyncTearDown(self):
        await self.client.aclose()

    def resolve(self, *ips):
        lookup = mock.AsyncMock(return_value=_info(*ips))
        return mock.patch.object(asyncio.get_running_loop(), "getaddrinfo", lookup), lookup

    async def test_name_resolving_to_metadata_is_refused(self):
        patcher, _ = self.resolve("169.254.169.254")
        with patcher, self.assertRaises(egress.BlockedDestination):
            await self.client.get("http://rebind.example/latest/meta-data/")
        self.assertEqual(self.seen, [])

    async def test_any_bad_record_refuses_the_name(self):
        patcher, _ = self.resolve("10.0.0.5", "169.254.169.254")
        with patcher, self.assertRaises(httpx.HTTPError):
            await self.client.get("http://mixed.example/")
        self.assertEqual(self.seen, [])

    async def test_connects_to_the_checked_address_keeping_host_and_sni(self):
        patcher, lookup = self.resolve("10.0.0.5")
        with patcher:
            await self.client.get("https://kong.internal:8444/status")
        lookup.assert_awaited_once()                       # resolved once: no second lookup to rebind
        sent = self.seen[0]
        self.assertEqual(sent.url.host, "10.0.0.5")
        self.assertEqual(sent.url.port, 8444)
        self.assertEqual(sent.url.path, "/status")
        self.assertEqual(sent.headers["host"], "kong.internal:8444")
        self.assertEqual(sent.extensions.get("sni_hostname"), "kong.internal")

    async def test_literal_private_address_passes_untouched(self):
        await self.client.get("http://127.0.0.1:11434/api/tags")
        self.assertEqual(str(self.seen[0].url), "http://127.0.0.1:11434/api/tags")

    async def test_literal_metadata_address_is_refused(self):
        with self.assertRaises(egress.BlockedDestination):
            await self.client.get("http://169.254.169.254/")


if __name__ == "__main__":
    unittest.main()
