# -*- coding: utf-8 -*-
"""Define the cert_manager.ssl.SSL unit tests."""
# Don't warn about things that happen as that is part of unit testing
# pylint: disable=protected-access
# pylint: disable=invalid-name

import aiohttp
import aiounittest
from aioresponses import CallbackResult, aioresponses

from cert_manager.ssl import SSL

from .lib.testbase import BaseTestClient


# pylint: disable=too-few-public-methods
class TestSSL(aiounittest.AsyncTestCase):  # pylint: disable=too-few-public-methods
    """Serve as a Base class for all tests of the Certificates class."""

    def setUp(self):  # pylint: disable=invalid-name
        """Initialize the class."""
        # Call the inherited setUp method
        super().setUp()

        # Make sure the Client fixture is created and setup
        self.cfixt = BaseTestClient()
        self.client = self.cfixt.client

        # Set some default values
        self.ep_path = "/ssl"
        self.api_version = "v1"
        self.api_url = self.cfixt.base_url + self.ep_path + "/" + self.api_version


class TestInit(TestSSL):
    """Test the class initializer."""

    def test_defaults(self):
        """Parameters should be set correctly inside the class using defaults."""
        end = SSL(client=self.client)

        # Check all the internal values
        self.assertEqual(end._client, self.client)
        self.assertEqual(end._api_version, self.api_version)
        self.assertEqual(end._api_url, self.api_url)

    def test_version(self):
        """Parameters should be set correctly inside the class with a custom version."""
        version = "v2"
        api_url = self.cfixt.base_url + self.ep_path + "/" + version

        end = SSL(client=self.client, api_version=version)

        # Check all the internal values
        self.assertEqual(end._client, self.client)
        self.assertEqual(end._api_version, version)
        self.assertEqual(end._api_url, api_url)

class TestList(TestSSL):
    @aioresponses()
    async def test_success(self, m):
        """It should return data correctly if a 200-level status code is returned with data."""
        # Setup the mocked response

        payload={"test": "data"}
        self.client.__session = aiohttp.ClientSession()
        self.client._api_url = self.api_url
        end = SSL(client=self.client, api_version=self.api_version)
        m.get(
            url=self.api_url,
            payload=payload,
        )

        cur_reqs = len(m.requests)
        # Call the function
        resp = await end.list()
        print("?????????????????????????")
        print("?????????????????????????")
        print(len(m.requests))
        print(cur_reqs)
        print(resp)
        print("?????????????????????????")
        print("?????????????????????????")

        # Verify all the query information
        self.assertEqual(resp, payload)
        self.assertEqual(len(m.requests), cur_reqs + 1)
        self.assertEqual(str(list(m.requests)[cur_reqs][0]), 'GET')
        self.assertEqual(str(list(m.requests)[cur_reqs][1]), self.api_url)
