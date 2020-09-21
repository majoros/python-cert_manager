# -*- coding: utf-8 -*-
"""Define the cert_manager.domain.Domain class."""

import logging

from ._endpoint import Endpoint

LOGGER = logging.getLogger(__name__)


class Domain(Endpoint):
    """Query the Sectigo Cert Manager REST API for Domain data."""

    def __init__(self, client, api_version="v1"):
        """Initialize the class.

        Note: The *all* method will be run on object instantiation to fetch all organizations

        :param object client: An instantiated cert_manager.Client object
        :param string api_version: The API version to use; the default is "v1"
        """
        super(Domain, self).__init__(client=client, endpoint="/domain", api_version=api_version)

        self.__orgs = None

    async def list(self, **kwargs):
        # size, position, name, state, status, orgId
        result = await self._client.get(self._api_url, params=kwargs)
        result = await result.json()
        return result
