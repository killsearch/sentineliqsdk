"""CrowdSec CTI API client for threat intelligence queries."""

from __future__ import annotations

import json
from typing import Any

import requests
from requests.compat import urljoin


class CrowdSecAPIError(Exception):
    """Exception raised when the CrowdSec API returns an error."""

    def __init__(self, message: str, status_code: int | None = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class CrowdSecRateLimitError(Exception):
    """Exception raised when the CrowdSec API returns a 429 rate limit error."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class CrowdSecClient:
    """Client for the CrowdSec CTI API.

    This client provides access to CrowdSec's threat intelligence data
    for IP addresses and other observables.
    """

    def __init__(self, api_key: str, base_url: str = "https://cti.api.crowdsec.net"):
        """Initialize the CrowdSec client.

        Args:
            api_key: The CrowdSec API key
            base_url: The base URL for the CrowdSec API (default: production)
        """
        self.api_key = api_key
        self.base_url = base_url

    def _request(self, path: str) -> dict[str, Any]:
        """Make a request to the CrowdSec API.

        Args:
            path: The API endpoint path

        Returns
        -------
            The JSON response as a dictionary

        Raises
        ------
            CrowdSecAPIError: If the API returns an error
            CrowdSecRateLimitError: If rate limited
        """
        headers = {
            "x-api-key": self.api_key,
            "accept": "application/json",
            "User-Agent": "sentineliqsdk-crowdsec/1.0.0",
        }

        url = urljoin(self.base_url, path)

        try:
            response = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as e:
            raise CrowdSecAPIError(f"Request failed: {e}") from e

        # Constants for HTTP status codes
        rate_limit_status = 429
        success_status = 200

        if response.status_code == rate_limit_status:
            raise CrowdSecRateLimitError("Rate limit exceeded")

        if response.status_code != success_status:
            raise CrowdSecAPIError(
                f"API request failed with status {response.status_code}",
                status_code=response.status_code,
            )

        try:
            return response.json()
        except json.JSONDecodeError as e:
            raise CrowdSecAPIError(f"Failed to parse JSON response: {e}") from e

    def get_ip_summary(self, ip_address: str) -> dict[str, Any]:
        """Get threat intelligence summary for an IP address.

        Args:
            ip_address: The IP address to analyze

        Returns
        -------
            Dictionary containing threat intelligence data
        """
        path = f"/v2/smoke/{ip_address}"
        return self._request(path)
