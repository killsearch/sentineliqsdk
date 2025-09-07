"""Cluster25 API client for threat intelligence queries."""

from __future__ import annotations

from typing import Any

import requests


class Cluster25Client:
    """Client for interacting with Cluster25 API."""

    def __init__(
        self,
        client_id: str,
        client_key: str,
        base_url: str,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.client_id = client_id
        self.client_key = client_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.current_token: str | None = None
        self.headers: dict[str, str] = {}

    def _get_token(self) -> str:
        """Get authentication token from Cluster25 API."""
        if self.current_token:
            return self.current_token

        payload = {"client_id": self.client_id, "client_secret": self.client_key}

        try:
            response = requests.post(
                url=f"{self.base_url}/token",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            response.raise_for_status()

            data = response.json()
            self.current_token = data["data"]["token"]
            self.headers = {"Authorization": f"Bearer {self.current_token}"}

            return self.current_token

        except requests.exceptions.RequestException as e:
            raise Exception(f"Unable to retrieve token from Cluster25 platform: {e}")

    def investigate(self, indicator: str) -> dict[str, Any]:
        """Investigate an indicator using Cluster25 API."""
        # Ensure we have a valid token
        self._get_token()

        params = {"indicator": indicator}

        try:
            response = requests.get(
                url=f"{self.base_url}/investigate",
                params=params,
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()

            data = response.json()
            return data["data"]

        except requests.exceptions.RequestException as e:
            return {
                "error": f"Unable to retrieve investigate result for indicator '{indicator}' "
                f"from Cluster25 platform: {e}"
            }
