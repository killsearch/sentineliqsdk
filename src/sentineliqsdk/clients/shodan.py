"""Shodan REST API client (httpx).

Implements all endpoints from https://developer.shodan.io/api/openapi.json
using httpx (sync). This client automatically injects the API key as a
`key` query parameter and respects HTTP proxies from the environment
(set by the SDK Worker).

Requirements: Python >= 3.13
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

# HTTP status code constants
HTTP_CLIENT_ERROR = 400


@dataclass
class RequestOptions:
    """Options for HTTP requests."""

    query: Mapping[str, Any] | None = None
    headers: Mapping[str, str] | None = None
    data: Mapping[str, Any] | bytes | None = None
    json_body: Mapping[str, Any] | None = None


def _merge_query(url: str, params: Mapping[str, Any] | None) -> str:
    if not params:
        return url
    parts = urllib.parse.urlsplit(url)
    current = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    extra = []
    for k, v in params.items():
        if v is None:
            continue
        value = str(v).lower() if isinstance(v, bool) else str(v)
        extra.append((k, value))
    query = urllib.parse.urlencode(current + extra)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


@dataclass(frozen=True)
class ShodanClient:
    """Minimal Shodan HTTP client covering all documented endpoints.

    - Uses httpx (sync client)
    - Respects environment proxies (`http_proxy`/`https_proxy`)
    - Adds `?key=...` to every request
    - Returns parsed JSON (dict/list/str) for 2xx responses; raises `URLError`/`HTTPError` otherwise
    """

    api_key: str
    base_url: str = "https://api.shodan.io"
    timeout: float = 30.0
    user_agent: str = "sentineliqsdk-shodan/1.0"

    # --- Core HTTP helpers ---
    def _request(
        self,
        method: str,
        path: str,
        options: RequestOptions | None = None,
    ) -> Any:
        """Make HTTP request to Shodan API."""
        if options is None:
            options = RequestOptions()

        url = self._build_url(path, options.query)
        req_headers = self._build_headers(options.headers)
        request_kwargs = self._build_request_kwargs(req_headers, options)
        return self._execute_request(method, url, request_kwargs)

    def _build_url(self, path: str, query: Mapping[str, Any] | None) -> str:
        """Build the complete URL with API key and query parameters."""
        url = self.base_url.rstrip("/") + path
        # Always include API key in query
        q = {"key": self.api_key}
        if query:
            q.update({k: v for k, v in query.items() if v is not None})
        return _merge_query(url, q)

    def _build_headers(self, custom_headers: Mapping[str, str] | None) -> dict[str, str]:
        """Build request headers."""
        req_headers = {"User-Agent": self.user_agent}
        if custom_headers:
            req_headers.update(custom_headers)
        return req_headers

    def _build_request_kwargs(
        self, req_headers: dict[str, str], options: RequestOptions
    ) -> dict[str, Any]:
        """Build request kwargs for httpx."""
        request_kwargs: dict[str, Any] = {"headers": req_headers}
        if options.json_body is not None:
            request_kwargs["json"] = options.json_body
        elif isinstance(options.data, dict | tuple):
            request_kwargs["data"] = urllib.parse.urlencode(options.data)
            req_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8"
            )
        elif isinstance(options.data, bytes):
            request_kwargs["content"] = options.data
        return request_kwargs

    def _execute_request(self, method: str, url: str, request_kwargs: dict[str, Any]) -> Any:
        """Execute the HTTP request and return parsed response."""
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.request(method.upper(), url, **request_kwargs)
            if resp.status_code >= HTTP_CLIENT_ERROR:
                # Include body text in error for easier debugging
                msg = f"HTTP {resp.status_code} for {resp.request.method} {resp.request.url}: {resp.text}"
                raise httpx.HTTPStatusError(msg, request=resp.request, response=resp)
            ctype = resp.headers.get("Content-Type", "application/json")
            if not resp.content:
                return None
            if "application/json" in ctype or "json" in ctype:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    return resp.text
            return resp.text

    def _get(self, path: str, **kwargs: Any) -> Any:
        """Make GET request."""
        options = RequestOptions(**kwargs)
        return self._request("GET", path, options)

    def _post(self, path: str, **kwargs: Any) -> Any:
        """Make POST request."""
        options = RequestOptions(**kwargs)
        return self._request("POST", path, options)

    def _put(self, path: str, **kwargs: Any) -> Any:
        """Make PUT request."""
        options = RequestOptions(**kwargs)
        return self._request("PUT", path, options)

    def _delete(self, path: str, **kwargs: Any) -> Any:
        """Make DELETE request."""
        options = RequestOptions(**kwargs)
        return self._request("DELETE", path, options)

    # --- Search Methods ---
    def host_information(
        self, ip: str, *, history: bool | None = None, minify: bool | None = None
    ) -> Any:
        """Get host information for an IP address."""
        return self._get(
            f"/shodan/host/{urllib.parse.quote(ip)}",
            query={"history": history, "minify": minify},
        )

    def search_host_count(self, query: str, *, facets: str | None = None) -> Any:
        """Get count of hosts matching query."""
        return self._get("/shodan/host/count", query={"query": query, "facets": facets})

    def search_host(
        self,
        query: str,
        *,
        page: int | None = None,
        facets: str | None = None,
        minify: bool | None = None,
    ) -> Any:
        """Search for hosts."""
        return self._get(
            "/shodan/host/search",
            query={"query": query, "page": page, "facets": facets, "minify": minify},
        )

    def search_host_facets(self) -> Any:
        """Get available search facets."""
        return self._get("/shodan/host/search/facets")

    def search_host_filters(self) -> Any:
        """Get available search filters."""
        return self._get("/shodan/host/search/filters")

    def search_host_tokens(self, query: str) -> Any:
        """Get search tokens for query."""
        return self._get("/shodan/host/search/tokens", query={"query": query})

    def ports(self) -> Any:
        """Get list of ports."""
        return self._get("/shodan/ports")

    def protocols(self) -> Any:
        """Get list of protocols."""
        return self._get("/shodan/protocols")

    # --- On-Demand Scanning ---
    def scan(self, ips: str) -> Any:
        """Start scan for IPs."""
        # x-www-form-urlencoded with "ips" param
        return self._post("/shodan/scan", data={"ips": ips})

    def scan_internet(self, port: int, protocol: str) -> Any:
        """Start internet scan for port and protocol."""
        return self._post("/shodan/scan/internet", data={"port": port, "protocol": protocol})

    def scans(self) -> Any:
        """Get list of scans."""
        return self._get("/shodan/scans")

    def scan_by_id(self, scan_id: str) -> Any:
        """Get scan by ID."""
        return self._get(f"/shodan/scans/{urllib.parse.quote(scan_id)}")

    # --- Network Alerts ---
    def alert_create(self, name: str, ips: list[str], *, expires: int | None = None) -> Any:
        """Create network alert."""
        body: dict[str, Any] = {"name": name, "filters": {"ip": ips}}
        if expires is not None:
            body["expires"] = expires
        return self._post("/shodan/alert", json_body=body)

    def alert_info(self, alert_id: str) -> Any:
        """Get alert information."""
        return self._get(f"/shodan/alert/{urllib.parse.quote(alert_id)}/info")

    def alert_delete(self, alert_id: str) -> Any:
        """Delete alert."""
        return self._delete(f"/shodan/alert/{urllib.parse.quote(alert_id)}")

    def alert_edit(self, alert_id: str, ips: list[str]) -> Any:
        """Edit alert IPs."""
        body = {"filters": {"ip": ips}}
        return self._post(f"/shodan/alert/{urllib.parse.quote(alert_id)}", json_body=body)

    def alerts(self) -> Any:
        """Get all alerts."""
        return self._get("/shodan/alert/info")

    def alert_triggers(self) -> Any:
        """Get alert triggers."""
        return self._get("/shodan/alert/triggers")

    def alert_enable_trigger(self, alert_id: str, trigger: str) -> Any:
        """Enable alert trigger."""
        return self._put(
            f"/shodan/alert/{urllib.parse.quote(alert_id)}/trigger/{urllib.parse.quote(trigger)}"
        )

    def alert_disable_trigger(self, alert_id: str, trigger: str) -> Any:
        """Disable alert trigger."""
        return self._delete(
            f"/shodan/alert/{urllib.parse.quote(alert_id)}/trigger/{urllib.parse.quote(trigger)}"
        )

    def alert_whitelist_service(self, alert_id: str, trigger: str, service: int) -> Any:
        """Whitelist service for alert."""
        return self._put(
            f"/shodan/alert/{urllib.parse.quote(alert_id)}/trigger/{urllib.parse.quote(trigger)}/ignore/{service}"
        )

    def alert_unwhitelist_service(self, alert_id: str, trigger: str, service: int) -> Any:
        """Remove service from alert whitelist."""
        return self._delete(
            f"/shodan/alert/{urllib.parse.quote(alert_id)}/trigger/{urllib.parse.quote(trigger)}/ignore/{service}"
        )

    def alert_add_notifier(self, alert_id: str, notifier_id: str) -> Any:
        """Add notifier to alert."""
        return self._put(
            f"/shodan/alert/{urllib.parse.quote(alert_id)}/notifier/{urllib.parse.quote(notifier_id)}"
        )

    def alert_remove_notifier(self, alert_id: str, notifier_id: str) -> Any:
        """Remove notifier from alert."""
        return self._delete(
            f"/shodan/alert/{urllib.parse.quote(alert_id)}/notifier/{urllib.parse.quote(notifier_id)}"
        )

    # --- Notifiers ---
    def notifiers(self) -> Any:
        """Get list of notifiers."""
        return self._get("/notifier")

    def notifier_providers(self) -> Any:
        """Get notifier providers."""
        return self._get("/notifier/provider")

    def notifier_create(self, provider: str, args: Mapping[str, Any]) -> Any:
        """Create notifier."""
        # Create not explicitly documented in this spec version, but supported via POST /notifier
        return self._post("/notifier", json_body={"provider": provider, "args": dict(args)})

    def notifier_delete(self, notifier_id: str) -> Any:
        """Delete notifier."""
        return self._delete(f"/notifier/{urllib.parse.quote(notifier_id)}")

    def notifier_get(self, notifier_id: str) -> Any:
        """Get notifier by ID."""
        return self._get(f"/notifier/{urllib.parse.quote(notifier_id)}")

    def notifier_update(self, notifier_id: str, provider: str, args: Mapping[str, Any]) -> Any:
        """Update notifier."""
        return self._put(
            f"/notifier/{urllib.parse.quote(notifier_id)}",
            json_body={"provider": provider, "args": dict(args)},
        )

    # --- Directory Methods ---
    def queries(
        self, *, page: int | None = None, sort: str | None = None, order: str | None = None
    ) -> Any:
        """Get queries."""
        return self._get("/shodan/query", query={"page": page, "sort": sort, "order": order})

    def query_search(self, query: str, *, page: int | None = None) -> Any:
        """Search queries."""
        return self._get("/shodan/query/search", query={"query": query, "page": page})

    def query_tags(self, *, size: int | None = None) -> Any:
        """Get query tags."""
        return self._get("/shodan/query/tags", query={"size": size})

    # --- Bulk Data (Enterprise) ---
    def data_datasets(self) -> Any:
        """Get data datasets."""
        return self._get("/shodan/data")

    def data_dataset(self, dataset: str) -> Any:
        """Get specific dataset."""
        return self._get(f"/shodan/data/{urllib.parse.quote(dataset)}")

    # --- Manage Organization (Enterprise) ---
    def org(self) -> Any:
        """Get organization info."""
        return self._get("/org")

    def org_member_update(self, user: str) -> Any:
        """Update organization member."""
        return self._put(f"/org/member/{urllib.parse.quote(user)}")

    def org_member_remove(self, user: str) -> Any:
        """Remove organization member."""
        return self._delete(f"/org/member/{urllib.parse.quote(user)}")

    # --- Account Methods ---
    def account_profile(self) -> Any:
        """Get account profile."""
        return self._get("/account/profile")

    # --- DNS Methods ---
    def dns_domain(self, domain: str) -> Any:
        """Get DNS domain info."""
        return self._get(f"/dns/domain/{urllib.parse.quote(domain)}")

    def dns_resolve(self, hostnames: list[str] | str) -> Any:
        """Resolve hostnames to IPs."""
        if isinstance(hostnames, list):
            hostnames = ",".join(hostnames)
        return self._get("/dns/resolve", query={"hostnames": hostnames})

    def dns_reverse(self, ips: list[str] | str) -> Any:
        """Reverse DNS lookup for IPs."""
        if isinstance(ips, list):
            ips = ",".join(ips)
        return self._get("/dns/reverse", query={"ips": ips})

    # --- Utility Methods ---
    def tools_httpheaders(self) -> Any:
        """Get HTTP headers tool."""
        return self._get("/tools/httpheaders")

    def tools_myip(self) -> Any:
        """Get my IP address."""
        return self._get("/tools/myip")

    # --- API Status Methods ---
    def api_info(self) -> Any:
        """Get API information."""
        return self._get("/api-info")
