"""Tests for sentineliqsdk.core.config module."""

from __future__ import annotations

import os
from unittest.mock import patch

from sentineliqsdk.core.config.proxy import EnvProxyConfigurator
from sentineliqsdk.core.config.secrets import sanitize_config


class TestEnvProxyConfigurator:
    """Test EnvProxyConfigurator class."""

    def test_set_environ_with_http_proxy(self):
        """Test setting HTTP proxy environment variable."""
        configurator = EnvProxyConfigurator()

        with patch.dict(os.environ, {}, clear=True):
            configurator.set_environ("http://proxy:8080", None)
            assert os.environ["http_proxy"] == "http://proxy:8080"
            assert "https_proxy" not in os.environ

    def test_set_environ_with_https_proxy(self):
        """Test setting HTTPS proxy environment variable."""
        configurator = EnvProxyConfigurator()

        with patch.dict(os.environ, {}, clear=True):
            configurator.set_environ(None, "https://proxy:8080")
            assert os.environ["https_proxy"] == "https://proxy:8080"
            assert "http_proxy" not in os.environ

    def test_set_environ_with_both_proxies(self):
        """Test setting both HTTP and HTTPS proxy environment variables."""
        configurator = EnvProxyConfigurator()

        with patch.dict(os.environ, {}, clear=True):
            configurator.set_environ("http://proxy:8080", "https://proxy:8080")
            assert os.environ["http_proxy"] == "http://proxy:8080"
            assert os.environ["https_proxy"] == "https://proxy:8080"

    def test_set_environ_with_none_values(self):
        """Test setting None values (should not set environment variables)."""
        configurator = EnvProxyConfigurator()

        with patch.dict(os.environ, {}, clear=True):
            configurator.set_environ(None, None)
            assert "http_proxy" not in os.environ
            assert "https_proxy" not in os.environ

    def test_set_environ_preserves_existing(self):
        """Test that existing environment variables are preserved."""
        configurator = EnvProxyConfigurator()

        with patch.dict(os.environ, {"http_proxy": "existing", "other": "value"}, clear=True):
            configurator.set_environ("http://new:8080", None)
            assert os.environ["http_proxy"] == "http://new:8080"
            assert os.environ["other"] == "value"


class TestSanitizeConfig:
    """Test sanitize_config function."""

    def test_sanitize_simple_config(self):
        """Test sanitizing a simple config dictionary."""
        config = {
            "api_key": "secret123",
            "password": "mypassword",
            "username": "user",
            "url": "https://api.example.com",
        }
        secret_phrases = ("key", "password", "secret")

        result = sanitize_config(config, secret_phrases)

        assert result["api_key"] == "REMOVED"
        assert result["password"] == "REMOVED"
        assert result["username"] == "user"
        assert result["url"] == "https://api.example.com"

    def test_sanitize_nested_config(self):
        """Test sanitizing a nested config dictionary."""
        config = {
            "auth": {
                "api_key": "secret123",
                "username": "user",
            },
            "settings": {
                "password": "mypassword",
                "timeout": 30,
            },
        }
        secret_phrases = ("key", "password")

        result = sanitize_config(config, secret_phrases)

        assert result["auth"]["api_key"] == "REMOVED"
        assert result["auth"]["username"] == "user"
        assert result["settings"]["password"] == "REMOVED"
        assert result["settings"]["timeout"] == 30

    def test_sanitize_config_with_lists(self):
        """Test sanitizing a config with lists."""
        config = {
            "credentials": [
                {"api_key": "secret1", "name": "cred1"},
                {"api_key": "secret2", "name": "cred2"},
            ],
            "settings": ["value1", "value2"],
        }
        secret_phrases = ("key",)

        result = sanitize_config(config, secret_phrases)

        assert result["credentials"][0]["api_key"] == "REMOVED"
        assert result["credentials"][0]["name"] == "cred1"
        assert result["credentials"][1]["api_key"] == "REMOVED"
        assert result["credentials"][1]["name"] == "cred2"
        assert result["settings"] == ["value1", "value2"]

    def test_sanitize_config_case_insensitive(self):
        """Test that sanitization is case insensitive."""
        config = {
            "API_KEY": "secret123",
            "Password": "mypassword",
            "SECRET_TOKEN": "token123",
            "username": "user",
        }
        secret_phrases = ("key", "password", "secret")

        result = sanitize_config(config, secret_phrases)

        assert result["API_KEY"] == "REMOVED"
        assert result["Password"] == "REMOVED"
        assert result["SECRET_TOKEN"] == "REMOVED"
        assert result["username"] == "user"

    def test_sanitize_config_substring_matching(self):
        """Test that sanitization matches substrings in keys."""
        config = {
            "my_api_key": "secret123",
            "user_password": "mypassword",
            "secret_token": "token123",
            "api_secret_key": "secret456",
            "username": "user",
        }
        secret_phrases = ("key", "password", "secret")

        result = sanitize_config(config, secret_phrases)

        assert result["my_api_key"] == "REMOVED"
        assert result["user_password"] == "REMOVED"
        assert result["secret_token"] == "REMOVED"
        assert result["api_secret_key"] == "REMOVED"
        assert result["username"] == "user"

    def test_sanitize_config_empty(self):
        """Test sanitizing an empty config."""
        result = sanitize_config({}, ("key", "password"))
        assert result == {}

    def test_sanitize_config_no_secrets(self):
        """Test sanitizing a config with no secret keys."""
        config = {
            "username": "user",
            "url": "https://api.example.com",
            "timeout": 30,
        }
        secret_phrases = ("key", "password")

        result = sanitize_config(config, secret_phrases)

        assert result == config

    def test_sanitize_config_preserves_original(self):
        """Test that the original config is not modified."""
        config = {
            "api_key": "secret123",
            "username": "user",
        }
        secret_phrases = ("key",)

        result = sanitize_config(config, secret_phrases)

        # Original should be unchanged
        assert config["api_key"] == "secret123"
        assert config["username"] == "user"

        # Result should be sanitized
        assert result["api_key"] == "REMOVED"
        assert result["username"] == "user"
