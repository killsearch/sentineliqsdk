"""Tests for sentineliqsdk.core.contracts module."""

from __future__ import annotations

from sentineliqsdk.core.contracts import OutputWriter, ProxyConfigurator, SecretSanitizer


class TestOutputWriter:
    """Test OutputWriter protocol."""

    def test_output_writer_protocol(self):
        """Test that OutputWriter protocol can be implemented."""

        class MockOutputWriter:
            def write(self, data: dict, job_directory: str | None, *, ensure_ascii: bool) -> None:
                pass

        # This should not raise any type errors
        writer: OutputWriter = MockOutputWriter()
        assert hasattr(writer, "write")

    def test_output_writer_method_signature(self):
        """Test that OutputWriter method has correct signature."""

        class MockOutputWriter:
            def write(self, data: dict, job_directory: str | None, *, ensure_ascii: bool) -> None:
                assert isinstance(data, dict)
                assert job_directory is None or isinstance(job_directory, str)
                assert isinstance(ensure_ascii, bool)

        writer = MockOutputWriter()
        writer.write({"test": "data"}, None, ensure_ascii=False)
        writer.write({"test": "data"}, "/path/to/job", ensure_ascii=True)


class TestProxyConfigurator:
    """Test ProxyConfigurator protocol."""

    def test_proxy_configurator_protocol(self):
        """Test that ProxyConfigurator protocol can be implemented."""

        class MockProxyConfigurator:
            def set_environ(self, http_proxy: str | None, https_proxy: str | None) -> None:
                pass

        # This should not raise any type errors
        configurator: ProxyConfigurator = MockProxyConfigurator()
        assert hasattr(configurator, "set_environ")

    def test_proxy_configurator_method_signature(self):
        """Test that ProxyConfigurator method has correct signature."""

        class MockProxyConfigurator:
            def set_environ(self, http_proxy: str | None, https_proxy: str | None) -> None:
                assert http_proxy is None or isinstance(http_proxy, str)
                assert https_proxy is None or isinstance(https_proxy, str)

        configurator = MockProxyConfigurator()
        configurator.set_environ("http://proxy:8080", "https://proxy:8080")
        configurator.set_environ(None, None)


class TestSecretSanitizer:
    """Test SecretSanitizer protocol."""

    def test_secret_sanitizer_protocol(self):
        """Test that SecretSanitizer protocol can be implemented."""

        class MockSecretSanitizer:
            def sanitize(self, config: dict, secret_phrases: tuple[str, ...]) -> dict:
                return config

        # This should not raise any type errors
        sanitizer: SecretSanitizer = MockSecretSanitizer()
        assert hasattr(sanitizer, "sanitize")

    def test_secret_sanitizer_method_signature(self):
        """Test that SecretSanitizer method has correct signature."""

        class MockSecretSanitizer:
            def sanitize(self, config: dict, secret_phrases: tuple[str, ...]) -> dict:
                assert isinstance(config, dict)
                assert isinstance(secret_phrases, tuple)
                return config

        sanitizer = MockSecretSanitizer()
        result = sanitizer.sanitize({"key": "value"}, ("secret",))
        assert result == {"key": "value"}
