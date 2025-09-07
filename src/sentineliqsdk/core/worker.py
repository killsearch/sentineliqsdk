"""Worker base class for SentinelIQ SDK (core).

Aplica princípios SOLID:
- SRP: classe focada em IO de job, configuração e envelope de saída.
- OCP: hooks `summary`, `artifacts`, `operations`, `run` para extensão.
- LSP: subclasses podem sobrescrever comportamentos sem quebrar contratos.
- ISP: interface mínima e coesa.
- DIP: dependências externas (stdin/env) encapsuladas atrás de métodos simples.
"""

from __future__ import annotations

import json
import os
import sys
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, NoReturn

from sentineliqsdk.constants import DEFAULT_SECRET_PHRASES, EXIT_ERROR, JSON_ENSURE_ASCII
from sentineliqsdk.core.config.proxy import EnvProxyConfigurator
from sentineliqsdk.core.config.secrets import sanitize_config
from sentineliqsdk.models import Artifact, Operation, WorkerError, WorkerInput


class Worker(ABC):
    """Common functionality for analyzers and responders."""

    def __init__(
        self,
        input_data: WorkerInput,
        secret_phrases: tuple[str, ...] | None = None,
    ) -> None:
        self.secret_phrases = DEFAULT_SECRET_PHRASES if secret_phrases is None else secret_phrases
        self._input = input_data

        # Set parameters from structured input
        self.data_type = self._input.data_type
        self.tlp = self._input.tlp
        self.pap = self._input.pap

        # Load configuration
        self.enable_check_tlp = self._input.config.check_tlp
        self.max_tlp = self._input.config.max_tlp
        self.enable_check_pap = self._input.config.check_pap
        self.max_pap = self._input.config.max_pap

        # Set proxy configuration
        self.http_proxy = self._input.config.proxy.http
        self.https_proxy = self._input.config.proxy.https
        self.__set_proxies()

        # Validate TLP/PAP
        self._validate_tlp_pap()

    def __set_proxies(self) -> None:
        EnvProxyConfigurator().set_environ(self.http_proxy, self.https_proxy)

    def _validate_tlp_pap(self) -> None:
        """Validate TLP and PAP values against configured limits."""
        if self.enable_check_tlp and self.tlp > self.max_tlp:
            self.error("TLP is higher than allowed.")
        if self.enable_check_pap and self.pap > self.max_pap:
            self.error("PAP is higher than allowed.")

    def get_data(self) -> Any:
        """Return data from input dict.

        :return: Data (observable value) given through Cortex
        """
        return self._input.data

    @staticmethod
    def build_operation(op_type: str, **parameters: Any) -> Operation:
        """
        Build an operation descriptor.

        :param op_type: an operation type as a string
        :param parameters: a dict including the operation's params
        :return: Operation dataclass
        """
        return Operation(operation_type=op_type, parameters=parameters)

    def operations(self, raw: Any) -> list[Operation]:
        """Return the list of operations to execute after the job completes.

        :returns: by default return an empty array
        """
        return []

    def get_env(self, key: str, default: Any | None = None, message: str | None = None) -> Any:
        """
        Wrap access to configuration values from the environment.

        :param key: Key of the environment variable to get.
        :param default: Default value, if not found. Default: None
        :param message: Error message. If given and key not found, exit with error.
                        Default: None
        """
        if key in os.environ:
            return os.environ[key]
        if message is not None:
            self.error(message)
        return default

    # Programmatic configuration accessors
    def _get_from_mapping(
        self, mapping: Mapping[str, Any], path: str, default: Any | None = None
    ) -> Any:
        """Resolve dotted-path keys from a mapping, returning default when missing."""
        cur: Any = mapping
        for part in str(path).split("."):
            if isinstance(cur, Mapping) and part in cur:
                cur = cur[part]  # type: ignore[index]
            else:
                return default
        return cur

    def get_config(self, path: str, default: Any | None = None) -> Any:
        """Get a value from WorkerConfig.params using a dotted path."""
        return self._get_from_mapping(self._input.config.params, path, default)

    def get_secret(self, path: str, default: Any | None = None, message: str | None = None) -> Any:
        """Get a value from WorkerConfig.secrets using a dotted path, with optional error."""
        val = self._get_from_mapping(self._input.config.secrets, path, default)
        if val is None and message is not None:
            self.error(message)
        return val

    def error(self, message: str, *, ensure_ascii: bool | None = None) -> NoReturn:
        """
        Stop analyzer with an error message.

        :param message: Error message
        """
        # Create error response using dataclass
        error_response = WorkerError(success=False, error_message=message, input_data=self._input)

        # Convert config to dict for sanitization
        config_dict = {
            "check_tlp": self._input.config.check_tlp,
            "max_tlp": self._input.config.max_tlp,
            "check_pap": self._input.config.check_pap,
            "max_pap": self._input.config.max_pap,
            "auto_extract": self._input.config.auto_extract,
            "proxy": {
                "http": self._input.config.proxy.http,
                "https": self._input.config.proxy.https,
            },
            # Include programmatic params/secrets for sanitization in error payloads
            "params": dict(getattr(self._input.config, "params", {})),
            "secrets": dict(getattr(self._input.config, "secrets", {})),
        }

        # Sanitize config to remove sensitive information
        sanitized_config = sanitize_config(config_dict, self.secret_phrases)

        # Convert to dict for JSON output
        error_dict = {
            "success": error_response.success,
            "errorMessage": error_response.error_message,
            "input": {
                "dataType": self._input.data_type,
                "data": self._input.data,
                "filename": self._input.filename,
                "tlp": self._input.tlp,
                "pap": self._input.pap,
                "config": sanitized_config,
            },
        }

        # Preserve Unicode by default per JSON_ENSURE_ASCII, allow override via parameter

        print(
            json.dumps(
                error_dict, ensure_ascii=JSON_ENSURE_ASCII if ensure_ascii is None else ensure_ascii
            )
        )
        sys.exit(EXIT_ERROR)

    def summary(self, raw: Any) -> dict[str, Any]:
        """Return a summary for 'short.html' template.

        Overwrite it for your needs!

        :returns: by default return an empty dict
        """
        return {}

    def artifacts(self, raw: Any) -> list[Artifact]:
        """Return a list of artifacts (empty by default)."""
        return []

    def report(self, output: dict[str, Any]) -> dict[str, Any] | Any:
        """Return a JSON dict in memory.

        :param output: worker output.
        :return: The output dict or report object
        """
        return output

    @abstractmethod
    def run(self) -> None:
        """Entry point to implement in subclasses."""
