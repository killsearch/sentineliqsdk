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

from sentineliqsdk.core.config.proxy import EnvProxyConfigurator
from sentineliqsdk.core.config.secrets import sanitize_config

DEFAULT_SECRET_PHRASES = ("key", "password", "secret", "token")


class Worker(ABC):
    """Common functionality for analyzers and responders."""

    def __init__(
        self,
        input_data: dict[str, Any],
        secret_phrases: tuple[str, ...] | None = None,
    ) -> None:
        self.secret_phrases = DEFAULT_SECRET_PHRASES if secret_phrases is None else secret_phrases
        self._input = input_data

        # Set parameters
        self.data_type = self.get_param("dataType", None, "Missing dataType field")
        self.tlp = self.get_param("tlp", 2)
        self.pap = self.get_param("pap", 2)

        # Load configuration
        config = self.get_param("config", {})
        self.enable_check_tlp = config.get("check_tlp", False)
        self.max_tlp = config.get("max_tlp", 2)
        self.enable_check_pap = config.get("check_pap", False)
        self.max_pap = config.get("max_pap", 2)

        # Set proxy configuration
        proxy_config = config.get("proxy", {})
        self.http_proxy = proxy_config.get("http")
        self.https_proxy = proxy_config.get("https")
        self.__set_proxies()

        # Validate TLP/PAP
        self._validate_tlp_pap()

    def __set_proxies(self) -> None:
        EnvProxyConfigurator().set_environ(self.http_proxy, self.https_proxy)

    def __get_param(
        self,
        source: Mapping[str, Any],
        name: str | list[str],
        default: Any | None = None,
        message: str | None = None,
    ) -> Any:
        """Extract a specific parameter from given source.

        :param source: Python dict to search through
        :param name: Name of the parameter to get. JSON-like syntax,
                     e.g. `config.username` at first, but in recursive calls a list
        :param default: Default value, if not found. Default: None
        :param message: Error message. If given and name not found, exit with error.
                        Default: None
        """
        if isinstance(name, str):
            name = name.split(".")

        if len(name) == 0:
            # The name is empty, return the source content
            return source
        new_source = source.get(name[0])
        if new_source is not None:
            return self.__get_param(new_source, name[1:], default, message)
        if message is not None:
            self.error(message)
        return default

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
        return self.get_param("data", None, "Missing data field")

    @staticmethod
    def build_operation(op_type: str, **parameters: Any) -> dict[str, Any]:
        """
        Build an operation descriptor.

        :param op_type: an operation type as a string
        :param parameters: a dict including the operation's params
        :return: dict
        """
        operation = {"type": op_type}
        operation.update(parameters)

        return operation

    def operations(self, raw: Any) -> list[dict[str, Any]]:
        """Return the list of operations to execute after the job completes.

        :returns: by default return an empty array
        """
        return []

    def get_param(self, name: str, default: Any | None = None, message: str | None = None) -> Any:
        """Dotted access into the input JSON; errors when `message` is provided."""
        return self.__get_param(self._input, name, default, message)

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

    def error(self, message: str) -> NoReturn:
        """
        Stop analyzer with an error message.

        :param message: Error message
        """
        # Get analyzer input
        analyzer_input = self._input

        # Loop over all the sensitive config names and clean them
        analyzer_input["config"] = sanitize_config(
            analyzer_input.get("config", {}), self.secret_phrases
        )

        error_result = {"success": False, "input": analyzer_input, "errorMessage": message}
        print(json.dumps(error_result))
        sys.exit(1)

    def summary(self, raw: Any) -> dict[str, Any]:
        """Return a summary for 'short.html' template.

        Overwrite it for your needs!

        :returns: by default return an empty dict
        """
        return {}

    def artifacts(self, raw: Any) -> list[dict[str, Any]]:
        """Return a list of artifacts (empty by default)."""
        return []

    def report(self, output: dict[str, Any]) -> dict[str, Any]:
        """Return a JSON dict in memory.

        :param output: worker output.
        :return: The output dict
        """
        return output

    @abstractmethod
    def run(self) -> None:
        """Entry point to implement in subclasses."""
