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
import select
import sys
from abc import ABC, abstractmethod
from collections.abc import Mapping
from contextlib import suppress
from typing import Any, NoReturn

from sentineliqsdk.core.config.proxy import EnvProxyConfigurator
from sentineliqsdk.core.config.secrets import sanitize_config
from sentineliqsdk.core.io.output_writer import JsonOutputWriter
from sentineliqsdk.core.runtime.encoding import ensure_utf8_streams

DEFAULT_SECRET_PHRASES = ("key", "password", "secret", "token")


class Worker(ABC):
    """Common functionality for analyzers and responders."""

    READ_TIMEOUT = 3  # seconds

    def __init__(
        self,
        job_directory: str | None = None,
        secret_phrases: tuple[str, ...] | None = None,
    ) -> None:
        # Compute initial job directory path or default; may switch to None for STDIN mode later
        initial_job_dir = (
            job_directory
            if job_directory is not None
            else (sys.argv[1] if len(sys.argv) > 1 else "/job")
        )
        self.job_directory: str | None = initial_job_dir
        self.secret_phrases = DEFAULT_SECRET_PHRASES if secret_phrases is None else secret_phrases
        # Load input
        self._input: dict[str, Any] = {}
        input_path = f"{self.job_directory}/input/input.json"
        if os.path.isfile(input_path):
            with open(input_path) as f_input:
                self._input = json.load(f_input)
        else:
            # If input file doesn't exist, read input from STDIN (with timeout)
            self.job_directory = None
            self.__set_encoding()
            is_tty = True
            with suppress(Exception):
                is_tty = bool(getattr(sys.stdin, "isatty", lambda: True)())
            if not is_tty:
                # Try a non-blocking readiness check where supported; fall back gracefully
                try:
                    fileno = sys.stdin.fileno()  # type: ignore[attr-defined]
                except Exception:
                    # e.g., StringIO without fileno(): try reading directly
                    try:
                        self._input = json.load(sys.stdin)
                    except Exception:
                        self.error(f"No input: missing '{input_path}' and STDIN.")
                else:
                    try:
                        rlist, _, _ = select.select([sys.stdin], [], [], self.READ_TIMEOUT)
                        if rlist:
                            self._input = json.load(sys.stdin)
                        else:
                            self.error(f"No input: missing '{input_path}' and STDIN.")
                    except Exception:
                        # If select is unsupported, attempt direct read
                        try:
                            self._input = json.load(sys.stdin)
                        except Exception:
                            self.error(f"No input: missing '{input_path}' and STDIN.")
            else:
                self.error(f"No input: missing '{input_path}' and STDIN.")

        # Set parameters
        self.data_type = self.get_param("dataType", None, "Missing dataType field")
        self.tlp = self.get_param("tlp", 2)
        self.pap = self.get_param("pap", 2)

        self.enable_check_tlp = self.get_param("config.check_tlp", False)
        self.max_tlp = self.get_param("config.max_tlp", 2)

        self.enable_check_pap = self.get_param("config.check_pap", False)
        self.max_pap = self.get_param("config.max_pap", 2)

        # Set proxy configuration if available
        self.http_proxy = self.get_param("config.proxy.http")
        self.https_proxy = self.get_param("config.proxy.https")

        self.__set_proxies()

        # Finally run check tlp/pap
        if not (self.__check_tlp()):
            self.error("TLP is higher than allowed.")

        if not (self.__check_pap()):
            self.error("PAP is higher than allowed.")

    def __set_proxies(self) -> None:
        EnvProxyConfigurator().set_environ(self.http_proxy, self.https_proxy)

    @staticmethod
    def __set_encoding() -> None:
        """Ensure stdout/stderr use UTF-8 writers when not already UTF-8."""
        with suppress(Exception):
            ensure_utf8_streams()

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

    def __check_tlp(self) -> bool:
        """Check if TLP is within allowed range; return False if too high."""
        return not (self.enable_check_tlp and self.tlp > self.max_tlp)

    def __check_pap(self) -> bool:
        """Check if PAP is within allowed range; return False if too high."""
        return not (self.enable_check_pap and self.pap > self.max_pap)

    def __write_output(self, data: dict[str, Any], ensure_ascii: bool = False) -> None:
        JsonOutputWriter().write(data, self.job_directory, ensure_ascii=ensure_ascii)

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

    def error(self, message: str, ensure_ascii: bool = False) -> NoReturn:
        """
        Stop analyzer with an error message.

        Changing ensure_ascii can be helpful when stucking with ascii <-> utf-8 issues.
        Additionally, the input as returned, too.
        Maybe helpful when dealing with errors.

        :param message: Error message
        :param ensure_ascii: Force ascii output. Default: False
        """
        # Get analyzer input
        analyzer_input = self._input

        # Loop over all the sensitive config names and clean them
        analyzer_input["config"] = sanitize_config(
            analyzer_input.get("config", {}), self.secret_phrases
        )

        self.__write_output(
            {"success": False, "input": analyzer_input, "errorMessage": message},
            ensure_ascii=ensure_ascii,
        )

        # Force exit after error
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

    def report(self, output: dict[str, Any], ensure_ascii: bool = False) -> None:
        """Return a JSON dict via stdout.

        :param output: worker output.
        :param ensure_ascii: Force ascii output. Default: False
        """
        self.__write_output(output, ensure_ascii=ensure_ascii)

    @abstractmethod
    def run(self) -> None:
        """Entry point to implement in subclasses."""
