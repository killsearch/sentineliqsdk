# FAQ

- How do I run an example?
  - Run `python examples/.../example.py --help` to see flags. By default, examples run in
    dry‑run mode; add `--execute` to perform network calls. Some actions also require
    `--include-dangerous`.

- Why dataclasses instead of dict input?
  - The public API uses dataclasses for type safety and clarity. Pass a `WorkerInput` to the
    worker constructor; legacy dict input is removed in this repo.

- How do I get results in memory?
  - Implement `execute()` returning `AnalyzerReport`/`ResponderReport` and have `run()` return
    `self.execute()`. Then call `.execute()` or `.run()` directly and read `.full_report`.

- Where do artifacts come from?
  - When `auto_extract` is enabled (default), the Analyzer uses the Extractor to find IOCs in
    your `full_report`, excluding the original observable. You can also add artifacts manually
    via `self.build_artifact(...)`.

- How do I add a new detector?
  - For local use, create a `@dataclass` with `name` and `matches()` and register it with
    `Extractor.register_detector(...)`. For core types, update `models.DataType` and the
    precedence list in `extractors/regex.py`.

- I’m behind a corporate proxy. How do I configure it?
  - Set `http_proxy`/`https_proxy` env vars or use `WorkerInput.config.proxy`. The Worker exports
    these to the environment at init.
