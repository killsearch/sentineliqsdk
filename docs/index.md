---
title: SentinelIQ SDK
---

# SentinelIQ SDK — Overview

SentinelIQ SDK provides utility classes to build analyzers and responders. It offers a small, opinionated API for workers (IO, config, reporting), analyzer conveniences (auto‑extraction, taxonomy/artifacts helpers), a responder base, and a simple runner helper.

- Worker: core IO/config/error/report interface
- Analyzer: file/data handling, taxonomy, artifacts, auto‑extraction
- Responder: simplified worker for action execution
- Extractor: stdlib IOC extraction for `ip`, `url`, `domain`, `hash`, etc.
- Runner: convenience to instantiate and run a worker class

Use the Guide for a quick start, and the API Reference for detailed docs.

Links:

- Repository: https://github.com/killsearch/sentineliqsdk
- Issues: https://github.com/killsearch/sentineliqsdk/issues
- Changelog: https://github.com/killsearch/sentineliqsdk/blob/main/CHANGELOG.md
