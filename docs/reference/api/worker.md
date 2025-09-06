# API Reference: Worker

The base class for analyzers and responders is `sentineliqsdk.core.worker.Worker`.
Key responsibilities:
- TLP/PAP validation
- Proxy env setup
- Error reporting with sanitized config
- Hooks: `summary`, `artifacts`, `operations`, `run`
