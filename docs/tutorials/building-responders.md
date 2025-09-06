# Building Responders

Follow AGENTS.md Responder section. Key points:
- Inherit from `sentineliqsdk.responders.Responder`.
- Implement `execute()` and make `run()` return it.
- Build operations with `self.build_operation(...)` and report.
