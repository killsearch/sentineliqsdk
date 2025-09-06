# Building Analyzers
 
Follow AGENTS.md Analyzer section. Key points:
- Inherit from `sentineliqsdk.analyzers.Analyzer`.
- Implement `execute()` and make `run()` return it.
- Use `WorkerInput` for inputs; build taxonomy and artifacts as needed.
