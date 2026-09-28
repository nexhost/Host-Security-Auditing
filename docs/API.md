# Internal API

`AuditService` is the stable boundary shared by GUI and CLI. Primary operations are `run_scan`, `import_xml`, `summary`, `assets`, and `findings`. Scanner integrations implement `ScannerAdapter.scan(target, profile)` and return `ScanExecution`.

