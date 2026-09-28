# Architecture

The GUI and CLI are delivery adapters only. Both call `AuditService`, which enforces scope through `ScopeValidator`, invokes an abstract `ScannerAdapter`, parses normalized XML, runs non-invasive assessment rules, and persists via SQLAlchemy repositories.

```text
GUI / CLI
   -> Application service
      -> Scope and authorization control
      -> Scanner adapter -> Nmap XML parser
      -> Security checks -> CPE/CVE provider -> HSA risk
      -> Fingerprints / historical comparison
      -> Compliance mappings
      -> SQLAlchemy database
      -> Reports / opt-in SOC integrations
```

SQLite is the default; database construction accepts any SQLAlchemy URL so PostgreSQL can be enabled with a suitable driver. Additive MVP migrations preserve earlier SQLite databases. CVE and SOC integrations use provider interfaces and offline mocks so unavailable external systems never prevent local operation.
