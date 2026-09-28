# Development

Use Python 3.12 and keep business logic independent of Qt. Scanner tests must inject a fake adapter or import fixture XML and must never touch the network. Add schema migrations before changing deployed database structures. Run tests, Ruff, mypy and both CLI/GUI smoke tests after each phase.

