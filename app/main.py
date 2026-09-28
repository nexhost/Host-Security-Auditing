from __future__ import annotations

import sys

from app.bootstrap import build_service


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        from app.gui.main_window import MainWindow
    except ImportError:
        print("PySide6 is required for the GUI. Install project dependencies first.", file=sys.stderr)
        return 2
    app = QApplication(sys.argv)
    try:
        window = MainWindow(build_service())
        window.show()
        return app.exec()
    except Exception as exc:
        QMessageBox.critical(None, "Nexhost HSA", str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

