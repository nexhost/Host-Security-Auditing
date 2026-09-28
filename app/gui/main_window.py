from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QMainWindow, QMessageBox, QPushButton, QStackedWidget, QTableWidget,
    QSpinBox, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.reports.export import export_json
from app.services.audit import AuditService
from app.services.demo import load_demo_data

NAV_ITEMS = ["Dashboard", "Assets", "Discover", "Scans", "Findings", "Vulnerabilities", "Services", "Compliance", "History", "Reports", "Integrations", "Settings"]


class WorkerSignals(QObject):
    completed = Signal(int)
    failed = Signal(str)


class ScanWorker(QRunnable):
    def __init__(self, service: AuditService, target: str, scope: str, profile: str):
        super().__init__()
        self.service, self.target, self.scope, self.profile = service, target, scope, profile
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.completed.emit(self.service.run_scan(self.target, self.scope, self.profile, True))
        except Exception as exc:
            self.signals.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self, service: AuditService):
        super().__init__()
        self.service = service
        self.pool = QThreadPool.globalInstance()
        self.setWindowTitle("Nexhost HSA — Authorized Security Posture")
        self.resize(1280, 760)
        root = QWidget()
        layout = QHBoxLayout(root)
        self.nav = QListWidget()
        self.nav.addItems(NAV_ITEMS)
        self.nav.setFixedWidth(190)
        self.pages = QStackedWidget()
        self.dashboard_labels: dict[str, QLabel] = {}
        for item in NAV_ITEMS:
            if item == "Dashboard": self.pages.addWidget(self._dashboard())
            elif item == "Discover": self.pages.addWidget(self._discover())
            elif item == "Assets": self.pages.addWidget(self._table_page("Assets", ["Address", "Hostname", "Status", "OS"]))
            elif item == "Findings": self.pages.addWidget(self._table_page("Findings", ["Severity", "Title", "Category", "Status"]))
            elif item == "Scans": self.pages.addWidget(self._table_page("Scans", ["ID", "Target", "Profile", "Status"]))
            elif item == "Services": self.pages.addWidget(self._table_page("Services", ["Address", "Port", "Protocol", "Service", "Product", "Version"]))
            elif item == "Vulnerabilities": self.pages.addWidget(self._table_page("Vulnerabilities", ["CVE", "CVSS", "State", "Source"]))
            elif item == "Compliance": self.pages.addWidget(self._table_page("Compliance", ["Framework", "Control", "Title", "Status"]))
            elif item == "History": self.pages.addWidget(self._history_page())
            elif item == "Reports": self.pages.addWidget(self._reports_page())
            elif item == "Integrations": self.pages.addWidget(self._integrations_page())
            elif item == "Settings": self.pages.addWidget(self._settings_page())
            else: self.pages.addWidget(self._placeholder(item))
        self.nav.currentRowChanged.connect(self._navigate)
        self.nav.setCurrentRow(0)
        layout.addWidget(self.nav)
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(root)
        self.setStyleSheet("""
            QWidget { background:#10151d; color:#d7e1ec; font-size:14px; }
            QListWidget { background:#151d27; border:0; padding:10px; }
            QListWidget::item { padding:10px; } QListWidget::item:selected { background:#176b87; }
            QPushButton { background:#16718f; padding:8px 14px; border-radius:4px; }
            QLineEdit,QComboBox,QTableWidget { background:#192431; border:1px solid #304458; padding:6px; }
        """)
        self.refresh()

    def _dashboard(self) -> QWidget:
        page, layout = QWidget(), QVBoxLayout()
        title = QLabel("Security Operations Dashboard")
        title.setStyleSheet("font-size:24px;font-weight:600")
        layout.addWidget(title)
        cards = QHBoxLayout()
        for key in ("assets", "ports", "services", "findings", "scans"):
            label = QLabel()
            label.setStyleSheet("background:#192431;padding:24px;font-size:18px;border-radius:6px")
            self.dashboard_labels[key] = label
            cards.addWidget(label)
        layout.addLayout(cards)
        demo = QPushButton("Load Demo Data")
        demo.clicked.connect(self._load_demo)
        export = QPushButton("Export JSON")
        export.clicked.connect(self._export)
        actions = QHBoxLayout(); actions.addWidget(demo); actions.addWidget(export); actions.addStretch()
        layout.addLayout(actions); layout.addStretch(); page.setLayout(layout); return page

    def _discover(self) -> QWidget:
        page, layout = QWidget(), QVBoxLayout()
        form = QFormLayout()
        self.target = QLineEdit(); self.target.setPlaceholderText("192.168.1.20 or 192.168.1.0/24")
        self.scope = QLineEdit(); self.scope.setPlaceholderText("192.168.1.0/24")
        self.profile = QComboBox(); self.profile.addItems(["quick", "standard", "deep", "compliance"])
        self.authorized = QCheckBox("I confirm I am authorized to scan this target")
        form.addRow("Target", self.target); form.addRow("Authorized scope", self.scope); form.addRow("Profile", self.profile); form.addRow("", self.authorized)
        self.start_button = QPushButton("START AUTHORIZED AUDIT"); self.start_button.clicked.connect(self._start_scan)
        self.cancel_button = QPushButton("Cancel scan"); self.cancel_button.setEnabled(False); self.cancel_button.clicked.connect(self._cancel_scan)
        self.scan_status = QLabel("Safe Mode enabled")
        buttons = QHBoxLayout(); buttons.addWidget(self.start_button); buttons.addWidget(self.cancel_button)
        layout.addLayout(form); layout.addLayout(buttons); layout.addWidget(self.scan_status); layout.addStretch(); page.setLayout(layout); return page

    def _table_page(self, title: str, columns: list[str]) -> QWidget:
        page, layout = QWidget(), QVBoxLayout(); layout.addWidget(QLabel(title)); table = QTableWidget(0, len(columns)); table.setHorizontalHeaderLabels(columns); table.setObjectName(title); layout.addWidget(table); page.setLayout(layout); return page

    def _placeholder(self, title: str) -> QWidget:
        page, layout = QWidget(), QVBoxLayout(); layout.addWidget(QLabel(f"{title}\nFoundation interface ready for the next phase.")); layout.addStretch(); page.setLayout(layout); return page

    def _reports_page(self) -> QWidget:
        page, layout = QWidget(), QVBoxLayout(); layout.addWidget(QLabel("Professional Reports"))
        for format_name in ("HTML", "PDF", "JSON"):
            button = QPushButton(f"Generate {format_name} report")
            report_format = format_name.lower()
            button.clicked.connect(lambda _checked=False, fmt=report_format: self._generate_report(fmt))
            layout.addWidget(button)
        layout.addStretch(); page.setLayout(layout); return page

    def _history_page(self) -> QWidget:
        page, layout = QWidget(), QVBoxLayout(); layout.addWidget(QLabel("Historical Comparison"))
        controls = QHBoxLayout(); self.previous_scan = QSpinBox(); self.previous_scan.setMinimum(1)
        self.current_scan = QSpinBox(); self.current_scan.setMinimum(1)
        compare = QPushButton("Compare scans"); compare.clicked.connect(self._compare_scans)
        controls.addWidget(QLabel("Previous")); controls.addWidget(self.previous_scan)
        controls.addWidget(QLabel("Current")); controls.addWidget(self.current_scan); controls.addWidget(compare)
        self.history_table = QTableWidget(0, 3); self.history_table.setHorizontalHeaderLabels(["Asset", "Change", "Value"])
        layout.addLayout(controls); layout.addWidget(self.history_table); page.setLayout(layout); return page

    def _integrations_page(self) -> QWidget:
        page, layout = QWidget(), QVBoxLayout(); layout.addWidget(QLabel(
            "SOC Integrations\n\nWazuh, n8n and MISP adapters are opt-in. HTTPS endpoints and credentials must be configured externally.\nMISP indicators always require explicit confirmation."
        )); layout.addStretch(); page.setLayout(layout); return page

    def _settings_page(self) -> QWidget:
        page, layout = QWidget(), QFormLayout()
        layout.addRow("Safe Mode", QLabel("Enabled" if self.service.config.safe_mode else "Disabled"))
        layout.addRow("Maximum targets", QLabel(str(self.service.config.max_targets)))
        layout.addRow("Timeout", QLabel(f"{self.service.config.scan_timeout_seconds}s"))
        layout.addRow("Data directory", QLabel(str(self.service.config.data_dir)))
        page.setLayout(layout); return page

    def _navigate(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        self.refresh()

    def _start_scan(self) -> None:
        if not self.authorized.isChecked():
            QMessageBox.warning(self, "Authorization required", "Confirm authorization before scanning."); return
        self.start_button.setEnabled(False); self.scan_status.setText("Audit running in background…")
        self.cancel_button.setEnabled(True)
        worker = ScanWorker(self.service, self.target.text(), self.scope.text(), self.profile.currentText())
        worker.signals.completed.connect(self._scan_done); worker.signals.failed.connect(self._scan_failed)
        self.pool.start(worker)

    def _scan_done(self, scan_id: int) -> None:
        self.start_button.setEnabled(True); self.cancel_button.setEnabled(False); self.scan_status.setText(f"Scan {scan_id} completed"); self.refresh()

    def _scan_failed(self, message: str) -> None:
        self.start_button.setEnabled(True); self.cancel_button.setEnabled(False); self.scan_status.setText("Scan stopped"); QMessageBox.critical(self, "Audit stopped", message)

    def _cancel_scan(self) -> None:
        if self.service.scanner.cancel(): self.scan_status.setText("Cancelling scan…")

    def _generate_report(self, format_name: str) -> None:
        from app.reports.service import ReportService
        extension = format_name
        name, _ = QFileDialog.getSaveFileName(self, "Generate report", f"nexhost-report.{extension}")
        if not name: return
        try:
            ReportService(self.service).generate(Path(name), format_name)
            QMessageBox.information(self, "Report ready", name)
        except Exception as exc:
            QMessageBox.critical(self, "Report failed", str(exc))

    def _compare_scans(self) -> None:
        from app.services.posture import PostureService
        changes = PostureService(self.service.database).compare_scans(self.previous_scan.value(), self.current_scan.value())
        rows = [(asset, change.kind, change.value) for asset, items in changes.items() for change in items]
        self.history_table.setRowCount(len(rows))
        for r, values in enumerate(rows):
            for c, value in enumerate(values): self.history_table.setItem(r, c, QTableWidgetItem(str(value)))

    def _load_demo(self) -> None:
        load_demo_data(self.service.database); self.refresh(); QMessageBox.information(self, "Demo ready", "Demo data loaded.")

    def _export(self) -> None:
        name, _ = QFileDialog.getSaveFileName(self, "Export", "nexhost-export.json", "JSON (*.json)")
        if name: export_json(self.service, Path(name))

    def refresh(self) -> None:
        summary = self.service.summary()
        for key, label in self.dashboard_labels.items(): label.setText(f"{summary[key]}\n{key.title()}")
        assets_table = self.findChild(QTableWidget, "Assets")
        if assets_table:
            rows = self.service.assets(); assets_table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                for c, key in enumerate(("address", "hostname", "status", "os")): assets_table.setItem(r, c, QTableWidgetItem(str(row.get(key) or "")))
        findings_table = self.findChild(QTableWidget, "Findings")
        if findings_table:
            rows = self.service.findings(); findings_table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                for c, key in enumerate(("severity", "title", "category", "status")): findings_table.setItem(r, c, QTableWidgetItem(str(row.get(key) or "")))
        datasets = [
            ("Scans", self.service.scans(), ("id", "target", "profile", "status")),
            ("Services", self.service.services(), ("address", "port", "protocol", "service", "product", "version")),
            ("Vulnerabilities", self.service.vulnerabilities(), ("cve", "cvss", "state", "source")),
            ("Compliance", self.service.compliance(), ("framework", "control", "title", "status")),
        ]
        for table_name, rows, keys in datasets:
            table = self.findChild(QTableWidget, table_name)
            if table:
                table.setRowCount(len(rows))
                for r, row in enumerate(rows):
                    for c, key in enumerate(keys): table.setItem(r, c, QTableWidgetItem(str(row.get(key) or "")))
