# port_scanner_gui.py
import socket
import sys
import concurrent.futures
from functools import partial

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QProgressBar, QFileDialog,
    QMessageBox, QSpinBox, QCheckBox, QHeaderView, QGroupBox, QGridLayout, QComboBox
)

# ---------- Simple built-in themes (no extra deps) ----------
LIGHT_QSS = """
* { font-family: 'Segoe UI', sans-serif; }
QWidget { background: #f7f7fb; color: #202124; }
QLineEdit, QSpinBox, QComboBox, QTableWidget, QGroupBox { background: white; border: 1px solid #d0d3d8; border-radius: 8px; padding: 6px; }
QPushButton { background: #1a73e8; color: white; border: none; padding: 8px 12px; border-radius: 10px; }
QPushButton:hover { background: #1669c1; }
QPushButton:disabled { background: #9bb7e6; }
QProgressBar { background: #e6e8ee; border-radius: 8px; text-align: center; }
QProgressBar::chunk { background: #1a73e8; border-radius: 8px; }
QGroupBox { border: 1px solid #d0d3d8; margin-top: 10px; padding-top: 12px; }
QHeaderView::section { background: #eef1f6; padding: 6px; border: none; }
"""

DARK_QSS = """
* { font-family: 'Segoe UI', sans-serif; }
QWidget { background: #0f1218; color: #e6e8ee; }
QLineEdit, QSpinBox, QComboBox, QTableWidget, QGroupBox { background: #171b22; border: 1px solid #2a2f3a; border-radius: 8px; padding: 6px; color: #e6e8ee; }
QPushButton { background: #3b82f6; color: white; border: none; padding: 8px 12px; border-radius: 10px; }
QPushButton:hover { background: #2563eb; }
QPushButton:disabled { background: #27344d; }
QProgressBar { background: #151923; border-radius: 8px; text-align: center; color: #e6e8ee; }
QProgressBar::chunk { background: #3b82f6; border-radius: 8px; }
QGroupBox { border: 1px solid #2a2f3a; margin-top: 10px; padding-top: 12px; }
QHeaderView::section { background: #0f141c; padding: 6px; border: none; }
"""


# ---------- Worker ----------
class PortScanWorker(QObject):
    progress = pyqtSignal(int, int)           # scanned, total
    found = pyqtSignal(int, str, str)         # port, service, banner
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, host: str, start_port: int, end_port: int, max_workers: int = 400):
        super().__init__()
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.max_workers = max_workers
        self._stopped = False

    def stop(self):
        self._stopped = True

    @staticmethod
    def _get_banner(sock):
        try:
            sock.settimeout(1)
            data = sock.recv(1024)
            if not data:
                return ""
            return data.decode(errors="ignore").strip()
        except Exception:
            return ""

    @staticmethod
    def _scan_one(ip, port):
        banner = ""
        service = "Unknown"
        status_open = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                status_open = True
                try:
                    service = socket.getservbyport(port, 'tcp')
                except Exception:
                    service = "Unknown"
                try:
                    # Send a gentle probe for banner (some services respond on connect anyway)
                    sock.sendall(b"\r\n")
                except Exception:
                    pass
                banner = PortScanWorker._get_banner(sock)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return status_open, service, banner

    def run(self):
        try:
            ip = socket.gethostbyname(self.host)
        except Exception as e:
            self.error.emit(f"Failed to resolve host: {e}")
            self.finished.emit()
            return

        ports = list(range(self.start_port, self.end_port + 1))
        total = len(ports)
        scanned = 0

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {ex.submit(self._scan_one, ip, p): p for p in ports}
                for fut in concurrent.futures.as_completed(futures):
                    if self._stopped:
                        break
                    p = futures[fut]
                    try:
                        status_open, service, banner = fut.result()
                        if status_open:
                            self.found.emit(p, service, banner)
                    except Exception:
                        # continue scanning even if one task fails
                        pass
                    scanned += 1
                    self.progress.emit(scanned, total)
        except Exception as e:
            self.error.emit(str(e))
        self.finished.emit()


# ---------- UI ----------
class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Scanner — GUI")
        self.thread = None
        self.worker = None
        self._dark = True

        self._build_ui()
        self._apply_theme()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Controls
        box = QGroupBox("Target & Settings")
        grid = QGridLayout()
        box.setLayout(grid)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("e.g., scanme.nmap.org or 192.168.1.10")

        self.start_spin = QSpinBox()
        self.start_spin.setRange(1, 65535)
        self.start_spin.setValue(1)

        self.end_spin = QSpinBox()
        self.end_spin.setRange(1, 65535)
        self.end_spin.setValue(1024)

        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 1000)
        self.workers_spin.setValue(400)

        self.scan_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)

        self.theme_toggle = QComboBox()
        self.theme_toggle.addItems(["Dark", "Light"])
        self.theme_toggle.currentIndexChanged.connect(self._toggle_theme)

        grid.addWidget(QLabel("Host/IP"), 0, 0)
        grid.addWidget(self.host_edit, 0, 1, 1, 3)
        grid.addWidget(QLabel("Start Port"), 1, 0)
        grid.addWidget(self.start_spin, 1, 1)
        grid.addWidget(QLabel("End Port"), 1, 2)
        grid.addWidget(self.end_spin, 1, 3)
        grid.addWidget(QLabel("Max Workers"), 2, 0)
        grid.addWidget(self.workers_spin, 2, 1)
        grid.addWidget(QLabel("Theme"), 2, 2)
        grid.addWidget(self.theme_toggle, 2, 3)

        btns = QHBoxLayout()
        btns.addWidget(self.scan_btn)
        btns.addWidget(self.stop_btn)

        layout.addWidget(box)
        layout.addLayout(btns)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Port", "Service", "Status", "Banner"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.table)

        # Progress / Export
        bottom = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.export_btn = QPushButton("Export Results")
        self.export_btn.setEnabled(False)
        bottom.addWidget(self.progress, 1)
        bottom.addWidget(self.export_btn)
        layout.addLayout(bottom)

        # Hooks
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn.clicked.connect(self.export_results)

    def _toggle_theme(self):
        self._dark = (self.theme_toggle.currentText() == "Dark")
        self._apply_theme()

    def _apply_theme(self):
        self.setStyleSheet(DARK_QSS if self._dark else LIGHT_QSS)

    def start_scan(self):
        host = self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(self, "Validation", "Please enter a host/IP to scan.")
            return
        start_p = self.start_spin.value()
        end_p = self.end_spin.value()
        if start_p > end_p:
            QMessageBox.warning(self, "Validation", "Start port must be <= End port.")
            return

        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.export_btn.setEnabled(False)

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.thread = QThread()
        self.worker = PortScanWorker(host, start_p, end_p, self.workers_spin.value())
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.found.connect(self.on_found)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)

        self.thread.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()

    def on_progress(self, scanned, total):
        pct = int((scanned / max(1, total)) * 100)
        self.progress.setMaximum(100)
        self.progress.setValue(pct)

    def on_found(self, port, service, banner):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(str(port)))
        self.table.setItem(r, 1, QTableWidgetItem(service))
        self.table.setItem(r, 2, QTableWidgetItem("Open"))
        self.table.setItem(r, 3, QTableWidgetItem(banner or ""))

    def on_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(self.table.rowCount() > 0)
        if self.thread:
            self.thread.quit()
            self.thread.wait()

    def on_error(self, msg):
        QMessageBox.critical(self, "Error", msg)

    def export_results(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Results", "port_scan_results.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Port,Service,Status,Banner\n")
                for r in range(self.table.rowCount()):
                    vals = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(4)]
                    # simple CSV escaping
                    vals = ['"{}"'.format(v.replace('"', '""')) for v in vals]
                    f.write(",".join(vals) + "\n")
            QMessageBox.information(self, "Export", f"Saved: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = PortScannerApp()
    w.resize(900, 600)
    w.show()
    sys.exit(app.exec_())
