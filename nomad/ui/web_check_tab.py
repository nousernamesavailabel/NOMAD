"""Web Check page: fetch a page once, timing each step, and show the server's certificate and reply."""
import logging

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QApplication, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, \
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from ..httpcheck import EXPIRY_WARNING_DAYS, check_with_redirects, normalize_url
from .common import ColumnFitter, StoppableThread, format_ms, release_thread, set_hint, set_invalid
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)


class WebCheckThread(StoppableThread):
    finished_check = pyqtSignal(list)

    def __init__(self, url, timeout, parent=None):
        super().__init__(parent)
        self.url, self.timeout = url, timeout

    def run(self):
        self.finished_check.emit(check_with_redirects(self.url, self.timeout, should_stop=lambda: self.stopping))


class WebCheckTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.web_worker = None
        self.web_results = []
        self.init_ui()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Fetch a web page once and see how long each step takes, the server's certificate and its "
                       "reply. Redirects are followed. Works with devices' own web pages, including ones with "
                       "self-signed certificates.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.url_input = QLineEdit("https://example.com")
        self.url_input.setPlaceholderText("https://host, http://host:8080/path, or just a host name")
        self.web_timeout_input = QSpinBox()
        self.web_timeout_input.setRange(1, 120)
        self.web_timeout_input.setValue(10)
        self.web_timeout_input.setButtonSymbols(QSpinBox.NoButtons)
        form = QFormLayout()
        form.addRow("Address:", self.url_input)
        form.addRow("Timeout (s):", self.web_timeout_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.web_button = accent_button("Check")
        self.web_copy_button = QPushButton("Copy Results")
        buttons.addWidget(self.web_button)
        buttons.addStretch()
        buttons.addWidget(self.web_copy_button)
        layout.addLayout(buttons)
        self.web_status = QLabel()
        self.web_status.setWordWrap(True)
        layout.addWidget(self.web_status)

        self.web_tree = QTreeWidget()
        self.web_tree.setHeaderLabels(["Check", "Result"])
        self.web_tree.setAlternatingRowColors(True)
        ColumnFitter(self.web_tree)
        layout.addWidget(self.web_tree, 1)

        self.web_button.clicked.connect(self.start_web_check)
        self.url_input.returnPressed.connect(self.start_web_check)
        self.web_copy_button.clicked.connect(self.copy_web_results)

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.url_input.setFocus()
        self.url_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("services/url", self.url_input.text())
        settings.setValue("services/web_timeout", self.web_timeout_input.value())

    def restore_settings(self, settings):
        self.url_input.setText(settings.value("services/url", "https://example.com", str))
        self.web_timeout_input.setValue(settings.value("services/web_timeout", 10, int))

    def shutdown(self):
        if self.web_worker is not None:
            self.web_worker.stop()
            release_thread(self.web_worker, self.web_timeout_input.value() * 1000 + 3000)

    # ----------------------------------------------------------------- Web check

    def check_url(self, url):
        """Check url now (used from other pages)."""
        self.url_input.setText(url)
        self.start_web_check()

    def start_web_check(self):
        if self.web_worker is not None:
            return
        try:
            url = normalize_url(self.url_input.text())
        except ValueError as error:
            set_invalid(self.url_input, True)
            set_hint(self.web_status, str(error), "error")
            return
        set_invalid(self.url_input, False)
        self.web_tree.clear()
        self.web_results = []
        set_hint(self.web_status, f"Checking {url}...", "info")
        self.web_worker = WebCheckThread(url, self.web_timeout_input.value(), self)
        self.web_worker.finished_check.connect(self.show_web_results)
        self.web_worker.finished.connect(self.on_web_finished)
        self.web_worker.start()
        self.update_buttons()

    def on_web_finished(self):
        self.web_worker.deleteLater()
        self.web_worker = None
        self.update_buttons()

    def web_rows(self, result):
        """(label, value, color or None) rows describing one request."""
        rows = [("Address", result.address, None)]
        for label, value in (("DNS lookup", result.dns_ms), ("TCP connect", result.connect_ms),
                             ("TLS handshake", result.tls_ms), ("Time to first byte", result.first_byte_ms),
                             ("Total", result.total_ms)):
            if value is not None:
                rows.append((label, format_ms(value), None))
        if result.tls_version:
            rows.append(("TLS version", f"{result.tls_version} ({result.cipher})", None))
        if result.verified is not None:
            rows.append(("Certificate check", "Trusted" if result.verified else f"Not trusted: {result.verify_error}",
                         COLORS["success"] if result.verified else COLORS["warning"]))
        certificate = result.certificate
        if certificate is not None:
            rows.append(("Issued to", certificate.subject, None))
            rows.append(("Issued by", "Itself (self-signed)" if certificate.self_signed else certificate.issuer, None))
            if certificate.names:
                rows.append(("Names it covers", ", ".join(certificate.names), None))
            if certificate.days_left is not None:
                days = certificate.days_left
                text = f"{certificate.not_after} ({'expired ' + str(-days) + ' days ago' if days < 0 else str(days) + ' days left'})"
                color = COLORS["error"] if days < 0 else COLORS["warning"] if days <= EXPIRY_WARNING_DAYS else None
                rows.append(("Valid until", text, color))
        if result.status is not None:
            color = COLORS["success"] if result.status < 400 else COLORS["error"] if result.status >= 500 \
                else COLORS["warning"]
            rows.append(("HTTP status", f"{result.status} {result.reason}", color))
        if result.server:
            rows.append(("Server software", result.server, None))
        if result.location:
            rows.append(("Redirects to", result.location, None))
        if result.error:
            rows.append(("Problem", result.error, COLORS["error"]))
        return rows

    def show_web_results(self, results):
        self.web_results = results
        for index, result in enumerate(results):
            title = f"{result.status} {result.reason}" if result.status else "Failed"
            top = QTreeWidgetItem([result.url if len(results) == 1 else f"{index + 1}. {result.url}", title])
            for label, value, color in self.web_rows(result):
                child = QTreeWidgetItem([label, value])
                if color:
                    child.setForeground(1, QColor(color))
                child.setToolTip(1, value)
                top.addChild(child)
            self.web_tree.addTopLevelItem(top)
            top.setExpanded(index == len(results) - 1 or bool(result.error))
        final = results[-1] if results else None
        if final is None:
            set_hint(self.web_status, "Stopped.", "warning")
        elif final.error:
            set_hint(self.web_status, final.error, "error")
        else:
            hops = f" after {len(results) - 1} redirect{'' if len(results) == 2 else 's'}" if len(results) > 1 else ""
            trusted = "" if final.verified is not False else " The certificate isn't trusted."
            kind = "warning" if final.verified is False or final.status >= 400 else "success"
            set_hint(self.web_status, f"{final.status} {final.reason}{hops} in {format_ms(final.total_ms)}."
                                      f"{trusted}", kind)

    def copy_web_results(self):
        lines = []
        for result in self.web_results:
            lines.append(result.url)
            lines += [f"    {label}: {value}" for label, value, _ in self.web_rows(result)]
        QApplication.clipboard().setText("\n".join(lines) + "\n")
        self.window.show_status("Copied the web check results to the clipboard.", "info")

    def update_buttons(self):
        self.web_button.setEnabled(self.web_worker is None)
        self.web_copy_button.setEnabled(bool(self.web_results) and self.web_worker is None)
