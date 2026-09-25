"""Interfaces tab: status, quick actions, IPv4 settings, MTU and saved profiles."""
import ipaddress
import logging
from dataclasses import replace

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QButtonGroup, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox, \
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QRadioButton, QVBoxLayout, QWidget

from ..ipconfig import ApplyError, apply_ip_config, build_apply_commands, config_from_adapter, release_dhcp, \
    renew_dhcp, reset_adapter, set_adapter_enabled, set_mtu, validate_ip_config, validate_mtu
from ..profiles import Profile
from .common import set_hint, set_invalid
from .dialogs import KeepChangesDialog, SaveProfileDialog
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)


class AdapterTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.form_adapter_index = None  # Adapter whose settings are loaded in the form
        self.form_dirty = False  # The user has edited the form since it was loaded
        self.form_config = None  # Validated IPConfig from the form, or None
        self.init_ui()
        window.snapshot_changed.connect(self.on_snapshot_changed)
        window.adapter_changed.connect(self.on_adapter_changed)
        self.refresh_profiles_combo()
        self.update_all()

    # ----------------------------------------------------------------- UI setup

    def init_ui(self):
        layout = QHBoxLayout(self)
        left = QVBoxLayout()
        right = QVBoxLayout()
        layout.addLayout(left, 1)
        layout.addLayout(right, 1)

        # Status
        status_group = QGroupBox("Status")
        status_form = QFormLayout(status_group)
        self.status_labels = {}
        for key, title in [("name", "Name"), ("description", "Description"), ("status", "Status"),
                           ("mac", "MAC address"), ("speed", "Link speed"), ("ipv4", "IPv4 addresses"),
                           ("ipv6", "IPv6 addresses"), ("gateway", "Default gateway"), ("dns", "DNS servers"),
                           ("dhcp", "DHCP"), ("mtu", "MTU"), ("metric", "Interface metric")]:
            label = QLabel("—")
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            label.setWordWrap(True)
            status_form.addRow(f"{title}:", label)
            self.status_labels[key] = label
        left.addWidget(status_group)

        # Quick actions
        actions_group = QGroupBox("Actions")
        actions_layout = QGridLayout(actions_group)
        self.enable_button = QPushButton("Disable Adapter")
        self.reset_button = QPushButton("Reset Adapter")
        self.reset_button.setToolTip("Disable and re-enable the adapter. Fixes many stuck connections.")
        self.release_button = QPushButton("Release DHCP")
        self.release_button.setToolTip("Give the DHCP address back (ipconfig /release). The adapter goes offline.")
        self.renew_button = QPushButton("Renew DHCP")
        self.renew_button.setToolTip("Ask the DHCP server for an address again (ipconfig /renew).")
        self.flush_button = QPushButton("Flush DNS Cache")
        self.flush_button.setToolTip("Forget cached DNS answers (ipconfig /flushdns).")
        actions_layout.addWidget(self.enable_button, 0, 0)
        actions_layout.addWidget(self.reset_button, 0, 1)
        actions_layout.addWidget(self.release_button, 1, 0)
        actions_layout.addWidget(self.renew_button, 1, 1)
        actions_layout.addWidget(self.flush_button, 2, 0)
        left.addWidget(actions_group)

        # MTU
        mtu_group = QGroupBox("MTU")
        mtu_layout = QFormLayout(mtu_group)
        self.mtu_input = QLineEdit()
        self.mtu_input.setPlaceholderText("576-9216, normally 1500")
        self.mtu_button = QPushButton("Apply MTU")
        mtu_row = QHBoxLayout()
        mtu_row.addWidget(self.mtu_input, 1)
        mtu_row.addWidget(self.mtu_button)
        mtu_layout.addRow("MTU:", mtu_row)
        self.mtu_hint = QLabel()
        self.mtu_hint.setWordWrap(True)
        # Layouts size wrapped labels as one line, which cut the hint off; leave room for two
        self.mtu_hint.setMinimumHeight(2 * self.mtu_hint.fontMetrics().lineSpacing())
        mtu_layout.addRow(self.mtu_hint)
        left.addWidget(mtu_group)
        left.addStretch()

        # IPv4 settings
        self.settings_group = QGroupBox("IPv4 Settings")
        settings_layout = QVBoxLayout(self.settings_group)
        self.dhcp_radio = QRadioButton("Obtain an IP address automatically (DHCP)")
        self.static_radio = QRadioButton("Use a static IP address")
        self.radio_group = QButtonGroup(self)
        self.radio_group.addButton(self.dhcp_radio)
        self.radio_group.addButton(self.static_radio)
        settings_layout.addWidget(self.dhcp_radio)
        settings_layout.addWidget(self.static_radio)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g. 192.168.1.10 or 192.168.1.10/24")
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("e.g. 255.255.255.0 (filled in for /24 notation)")
        self.gateway_input = QLineEdit()
        self.gateway_input.setPlaceholderText("Optional, e.g. 192.168.1.1")
        self.dns_auto_check = QCheckBox("Obtain DNS server addresses automatically")
        self.primary_dns_input = QLineEdit()
        self.primary_dns_input.setPlaceholderText("e.g. 1.1.1.1")
        self.backup_dns_input = QLineEdit()
        self.backup_dns_input.setPlaceholderText("Optional, e.g. 8.8.8.8")
        form = QFormLayout()
        form.addRow("IP address:", self.ip_input)
        form.addRow("Subnet mask:", self.subnet_input)
        form.addRow("Default gateway:", self.gateway_input)
        form.addRow("", self.dns_auto_check)
        form.addRow("Primary DNS:", self.primary_dns_input)
        form.addRow("Backup DNS:", self.backup_dns_input)
        settings_layout.addLayout(form)
        self.settings_hint = QLabel()
        self.settings_hint.setWordWrap(True)
        settings_layout.addWidget(self.settings_hint)
        settings_buttons = QHBoxLayout()
        self.apply_button = accent_button("Apply Settings")
        self.undo_edits_button = QPushButton("Undo Edits")
        self.undo_edits_button.setToolTip("Reload the adapter's current settings into the form.")
        settings_buttons.addWidget(self.apply_button)
        settings_buttons.addWidget(self.undo_edits_button)
        settings_layout.addLayout(settings_buttons)
        right.addWidget(self.settings_group)

        # Profiles
        profiles_group = QGroupBox("Profiles")
        profiles_layout = QVBoxLayout(profiles_group)
        self.profile_combo = QComboBox()
        profiles_layout.addWidget(self.profile_combo)
        self.profile_description = QLabel()
        self.profile_description.setWordWrap(True)
        self.profile_description.setStyleSheet(f"color: {COLORS['muted']};")
        profiles_layout.addWidget(self.profile_description)
        profile_buttons = QGridLayout()
        self.apply_profile_button = QPushButton("Apply Profile")
        self.apply_profile_button.setToolTip("Apply the profile to the selected adapter.")
        self.load_profile_button = QPushButton("Load into Form")
        self.load_profile_button.setToolTip("Copy the profile into the settings form without applying it.")
        self.save_profile_button = QPushButton("Save Form as Profile...")
        self.delete_profile_button = QPushButton("Delete Profile")
        self.import_button = QPushButton("Import...")
        self.export_button = QPushButton("Export...")
        profile_buttons.addWidget(self.apply_profile_button, 0, 0)
        profile_buttons.addWidget(self.load_profile_button, 0, 1)
        profile_buttons.addWidget(self.save_profile_button, 1, 0)
        profile_buttons.addWidget(self.delete_profile_button, 1, 1)
        profile_buttons.addWidget(self.import_button, 2, 0)
        profile_buttons.addWidget(self.export_button, 2, 1)
        profiles_layout.addLayout(profile_buttons)
        right.addWidget(profiles_group)
        right.addStretch()

        # Signals
        self.enable_button.clicked.connect(self.toggle_adapter_enabled)
        self.reset_button.clicked.connect(self.reset_adapter)
        self.release_button.clicked.connect(self.release_dhcp)
        self.renew_button.clicked.connect(self.renew_dhcp)
        self.flush_button.clicked.connect(self.window.flush_dns)
        self.mtu_button.clicked.connect(self.apply_mtu)
        self.mtu_input.textChanged.connect(self.validate_mtu_field)
        self.dhcp_radio.toggled.connect(self.on_form_changed)
        self.dhcp_radio.clicked.connect(self.mark_dirty)
        self.static_radio.clicked.connect(self.mark_dirty)
        self.dns_auto_check.toggled.connect(self.on_form_changed)
        self.dns_auto_check.clicked.connect(self.mark_dirty)
        self.ip_input.textChanged.connect(self.on_ip_changed)
        for line_edit in self.settings_inputs():
            line_edit.textChanged.connect(self.on_form_changed)
            line_edit.textEdited.connect(self.mark_dirty)
        self.apply_button.clicked.connect(lambda: self.apply_settings())
        self.undo_edits_button.clicked.connect(self.reload_form)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_selected)
        self.apply_profile_button.clicked.connect(self.apply_profile)
        self.load_profile_button.clicked.connect(self.load_profile_into_form)
        self.save_profile_button.clicked.connect(self.save_profile)
        self.delete_profile_button.clicked.connect(self.delete_profile)
        self.import_button.clicked.connect(self.import_profiles)
        self.export_button.clicked.connect(self.export_profiles)

    def settings_inputs(self):
        return [self.ip_input, self.subnet_input, self.gateway_input, self.primary_dns_input, self.backup_dns_input]

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("adapter/profile", self.profile_combo.currentText())

    def restore_settings(self, settings):
        index = self.profile_combo.findText(settings.value("adapter/profile", "", str))
        if index >= 0:
            self.profile_combo.setCurrentIndex(index)

    def shutdown(self):
        pass

    # ----------------------------------------------------------------- Showing the adapter

    def on_snapshot_changed(self, _snapshot):
        self.update_all()

    def on_adapter_changed(self, _adapter):
        self.form_dirty = False
        self.update_all()

    def update_all(self):
        adapter = self.window.current_adapter()
        self.update_status(adapter)
        self.update_actions(adapter)
        index = adapter.index if adapter else None
        if index != self.form_adapter_index or not self.form_dirty:
            self.reload_form()
        self.update_field_states()
        self.validate_mtu_field()

    def update_status(self, adapter):
        labels = self.status_labels
        if adapter is None:
            for label in labels.values():
                label.setText("—")
            labels["name"].setText("No adapter selected")
            return
        labels["name"].setText(adapter.name)
        labels["description"].setText(adapter.description or "—")
        status_colors = {"Up": COLORS["success"], "Disconnected": COLORS["warning"], "Disabled": COLORS["error"]}
        labels["status"].setText(f'<span style="color:{status_colors.get(adapter.status, "")}">'
                                 f'{adapter.status}</span>')
        labels["mac"].setText(adapter.mac or "—")
        labels["speed"].setText(adapter.speed_text if adapter.status == "Up" and adapter.speed_text else "—")
        labels["ipv4"].setText("\n".join(str(address) for address in adapter.ipv4) or "—")
        labels["ipv6"].setText("\n".join(str(address) for address in adapter.ipv6) or "—")
        labels["gateway"].setText(", ".join(adapter.gateways4 + adapter.gateways6) or "—")
        dns = ", ".join(adapter.dns4 + adapter.dns6) or "—"
        if adapter.dns4 and adapter.dns_static is not None:
            dns += "  (manual)" if adapter.dns_static else "  (automatic)"
        labels["dns"].setText(dns)
        labels["dhcp"].setText("—" if adapter.dhcp is None else ("Enabled" if adapter.dhcp else "Disabled"))
        labels["mtu"].setText(str(adapter.mtu4) if adapter.mtu4 else "—")
        labels["metric"].setText(str(adapter.metric4) if adapter.metric4 is not None else "—")

    def update_actions(self, adapter):
        has_adapter = adapter is not None and adapter.is_adapter
        enabled = has_adapter and adapter.enabled
        self.enable_button.setEnabled(has_adapter)
        self.enable_button.setText("Enable Adapter" if has_adapter and not adapter.enabled else "Disable Adapter")
        self.reset_button.setEnabled(enabled)
        uses_dhcp = enabled and bool(adapter.dhcp)
        self.release_button.setEnabled(uses_dhcp)
        self.renew_button.setEnabled(uses_dhcp)
        for button in (self.release_button, self.renew_button):
            button.setToolTip(button.toolTip().split("\n")[0] +
                              ("" if uses_dhcp else "\nOnly available for adapters using DHCP."))
        self.mtu_input.setEnabled(enabled and 4 in adapter.families)

    def configurable_adapter(self):
        """The selected adapter if its IPv4 settings can be changed, otherwise None."""
        adapter = self.window.current_adapter()
        if adapter is None or not adapter.is_adapter or not adapter.enabled or 4 not in adapter.families:
            return None
        return adapter

    # ----------------------------------------------------------------- Settings form

    def reload_form(self):
        """Load the selected adapter's current settings into the form."""
        adapter = self.window.current_adapter()
        self.form_adapter_index = adapter.index if adapter else None
        if adapter is not None and 4 in adapter.families:
            config = config_from_adapter(adapter)
            self.load_config_into_form(config)
            if adapter.mtu4:
                self.mtu_input.setText(str(adapter.mtu4))
        else:
            for line_edit in self.settings_inputs():
                line_edit.clear()
            self.mtu_input.clear()
        self.form_dirty = False

    def load_config_into_form(self, config):
        (self.dhcp_radio if config.dhcp else self.static_radio).setChecked(True)
        self.ip_input.setText(config.address)
        self.subnet_input.setText(config.netmask)
        self.gateway_input.setText(config.gateway)
        dns = config.dns + ["", ""]
        self.primary_dns_input.setText(dns[0])
        self.backup_dns_input.setText(dns[1])
        self.dns_auto_check.setChecked(config.dns_auto)
        if config.mtu:
            self.mtu_input.setText(str(config.mtu))
        self.update_field_states()

    def mark_dirty(self, *_):
        self.form_dirty = True

    def on_ip_changed(self, text):
        """Fill in the subnet mask when the address is typed in CIDR notation."""
        if "/" in text:
            try:
                self.subnet_input.setText(str(ipaddress.IPv4Interface(text.strip()).netmask))
            except ValueError:
                pass
        self.update_field_states()

    def on_form_changed(self, *_):
        self.update_field_states()

    def update_field_states(self):
        """Enable only the fields that apply to the chosen DHCP/static and DNS options, then validate."""
        configurable = self.configurable_adapter() is not None
        self.settings_group.setEnabled(configurable)
        static = self.static_radio.isChecked()
        for line_edit in (self.ip_input, self.gateway_input):
            line_edit.setEnabled(static)
        self.subnet_input.setEnabled(static and "/" not in self.ip_input.text())
        self.dns_auto_check.setEnabled(not static)
        manual_dns = static or not self.dns_auto_check.isChecked()
        self.primary_dns_input.setEnabled(manual_dns)
        self.backup_dns_input.setEnabled(manual_dns)
        self.validate_form()

    def validate_form(self):
        config, errors, warnings = validate_ip_config(
            self.dhcp_radio.isChecked(), self.ip_input.text(), self.subnet_input.text(), self.gateway_input.text(),
            self.primary_dns_input.text(), self.backup_dns_input.text(), self.dns_auto_check.isChecked())
        self.form_config = config
        fields = {"address": self.ip_input, "netmask": self.subnet_input, "gateway": self.gateway_input,
                  "primary_dns": self.primary_dns_input, "backup_dns": self.backup_dns_input}
        for name, line_edit in fields.items():
            set_invalid(line_edit, name in errors and line_edit.isEnabled() and bool(line_edit.text().strip()))

        adapter = self.configurable_adapter()
        if self.window.current_adapter() is not None and adapter is None:
            set_hint(self.settings_hint, "This adapter's IPv4 settings can't be changed (it's disabled, a "
                                         "pseudo-interface, or has IPv4 turned off).", "info")
        elif errors:
            set_hint(self.settings_hint, next(iter(errors.values())), "error")
        elif warnings:
            set_hint(self.settings_hint, warnings[0], "warning")
        elif adapter is not None and config is not None:
            changed = bool(build_apply_commands(adapter.index, config, config_from_adapter(adapter)))
            set_hint(self.settings_hint, "Ready to apply: " + config.describe() if changed
                     else "The form matches the adapter's current settings.", "info")
        else:
            self.settings_hint.clear()
        self.apply_button.setEnabled(adapter is not None and config is not None)

    def validate_mtu_field(self):
        adapter = self.configurable_adapter()
        text = self.mtu_input.text().strip()
        mtu, error = validate_mtu(text) if text else (None, None)
        set_invalid(self.mtu_input, bool(error))
        if error:
            set_hint(self.mtu_hint, error, "error")
        elif mtu and mtu > 1500:
            set_hint(self.mtu_hint, "MTUs above 1500 (jumbo frames) only work if every device on the network "
                                    "supports them.", "warning")
        elif adapter is not None and adapter.mtu4:
            set_hint(self.mtu_hint, f"Current MTU: {adapter.mtu4}. Use the MTU tab to find the best value.", "info")
        else:
            self.mtu_hint.clear()
        self.mtu_button.setEnabled(adapter is not None and mtu is not None and mtu != adapter.mtu4)

    # ----------------------------------------------------------------- Applying settings

    def apply_settings(self, config=None):
        """Apply the form (or the given config) to the adapter, then ask whether to keep it."""
        adapter = self.configurable_adapter()
        if adapter is None:
            return
        if config is None:
            if self.form_config is None:
                return
            config = self.form_config
        old = config_from_adapter(adapter)
        if not build_apply_commands(adapter.index, config, old):
            self.window.show_status("No changes to apply.", "info")
            return
        self.window.run_change(
            f"Applying settings to {adapter.name}",
            lambda: apply_ip_config(adapter.index, config, old),
            on_success=lambda _: self.confirm_keep(adapter, config, old),
            on_error=lambda error: self.apply_failed(adapter, config, old, error))

    def confirm_keep(self, adapter, config, old):
        self.form_dirty = False
        self.update_all()
        dialog = KeepChangesDialog(self, f"{adapter.name}: {config.describe()}\n\nPrevious: {old.describe()}")
        if dialog.exec_() == KeepChangesDialog.Accepted:
            self.window.show_status(f"Kept the new settings on {adapter.name}.")
        else:
            self.revert(adapter, old, config)

    def revert(self, adapter, old, current):
        def failed(error):
            QMessageBox.critical(self, "Revert Failed",
                                 f"Could not restore the previous settings on {adapter.name}:\n\n{error}\n\n"
                                 f"The previous settings were: {old.describe()}")

        self.window.run_change(
            f"Restoring previous settings on {adapter.name}",
            lambda: apply_ip_config(adapter.index, old, current),
            on_success=lambda _: self.window.show_status(f"Restored the previous settings on {adapter.name}."),
            on_error=failed)

    def apply_failed(self, adapter, config, old, error):
        if isinstance(error, ApplyError) and error.applied_steps > 0:
            QMessageBox.critical(self, "Error", f"Applying settings to {adapter.name} failed part-way:\n\n{error}\n\n"
                                                "The previous settings will now be restored.")
            self.revert(adapter, old, config)
        else:
            QMessageBox.critical(self, "Error", f"Applying settings to {adapter.name} failed; nothing was changed."
                                                f"\n\n{error}")

    def apply_mtu(self):
        adapter = self.configurable_adapter()
        mtu, error = validate_mtu(self.mtu_input.text())
        if adapter is None or error:
            return
        self.window.run_change(f"Setting the MTU of {adapter.name} to {mtu}", lambda: set_mtu(adapter.index, mtu),
                               on_success=lambda _: self.window.show_status(f"MTU of {adapter.name} set to {mtu}."))

    def set_mtu_from_test(self, mtu):
        """Called by the MTU tab to apply a tested MTU."""
        self.mtu_input.setText(str(mtu))
        self.apply_mtu()

    # ----------------------------------------------------------------- Adapter actions

    def carries_default_route(self, adapter):
        return bool(adapter.gateways4 or adapter.gateways6)

    def confirm(self, title, message, adapter):
        if self.carries_default_route(adapter):
            message += ("\n\nThis adapter has the default gateway, so this computer will probably lose internet "
                        "access (and any remote session through it) until it reconnects.")
        return QMessageBox.question(self, title, message, QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No) == QMessageBox.Yes

    def toggle_adapter_enabled(self):
        adapter = self.window.current_adapter()
        if adapter is None or not adapter.is_adapter:
            return
        enable = not adapter.enabled
        if not enable and not self.confirm("Disable Adapter", f"Disable {adapter.name}?", adapter):
            return
        verb = "Enabling" if enable else "Disabling"
        self.window.run_change(f"{verb} {adapter.name}", lambda: set_adapter_enabled(adapter.index, enable),
                               on_success=lambda _: self.window.show_status(
                                   f"{adapter.name} {'enabled' if enable else 'disabled'}."))

    def reset_adapter(self):
        adapter = self.configurable_adapter()
        if adapter is None or not self.confirm("Reset Adapter", f"Disable and re-enable {adapter.name}?", adapter):
            return
        self.window.run_change(f"Resetting {adapter.name}", lambda: reset_adapter(adapter.index),
                               on_success=lambda _: self.window.show_status(f"{adapter.name} was reset."))

    def release_dhcp(self):
        adapter = self.configurable_adapter()
        if adapter is None or not self.confirm(
                "Release DHCP", f"Release {adapter.name}'s DHCP address? It stays offline until renewed.", adapter):
            return
        self.window.run_change(f"Releasing the DHCP address of {adapter.name}", lambda: release_dhcp(adapter.name),
                               on_success=lambda _: self.window.show_status(f"Released {adapter.name}'s address."))

    def renew_dhcp(self):
        adapter = self.configurable_adapter()
        if adapter is None:
            return
        self.window.run_change(f"Renewing the DHCP address of {adapter.name}", lambda: renew_dhcp(adapter.name),
                               on_success=lambda _: self.window.show_status(f"Renewed {adapter.name}'s address."))

    # ----------------------------------------------------------------- Profiles

    def refresh_profiles_combo(self, select=None):
        combo = self.profile_combo
        previous = select or combo.currentText()
        combo.blockSignals(True)
        combo.clear()
        for profile in self.window.profile_store.sorted():
            combo.addItem(profile.name)
            combo.setItemData(combo.count() - 1, profile.config.describe(), Qt.ToolTipRole)
        index = combo.findText(previous)
        combo.setCurrentIndex(max(index, 0) if combo.count() else -1)
        combo.blockSignals(False)
        self.on_profile_selected()

    def selected_profile(self):
        return self.window.profile_store.get(self.profile_combo.currentText())

    def on_profile_selected(self):
        profile = self.selected_profile()
        self.profile_description.setText(profile.config.describe() if profile else
                                         "No saved profiles yet. Fill in the settings and click "
                                         "\"Save Form as Profile...\".")
        for button in (self.apply_profile_button, self.load_profile_button, self.delete_profile_button):
            button.setEnabled(profile is not None)
        self.export_button.setEnabled(bool(self.window.profile_store.profiles))

    def apply_profile(self):
        profile = self.selected_profile()
        if profile is None or self.configurable_adapter() is None:
            return
        self.load_config_into_form(profile.config)
        self.form_dirty = True
        self.apply_settings(profile.config)

    def load_profile_into_form(self):
        profile = self.selected_profile()
        if profile is None:
            return
        self.load_config_into_form(profile.config)
        self.form_dirty = True
        self.window.show_status(f"Loaded profile '{profile.name}' into the form. Click Apply Settings to use it.",
                                "info")

    def save_profile(self):
        if self.form_config is None:
            QMessageBox.warning(self, "Save Profile", "Fix the settings form before saving it as a profile.")
            return
        mtu, mtu_error = validate_mtu(self.mtu_input.text())
        dialog = SaveProfileDialog(self, self.window.profile_store.profiles.keys(), self.profile_combo.currentText(),
                                   None if mtu_error else mtu)
        if dialog.exec_() != SaveProfileDialog.Accepted:
            return
        config = replace(self.form_config, dns=list(self.form_config.dns),
                         mtu=mtu if dialog.include_mtu and not mtu_error else None)
        try:
            self.window.profile_store.put(Profile(dialog.name, config))
        except OSError as error:
            QMessageBox.critical(self, "Save Profile", f"Could not save the profile:\n\n{error}")
            return
        self.refresh_profiles_combo(select=dialog.name)
        self.window.show_status(f"Saved profile '{dialog.name}'.")

    def delete_profile(self):
        profile = self.selected_profile()
        if profile is None:
            return
        if QMessageBox.question(self, "Delete Profile", f"Delete the profile '{profile.name}'?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.window.profile_store.delete(profile.name)
        self.refresh_profiles_combo()
        self.window.show_status(f"Deleted profile '{profile.name}'.")

    def import_profiles(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Profiles", "", "Profiles (*.json);;All files (*)")
        if not path:
            return
        try:
            added, replaced, problems = self.window.profile_store.import_file(path)
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, "Import Profiles", f"Could not import profiles:\n\n{error}")
            return
        self.refresh_profiles_combo()
        message = f"Imported {added} new profile(s) and replaced {replaced}."
        if problems:
            message += "\n\nSkipped:\n" + "\n".join(problems)
            QMessageBox.warning(self, "Import Profiles", message)
        self.window.show_status(message.split("\n")[0])

    def export_profiles(self):
        if not self.window.profile_store.profiles:
            QMessageBox.information(self, "Export Profiles", "There are no profiles to export yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Profiles", "nomad-profiles.json",
                                              "Profiles (*.json)")
        if not path:
            return
        try:
            count = self.window.profile_store.export_file(path)
        except OSError as error:
            QMessageBox.critical(self, "Export Profiles", f"Could not export profiles:\n\n{error}")
            return
        self.window.show_status(f"Exported {count} profile(s) to {path}.")
