"""The Assets page's Software Targets: the software each model should run, and how many devices run it."""
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, \
    QLineEdit, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout

from ..ipam.assets import IN_SERVICE, is_part
from ..ipam.store import IpamError
from ..ipam.targets import AHEAD, BEHIND, NO_SOFTWARE, ON_TARGET, OTHER, counts, newest_first, suggestions
from .common import set_hint
from .ipam_dialogs import _EditDialog
from .theme import COLORS

STATE_COLORS = {ON_TARGET: "success", BEHIND: "warning", AHEAD: "link", OTHER: "link"}


def models_and_versions(assets):
    """{model: {version: how many in service run it}} of the devices in an asset list."""
    found = {}
    for asset in assets:
        if is_part(asset.kind) or not asset.model:
            continue
        versions = found.setdefault(asset.model, {})
        if asset.software and asset.status == IN_SERVICE:
            versions[asset.software] = versions.get(asset.software, 0) + 1
    return found


class TargetDialog(_EditDialog):
    """Add or change one model's software target."""

    def __init__(self, parent, targets, assets, target=None, model="", version=""):
        super().__init__(parent, f"Software Target for {target.model}" if target else "Add Software Target")
        self.targets, self.target = targets, target
        self.versions = models_and_versions(assets)
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.addItems(sorted(self.versions, key=str.lower))
        self.model_combo.setCurrentText(target.model if target else model)
        self.model_combo.setToolTip("The model, as the asset list has it (C9300-48P), or a wildcard for a family "
                                    "(C9300-*, CP-88??): the most exact target for a model counts.")
        self.version_combo = QComboBox()
        self.version_combo.setEditable(True)
        self.version_combo.setToolTip("The version it should run, written as the device says it (17.9.4a, "
                                      "15.2(7)E10); the list has the versions this model runs now, newest first.")
        self.allowed_input = QLineEdit(target.allowed if target else "")
        self.allowed_input.setPlaceholderText("Optional: other versions that are fine, separated by commas")
        self.note_input = QLineEdit(target.note if target else "")
        self.note_input.setPlaceholderText("Optional: why, such as the change that approved it")
        self.form.addRow("Model:", self.model_combo)
        self.form.addRow("Target version:", self.version_combo)
        self.form.addRow("Also allowed:", self.allowed_input)
        self.form.addRow("Note:", self.note_input)
        self.fill_versions()
        self.version_combo.setCurrentText(target.target if target else version)
        self.model_combo.currentTextChanged.connect(self.on_model_changed)
        self.finish_layout()

    def on_model_changed(self, *_):
        typed = self.version_combo.currentText()
        self.fill_versions()
        self.version_combo.setCurrentText(typed)

    def fill_versions(self):
        from ..ipam.targets import matches
        model = self.model_combo.currentText().strip()
        found = {}
        for name, versions in self.versions.items():
            if model and matches(model, name):
                for version, count in versions.items():
                    found[version] = found.get(version, 0) + count
        self.version_combo.blockSignals(True)
        self.version_combo.clear()
        for version in newest_first(found):
            self.version_combo.addItem(version)
            self.version_combo.setItemData(self.version_combo.count() - 1, f"{found[version]} in service run it",
                                           Qt.ToolTipRole)
        self.version_combo.blockSignals(False)

    def apply(self):
        if not self.targets.can_change:
            raise IpamError(getattr(self.targets, "why_not", "") or "Software targets can't be changed right now.")
        return self.targets.set_target(self.target.id if self.target else None, model=self.model_combo.currentText(),
                                       target=self.version_combo.currentText(), allowed=self.allowed_input.text(),
                                       note=self.note_input.text())


class SuggestedTargetsDialog(QDialog):
    """Targets for the models no target covers yet, from the version most of each runs: tick the ones to add."""

    def __init__(self, parent, suggested):
        super().__init__(parent)
        self.setWindowTitle("Add Targets from the Asset List")
        self.resize(640, 420)
        layout = QVBoxLayout(self)
        intro = QLabel("These models have no software target yet. Each is offered the version most of it runs now: "
                       "tick the ones that are right (a version can be changed after).")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.table = QTableWidget(len(suggested), 3)
        self.table.setHorizontalHeaderLabels(["Model", "Target", "Runs now"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        for row, (model, version, versions) in enumerate(suggested):
            item = QTableWidgetItem(model)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if len(versions) == 1 else Qt.Unchecked)
            item.setData(Qt.UserRole, (model, version))
            self.table.setItem(row, 0, item)
            self.table.setItem(row, 1, QTableWidgetItem(version))
            runs = ", ".join(f"{name} ({count})" for name, count in sorted(versions.items(),
                                                                         key=lambda pair: -pair[1]))
            self.table.setItem(row, 2, QTableWidgetItem(runs))
        self.table.resizeColumnsToContents()
        layout.addWidget(self.table, 1)
        note = QLabel("Models running more than one version start unticked: check which one is meant.")
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Add Ticked")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def chosen(self):
        return [self.table.item(row, 0).data(Qt.UserRole) for row in range(self.table.rowCount())
                if self.table.item(row, 0).checkState() == Qt.Checked]


class TargetsDialog(QDialog):
    """Every software target, with how many devices in service are on it, behind it and ahead of it."""

    COLUMNS = ["Model", "Target", "Also Allowed", "On Target", "Behind", "Ahead / Other", "Note", "Set By"]

    def __init__(self, parent, source):
        super().__init__(parent)
        self.source = source
        self.changed = False
        self.setWindowTitle(f"Software Targets ({source.label})")
        self.resize(980, 460)
        layout = QVBoxLayout(self)
        intro = QLabel("The software each model should run. Devices off their model's target are listed under "
                       "Problems on the Assets page, and the Network Map's Overlay > Software colors them. A target "
                       "can be for a family of models with a wildcard (C9300-*): the most exact one counts.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.table.itemDoubleClicked.connect(self.edit_target)
        layout.addWidget(self.table, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        buttons = QHBoxLayout()
        self.add_button = QPushButton("Add...")
        self.suggest_button = QPushButton("Add from the Asset List...")
        self.suggest_button.setToolTip("A target for each model without one, from the version most of it runs.")
        self.edit_button = QPushButton("Edit...")
        self.delete_button = QPushButton("Delete")
        self.close_button = QPushButton("Close")
        for button in (self.add_button, self.suggest_button, self.edit_button, self.delete_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(self.close_button)
        layout.addLayout(buttons)
        self.add_button.clicked.connect(self.add_target)
        self.suggest_button.clicked.connect(self.add_suggested)
        self.edit_button.clicked.connect(self.edit_target)
        self.delete_button.clicked.connect(self.delete_target)
        self.close_button.clicked.connect(self.accept)
        self.fill()

    @property
    def targets(self):
        return self.source.targets

    def fill(self, select=None):
        listed = self.targets.targets()
        assets = self.source.assets.assets()
        tally = counts(assets, listed)
        self.table.setRowCount(len(listed))
        for row, target in enumerate(listed):
            states = tally.get(target.id, {})
            values = [(target.model, None), (target.target, None), (target.allowed, None),
                      (str(states.get(ON_TARGET, 0)), ON_TARGET), (str(states.get(BEHIND, 0)), BEHIND),
                      (str(states.get(AHEAD, 0) + states.get(OTHER, 0)), AHEAD), (target.note, None),
                      (f"{target.modified_by}, {target.modified[:10]}", None)]
            for column, (text, state) in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if column == 0:
                    item.setData(Qt.UserRole, target.id)
                if state is not None and text != "0":
                    item.setForeground(QColor(COLORS[STATE_COLORS[state]]))
                self.table.setItem(row, column, item)
            if states.get(NO_SOFTWARE):
                self.table.item(row, 0).setToolTip(f"{target.model}: {states[NO_SOFTWARE]} in service with no "
                                                   "software known (not read yet)")
            if target.id == select:
                self.table.selectRow(row)
        self.table.resizeColumnsToContents()
        why = getattr(self.targets, "why_not", "")
        if why:
            set_hint(self.status_label, why, "warning")
        elif not listed:
            set_hint(self.status_label, "No targets yet: Add from the Asset List starts one for each model from the "
                                        "version most of it runs.", "info")
        else:
            self.status_label.clear()
        self.update_buttons()

    def selected_target(self):
        rows = {index.row() for index in self.table.selectedIndexes()}
        if len(rows) != 1:
            return None
        return self.targets.target(self.table.item(rows.pop(), 0).data(Qt.UserRole))

    def update_buttons(self):
        editable = self.targets.can_change
        selected = self.selected_target()
        self.add_button.setEnabled(editable)
        self.suggest_button.setEnabled(editable)
        self.edit_button.setEnabled(editable and selected is not None)
        self.delete_button.setEnabled(editable and selected is not None)

    def add_target(self, *_, model="", version=""):
        dialog = TargetDialog(self, self.targets, self.source.assets.assets(), model=model, version=version)
        if dialog.exec_():
            self.changed = True
            self.fill(select=dialog.result_item.id if dialog.result_item is not None else None)

    def edit_target(self, *_):
        target = self.selected_target()
        if target is None or not self.targets.can_change:
            return
        dialog = TargetDialog(self, self.targets, self.source.assets.assets(), target)
        if dialog.exec_():
            self.changed = True
            self.fill(select=target.id)

    def delete_target(self):
        target = self.selected_target()
        if target is None:
            return
        answer = QMessageBox.question(self, "Delete Target", f"Delete the software target for {target.model} "
                                                             f"({target.target})?")
        if answer != QMessageBox.Yes:
            return
        try:
            self.targets.delete_target(target.id)
        except IpamError as error:
            set_hint(self.status_label, str(error), "error")
            return
        self.changed = True
        self.fill()

    def add_suggested(self):
        suggested = suggestions(self.source.assets.assets(), self.targets.targets())
        if not suggested:
            set_hint(self.status_label, "Every model in service has a target already (or runs no known software).",
                     "info")
            return
        dialog = SuggestedTargetsDialog(self, suggested)
        if not dialog.exec_():
            return
        added, problems = 0, []
        for model, version in dialog.chosen():
            try:
                self.targets.set_target(None, model=model, target=version)
                added += 1
            except IpamError as error:
                problems.append(f"{model}: {error}")
        self.changed = self.changed or bool(added)
        self.fill()
        if problems:
            set_hint(self.status_label, f"Added {added}; " + "; ".join(problems), "error")
        else:
            set_hint(self.status_label, f"Added {added} target{'s' if added != 1 else ''}.", "success")

