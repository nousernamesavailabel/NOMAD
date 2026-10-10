"""Enter answers Yes: yes/no boxes open with Yes as the default, even when they were made with No as the default.
(Showing a QMessageBox crashes the offscreen platform, so these check the default as the box would open, unshown.)"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtGui import QShowEvent  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402

from nomad.ui.yes_default import YesByDefault, default_to_yes  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def opened(box):
    """The box as the Show event leaves it."""
    YesByDefault().eventFilter(box, QShowEvent())
    return box


def test_yes_replaces_a_no_default(app):
    box = QMessageBox(QMessageBox.Question, "Delete", "Delete it?", QMessageBox.Yes | QMessageBox.No)
    box.setDefaultButton(QMessageBox.No)
    assert opened(box).defaultButton() is box.button(QMessageBox.Yes)
    box = QMessageBox(QMessageBox.Question, "Save", "Save it?", QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
    box.setDefaultButton(QMessageBox.Cancel)
    assert opened(box).defaultButton() is box.button(QMessageBox.Yes)


def test_ok_replaces_a_cancel_default(app):
    box = QMessageBox(QMessageBox.Warning, "Restart", "Restart now?", QMessageBox.Ok | QMessageBox.Cancel)
    box.setDefaultButton(QMessageBox.Cancel)
    assert opened(box).defaultButton() is box.button(QMessageBox.Ok)


def test_two_custom_buttons_default_to_the_accepting_one(app):
    box = QMessageBox(QMessageBox.Question, "Delete Subnet", "Delete it?")
    delete = box.addButton("Delete", QMessageBox.AcceptRole)
    box.setDefaultButton(box.addButton(QMessageBox.Cancel))
    default_to_yes(box)
    assert box.defaultButton() is delete


def test_boxes_with_more_choices_keep_their_default(app):
    box = QMessageBox(QMessageBox.Warning, "Host Key Changed", "Trust the new key?")
    box.addButton("Trust the New Key", QMessageBox.AcceptRole)
    box.addButton("Connect Once", QMessageBox.ActionRole)
    cancel = box.addButton(QMessageBox.Cancel)
    box.setDefaultButton(cancel)
    default_to_yes(box)
    assert box.defaultButton() is cancel
    box = QMessageBox(QMessageBox.Question, "Unsaved Changes", "Save your changes?",
                      QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
    box.setDefaultButton(QMessageBox.Save)
    assert opened(box).defaultButton() is box.button(QMessageBox.Save)
