"""Command buttons (SecureCRT's button bar, MobaXterm's macros): saved commands, or whole blocks of configuration,
sent to a session with one click. Saved as JSON in the roaming app data folder, shared by every window."""
import dataclasses
import json
import logging
import os
import uuid
from dataclasses import dataclass, field

from ..system import app_data_dir, replace_file

log = logging.getLogger(__name__)

FILE_NAME = "commands.json"


@dataclass
class CommandButton:
    name: str
    text: str = ""  # One command per line
    press_enter: bool = True  # After the last line too (off for a command to finish typing by hand)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)


def button_from_dict(data):
    known = {item.name for item in dataclasses.fields(CommandButton)}
    return CommandButton(**{"name": "Command", **{key: value for key, value in data.items() if key in known}})


class CommandStore:
    """The buttons, in order. Listeners are called after every save, so every window's bar can refresh."""

    def __init__(self, path=None):
        self.path = path or os.path.join(app_data_dir(), FILE_NAME)
        self.buttons = []
        self.listeners = []
        self.load()

    def load(self):
        self.buttons = []
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, ValueError) as error:
            log.error("Couldn't read %s: %s", self.path, error)
            return
        self.buttons = [button_from_dict(item) for item in data.get("buttons", []) if isinstance(item, dict)]

    def save(self):
        data = {"buttons": [dataclasses.asdict(button) for button in self.buttons]}
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        replace_file(temporary, self.path)
        for listener in list(self.listeners):
            listener()

    def get(self, button_id):
        return next((button for button in self.buttons if button.id == button_id), None)

    def put(self, button):
        """Add a button, or replace the one with the same id where it is."""
        for index, existing in enumerate(self.buttons):
            if existing.id == button.id:
                self.buttons[index] = button
                break
        else:
            self.buttons.append(button)
        self.save()

    def delete(self, button_id):
        self.buttons = [button for button in self.buttons if button.id != button_id]
        self.save()

    def index_of(self, button_id):
        return next((index for index, button in enumerate(self.buttons) if button.id == button_id), None)

    def move(self, button_id, step):
        """Move a button left (-1) or right (+1)."""
        index = self.index_of(button_id)
        if index is not None:
            self.move_to(button_id, index + step)

    def move_to(self, button_id, position):
        """Put a button at a position (0 first), shifting the others along; its Ctrl+number follows."""
        index = self.index_of(button_id)
        if index is None:
            return
        target = max(0, min(len(self.buttons) - 1, position))
        if target != index:
            self.buttons.insert(target, self.buttons.pop(index))
            self.save()
