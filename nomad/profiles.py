"""Named IPv4 configurations ("profiles") saved as JSON."""
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from .ipconfig import IPConfig, validate_ip_config, validate_mtu
from .system import app_data_dir

log = logging.getLogger(__name__)

FILE_VERSION = 1


@dataclass
class Profile:
    name: str
    config: IPConfig

    def to_dict(self):
        return {"name": self.name, **self.config.to_dict()}

    @classmethod
    def from_dict(cls, data):
        """Build a profile from JSON, rejecting anything that wouldn't pass the settings form."""
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Profile has no name.")
        raw = IPConfig.from_dict(data)
        dns = raw.dns + ["", ""]
        config, errors, _ = validate_ip_config(raw.dhcp, raw.address, raw.netmask, raw.gateway, dns[0], dns[1],
                                               raw.dns_auto)
        if errors:
            raise ValueError(f"Profile '{name}': {' '.join(errors.values())}")
        if raw.mtu is not None:
            config.mtu, error = validate_mtu(str(raw.mtu))
            if error:
                raise ValueError(f"Profile '{name}': {error}")
        return cls(name, config)


def read_profiles_file(path):
    """Read profiles from a JSON file. Returns (profiles, problems) where problems lists skipped entries."""
    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    entries = data.get("profiles", []) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError("The file doesn't contain a list of profiles.")
    profiles, problems = [], []
    for entry in entries:
        try:
            if not isinstance(entry, dict):
                raise ValueError("Entry is not an object.")
            profiles.append(Profile.from_dict(entry))
        except (ValueError, TypeError) as error:
            problems.append(str(error))
    return profiles, problems


def write_profiles_file(path, profiles):
    """Write profiles to a JSON file atomically."""
    path = Path(path)
    data = {"version": FILE_VERSION, "profiles": [profile.to_dict() for profile in profiles]}
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
    os.replace(temporary, path)


class ProfileStore:
    """The user's saved profiles, kept in their roaming app data folder."""

    def __init__(self, path=None):
        self.path = Path(path) if path else app_data_dir() / "profiles.json"
        self.profiles = {}
        self.load()

    def load(self):
        self.profiles = {}
        if not self.path.exists():
            return
        try:
            profiles, problems = read_profiles_file(self.path)
        except (OSError, ValueError) as error:
            log.error("Could not read profiles from %s: %s", self.path, error)
            return
        for problem in problems:
            log.warning("Skipped a saved profile: %s", problem)
        self.profiles = {profile.name: profile for profile in profiles}

    def save(self):
        write_profiles_file(self.path, self.sorted())

    def sorted(self):
        return sorted(self.profiles.values(), key=lambda profile: profile.name.lower())

    def get(self, name):
        return self.profiles.get(name)

    def put(self, profile):
        self.profiles[profile.name] = profile
        self.save()

    def delete(self, name):
        self.profiles.pop(name, None)
        self.save()

    def import_file(self, path):
        """Merge profiles from a file, replacing any with the same name.

        Returns (added, replaced, problems).
        """
        profiles, problems = read_profiles_file(path)
        added = replaced = 0
        for profile in profiles:
            if profile.name in self.profiles:
                replaced += 1
            else:
                added += 1
            self.profiles[profile.name] = profile
        self.save()
        return added, replaced, problems

    def export_file(self, path):
        write_profiles_file(path, self.sorted())
        return len(self.profiles)
