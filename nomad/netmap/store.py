"""Saved maps: JSON files in the app's folder (or wherever the user saves one)."""
import datetime
from pathlib import Path

from ..system import app_data_dir, replace_file
from .model import NetworkMap

EXTENSION = ".nomadmap"
RECENT_LIMIT = 10


def maps_dir():
    path = app_data_dir() / "maps"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_name(network_map):
    try:
        started = datetime.datetime.fromisoformat(network_map.started)
    except ValueError:
        started = datetime.datetime.now()
    return f"Network map {started:%Y-%m-%d %H%M}{EXTENSION}"


def save(network_map, path=None, folder=None):
    """Write the map; with no path, to a new file named after when the crawl started (never over another map
    started the same minute). Returns the path."""
    if path:
        path = Path(path)
    else:
        folder = Path(folder) if folder else maps_dir()
        path = folder / default_name(network_map)
        number = 2
        while path.exists():
            path = folder / f"{default_name(network_map)[:-len(EXTENSION)]} ({number}){EXTENSION}"
            number += 1
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(network_map.to_json(), encoding="utf-8")
    replace_file(temporary, path)
    return path


def load(path):
    """Raises ValueError (or OSError) with a message worth showing."""
    try:
        return NetworkMap.from_json(Path(path).read_text(encoding="utf-8"))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError(f"The map file is damaged ({error}).") from None
    except ValueError as error:
        raise ValueError(str(error) if "NOMAD" in str(error) else f"The map file is damaged ({error}).") from None


def recent(folder=None, limit=RECENT_LIMIT):
    """Saved maps in the app's folder, newest first."""
    folder = Path(folder) if folder else maps_dir()
    return sorted(folder.glob(f"*{EXTENSION}"), key=lambda path: path.stat().st_mtime, reverse=True)[:limit]
