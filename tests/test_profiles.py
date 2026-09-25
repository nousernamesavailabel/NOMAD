import json

from nomad.ipconfig import IPConfig
from nomad.profiles import Profile, ProfileStore


def test_save_and_reload(tmp_path):
    store = ProfileStore(tmp_path / "profiles.json")
    config = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="10.0.0.1",
                      dns=["1.1.1.1"], mtu=1400)
    store.put(Profile("Lab", config))
    store.put(Profile("Office", IPConfig(dhcp=True, dns_auto=True)))

    reloaded = ProfileStore(tmp_path / "profiles.json")
    assert [profile.name for profile in reloaded.sorted()] == ["Lab", "Office"]
    assert reloaded.get("Lab").config == config


def test_import_merges_and_rejects_bad_entries(tmp_path):
    store = ProfileStore(tmp_path / "profiles.json")
    store.put(Profile("Lab", IPConfig(dhcp=True, dns_auto=True)))
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps({"version": 1, "profiles": [
        {"name": "Lab", "dhcp": False, "address": "10.0.0.5", "netmask": "255.255.255.0"},
        {"name": "New", "dhcp": True, "dns_auto": True},
        {"name": "Broken", "dhcp": False, "address": "10.0.0.5 & calc", "netmask": "255.255.255.0"},
        {"dhcp": True},
    ]}))

    added, replaced, problems = store.import_file(import_file)
    assert (added, replaced, len(problems)) == (1, 1, 2)
    assert store.get("Lab").config.address == "10.0.0.5"
    assert store.get("Broken") is None


def test_export_round_trip(tmp_path):
    store = ProfileStore(tmp_path / "profiles.json")
    store.put(Profile("Lab", IPConfig(dhcp=True, dns=["9.9.9.9"])))
    assert store.export_file(tmp_path / "export.json") == 1
    other = ProfileStore(tmp_path / "other.json")
    assert other.import_file(tmp_path / "export.json") == (1, 0, [])
    assert other.get("Lab").config.dns == ["9.9.9.9"]
