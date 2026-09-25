import csv

from nomad.latency import CSV_HEADER, DEFAULT_TARGETS, HISTORY_SECONDS, CsvLog, LatencyTarget, autoscale, \
    latency_level, targets_from_dicts


def test_stats_cover_only_the_window():
    target = LatencyTarget("t", "1.1.1.1")
    target.add(100, 50)  # Outside a 60 s window ending at 200
    target.add(150, 10)
    target.add(160, None, "Request timed out.")
    target.add(170, 30)
    stats = target.stats(60, now=200)
    assert (stats.sent, stats.lost, stats.average, stats.minimum, stats.maximum) == (3, 1, 20, 10, 30)
    assert round(stats.loss_percent) == 33
    assert stats.last == 30 and not stats.last_lost


def test_last_lost_keeps_last_reply_time():
    target = LatencyTarget("t", "1.1.1.1")
    target.add(1, 12)
    target.add(2, None, "Request timed out.")
    stats = target.stats(60, now=2)
    assert stats.last_lost and stats.last == 12 and target.last_error == "Request timed out."
    target.add(3, 9)
    assert target.last_error == "" and not target.last_lost


def test_history_is_trimmed():
    target = LatencyTarget("t", "1.1.1.1")
    target.add(0, 1)
    target.add(HISTORY_SECONDS + 1, 2)
    assert list(target.samples) == [(HISTORY_SECONDS + 1, 2)]


def test_no_data():
    stats = LatencyTarget("t", "1.1.1.1").stats(60, now=0)
    assert stats.average is None and stats.last is None and stats.loss_percent == 0


def test_levels():
    assert [latency_level(ms) for ms in (None, 5, 60, 149, 150)] == [None, "good", "fair", "fair", "poor"]


def test_autoscale():
    assert autoscale([]) == (0.0, 200.0)
    low, high = autoscale([20, 40])
    assert low == 18 and high == 42
    low, high = autoscale([5, 5])  # A flat line still gets a usable span
    assert low == 4 and high >= 14


def test_saved_targets():
    targets = targets_from_dicts([{"name": "Gateway", "host": "192.168.1.1", "enabled": False},
                                  {"name": "", "host": "x"}, "junk", {"name": "DNS", "host": "1.1.1.1"}])
    assert [(t.name, t.host, t.enabled, t.color_index) for t in targets] == \
        [("Gateway", "192.168.1.1", False, 0), ("DNS", "1.1.1.1", True, 1)]
    assert [t.to_dict()["name"] for t in targets] == ["Gateway", "DNS"]
    assert [(t.name, t.host) for t in targets_from_dicts(None)] == DEFAULT_TARGETS


def test_csv_log(tmp_path):
    path = tmp_path / "logs" / "latency.csv"
    target = LatencyTarget("Google", "8.8.8.8")
    for _ in range(2):  # Reopening appends without a second header
        log = CsvLog(str(path))
        log.write(0, target, 12.0, 117, "")
        log.write(1, target, None, None, "Request timed out.")
        log.close()
    rows = list(csv.reader(path.open(encoding="utf-8")))
    assert rows[0] == CSV_HEADER and len(rows) == 5
    assert rows[1][1:] == ["Google", "8.8.8.8", "OK", "12.0", "117", ""]
    assert rows[2][3:] == ["FAIL", "", "", "Request timed out."]
