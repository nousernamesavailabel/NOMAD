"""The NOMAD Syslog Collector: syslog messages kept on this computer all the time (a Windows service), read by NOMAD in
every session over 127.0.0.1, and by the Map Watcher instead of listening on port 514 itself.

store.py keeps them (SQLite), collector.py listens and writes, api.py answers NOMAD, feed.py hands new messages to
whoever wants them, service.py is the Windows service.
"""
