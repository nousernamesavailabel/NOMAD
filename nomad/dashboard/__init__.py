"""The NOMAD Dashboard: a read-only HTTPS web site showing the network's state to people without NOMAD.

It runs as a Windows service beside the Map Watcher and the Syslog and Flow Collectors, reads what they collected and
the tribe (with a viewer key, which can only read), keeps a history of its own for trends, and never asks the network
anything itself. See docs/dashboard.md.
"""
