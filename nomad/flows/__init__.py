"""NetFlow: collecting the flow records Cisco routers and switches export (NetFlow v5, Flexible NetFlow v9 and IPFIX),
summing them a minute at a time, and answering who and what is using each interface.

decode.py reads the export packets, store.py keeps the flows (raw for a short while, then minute summaries),
collector.py listens and fills the store, api.py answers NOMAD (on this computer) from the store, and service.py runs
the collector as the NOMAD Flow Collector Windows service, so every NOMAD on a shared server reads the one collector.
"""
