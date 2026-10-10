"""Disconnect from the Tribe (Tools > Tribe Management, the one place to leave): asks first, then each step is shown
as it happens. Changes made offline that haven't reached the tribe server are sent first, if it can be reached
(otherwise they can be given up, or the leaving put off); then syncing stops (a wait still open on the server is
given a few seconds to end, while the window keeps moving), the saved tribe key is forgotten, the copies of the
tribe's networks and maps are emptied (a tribe map open is kept as a file), and the pages go back to this computer's
own networks and maps."""
import logging
import time

from PyQt5.QtCore import QTimer

from ..ipam.client import forget_key
from .common import run_in_background
from .theme import accent_button
from .tribe_join_dialog import plural
from .tribe_steps import DONE, FAILED, SKIPPED, WARNING, WORKING, StepsDialog

log = logging.getLogger(__name__)

SEND, STOP, FORGET, NETWORKS, MAPS, OWN = range(6)
STEPS = {SEND: "Send changes not yet sent to the tribe server", STOP: "Stop syncing with the tribe server",
         FORGET: "Forget the saved tribe key", NETWORKS: "Remove the copy of the tribe's IPAM networks",
         MAPS: "Remove the copy of the tribe's network maps", OWN: "Go back to this computer's own networks and maps"}
STEP_MS = 150  # Between the quick steps, so each can be seen to happen
STOP_WAIT_SECONDS = 3  # For the map sync's wait on the server to end, before it's left to end on its own
POLL_MS = 100


def disconnect_from_tribe(parent, window):
    """Ask, then stop using the tribe on this computer, showing the steps. Returns whether it left."""
    dialog = LeaveTribeDialog(parent, window)
    dialog.exec_()
    return dialog.left


class LeaveTribeDialog(StepsDialog):
    def __init__(self, parent, window):
        super().__init__(parent, "Disconnect from the Tribe", STEPS, "Disconnect from the tribe?")
        self.window = window
        self.ipam, self.netmap = window.ipam_tab, window.netmap_tab
        self.tribe = self.netmap.tribe
        self.left = False
        self.leaving = False  # Removing: too far along to stop
        self.closed = False
        self.waiting_for = set()  # What's still sending: "networks", "maps"
        self.stop_deadline = 0.0
        self.ipam.open_store()  # Open both copies, so changes waiting in them are counted (and then emptied)
        self.tribe.ensure()
        self.unsent = self.count_unsent()
        self.disconnect_button = self.add_button(accent_button("Disconnect"))
        self.disconnect_button.clicked.connect(self.start)
        self.anyway_button = self.add_button(accent_button("Disconnect Anyway"))
        self.anyway_button.setToolTip("Give up the changes that haven't reached the tribe server, and disconnect.")
        self.anyway_button.clicked.connect(self.remove)
        self.disconnect_button.show()
        self.disconnect_button.setDefault(True)
        self.bar.hide()  # Until there's something to show
        warning = (f" {plural(self.unsent, 'change')} made here {'hasn' if self.unsent == 1 else 'haven'}'t reached "
                   "the tribe server yet: NOMAD sends them first." if self.unsent else "")
        self.say("Stop using the tribe on this computer? The saved tribe key and the copies of the tribe's networks "
                 "and maps are removed (a tribe map open is kept as a file); your own networks and maps are kept." +
                 warning, "warning" if self.unsent else "info")

    def count_unsent(self):
        return self.ipam.unsent_tribe_changes() + self.netmap.unsent_tribe_changes()

    # ----------------------------------------------------------------- Sending what's waiting

    def start(self):
        self.disconnect_button.hide()
        self.message.hide()
        self.bar.show()
        self.headline.setText("Disconnecting from the tribe...")
        if not self.unsent:
            self.set_state(SEND, SKIPPED, "Nothing waiting to be sent")
            self.remove()
            return
        self.set_state(SEND, WORKING, f"Sending {plural(self.unsent, 'change')}...")
        team, maps = self.ipam.team, self.tribe.maps
        if team is not None and self.ipam.unsent_tribe_changes():
            self.waiting_for.add("networks")
            self.follow(self.ipam.tribe_synced, self.on_networks_sent)
            self.follow(self.ipam.tribe_sync_failed, self.on_networks_sent)
            self.ipam.sync_now()  # Sends what's waiting first (a sync already under way says when it's done)
        if maps is not None and maps.pending_count():
            self.waiting_for.add("maps")
            run_in_background(maps.send_pending, self.on_maps_sent, self.on_maps_sent)
        self.check_sent()

    def on_networks_sent(self, *_):
        self.waiting_for.discard("networks")
        self.check_sent()

    def on_maps_sent(self, *_):
        self.waiting_for.discard("maps")
        self.check_sent()

    def check_sent(self):
        if self.closed or self.waiting_for or self.states[SEND] != WORKING:
            return
        remaining = self.count_unsent()
        if not remaining:
            self.set_state(SEND, DONE, f"Sent {plural(self.unsent, 'change')}")
            self.remove()
            return
        team = self.ipam.team
        refused = len(team.refused()) if team is not None else 0
        why = []
        if refused:
            why.append(f"{refused} {'was' if refused == 1 else 'were'} refused because someone else changed those "
                       "addresses first (Review Refused Changes on the IP Addresses page)")
        if remaining > refused:
            reason = (team.last_error if team is not None and team.last_error else self.tribe.error) or \
                "the tribe server can't be reached"
            why.append(f"{remaining - refused} couldn't be sent: {reason.rstrip('.')}")
        self.set_state(SEND, WARNING, f"{plural(remaining, 'change')} still {'hasn' if remaining == 1 else 'haven'}'t "
                                      f"reached the tribe server. " + "; ".join(why) + ".")
        self.headline.setText("Some changes haven't reached the tribe server")
        self.say("Disconnect anyway and they're lost, or cancel and disconnect once they've been sent.", "warning")
        self.anyway_button.show()
        self.anyway_button.setDefault(True)

    # ----------------------------------------------------------------- Removing

    def remove(self):
        """The rest, one step at a time; it can't be stopped part of the way through."""
        self.anyway_button.hide()
        self.message.hide()
        self.headline.setText("Disconnecting from the tribe...")
        self.leaving = True
        self.close_button.setEnabled(False)
        self.set_state(STOP, WORKING, "Stopping...")
        self.ipam.stop_watching()  # Ends by itself when its wait on the server returns
        if self.tribe.thread is not None:
            self.tribe.thread.stop()
        self.stop_deadline = time.monotonic() + STOP_WAIT_SECONDS
        QTimer.singleShot(STEP_MS, self.wait_for_sync_to_stop)

    def wait_for_sync_to_stop(self):
        thread = self.tribe.thread
        if thread is not None and not thread.isFinished() and time.monotonic() < self.stop_deadline:
            self.notes[STOP].setText("Waiting for the tribe server to answer the last request...")
            QTimer.singleShot(POLL_MS, self.wait_for_sync_to_stop)
            return
        still_waiting = thread is not None and not thread.isFinished()
        self.tribe.shutdown(wait_ms=0)
        self.set_state(STOP, DONE, "Stopped; the tribe server's last answer will be ignored" if still_waiting else
                       "Stopped")
        QTimer.singleShot(STEP_MS, self.forget)

    def forget(self):
        self.set_state(FORGET, WORKING)
        try:
            forget_key()
        except OSError as error:
            log.warning("Couldn't forget the tribe key: %s", error)
            self.set_state(FORGET, FAILED, f"Couldn't remove it: {error.strerror or error}")
            self.skip_the_rest()
            self.window.tribe_key_changed()  # Carry on syncing with it
            self.headline.setText("Couldn't disconnect from the tribe")
            self.say("Nothing was removed, and this computer is still in the tribe.", "error")
            self.close_button.setEnabled(True)
            self.finished_with()
            return
        self.set_state(FORGET, DONE)
        QTimer.singleShot(STEP_MS, self.remove_networks)

    def remove_networks(self):
        team = self.ipam.team
        if team is None:
            self.set_state(NETWORKS, SKIPPED, "There was no copy here")
        else:
            self.set_state(NETWORKS, WORKING)
            count = len(team.networks())
            self.ipam.forget_team_copy()
            self.set_state(NETWORKS, DONE, f"Removed {plural(count, 'network')}")
        QTimer.singleShot(STEP_MS, self.remove_maps)

    def remove_maps(self):
        maps = self.tribe.maps
        self.set_state(MAPS, WORKING)
        count = len(maps.maps()) if maps is not None else 0
        kept = self.netmap.tribe_map_id is not None
        self.netmap.tribe_key_changed(forget=True)
        self.set_state(MAPS, DONE, f"Removed {plural(count, 'map')}" +
                       ("; the tribe map that was open is kept as a file on this computer" if kept else ""))
        QTimer.singleShot(STEP_MS, self.own_data)

    def own_data(self):
        self.set_state(OWN, WORKING)
        if self.ipam.local_store is not None:
            self.ipam.connect_team()  # No tribe key now: only this computer's own networks
            self.ipam.fill_networks()
        self.set_state(OWN, DONE, "Your own networks and maps are kept")
        self.left = True
        self.leaving = False
        self.close_button.setEnabled(True)
        self.headline.setText("Disconnected from the tribe")
        self.say("To join again, use Connect with Key File with the tribe key file.", "success")
        self.finished_with()

    # ----------------------------------------------------------------- Closing

    def reject(self):
        if not self.leaving:  # Not part of the way through removing
            super().reject()

    def done(self, result):
        self.closed = True
        super().done(result)
