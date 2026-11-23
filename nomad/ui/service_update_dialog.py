"""The window the service banner's Update Now opens: each service being updated (service_updates.ServiceUpdater),
marked as it starts and as it's done or fails, with why. Closing it early leaves the update going; the banner still
says so."""
from .service_banner import and_list
from .tribe_steps import DONE, FAILED, SKIPPED, WAITING, WORKING, StepsDialog


class ServiceUpdateDialog(StepsDialog):
    def __init__(self, parent, entries, updater):
        """entries: the services_catalog entries being updated, in the order they'll go."""
        self.titles_by_key = {entry.key: entry.title for entry in entries}
        names = and_list(list(self.titles_by_key.values()))
        super().__init__(parent, "Update Services", {entry.key: f"Update the {entry.title}" for entry in entries},
                         f"Updating the {names}")
        self.close_button.setText("Hide")
        self.close_button.setToolTip("The update carries on, and the banner says when it's done")
        self.follow(updater.progressed, self.on_progressed)
        self.follow(updater.finished, self.on_finished)

    def on_progressed(self, key, error):
        if key not in self.steps:
            return
        if error is None:
            self.set_state(key, WORKING, "Updating it with the settings it has...")
        elif error:
            self.set_state(key, FAILED, error)
        else:
            self.set_state(key, DONE, "")

    def on_finished(self, problems):
        failed_before = any(state == FAILED for state in self.states.values())
        for key in self.steps:  # Only left like this when the job itself failed
            if self.states.get(key) in (WAITING, WORKING):
                self.set_state(key, FAILED if problems else SKIPPED, "")
        if problems and not failed_before:  # The job itself failed: say why under the steps
            self.say(" ".join(problems), "error")
        names = and_list(list(self.titles_by_key.values()))
        failed = sum(state == FAILED for state in self.states.values())
        if not failed:
            self.headline.setText(f"The {names} {'is' if len(self.steps) == 1 else 'are'} up to date")
        elif failed < len(self.steps):
            self.headline.setText("Some services weren't updated")
        else:
            self.headline.setText(f"The {names} {'wasn' if len(self.steps) == 1 else 'weren'}'t updated")
        self.finished_with()
