"""The tribe's software targets on a laptop: read from the copy of the server's data (so the Assets page works
offline), changed through the server only. Like subnet roles, they change rarely and matter to everyone, so a change
waits for the server rather than risk two people setting one model's target at once."""
from .client import OldServerError, ServerUnreachable
from .targets import TargetStore, clean_target_values

OLD_SERVER = "The IPAM server is running an older version of NOMAD that doesn't keep software targets: it needs " \
             "updating (Tools > Tribe Management > Update Service, on the server)."


class TeamTargetStore:
    def __init__(self, team):
        self.team = team
        self.local = TargetStore(team.copy)

    def __getattr__(self, name):
        if name in ("targets", "target", "by_model"):
            return getattr(self.local, name)
        raise AttributeError(name)

    @property
    def can_change(self):
        return self.team.online and self.team.server_keeps_targets

    @property
    def why_not(self):
        """Why targets can't be changed now, or ""."""
        if not self.team.server_keeps_targets:
            return OLD_SERVER
        if not self.team.online:
            return "The IPAM server can't be reached: software targets can be changed when it's back."
        return ""

    def _send(self, action, **arguments):
        if not self.team.server_keeps_targets:
            raise OldServerError(OLD_SERVER)
        try:
            reply = self.team.client.edit(action, **arguments)
        except ServerUnreachable as error:
            self.team.online, self.team.last_error = False, str(error)
            raise ServerUnreachable("The IPAM server can't be reached, so software targets can't be changed right "
                                    "now.") from None
        self.team.online = True
        self.team.copy.apply_rows(reply["items"])
        return reply

    def set_target(self, target_id=None, model="", target="", allowed="", note=""):
        values = clean_target_values(model, target, allowed, note)
        current = self.local.target(target_id) if target_id else None
        reply = self._send("set_target", target_id=target_id, values=values,
                           expected_version=current.version if current is not None else None)
        made = [item["row"]["id"] for item in reply["items"] if item["entity"] == "software_targets"]
        return self.local.target(target_id or (made[-1] if made else "")) or self.local.by_model(values["model"])

    def delete_target(self, target_id):
        current = self.local.target(target_id)
        self._send("delete_target", target_id=target_id,
                   expected_version=current.version if current is not None else -1)
