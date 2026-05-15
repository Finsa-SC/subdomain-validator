from distutils.command.install import key

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import SelectionList

from utils import COMMAND_TEMPLATES, launch_terminal


class ActionModal(ModalScreen):
    def __init__(self, selected_result):
        self.result = selected_result
        self.target = selected_result['subdomain']

    def compose(self) -> ComposeResult:
        actions = [
            (f"{key.upper()} ({self.target})", key)
            for key in COMMAND_TEMPLATES.keys()
        ]
        with Container(id="action-modal-container"):
            yield SelectionList(*actions)

    def on_selection_list_selected(self, event):
        action_key = event.value
        if launch_terminal(action_key, self.target):
            self.notify(f"Terminal opened for {action_key}")
        else:
            self.notify(f"Terminal emulator not found!", severity='error')
        self.dismiss()