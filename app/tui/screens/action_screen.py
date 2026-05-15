from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import SelectionList, Input, Static
from utils import COMMAND_TEMPLATES, launch_terminal


class ActionModal(ModalScreen):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q", "dismiss", "Close")
    ]

    def __init__(self, selected_result):
        super().__init__()
        self.result = selected_result
        self.target = selected_result['subdomain']
        self.action = list(COMMAND_TEMPLATES.items())
        self.current_index = 0
        self.cmd_preview = ""

    def compose(self) -> ComposeResult:
        with Container(id="action-modal-container"):
            yield Static(id="action-list")
            yield Static(id="action-preview")
    def on_mount(self):
        self._render_list()
        self._update_preview()

    def on_key(self, event):
            if event.key == 'down':
                self.current_index = (self.current_index + 1) % len(self.action)
                self._render_list()
                self._update_preview()
                event.stop()
            elif event.key == 'up':
                self.current_index = (self.current_index - 1) % len(self.action)
                self._render_list()
                self._update_preview()
                event.stop()
            elif event.character and event.character.isdigit():
                idx = int(event.character) - 1
                if 0 <= idx < len(self.actions):
                    self.current_index = idx
                    self._execute_action()
                event.stop()
            elif event.key == "enter":
                self._execute_action()
                event.stop()

    def _render_list(self):
        layout = Table.grid(padding=(0, 3), expand=True)
        layout.add_column(ratio=1)
        layout.add_column(ratio=1)

        mid = len(self.action) // 2
        left_table = self._build_column(self.action[:mid])
        right_table = self._build_column(self.action[mid:])
        layout.add_row(left_table, right_table)

        panel = Panel(
            layout,
            title="[bold #FFD700]External Tools[/]",
            border_style="#00A3FF",
            padding=(1, 2)
        )
        self.query_one("#action-list", Static).update(panel)

    def _build_column(self, action_subset) -> Table:
        table = Table.grid(padding=(0, 1), expand=False)
        table.add_column(width=3)
        table.add_column(width=18)
        table.add_column(width=25)

        for key, template in action_subset:
            actual_idx = self.action.index((key, template))
            is_selected = actual_idx == self.current_index

            indicator = "▶" if is_selected else " "
            indicator_style = "#FFD700" if is_selected else "#565F89"

            tool_style = "#FFD700 bold" if is_selected else "#00E0FF"
            tool_name = key.split("_")[0].upper()

            action_style = "#FFD700 bold" if is_selected else "#00A3FF"
            action_name = " ".join(key.split("_")[1:]).title()

            table.add_row(
                Text(indicator, style=indicator_style),
                Text(tool_name, style=tool_style),
                Text(action_name, style=action_style)
            )
        return table

    def _update_preview(self):
        if self.current_index < len(self.action):
            key, template = self.action[self.current_index]
            full_cmd = template.format(target=self.target)
            self.cmd_preview = full_cmd

            preview_text = f"[#00A3FF]{full_cmd}[/]\n\n[#565F89]Press ENTER to execute or ESC to close[/]"

            preview_panel = Panel(
                Text.from_markup(preview_text),
                title="[bold #FFD700]Command[/]",
                border_style="#565F89",
                padding=(1, 2)
            )
            self.query_one("#action-preview", Static).update(preview_panel)

    def _execute_action(self):
        if self.current_index < len(self.action):
            key, template = self.action[self.current_index]
            self.notify(f"Launching: {key.upper()}", timeout=2)
            success = launch_terminal(key, self.target)

            if success:
                self.app.pop_screen()
            else:
                self.notify("Terminal emulator not found", severity='error')

    def action_dismiss(self):
        self.app.pop_screen()