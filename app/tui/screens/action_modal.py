from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Input, Static
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
        self.edit_mode = False

        h_tech = self.result.get("http", {}).get('tech', [])
        s_tech = self.result.get("https", {}).get('tech', [])
        self.combined = list(set(h_tech) | set(s_tech))

    def compose(self) -> ComposeResult:
        with Container(id="action-modal-container"):
            yield Static(id="action-list")
            yield Static(id="action-preview")
            yield Input(
                placeholder="TAB to edit command, then ENTER to execute",
                id="action-input"
            )
    def on_mount(self):
        self._render_list()
        self._update_preview()
        input_widget = self.query_one("#action-input", Input)
        input_widget.display = False

    def on_key(self, event):
        input_widget = self.query_one("#action-input", Input)
        if event.key == 'tab':
            self.edit_mode = not self.edit_mode

            if self.edit_mode:
                input_widget.display = True
                input_widget.focus()
            else:
                input_widget.display = False
                self.focus()
            event.stop()
            return

        if self.edit_mode:
            if event.key == 'enter':
                self._execute_custom_cmd(input_widget.value)
                event.stop()
            return

        mid = (len(self.action) + 1) // 2

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
        elif event.key == 'right':
            if self.current_index < mid:
                new_idx = self.current_index + mid
                if new_idx < len(self.action):
                    self.current_index = new_idx
                    self._render_list()
                    self._update_preview()
            event.stop()
        elif event.key == 'left':
            if self.current_index >= mid:
                self.current_index -= mid
                self._render_list()
                self._update_preview()
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

        help_text = (
            "[#565F89]"
            "↑ ↓ ← → Navigate   •   "
            "TAB Toggle Edit Mode   •   "
            "ENTER Execute   •   "
            "ESC Close"
            "[/]"
        )

        panel = Panel(
            layout,
            title="[bold #FFD700]External Tools[/]",
            subtitle=help_text,
            border_style="#00A3FF",
            padding=(1, 2)
        )
        self.query_one("#action-list", Static).update(panel)

    def _build_column(self, action_subset) -> Table:
        table = Table.grid(padding=(0, 1), expand=False)
        table.add_column(width=3)
        table.add_column(width=10)
        table.add_column(width=40)

        for key, template in action_subset:
            actual_idx = self.action.index((key, template))
            is_selected = actual_idx == self.current_index

            indicator = "▶" if is_selected else " "
            indicator_style = "#FFD700" if is_selected else "#565F89"

            tool_style = "#FFD700 bold" if is_selected else "#00E0FF"
            tool_name = f"({template['tool']})"

            action_style = "#FFD700 bold" if is_selected else "#00A3FF"
            action_name = template['description']

            table.add_row(
                Text(indicator, style=indicator_style),
                Text(tool_name, style=tool_style),
                Text(action_name, style=action_style)
            )
        return table

    def _update_preview(self):
        if self.current_index < len(self.action):
            key, template = self.action[self.current_index]
            full_cmd = template['command'].format(target=self.target)
            self.cmd_preview = full_cmd

            preview_panel = Panel(
                Text.from_markup(
                    full_cmd,
                    justify='center'
                ),
                title="[bold #FFD700]Command[/]",
                border_style="#565F89",
                padding=(1, 2)
            )
            self.query_one("#action-preview", Static).update(preview_panel)

            input_widget = self.query_one("#action-input", Input)
            input_widget.value = full_cmd

    def _execute_action(self):
        if self.current_index < len(self.action):
            key, template = self.action[self.current_index]
            self.notify(f"Launching: {key.upper()}", timeout=2)
            success = launch_terminal(key, self.target, technologies=self.combined)

            if success:
                self.app.pop_screen()
            else:
                self.notify("Terminal emulator not found", severity='error')

    def _execute_custom_cmd(self, custom_cmd: str):
        if custom_cmd:
            self.notify("Launch custom command", timeout=1)
            success = self._run_with_cmd(custom_cmd)
            if success:
                self.app.pop_screen()
            else:
                self.notify("Terminal emulatot not found", severity='error')

    def _run_with_cmd(self, cmd: str) -> bool:
        key = self.action[self.current_index][0] if self.current_index < len(self.action) else 'custom'
        return launch_terminal(key, self.target, cmd)

    def action_dismiss(self):
        self.app.pop_screen()