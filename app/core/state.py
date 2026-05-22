import threading

class AppState:
    def __init__(self):
        self.is_running = True
        self.data_store = {}
        self._lock = threading.Lock()
        self.executor = None

    def stop(self):
        with self._lock:
            self.is_running = False

app_state = AppState()