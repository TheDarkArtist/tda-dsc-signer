"""Hot-plug by polling: report a change only after it has been stable for `debounce` consecutive polls."""

import threading


class Poller:
    """snapshot() -> comparable or None (None = skip this tick). on_change(snapshot) runs on the poller thread."""

    def __init__(self, snapshot, on_change, interval=2.0, debounce=2, on_error=None):
        self.snapshot, self.on_change, self.interval, self.debounce = snapshot, on_change, interval, debounce
        self.on_error, self.last_error = on_error, None  # an exception in snapshot/on_change is reported, never fatal to the thread
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="token-poller", daemon=True)
        self.known = None
        self._pending, self._count = None, 0

    def start(self, initial):
        self.known = initial
        self._thread.start()

    def stop(self):
        self._stop.set()

    def tick(self):
        """One poll; returns True when a stable change was reported."""
        snap = self.snapshot()
        if snap is None or snap == self.known:
            self._pending, self._count = None, 0
            return False
        self._count = self._count + 1 if snap == self._pending else 1
        self._pending = snap
        if self._count < self.debounce:
            return False
        self.known, self._pending, self._count = snap, None, 0
        self.on_change(snap)
        return True

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                self.last_error = e
                if self.on_error:
                    try:
                        self.on_error(e)
                    except Exception:  # noqa: BLE001, S110
                        pass
