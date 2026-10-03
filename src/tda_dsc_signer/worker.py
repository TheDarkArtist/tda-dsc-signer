"""One dedicated thread owns every PKCS#11 call (the vendor driver is per-process and not thread-friendly)."""

import queue
import threading


class Worker:
    """submit(fn, done): fn runs on the worker thread; done(result, error) runs via `dispatch` (GLib.idle_add in the GUI)."""

    def __init__(self, dispatch=lambda f, *a: f(*a)):
        self._q = queue.Queue()
        self._dispatch = dispatch
        self._thread = threading.Thread(target=self._loop, name="pkcs11-worker", daemon=True)

    def start(self):
        self._thread.start()
        return self

    def submit(self, fn, done):
        self._q.put((fn, done))

    def stop(self):
        self._q.put(None)

    def _loop(self):
        while (job := self._q.get()) is not None:
            fn, done = job
            try:
                res, err = fn(), None
            except BaseException as e:  # noqa: BLE001 - every failure must reach the UI, never kill the thread
                res, err = None, e
            self._dispatch(done, res, err)
