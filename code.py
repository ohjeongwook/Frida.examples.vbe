import os
import sys
import frida
import process

class Instrumenter:
    def __init__(self, script_text):
        self.sessions = []
        self.script_text = script_text
        self._device = frida.get_local_device()
        self._device.on("child-added", self._on_child_added)
        self._device.on("child-removed", self._on_child_removed)
        self._device.on("output", self._on_output)
        
    def __del__(self):
        for session in self.sessions:
            session.detach()

    def run(self, process_name):
        proc = process.Runner(process_name, suspended = True)
        if not proc.create():
            return
        process_id = proc.get_id()

        self.instrument(process_id)

        if proc:
            proc.resume()

    def instrument(self, process_id):
        session = frida.attach(process_id)
        self.sessions.append(session)
        session.enable_child_gating()
        script = session.create_script(self.script_text)
        script.on('message', self.on_message)
        script.load()

    def on_message(self, message, data):
        print("[%s] => %s" % (message, data))

    def _on_child_added(self, child):
        print("⚡ new child: {}".format(child))
        self.instrument(child.pid)

    def _on_child_removed(self, child):
        print("⚡ child terminated: {}".format(child))

    def _on_output(self, pid, fd, data):
        print("⚡ output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))

