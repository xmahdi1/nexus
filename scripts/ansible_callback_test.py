#!/usr/bin/env python3
"""Exercise callback bounds and redaction without installing Ansible locally."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

for name in ("ansible", "ansible.plugins", "ansible.plugins.callback"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["ansible.plugins.callback"].CallbackBase = object
spec = importlib.util.spec_from_file_location(
    "nexus_callback",
    Path(__file__).resolve().parent.parent / "nexus/internal/ansible/job_callback.py",
)
callback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(callback)


class CallbackTest(unittest.TestCase):
    def test_result_bounds_and_private_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            os.environ.update(
                NEXUS_APPROVED_ALIASES='["approved"]',
                NEXUS_RECAP_FILE=directory + "/recap",
                NEXUS_TASKS_FILE=directory + "/tasks",
            )
            module = callback.CallbackModule()
            host = types.SimpleNamespace(get_name=lambda: "approved")
            for i in range(205):
                task = types.SimpleNamespace(_uuid=str(i), name="private task name", no_log=True)
                result = types.SimpleNamespace(
                    _task=task,
                    _host=host,
                    _result={"changed": i % 2 == 0, "stdout": "private task payload"},
                )
                module.v2_playbook_on_task_start(task, False)
                module.v2_runner_on_start(host, task)
                module.v2_runner_on_ok(result)
            outsider = types.SimpleNamespace(
                _task=task, _host=types.SimpleNamespace(get_name=lambda: "other"), _result={}
            )
            module.v2_runner_on_failed(outsider)
            stats = types.SimpleNamespace(
                processed={"approved": {}, "other": {}}, summarize=lambda _: {"ok": 205}
            )
            module.v2_playbook_on_stats(stats)
            raw = Path(directory + "/tasks").read_text()
            self.assertNotIn("private", raw)
            self.assertNotIn("other", raw)
            history = json.loads(raw)
            self.assertTrue(history["truncated"])
            self.assertEqual(len(history["events"]), 200)
            self.assertEqual(history["events"][0]["status"], "changed")
            self.assertEqual(history["events"][1]["status"], "ok")
            self.assertEqual(history["events"][-1]["task"], 200)
            self.assertEqual(
                json.loads(Path(directory + "/recap").read_text())["approved"]["ok"], 205
            )


if __name__ == "__main__":
    unittest.main()
