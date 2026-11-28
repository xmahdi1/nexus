"""Export bounded numeric recaps and task timing, never task names or payloads."""
import json
import os
import time
from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'nexus_safe'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed = set(json.loads(os.environ['NEXUS_APPROVED_ALIASES']))
        self.epoch = time.monotonic()
        self.tasks = {}
        self.starts = {}
        self.events = []
        self.ordinal = 0
        self.truncated = False

    def task_number(self, task):
        key = task._uuid
        if key not in self.tasks:
            self.ordinal += 1
            if len(self.tasks) >= 2000:
                self.tasks.pop(next(iter(self.tasks)))
            self.tasks[key] = self.ordinal
        return self.tasks[key]

    def v2_playbook_on_task_start(self, task, is_conditional):
        self.task_number(task)

    def v2_playbook_on_handler_task_start(self, task):
        self.task_number(task)

    def v2_runner_on_start(self, host, task):
        if host.get_name() in self.allowed and len(self.events) < 200:
            if len(self.starts) >= 2000:
                self.starts.pop(next(iter(self.starts)))
            self.starts[(task._uuid, host.get_name())] = time.monotonic()

    def record(self, result, status):
        host = result._host.get_name()
        if host not in self.allowed:
            return
        now = time.monotonic()
        start = self.starts.pop((result._task._uuid, host), now)
        if len(self.events) >= 200:
            self.truncated = True
            return
        self.events.append({'task': self.task_number(result._task), 'host': host,
                            'status': status,
                            'startedMs': max(0, min(600000, int((start - self.epoch) * 1000))),
                            'durationMs': max(0, min(600000, int((now - start) * 1000)))})

    def v2_runner_on_ok(self, result):
        self.record(result, 'changed' if result._result.get('changed', False) else 'ok')

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.record(result, 'ignored' if ignore_errors else 'failed')

    def v2_runner_on_unreachable(self, result):
        self.record(result, 'unreachable')

    def v2_runner_on_skipped(self, result):
        self.record(result, 'skipped')

    def v2_playbook_on_stats(self, stats):
        rows = {}
        for host in stats.processed:
            if host not in self.allowed:
                continue
            values = stats.summarize(host)
            rows[host] = {key: int(values.get(key, 0)) for key in ('ok', 'changed', 'failures', 'unreachable', 'skipped', 'rescued', 'ignored')}
        with open(os.environ['NEXUS_RECAP_FILE'], 'x') as target:
            json.dump(rows, target)
        with open(os.environ['NEXUS_TASKS_FILE'], 'x') as target:
            json.dump({'events': self.events, 'truncated': self.truncated}, target)
