"""
Tests for node-level container logs (Kubernetes DaemonSet) and wildcard sources:
log line formats, naming rules, following many files, config validation, ${ENV}.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402
from agent import (  # noqa: E402
    GlobTailer, LineJoiner, RuleResolver, expand_env, load_config,
    parse_container_line, parse_k8s_log_name, validate_sources,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks and rename-while-open are POSIX")
CID = "a" * 64


def k8s_name(pod, ns, container, cid=CID):
    return f"{pod}_{ns}_{container}-{cid}.log"


def append(path: Path, text: str) -> None:
    with open(path, "ab") as f:
        f.write(text.encode("utf-8"))


@pytest.fixture(autouse=True)
def _clean():
    agent.SOURCES._sources.clear()
    agent._last_logged.clear()
    yield


# ---------------------------------------------------------------------------
# Line formats
# ---------------------------------------------------------------------------

class TestLineFormats:
    def test_cri_full_line(self):
        assert parse_container_line("2026-10-05T10:00:00.123456789Z stdout F hello world", "cri") == ("hello world", False)

    def test_cri_partial_line_is_marked(self):
        assert parse_container_line("2026-10-05T10:00:00Z stderr P first half", "cri") == ("first half", True)

    def test_docker_json_line(self):
        line = json.dumps({"log": "hello world\n", "stream": "stdout", "time": "2026-10-05T10:00:00Z"})
        assert parse_container_line(line, "docker") == ("hello world", False)

    def test_docker_partial_has_no_trailing_newline(self):
        line = json.dumps({"log": "first half", "stream": "stdout", "time": "t"})
        assert parse_container_line(line, "docker") == ("first half", True)

    def test_auto_detects_each_format_per_line(self):
        cri = "2026-10-05T10:00:00Z stdout F from cri"
        dock = json.dumps({"log": "from docker\n", "stream": "stdout", "time": "t"})
        assert parse_container_line(cri, "auto")[0] == "from cri"
        assert parse_container_line(dock, "auto")[0] == "from docker"
        assert parse_container_line("just a plain line", "auto") == ("just a plain line", False)

    def test_raw_never_rewrites_a_line(self):
        cri = "2026-10-05T10:00:00Z stdout F from cri"
        assert parse_container_line(cri, "raw") == (cri, False)

    def test_json_application_logs_without_a_log_field_are_kept_whole(self):
        line = '{"level":"info","msg":"customer phone 9876543210"}'
        assert parse_container_line(line, "auto") == (line, False)

    def test_malformed_json_falls_back_to_the_raw_line(self):
        assert parse_container_line('{"log": broken', "auto") == ('{"log": broken', False)


class TestLineJoiner:
    def test_partial_pieces_are_joined_into_one_message(self):
        j = LineJoiner("cri")
        assert j.feed("2026-10-05T10:00:00Z stdout P customer phone 98765") is None
        assert j.feed("2026-10-05T10:00:00Z stdout P 43210 and ") is None
        assert j.feed("2026-10-05T10:00:00Z stdout F aadhaar 2345 6789 0124") == \
            "customer phone 9876543210 and aadhaar 2345 6789 0124"

    def test_a_value_split_across_pieces_is_whole_again(self):
        j = LineJoiner("docker")
        a = json.dumps({"log": "phone 98765", "stream": "stdout", "time": "t"})
        b = json.dumps({"log": "43210 leaked\n", "stream": "stdout", "time": "t"})
        assert j.feed(a) is None
        assert j.feed(b) == "phone 9876543210 leaked"

    def test_joining_is_bounded(self):
        j = LineJoiner("cri")
        big = "x" * 40000
        assert j.feed(f"2026-10-05T10:00:00Z stdout P {big}") is None
        out = j.feed(f"2026-10-05T10:00:00Z stdout P {big}")
        assert out is not None and len(out) == 80000, "emitted once the limit is passed, not held forever"

    def test_empty_messages_are_skipped(self):
        j = LineJoiner("cri")
        assert j.feed("2026-10-05T10:00:00Z stdout F ") is None


# ---------------------------------------------------------------------------
# Naming rules
# ---------------------------------------------------------------------------

class TestFileNameParsing:
    def test_standard_kubelet_name(self):
        assert parse_k8s_log_name(k8s_name("order-7d9f6b-abcde", "shop", "app")) == \
            {"pod": "order-7d9f6b-abcde", "namespace": "shop", "container": "app"}

    def test_container_names_with_dashes_and_pods_with_dots(self):
        assert parse_k8s_log_name(k8s_name("web.v2-0", "kube-system", "side-car-proxy")) == \
            {"pod": "web.v2-0", "namespace": "kube-system", "container": "side-car-proxy"}

    @pytest.mark.parametrize("name", ["app.log", "order_shop_app.log", f"order_shop_app-{'z' * 64}.log", "x.txt"])
    def test_other_names_are_not_node_logs(self, name):
        assert parse_k8s_log_name(name) is None


RULES = [
    {"match": {"namespace": "shop", "pod": "order-*"}, "source_system": "order-service"},
    {"match": {"namespace": "shop", "container": "payments*"}, "source_system": "payments-service"},
    {"match": {"namespace": "tenant-*"}, "source_system": "{namespace}-{container}"},
]


class TestRuleResolver:
    r = RuleResolver(RULES)

    def test_first_matching_rule_wins(self):
        assert self.r.resolve(f"/var/log/containers/{k8s_name('order-1-x', 'shop', 'payments')}") == "order-service"

    def test_every_key_in_a_rule_must_match(self):
        assert self.r.resolve(k8s_name("cart-1", "shop", "app")) is None
        assert self.r.resolve(k8s_name("order-1", "other", "app")) is None

    def test_container_rule(self):
        assert self.r.resolve(k8s_name("cart-1", "shop", "payments-api")) == "payments-service"

    def test_placeholders_fill_in_names(self):
        assert self.r.resolve(k8s_name("p-1", "tenant-acme", "billing")) == "tenant-acme-billing"

    def test_files_that_are_not_node_logs_are_unmapped(self):
        assert self.r.resolve("/var/log/containers/not-a-pod-log.log") is None

    def test_matching_is_case_sensitive(self):
        assert self.r.resolve(k8s_name("order-1", "Shop", "app")) is None


class TestConfigValidation:
    good = [{"type": "kubernetes_logs", "rules": RULES}]

    def test_valid_config_has_no_problems(self):
        assert validate_sources(self.good) == []
        assert validate_sources([{"type": "file", "path": "/var/log/*.log", "source_system": "x", "format": "auto"}]) == []

    @pytest.mark.parametrize("sources, fragment", [
        ([{"type": "kubernetes_logs"}], "at least one rule"),
        ([{"type": "kubernetes_logs", "rules": []}], "at least one rule"),
        ([{"type": "kubernetes_logs", "rules": [{"match": {}, "source_system": "x"}]}], "'match' must list"),
        ([{"type": "kubernetes_logs", "rules": [{"match": {"node": "n1"}, "source_system": "x"}]}], "unknown match key"),
        ([{"type": "kubernetes_logs", "rules": [{"match": {"pod": "a"}}]}], "source_system is required"),
        ([{"type": "kubernetes_logs", "rules": [{"match": {"pod": "a"}, "source_system": "{nope}"}]}], "may only use"),
        ([{"type": "kubernetes_logs", "unmapped": "default", "rules": RULES}], "unmapped must be 'drop'"),
        ([{"type": "file", "path": "/x.log"}], "needs a source_system"),
        ([{"type": "file", "source_system": "x"}], "needs a path"),
        ([{"type": "file", "path": "/x", "source_system": "x", "format": "yaml"}], "format must be one of"),
        ([{"type": "file", "path": "/x", "source_system": "x", "max_files": 0}], "max_files"),
        ([{"type": "carrier-pigeon"}], "unknown type"),
        ("nope", "must be a list"),
    ])
    def test_problems_are_reported(self, sources, fragment):
        assert any(fragment in p for p in validate_sources(sources)), validate_sources(sources)

    def test_load_config_exits_78_on_invalid_sources(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("veritas_address: https://v:8000\nsources:\n  - type: kubernetes_logs\n")
        with pytest.raises(SystemExit) as e:
            load_config(cfg)
        assert e.value.code == agent.EXIT_CONFIG


class TestEnvExpansion:
    def test_variables_are_replaced_everywhere(self, monkeypatch):
        monkeypatch.setenv("VERITAS_REGISTRATION_KEY", "k-123")
        monkeypatch.setenv("NODE_NAME", "node-7")
        out = expand_env({"registration_key": "${VERITAS_REGISTRATION_KEY}",
                          "source_label": "k8s-${NODE_NAME}",
                          "sources": [{"path": "/x/${NODE_NAME}.log"}]})
        assert out["registration_key"] == "k-123"
        assert out["source_label"] == "k8s-node-7"
        assert out["sources"][0]["path"] == "/x/node-7.log"

    def test_a_missing_variable_is_reported_not_left_as_text(self):
        missing = []
        out = expand_env({"registration_key": "${NOT_SET_ANYWHERE_XYZ}"}, missing)
        assert missing == ["NOT_SET_ANYWHERE_XYZ"]

    def test_load_config_refuses_unset_variables(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VERITAS_REGISTRATION_KEY", raising=False)
        cfg = tmp_path / "c.yaml"
        cfg.write_text('veritas_address: https://v:8000\nregistration_key: "${VERITAS_REGISTRATION_KEY}"\n')
        with pytest.raises(SystemExit) as e:
            load_config(cfg)
        assert e.value.code == agent.EXIT_CONFIG

    def test_source_system_placeholders_are_not_touched(self):
        assert expand_env({"s": "{container}-{namespace}"}) == {"s": "{container}-{namespace}"}

    def test_load_config_end_to_end(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VERITAS_REGISTRATION_KEY", "k-999")
        cfg = tmp_path / "c.yaml"
        cfg.write_text('veritas_address: https://v:8000\nregistration_key: "${VERITAS_REGISTRATION_KEY}"\n')
        assert load_config(cfg)["registration_key"] == "k-999"


# ---------------------------------------------------------------------------
# Following many files
# ---------------------------------------------------------------------------

def cri(text, flag="F"):
    return f"2026-10-05T10:00:00.000000000Z stdout {flag} {text}\n"


def make_tailer(tmp_path, rules=RULES, fmt="auto", **kw):
    resolver = RuleResolver(rules)
    clock = {"t": 0.0}
    t = GlobTailer(str(tmp_path / "*.log"), resolver.resolve, fmt=fmt, describe=resolver.describe,
                   clock=lambda: clock["t"], **kw)

    def poll():
        clock["t"] += 100  # every poll rescans
        return t.poll()

    return t, poll


class TestGlobTailer:
    def test_existing_files_start_at_the_end_and_new_files_from_the_start(self, tmp_path):
        old = tmp_path / k8s_name("order-1", "shop", "app")
        append(old, cri("history that must not be replayed"))
        t, poll = make_tailer(tmp_path)
        assert poll() == []
        append(old, cri("a new line"))
        new = tmp_path / k8s_name("order-2", "shop", "app", "b" * 64)   # a pod created after the agent started
        append(new, cri("first line of the new pod"))
        got = poll()
        assert sorted(got) == [("a new line", "order-service"), ("first line of the new pod", "order-service")]

    def test_container_runtime_prefix_is_removed_and_system_comes_from_the_rule(self, tmp_path):
        f = tmp_path / k8s_name("order-1", "shop", "app")
        append(f, "")
        t, poll = make_tailer(tmp_path)
        poll()
        append(f, cri("customer phone 9876543210"))
        assert poll() == [("customer phone 9876543210", "order-service")]

    def test_unmapped_pods_are_ignored_and_counted(self, tmp_path):
        mapped = tmp_path / k8s_name("order-1", "shop", "app")
        other = tmp_path / k8s_name("cart-1", "shop", "app", "c" * 64)
        append(mapped, ""); append(other, "")
        t, poll = make_tailer(tmp_path)
        poll()
        append(mapped, cri("keep")); append(other, cri("never forwarded: customer phone 9123456780"))
        assert poll() == [("keep", "order-service")]
        assert (t.files_followed, t.files_ignored) == (1, 1)
        assert t.ignored_names() == ["shop/cart-1"]

    def test_files_that_are_not_node_logs_are_ignored(self, tmp_path):
        append(tmp_path / "random.log", "x\n")
        t, poll = make_tailer(tmp_path)
        poll()
        assert t.files_followed == 0 and t.files_ignored == 1

    def test_partial_pieces_are_joined_across_polls(self, tmp_path):
        f = tmp_path / k8s_name("order-1", "shop", "app")
        append(f, "")
        t, poll = make_tailer(tmp_path)
        poll()
        append(f, cri("phone 98765", "P"))
        assert poll() == []
        append(f, cri("43210 leaked", "F"))
        assert poll() == [("phone 9876543210 leaked", "order-service")]

    @posix_only
    def test_a_deleted_file_is_dropped_after_draining(self, tmp_path):
        f = tmp_path / k8s_name("order-1", "shop", "app")
        append(f, "")
        t, poll = make_tailer(tmp_path)
        poll()
        append(f, cri("last words"))
        f.unlink()
        got = poll() + poll() + poll()
        assert ("last words", "order-service") in got or t.files_followed == 0
        assert t.files_followed == 0

    def test_file_limit_is_enforced(self, tmp_path):
        for i in range(5):
            append(tmp_path / k8s_name(f"order-{i}", "shop", "app", str(i) * 64), "")
        t, poll = make_tailer(tmp_path, max_files=3)
        poll()
        assert t.files_followed == 3 and t.files_over_limit == 2

    def test_plain_wildcard_files_with_a_fixed_system(self, tmp_path):
        a, b = tmp_path / "a.log", tmp_path / "b.log"
        append(a, ""); append(b, "")
        t = GlobTailer(str(tmp_path / "*.log"), lambda p: "web-app", fmt="raw", clock=lambda: 1e9)
        t.poll()
        append(a, "line from a\n"); append(b, "line from b\n")
        assert sorted(t.poll()) == [("line from a", "web-app"), ("line from b", "web-app")]

    @posix_only
    def test_kubelet_style_symlinks_and_rotation(self, tmp_path):
        pods = tmp_path / "pods" / "shop_order-1_uid" / "app"
        pods.mkdir(parents=True)
        containers = tmp_path / "containers"
        containers.mkdir()
        target = pods / "0.log"
        append(target, "")
        link = containers / k8s_name("order-1", "shop", "app")
        link.symlink_to(target)

        resolver = RuleResolver(RULES)
        clock = {"t": 0.0}
        t = GlobTailer(str(containers / "*.log"), resolver.resolve, fmt="auto", clock=lambda: clock["t"])

        def poll():
            clock["t"] += 100
            return t.poll()

        poll()
        append(target, cri("before rotation"))
        got = poll()
        # kubelet rotation: current file renamed away, a new one created under the same name
        append(target, cri("written just before rotation"))
        os.rename(target, pods / "0.log.20261005-100000")
        append(target, cri("after rotation"))
        got += poll() + poll()
        assert [m for m, _ in got] == ["before rotation", "written just before rotation", "after rotation"]


class TestTailGlobThread:
    @posix_only
    def test_end_to_end_with_health_reporting(self, tmp_path):
        pod = tmp_path / k8s_name("order-1", "shop", "app")
        other = tmp_path / k8s_name("cart-1", "shop", "app", "d" * 64)
        append(pod, ""); append(other, "")
        resolver = RuleResolver(RULES)
        q: queue.Queue = queue.Queue()
        stop = threading.Event()
        pattern = str(tmp_path / "*.log")
        t = threading.Thread(
            target=agent.tail_glob,
            args=(pattern, "kubernetes_logs", resolver.resolve, q),
            kwargs={"fmt": "auto", "poll_interval": 0.02, "rescan_seconds": 0.05,
                    "stop_event": stop, "describe": resolver.describe},
            daemon=True,
        )
        t.start()
        try:
            time.sleep(0.3)
            append(pod, cri("customer phone 9876543210"))
            append(other, cri("must be dropped, phone 9123456780"))
            time.sleep(0.4)
        finally:
            stop.set()
            t.join(timeout=3)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        assert items == [("customer phone 9876543210", "order-service")]
        state = {s["target"]: s for s in agent.SOURCES.snapshot()}[pattern]
        assert state["state"] == "reading"
        assert "1 file(s) followed" in state["detail"] and "1 ignored" in state["detail"]
        assert state["last_line_at"] is not None
