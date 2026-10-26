# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/review-served, which records what answered the enrollment review and whether it is the
provider and model the review asked for: python3 -m pytest tools/tests. test_check_checks.py tests its two callers,
review-run and review-comment.

Each stand-in agent prints events in the shapes Claude Code prints them (`--output-format stream-json
--verbose`): a `system` event, an `assistant` event for each content block of a response, with the response's model and
message id, and a `result` event whose `modelUsage` names the tool's provider."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVED = os.path.join(ROOT, ".github", "scripts", "review-served")
ASKED = "anthropic/model-a-1"
REVIEW = "Thanks.\n"
HOST = "api.anthropic.com"
HEAD = f"asked {ASKED}\nendpoint {HOST}\n"   # the record's first lines, when the tool sends its requests to the API
# The variables that send the tool's requests elsewhere: no test inherits one from the environment it runs in.
ELSEWHERE = ("ANTHROPIC_BASE_URL", "ANTHROPIC_UNIX_SOCKET", "CLAUDE_CODE_API_BASE_URL",
             "_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL", "CLAUDE_CONFIG_DIR", "NODE_TLS_REJECT_UNAUTHORIZED",
             "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
             "ANTHROPIC_PROFILE", "ANTHROPIC_CONFIG_DIR", "XDG_CONFIG_HOME", "CLAUDE_CODE_EXTRA_BODY",
             "ANTHROPIC_BETAS", "CLAUDE_CODE_MANAGED_SETTINGS_PATH", "CLAUDE_CODE_REMOTE_SETTINGS_PATH",
             "CLAUDE_CODE_DISABLE_ADMIN_ENV_UNION", "CLAUDE_CODE_MOCK_REMOTE_SETTINGS", "ANTHROPIC_CUSTOM_HEADERS",
             "CLAUDE_CODE_CUSTOM_OAUTH_URL")
# A stand-in agent: prints the events of the JSON list in $HOME/events.json, each on a line of its own as it comes; an
# item {"sleep": seconds} waits, {"exit": status} ends there, {"raw": text} prints the text as it is, and {"child":
# seconds} starts a process of its own that sleeps that long, as a tool the agent runs would. It writes its arguments
# to $HOME/argv.json, and its own process id and its child's to $HOME/pids.
FAKE_AGENT = r"""#!/usr/bin/env python3
import json, os, subprocess, sys, time
home = os.environ.get("HOME", "")
with open(os.path.join(home, "argv.json"), "w") as f:
    json.dump(sys.argv[1:], f)
with open(os.path.join(home, "events.json")) as f:
    events = json.load(f)
pids = [os.getpid()]


def write_pids():
    with open(os.path.join(home, "pids.new"), "w") as f:
        f.write(" ".join(map(str, pids)))
    os.replace(os.path.join(home, "pids.new"), os.path.join(home, "pids"))


write_pids()
for event in events:
    if "sleep" in event:
        time.sleep(event["sleep"])
    elif "exit" in event:
        sys.exit(event["exit"])
    elif "raw" in event:
        print(event["raw"], flush=True)
    elif "child" in event:
        pids.append(subprocess.Popen(["sleep", str(event["child"])]).pid)
        write_pids()
    else:
        print(json.dumps(event), flush=True)
"""


def init():
    return {"type": "system", "subtype": "init", "model": "model-a-1", "apiKeySource": "none"}


def turn(n, model="model-a-1", blocks=1):
    """The events of the agent's turn n: one per content block, each with the response's model and message id."""
    message = {"id": f"msg_{n:04d}", "role": "assistant", "content": [{"type": "text", "text": "..."}]}
    if model is not None:
        message["model"] = model
    return [{"type": "assistant", "message": message, "parent_tool_use_id": None} for _ in range(blocks)]


def result(text=REVIEW, providers=("firstParty",), is_error=False, turns=2):
    usage = {f"model-a-1{'' if i == 0 else f'-{i}'}": {"canonicalModel": "model-a-1", "provider": p}
             for i, p in enumerate(providers)}
    return {"type": "result", "subtype": "success", "is_error": is_error, "result": text, "num_turns": turns,
            "modelUsage": usage}


def check(record):
    r = subprocess.run([sys.executable, SERVED, "check"], input=record, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def environment(**variables):
    """The environment a test runs a script in: this one's, without the variables that send the tool's requests
    elsewhere, and with `variables`."""
    env = {k: v for k, v in os.environ.items()
           if k.upper() not in ELSEWHERE and not k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "_CLAUDE_CODE_"))}
    env.update(variables)
    return env


class StandIn(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="review-served-")
        self.dir = os.path.realpath(self._tmp.name)
        self.bin = os.path.join(self.dir, "bin")
        os.mkdir(self.bin)
        self.review = os.path.join(self.dir, ".review")
        os.mkdir(self.review)

    def tearDown(self):
        self._tmp.cleanup()

    def agent(self, name, events):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write(FAKE_AGENT)
        os.chmod(path, 0o755)
        with open(os.path.join(self.dir, "events.json"), "w") as f:
            json.dump(events, f)
        return path

    def read(self, name):
        with open(os.path.join(self.review, name)) as f:
            return f.read()


class Run(StandIn):
    """review-served run: the record it writes, its exit status, and that it stops the agent at a turn another
    model answers."""

    def run_agent(self, events, asked=ASKED, **variables):
        agent = self.agent("agent", events)
        env = environment(HOME=self.dir, **variables)
        started = time.monotonic()
        r = subprocess.run([sys.executable, SERVED, "run", self.review, asked, "--", agent], env=env, cwd=self.dir,
                           capture_output=True, text=True, timeout=120)
        return r.returncode, r.stderr, time.monotonic() - started

    def test_the_provider_asked_for_answered_every_turn(self):
        events = [init()] + turn(1, blocks=2) + turn(2) + [result()]
        code, err, _ = self.run_agent(events)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read("served"), f"{HEAD}usage firstParty/model-a-1\nfirstParty/model-a-1 2\n")
        self.assertEqual(json.loads(self.read("claude.json")), result())
        self.assertEqual(len(self.read("claude.jsonl").splitlines()), len(events))
        self.assertEqual(check(self.read("served")), (0, "firstParty/model-a-1 (2 turns)"))

    def test_another_model_at_the_first_turn_stops_the_agent_at_once(self):
        events = [init()] + turn(1, "other-b-1") + [{"sleep": 100}] + turn(2) + [result()]
        code, err, seconds = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60, "the agent was not stopped at its first turn")
        self.assertIn("turn 1 was answered by other-b-1, not model-a-1", err)
        self.assertEqual(self.read("served"), f"{HEAD}none/other-b-1 1\n")
        self.assertEqual(self.read("claude.json"), "", "no result: an empty claude.json")
        code, line = check(self.read("served"))
        self.assertEqual(code, 1)
        self.assertIn("but none/other-b-1 (1 turn) answered", line)

    def test_another_model_after_some_turns_stops_the_agent_there(self):
        events = [init()] + turn(1) + turn(2) + turn(3, "other-b-1") + [{"sleep": 100}, result()]
        code, err, seconds = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        self.assertIn("turn 3 was answered by other-b-1", err)
        self.assertEqual(check(self.read("served"))[0], 1)

    def test_a_turn_that_names_no_model_stops_the_agent(self):
        events = [init()] + turn(1, None) + [{"sleep": 100}, result()]
        code, err, seconds = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        self.assertIn("turn 1 was answered by no model it named", err)
        self.assertEqual(self.read("served"), f"{HEAD}none/none 1\n")
        self.assertEqual(check(self.read("served"))[0], 3)

    def test_another_provider_at_the_end_is_not_the_one_asked_for(self):
        events = [init()] + turn(1) + turn(2) + [result(providers=("bedrock",))]
        code, err, _ = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertEqual(self.read("served"), f"{HEAD}usage bedrock/model-a-1\nbedrock/model-a-1 2\n")
        code, line = check(self.read("served"))
        self.assertEqual(code, 1)
        self.assertIn("which the tool calls firstParty/model-a-1, but bedrock/model-a-1 (2 turns) answered, and the "
                      "tool's usage names bedrock/model-a-1", line)
        # the review is still there, though it is not to be posted
        self.assertEqual(json.loads(self.read("claude.json"))["result"], REVIEW)

    def test_two_providers_at_the_end_are_not_the_one_asked_for(self):
        events = [init()] + turn(1) + [result(providers=("firstParty", "vertex"))]
        code, err, _ = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertEqual(self.read("served"), f"{HEAD}usage firstParty/model-a-1\nusage vertex/model-a-1\n"
                                              "firstParty+vertex/model-a-1 1\n")
        self.assertEqual(check(self.read("served"))[0], 1)

    def test_a_usage_entry_of_another_model_is_not_the_one_asked_for(self):
        """Every turn answered by the model asked for, but the tool's usage names a request of another model."""
        side = result()
        side["modelUsage"]["other-b-1"] = {"canonicalModel": "other-b-1", "provider": "firstParty"}
        code, err, _ = self.run_agent([init()] + turn(1) + [side])
        self.assertEqual(code, 4, err)
        self.assertIn("usage firstParty/other-b-1\n", self.read("served"))
        code, line = check(self.read("served"))
        self.assertEqual(code, 1)
        self.assertIn("the tool's usage names firstParty/model-a-1, firstParty/other-b-1", line)

    def test_a_review_whose_result_names_no_provider_is_not_attributable(self):
        """The tool's `.modelUsage` is {} when no request got a response: a review beside it names no provider."""
        events = [init()] + turn(1) + turn(2) + [result(providers=())]
        code, err, _ = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertEqual(self.read("served"), f"{HEAD}none/model-a-1 2\n")
        code, line = check(self.read("served"))
        self.assertEqual(code, 3)
        self.assertIn("it is not attributable", line)

    def test_a_message_the_tool_wrote_itself_is_no_turn(self):
        """A refused key: the tool's own message, model "<synthetic>", then an error result with {} for modelUsage."""
        synthetic = {"type": "assistant", "message": {"id": "0068f1fb", "model": "<synthetic>", "content": []},
                     "error": "authentication_failed", "is_api_error_message": True}
        events = [init(), synthetic, result("Invalid API key", providers=(), is_error=True, turns=1), {"exit": 1}]
        code, err, _ = self.run_agent(events)
        self.assertEqual(code, 1, "the agent's own failure, not a stop")
        self.assertEqual(self.read("served"), HEAD)
        self.assertEqual(check(self.read("served"))[0], 3)

    def test_an_agent_that_fails_by_itself_keeps_its_status(self):
        events = [init()] + turn(1) + [{"exit": 7}]
        code, err, _ = self.run_agent(events)
        self.assertEqual(code, 7, err)
        self.assertEqual(self.read("served"), f"{HEAD}none/model-a-1 1\n")

    def test_a_provider_it_has_no_name_for_is_refused_before_the_agent_runs(self):
        code, err, _ = self.run_agent([init()] + turn(1) + [result()], asked="openai/model-a-1")
        self.assertEqual(code, 2)
        self.assertIn("not <provider>/<model>", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")

    def test_a_stale_record_and_result_do_not_survive_a_run(self):
        for name in ("served", "claude.json"):
            with open(os.path.join(self.review, name), "w") as f:
                f.write(f"asked {ASKED}\nfirstParty/model-a-1 9\n")
        self.run_agent([init()] + turn(1, "other-b-1"))
        self.assertEqual(self.read("served"), f"{HEAD}none/other-b-1 1\n")
        self.assertEqual(self.read("claude.json"), "")

    def test_an_endpoint_other_than_the_provider_s_own_starts_no_agent(self):
        """The tool calls its provider firstParty also when ANTHROPIC_BASE_URL names a proxy, which could answer with
        any model under any name: such a review is refused before the agent runs."""
        for variables, where in (({"ANTHROPIC_BASE_URL": "https://proxy.example/"}, "https:proxy.example"),
                                 ({"ANTHROPIC_BASE_URL": "http://api.anthropic.com"}, "http:api.anthropic.com"),
                                 ({"ANTHROPIC_BASE_URL": "https://api.anthropic.com:8443"},
                                  "https:api.anthropic.com:8443"),
                                 ({"ANTHROPIC_BASE_URL": "https://x@api.anthropic.com"},
                                  "https:api.anthropic.com+userinfo"),
                                 ({"ANTHROPIC_BASE_URL": "https://api.anthropic.com.proxy.example"},
                                  "https:api.anthropic.com.proxy.example"),
                                 ({"ANTHROPIC_BASE_URL": ""}, "none:none"),
                                 ({"ANTHROPIC_BASE_URL": "https://[::1"}, "unreadable-url"),
                                 ({"ANTHROPIC_BASE_URL": "https://api.anthropic.com:x"}, "unreadable-url"),
                                 ({"https_proxy": "http://proxy.example"}, "https_proxy"),
                                 ({"NODE_EXTRA_CA_CERTS": "/tmp/ca.pem"}, "NODE_EXTRA_CA_CERTS"),
                                 ({"NODE_TLS_REJECT_UNAUTHORIZED": "0"}, "NODE_TLS_REJECT_UNAUTHORIZED"),
                                 ({"SSL_CERT_FILE": "/tmp/ca.pem"}, "SSL_CERT_FILE"),
                                 ({"SSL_CERT_DIR": "/tmp/certs"}, "SSL_CERT_DIR"),
                                 ({"HTTP_PROXY": "http://proxy.example"}, "HTTP_PROXY"),
                                 ({"all_proxy": "socks5://proxy.example"}, "all_proxy"),
                                 ({"CLAUDE_CODE_EXTRA_BODY": '{"x": 1}'}, "CLAUDE_CODE_EXTRA_BODY"),
                                 ({"ANTHROPIC_BETAS": "x-2026-01-01"}, "ANTHROPIC_BETAS"),
                                 ({"CLAUDE_CODE_MANAGED_SETTINGS_PATH": "/tmp/managed"},
                                  "CLAUDE_CODE_MANAGED_SETTINGS_PATH"),
                                 ({"CLAUDE_CODE_REMOTE_SETTINGS_PATH": "/tmp/remote.json"},
                                  "CLAUDE_CODE_REMOTE_SETTINGS_PATH"),
                                 ({"CLAUDE_CODE_DISABLE_ADMIN_ENV_UNION": "1"}, "CLAUDE_CODE_DISABLE_ADMIN_ENV_UNION"),
                                 ({"CLAUDE_CODE_MOCK_REMOTE_SETTINGS": "1"}, "CLAUDE_CODE_MOCK_REMOTE_SETTINGS"),
                                 ({"ANTHROPIC_CUSTOM_HEADERS": "anthropic-beta: x"}, "ANTHROPIC_CUSTOM_HEADERS"),
                                 ({"CLAUDE_CODE_CUSTOM_OAUTH_URL": "https://claude.ai"},
                                  "CLAUDE_CODE_CUSTOM_OAUTH_URL"),
                                 ({"ANTHROPIC_UNIX_SOCKET": "/tmp/s"}, "ANTHROPIC_UNIX_SOCKET"),
                                 ({"CLAUDE_CODE_API_BASE_URL": "https://proxy.example"}, "CLAUDE_CODE_API_BASE_URL"),
                                 ({"_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL": "1"},
                                  "_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL"),
                                 ({"CLAUDE_CODE_USE_BEDROCK": "1"}, "CLAUDE_CODE_USE_BEDROCK"),
                                 ({"CLAUDE_CODE_USE_GATEWAY": "1", "ANTHROPIC_UNIX_SOCKET": "/s"},
                                  "ANTHROPIC_UNIX_SOCKET+CLAUDE_CODE_USE_GATEWAY")):
            with self.subTest(variables=variables):
                code, err, _ = self.run_agent([init()] + turn(1) + [result()], **variables)
                self.assertEqual(code, 4, err)
                self.assertIn(f"did not start Claude Code: the tool's environment or settings set {where}, which can "
                              f"send its requests elsewhere than {HOST}", err)
                self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")
                self.assertEqual(self.read("served"), f"asked {ASKED}\nendpoint {where}\n")
                self.assertEqual(check(self.read("served"))[0], 1)

    def test_an_endpoint_a_settings_file_sets_starts_no_agent(self):
        """The tool applies the `env` of its settings files as it starts: the user's, and the checkout's."""
        for path in (os.path.join(self.dir, ".claude", "settings.json"),
                     os.path.join(self.dir, ".claude", "settings.local.json")):
            for settings, where in (({"env": {"ANTHROPIC_BASE_URL": "https://proxy.example"}}, "https:proxy.example"),
                                    ({"env": ["not", "a", "map"]}, "unreadable-settings"),
                                    ("{", "unreadable-settings")):
                with self.subTest(path=path, settings=settings):
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w") as f:
                        f.write(settings if isinstance(settings, str) else json.dumps(settings))
                    self.addCleanup(lambda p=path: os.path.exists(p) and os.remove(p))
                    code, err, _ = self.run_agent([init()] + turn(1) + [result()])
                    os.remove(path)
                    self.assertEqual(code, 4, err)
                    self.assertIn(f"settings set {where}, which", err)
                    self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")

    def test_an_endpoint_the_settings_of_claude_config_dir_set_starts_no_agent(self):
        config = os.path.join(self.dir, "config")
        os.mkdir(config)
        with open(os.path.join(config, "settings.json"), "w") as f:
            json.dump({"env": {"CLAUDE_CODE_USE_VERTEX": "1"}}, f)
        code, err, _ = self.run_agent([init()] + turn(1) + [result()], CLAUDE_CONFIG_DIR=config)
        self.assertEqual(code, 4, err)
        self.assertIn("settings set CLAUDE_CODE_USE_VERTEX, which", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")

    def test_the_provider_s_own_endpoint_named_or_in_settings_is_the_one_asked_for(self):
        os.makedirs(os.path.join(self.dir, ".claude"))
        with open(os.path.join(self.dir, ".claude", "settings.json"), "w") as f:
            json.dump({"env": {"ANTHROPIC_BASE_URL": f"https://{HOST}"}, "permissions": {}}, f)
        for base in (f"https://{HOST}", f"https://{HOST}/", f"https://{HOST}:443"):
            with self.subTest(base=base):
                code, err, _ = self.run_agent([init()] + turn(1) + [result()], ANTHROPIC_BASE_URL=base)
                self.assertEqual(code, 0, err)
                self.assertEqual(self.read("served"), f"{HEAD}usage firstParty/model-a-1\nfirstParty/model-a-1 1\n")

    def test_a_message_named_as_the_tool_s_own_but_not_marked_so_is_a_turn_of_another_model(self):
        """The model's name comes from the response: "<synthetic>" without the tool's own mark of an API error is a
        model's turn, and not of the model asked for."""
        for mark in ({}, {"is_api_error_message": False}, {"is_api_error_message": "true"}):
            with self.subTest(mark=mark):
                unmarked = dict(turn(2, "<synthetic>")[0], **mark)
                events = [init()] + turn(1) + [unmarked, {"sleep": 100}, result()]
                code, err, seconds = self.run_agent(events)
                self.assertEqual(code, 4, err)
                self.assertLess(seconds, 60)
                self.assertIn("turn 2 was answered by ?synthetic?, not model-a-1", err)
                self.assertEqual(check(self.read("served"))[0], 1)

    def test_a_line_it_cannot_read_stops_the_agent_and_is_not_attributable(self):
        """A line of the stream that is not an event could hide a turn; a deeply nested one once crashed the reader
        with RecursionError and no record."""
        for line, why in (("[" * 100000 + "]" * 100000, "nested too deeply to read"),
                          ('{"type": "assistant", "message": {"model": "other-b-1"', "not JSON")):
            with self.subTest(why=why):
                events = [init()] + turn(1) + [{"raw": line}, {"sleep": 100}] + turn(2) + [result()]
                code, err, seconds = self.run_agent(events)
                self.assertEqual(code, 4, err)
                self.assertLess(seconds, 60)
                self.assertIn(f"line 3 of its stream is {why}: what answered is not attributable", err)
                self.assertNotIn("Traceback", err)
                self.assertEqual(self.read("served"), f"{HEAD}none/model-a-1 1\n")
                self.assertEqual(self.read("claude.json"), "")
                self.assertEqual(check(self.read("served"))[0], 3)

    def test_a_password_in_a_refused_base_url_is_never_shown(self):
        """The record, and so the log and the comment, name a refused URL's scheme, host and port, never its user or
        password."""
        code, err, _ = self.run_agent([init()] + turn(1) + [result()],
                                      ANTHROPIC_BASE_URL="https://ci-bot:p4ssw0rdp4ssw0rd@proxy.example:8443/v1")
        self.assertEqual(code, 4, err)
        self.assertEqual(self.read("served"), f"asked {ASKED}\nendpoint https:proxy.example:8443+userinfo\n")
        for text in (err, self.read("served"), check(self.read("served"))[1]):
            self.assertNotIn("p4ssw0rd", text)
            self.assertNotIn("ci-bot", text)

    def test_a_proxy_or_trust_a_settings_file_sets_starts_no_agent(self):
        """A proxy, with a CA it trusts, can answer as the API: the tool's settings set either."""
        os.makedirs(os.path.join(self.dir, ".claude"))
        with open(os.path.join(self.dir, ".claude", "settings.json"), "w") as f:
            json.dump({"env": {"HTTPS_PROXY": "http://proxy.example", "NODE_EXTRA_CA_CERTS": "/tmp/ca.pem"}}, f)
        code, err, _ = self.run_agent([init()] + turn(1) + [result()])
        self.assertEqual(code, 4, err)
        self.assertIn("settings set HTTPS_PROXY+NODE_EXTRA_CA_CERTS, which can send its requests elsewhere than "
                      "api.anthropic.com", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")

    def test_the_base_url_of_the_anthropic_profile_is_an_endpoint(self):
        """The tool reads <config dir>/configs/<profile>.json's base_url."""
        def profile(directory, name, url, active=None):
            os.makedirs(os.path.join(directory, "configs"), exist_ok=True)
            with open(os.path.join(directory, "configs", f"{name}.json"), "w") as f:
                json.dump({"base_url": url, "authentication": {"type": "user_oauth"}}, f)
            if active is not None:
                with open(os.path.join(directory, "active_config"), "w") as f:
                    f.write(active + "\n")
        home = os.path.join(self.dir, ".config", "anthropic")
        profile(home, "default", "https://proxy.example")
        code, err, _ = self.run_agent([init()] + turn(1) + [result()])
        self.assertEqual(code, 4, err)
        self.assertIn("settings set https:proxy.example, which", err)
        profile(home, "default", f"https://{HOST}")
        self.assertEqual(self.run_agent([init()] + turn(1) + [result()])[0], 0)
        profile(home, "work", "https://work.example", active="work")
        self.assertIn("https:work.example", self.run_agent([init()] + turn(1) + [result()])[1])
        named = os.path.join(self.dir, "named")
        profile(named, "other", "http://other.example")
        code, err, _ = self.run_agent([init()] + turn(1) + [result()], ANTHROPIC_CONFIG_DIR=named,
                                      ANTHROPIC_PROFILE="other")
        self.assertIn("http:other.example", err)
        with open(os.path.join(named, "configs", "other.json"), "w") as f:
            f.write("{")
        self.assertIn("unreadable-profile", self.run_agent([init()] + turn(1) + [result()], ANTHROPIC_CONFIG_DIR=named,
                                                           ANTHROPIC_PROFILE="other")[1])

    def test_another_model_of_the_family_stops_the_agent(self):
        events = [init()] + turn(1) + turn(2, "model-b-2") + [{"sleep": 100}, result()]
        code, err, seconds = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        self.assertIn("turn 2 was answered by model-b-2, not model-a-1", err)
        self.assertEqual(check(self.read("served"))[0], 1)

    def test_a_dated_snapshot_of_the_model_answers_for_it(self):
        code, err, _ = self.run_agent([init()] + turn(1, "model-a-1-20251001") + [result()])
        self.assertEqual(code, 0, err)

    def test_another_model_in_a_later_event_of_a_response_stops_the_agent(self):
        """The tool can switch models within a response: every event's model is checked, not only the first of its
        message id."""
        switched = turn(1, blocks=2)
        switched[1]["message"] = dict(switched[1]["message"], model="other-b-1")
        code, err, seconds = self.run_agent([init()] + switched + [{"sleep": 100}, result()])
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        self.assertIn("turn 1 was answered by other-b-1", err)
        self.assertEqual(self.read("served"), f"{HEAD}none/other-b-1 1\n")

    def test_a_json_line_that_is_not_an_object_stops_the_agent(self):
        hidden = json.dumps(turn(2, "other-b-1"))
        code, err, seconds = self.run_agent([init()] + turn(1) + [{"raw": hidden}, {"sleep": 100}, result()])
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        self.assertIn("line 3 of its stream is not a JSON object", err)
        self.assertEqual(check(self.read("served"))[0], 3)

    def test_a_deeply_nested_result_is_kept_as_it_came(self):
        """A result that json.loads reads but json.dump cannot write again once crashed after the agent ended, with no
        record: claude.json is the line as it came."""
        line = json.dumps(result())[:-1] + ', "deep": ' + "[" * 3000 + "]" * 3000 + "}"
        code, err, _ = self.run_agent([init()] + turn(1) + [{"raw": line}])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read("claude.json"), line)
        self.assertEqual(self.read("served"), f"{HEAD}usage firstParty/model-a-1\nfirstParty/model-a-1 1\n")

    def test_a_provider_or_model_it_cannot_check_is_refused(self):
        for asked, status in ((ASKED, 0), ("openai/model-a-1", 2), ("anthropic/", 2), ("anthropic/none", 2),
                              ("anthropic/a b", 2)):
            with self.subTest(asked=asked):
                r = subprocess.run([sys.executable, SERVED, "asked", asked], capture_output=True, text=True)
                self.assertEqual(r.returncode, status, r.stderr)

    def test_a_server_fallback_to_another_model_within_a_response_stops_the_agent(self):
        """The API can hand a response to another model part way, with a content block naming it; the tool renames the
        response only when it asked for the fallback itself, so the event still names the model asked for."""
        handed = turn(2)
        handed[0]["message"]["content"] = [{"type": "fallback", "from": {"model": "model-a-1"},
                                            "to": {"model": "other-b-1"}}, {"type": "text", "text": "..."}]
        code, err, seconds = self.run_agent([init()] + turn(1) + handed + [{"sleep": 100}, result()])
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        self.assertIn("turn 2 was answered by other-b-1 (a server fallback within the response), not model-a-1", err)
        self.assertEqual(self.read("served"), f"{HEAD}none/model-a-1 1\nnone/other-b-1 1\n")
        self.assertEqual(check(self.read("served"))[0], 1)
        # A fallback to the model asked for is no other model.
        handed[0]["message"]["content"][0]["to"]["model"] = "model-a-1"
        self.assertEqual(self.run_agent([init()] + turn(1) + handed + [result()])[0], 0)

    def test_a_setting_that_lets_another_model_answer_starts_no_agent(self):
        """advisorModel, and a policy helper (which managed settings use to give the tool settings, an env among them),
        in any settings file the script reads; /etc/claude-code's files are read the same way."""
        os.makedirs(os.path.join(self.dir, ".claude"))
        for key, value in (("advisorModel", "other-b-1"),
                           ("policyHelper", {"default": {"env": {"ANTHROPIC_BASE_URL": "https://proxy.example"}}}),
                           ("policyHelpers", [{"command": "/usr/local/bin/settings"}])):
            with self.subTest(key=key):
                with open(os.path.join(self.dir, ".claude", "settings.json"), "w") as f:
                    json.dump({key: value}, f)
                code, err, _ = self.run_agent([init()] + turn(1) + [result()])
                self.assertEqual(code, 4, err)
                self.assertIn(f"settings set {key}, which can send its requests elsewhere than api.anthropic.com or "
                              "let another model answer", err)
                self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")

    def test_a_usage_entry_that_is_not_an_object_is_not_attributable(self):
        side = result()
        side["modelUsage"]["model-a-1-20251001"] = None
        code, err, _ = self.run_agent([init()] + turn(1) + [side])
        self.assertEqual(code, 4, err)
        self.assertIn("usage none/model-a-1-20251001\n", self.read("served"))
        self.assertIn("firstParty+none/model-a-1 1\n", self.read("served"))
        self.assertNotEqual(check(self.read("served"))[0], 0)

    def test_a_long_name_that_the_record_cuts_to_the_model_asked_for_is_another(self):
        """The record cuts a name to 100 characters; the stream's own name is compared."""
        asked = "model-" + "a" * 94
        code, err, _ = self.run_agent([init()] + turn(1, asked + "-evil") + [{"sleep": 100}, result()],
                                      asked=f"anthropic/{asked}")
        self.assertEqual(code, 4, err)

    def test_the_profile_under_xdg_config_home_is_read(self):
        xdg = os.path.join(self.dir, "xdg")
        os.makedirs(os.path.join(xdg, "anthropic", "configs"))
        with open(os.path.join(xdg, "anthropic", "configs", "default.json"), "w") as f:
            json.dump({"base_url": "https://proxy.example"}, f)
        code, err, _ = self.run_agent([init()] + turn(1) + [result()], XDG_CONFIG_HOME=xdg)
        self.assertEqual(code, 4, err)
        self.assertIn("https:proxy.example", err)

    def test_the_env_of_the_global_config_is_read(self):
        """The tool applies the `env` of its global config, ~/.claude.json, as it starts, like a settings file's."""
        for directory, variables in ((self.dir, {}), (os.path.join(self.dir, "config"),
                                                      {"CLAUDE_CONFIG_DIR": os.path.join(self.dir, "config")})):
            with self.subTest(directory=directory):
                os.makedirs(directory, exist_ok=True)
                path = os.path.join(directory, ".claude.json")
                with open(path, "w") as f:
                    json.dump({"env": {"ANTHROPIC_BASE_URL": "https://proxy.example"}, "numStartups": 3}, f)
                code, err, _ = self.run_agent([init()] + turn(1) + [result()], **variables)
                os.remove(path)
                self.assertEqual(code, 4, err)
                self.assertIn("settings set https:proxy.example, which", err)
                self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")
        with open(os.path.join(self.dir, ".claude.json"), "w") as f:
            json.dump({"numStartups": 3, "env": {}}, f)
        self.assertEqual(self.run_agent([init()] + turn(1) + [result()])[0], 0)

    def test_the_env_of_every_file_the_global_config_can_come_from_is_read(self):
        """The tool takes its global config from .config.json in its config home when that is not empty, and names
        .claude.json after its OAuth setting (.claude-custom-oauth.json, for one): each is read."""
        config = os.path.join(self.dir, "config")
        for path, variables in ((os.path.join(self.dir, ".claude", ".config.json"), {}),
                                (os.path.join(config, ".config.json"), {"CLAUDE_CONFIG_DIR": config}),
                                (os.path.join(self.dir, ".claude-custom-oauth.json"), {}),
                                (os.path.join(self.dir, ".claude-staging-oauth.json"), {}),
                                (os.path.join(config, ".claude-local-oauth.json"), {"CLAUDE_CONFIG_DIR": config})):
            with self.subTest(path=path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    json.dump({"env": {"ANTHROPIC_BASE_URL": "https://proxy.example"}}, f)
                code, err, _ = self.run_agent([init()] + turn(1) + [result()], **variables)
                os.remove(path)
                self.assertEqual(code, 4, err)
                self.assertIn("settings set https:proxy.example, which", err)
                self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")
        # An empty .config.json holds no env: the tool reads none from it, and it refuses nothing.
        os.makedirs(os.path.join(self.dir, ".claude"), exist_ok=True)
        open(os.path.join(self.dir, ".claude", ".config.json"), "w").close()
        self.assertEqual(self.run_agent([init()] + turn(1) + [result()])[0], 0)

    def test_a_fallback_block_or_content_that_hides_its_model_stops_the_agent(self):
        """A fallback block whose `to` names no model, and content that is not a list, could hide another model."""
        for content in ([{"type": "fallback", "from": {"model": "model-a-1"}, "to": "other-b-1"}],
                        [{"type": "fallback", "from": {"model": "model-a-1"}}], {"type": "text", "text": "..."}):
            with self.subTest(content=content):
                hidden = turn(1)
                hidden[0]["message"]["content"] = content
                code, err, seconds = self.run_agent([init()] + hidden + [{"sleep": 100}, result()])
                self.assertEqual(code, 4, err)
                self.assertLess(seconds, 60)
                self.assertIn("turn 1 was answered by no model it named", err)

    def test_a_stale_record_is_gone_also_when_no_agent_starts(self):
        for name in ("served", "claude.json"):
            with open(os.path.join(self.review, name), "w") as f:
                f.write(f"{HEAD}usage firstParty/model-a-1\nfirstParty/model-a-1 9\n")
        self.run_agent([init()] + turn(1) + [result()], ANTHROPIC_BASE_URL="https://proxy.example")
        self.assertEqual(self.read("served"), f"asked {ASKED}\nendpoint https:proxy.example\n")
        self.assertEqual(self.read("claude.json"), "")

    def test_a_variable_of_the_tool_s_own_that_is_not_allowed_starts_no_agent(self):
        """Of the tool's own variables only credentials and knobs that move no request are allowed: any other, a new
        one included, is refused (a host's credentials file, for one, sets the base URL another way)."""
        for variables in ({"CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST": "1", "CLAUDE_CODE_HOST_CREDS_FILE": "/tmp/c.json"},
                          {"CLAUDE_CODE_SOMETHING_NEW": "1"}, {"ANTHROPIC_MODEL": "other-b-1"},
                          {"ANTHROPIC_PROFILE": "work"}):
            with self.subTest(variables=variables):
                code, err, _ = self.run_agent([init()] + turn(1) + [result()], **variables)
                self.assertEqual(code, 4, err)
                self.assertIn(f"settings set {'+'.join(sorted(variables))}, which", err)
                self.assertFalse(os.path.exists(os.path.join(self.dir, "argv.json")), "the agent ran")
        # The same in a settings file's env.
        os.makedirs(os.path.join(self.dir, ".claude"), exist_ok=True)
        with open(os.path.join(self.dir, ".claude", "settings.json"), "w") as f:
            json.dump({"env": {"CLAUDE_CODE_HOST_CREDS_FILE": "/tmp/c.json"}}, f)
        code, err, _ = self.run_agent([init()] + turn(1) + [result()])
        self.assertIn("settings set CLAUDE_CODE_HOST_CREDS_FILE, which", err)
        os.remove(os.path.join(self.dir, ".claude", "settings.json"))
        # The credentials and knobs that are allowed.
        allowed = {"ANTHROPIC_API_KEY": "k", "ANTHROPIC_AUTH_TOKEN": "t", "CLAUDE_CODE_OAUTH_TOKEN": "o",
                   "ANTHROPIC_IDENTITY_TOKEN_FILE": "/tmp/jwt", "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_x",
                   "ANTHROPIC_ORGANIZATION_ID": "o", "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_x",
                   "ANTHROPIC_WORKSPACE_ID": "wrkspc_x", "ANTHROPIC_SCOPE": "workspace:inference",
                   "CLAUDE_CODE_ENABLE_TELEMETRY": "1", "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "1000",
                   "ANTHROPIC_BASE_URL": f"https://{HOST}"}
        code, err, _ = self.run_agent([init()] + turn(1) + [result()], **allowed)
        self.assertEqual(code, 0, err)

    def gone(self, pid):
        """Whether the process `pid` has ended (and been reaped), waiting up to 10 seconds."""
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.1)
        return False

    def test_a_stopped_agent_s_own_processes_are_stopped_too(self):
        """A process the agent started holds the stream open after the agent ends: it is stopped with the agent."""
        events = [init(), {"child": 600}] + turn(1, "other-b-1") + [{"sleep": 600}]
        code, err, seconds = self.run_agent(events)
        self.assertEqual(code, 4, err)
        self.assertLess(seconds, 60)
        with open(os.path.join(self.dir, "pids")) as f:
            pids = [int(p) for p in f.read().split()]
        self.assertEqual(len(pids), 2)
        for pid in pids:
            self.assertTrue(self.gone(pid), f"process {pid} still runs")

    def test_a_stop_of_the_script_stops_the_agent(self):
        """The step's timeout or a cancelled run stops review-served with SIGTERM: the agent goes with it."""
        agent = self.agent("agent", [init(), {"child": 600}] + turn(1) + [{"sleep": 600}])
        served = subprocess.Popen([sys.executable, SERVED, "run", self.review, ASKED, "--", agent],
                                  env=environment(HOME=self.dir), cwd=self.dir, stderr=subprocess.DEVNULL)
        self.addCleanup(served.kill)
        for _ in range(100):
            if os.path.exists(os.path.join(self.review, "claude.jsonl")) and "msg_0001" in self.read("claude.jsonl"):
                break
            time.sleep(0.1)
        served.terminate()
        self.assertEqual(served.wait(timeout=60), 143)
        # What answered until the stop is recorded.
        self.assertEqual(self.read("served"), f"{HEAD}none/model-a-1 1\n")
        with open(os.path.join(self.dir, "pids")) as f:
            for pid in map(int, f.read().split()):
                self.assertTrue(self.gone(pid), f"process {pid} still runs")


class Check(unittest.TestCase):
    def test_a_record_with_no_asked_line_is_not_attributable(self):
        self.assertEqual(check("firstParty/model-a-1 3\n")[0], 3)
        self.assertEqual(check("")[0], 3)

    def test_a_line_that_is_not_one_is_not_attributable(self):
        self.assertEqual(check(f"{HEAD}firstParty/model-a-1 three\n")[0], 3)

    def test_a_line_of_no_turns_is_not_attributable(self):
        """run never writes a count of 0, so only a hand-written or damaged record holds one: no turn is no evidence,
        whatever the other lines say."""
        for record in (f"{HEAD}firstParty/model-a-1 0\n",
                       f"{HEAD}usage firstParty/model-a-1\nfirstParty/model-a-1 0\n",
                       f"{HEAD}firstParty/model-a-1 3\nfirstParty/model-a-1 0\n",
                       f"{HEAD}firstParty/model-a-1 00\n"):
            with self.subTest(record=record):
                self.assertEqual(check(record)[0], 3)

    def test_another_model_of_the_same_family_is_another_model(self):
        """The review asked for one model: another of its family (a fallback model, say) is another."""
        for record in (f"{HEAD}firstParty/model-a-1 3\nfirstParty/model-b-2 1\n",
                       f"{HEAD}usage firstParty/model-b-2\nfirstParty/model-a-1 3\n",
                       f"{HEAD}firstParty/model-a-1-x 3\n", f"{HEAD}firstParty/modelx-a-1 3\n",
                       f"{HEAD}firstParty/model-a-1-2025010 3\n"):
            with self.subTest(record=record):
                self.assertEqual(check(record)[0], 1)

    def test_a_dated_snapshot_of_the_model_is_the_model(self):
        self.assertEqual(check(f"{HEAD}usage firstParty/model-a-1\nfirstParty/model-a-1-20251001 3\n"),
                         (0, "firstParty/model-a-1-20251001 (3 turns)"))

    def test_a_usage_entry_that_names_no_model_is_not_attributable(self):
        self.assertEqual(check(f"{HEAD}usage firstParty/none\nfirstParty/model-a-1 3\n")[0], 3)

    def test_a_record_with_no_usage_line_is_not_attributable(self):
        """run writes a usage line for each entry of the tool's .modelUsage; with none, nothing names the provider."""
        code, line = check(f"{HEAD}firstParty/model-a-1 3\n")
        self.assertEqual(code, 3, line)
        self.assertIn("the tool's usage names nothing", line)

    def test_a_count_of_digits_that_are_not_ascii_is_not_attributable_and_no_crash(self):
        """str.isdigit takes "²" for a digit and int() does not: that once crashed check with exit 1, which is the
        exit of another provider."""
        code, line = check(f"asked {ASKED}\nfirstParty/model-a-1 ²\n")
        self.assertEqual(code, 3, line)
        self.assertIn("a line of the record of what answered the review is not one", line)

    def test_a_record_that_names_another_endpoint_is_another_provider(self):
        code, line = check(f"asked {ASKED}\nendpoint https:proxy.example\nfirstParty/model-a-1 3\n")
        self.assertEqual(code, 1, line)
        self.assertIn(f"whose API is {HOST}, but the tool's environment or settings set https:proxy.example, which can "
                      "send its requests elsewhere or let another model answer, and firstParty/model-a-1 (3 turns) "
                      "answered", line)
        self.assertEqual(check(f"{HEAD}endpoint https:proxy.example\nfirstParty/model-a-1 3\n")[0], 1)

    def test_a_record_that_names_no_endpoint_is_not_attributable(self):
        code, line = check(f"asked {ASKED}\nusage firstParty/model-a-1\nfirstParty/model-a-1 3\n")
        self.assertEqual(code, 3, line)
        self.assertIn("nothing recorded where the tool sent its requests", line)


if __name__ == "__main__":
    unittest.main()
