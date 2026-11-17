import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import threading
import unittest

SPEC = importlib.util.spec_from_file_location("mail_deploy_guard", Path(__file__).with_name("deploy-guard.py"))
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class DeploymentGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mail-deploy-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = self.root / "mail.env"
        self.set_env("true")
        self.old, self.new = b"owned old binary", b"owned new binary"
        (self.root / "mail-server").write_bytes(self.old)
        self.key = "a" * 24
        self.next = self.root / ("mail-server.next-" + self.key)
        self.next.write_bytes(self.new)
        self.live = {"status": "ok", "version": "123abcd", "access_enforced": True}
        self.live_path = self.root / "health.json"
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                value = json.loads(fixture.live_path.read_text()) if fixture.live_path.exists() else fixture.live
                self.wfile.write(json.dumps(value).encode())

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:%s/healthz" % self.server.server_port

    def set_env(self, flag):
        self.env.write_text("MAIL_ID_CLIENT_SECRET=eval-owned-credential\nMAIL_ID_ACCESS_ENABLED=" + flag + "\n")
        self.env.chmod(0o600)

    def capture(self):
        return guard.capture(self.root, self.env, self.url, self.key, "456abcd", hashlib.sha256(self.new).hexdigest())

    def test_activation_and_rollback_retain_enforcement_and_secret_file(self):
        before = self.env.read_bytes()
        record = self.capture()
        state = self.root / (".deploy-" + self.key + ".json")
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("eval-owned-credential", state.read_text())
        guard.activate(self.root, self.env, record)
        self.live["version"] = "456abcd"
        guard.verify(self.env, self.url, record)
        self.assertTrue(guard.rollback(self.root, self.env, record))
        self.live["version"] = "123abcd"
        guard.verify(self.env, self.url, record, previous=True)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.old)
        self.assertEqual(before, self.env.read_bytes())
        self.assertFalse(guard.rollback(self.root, self.env, record))

    def test_wrong_version_or_mode_never_passes_health(self):
        record = self.capture()
        with self.assertRaises(guard.GuardError):
            guard.verify(self.env, self.url, record)
        self.live.update(version="456abcd", access_enforced=False)
        with self.assertRaises(guard.GuardError):
            guard.verify(self.env, self.url, record)
        del self.live["access_enforced"]
        with self.assertRaises(guard.GuardError):
            guard.verify(self.env, self.url, record)

    def test_legacy_can_only_be_captured_with_enforcement_off(self):
        self.live = {"status": "ok"}
        with self.assertRaises(guard.GuardError):
            self.capture()
        self.set_env("false")
        record = self.capture()
        guard.verify(self.env, self.url, record, previous=True)
        self.assertFalse(record["access_enforced"])
        with self.assertRaises(guard.GuardError):
            guard.verify(self.env, self.url, record)

    def test_config_drift_blocks_activation_and_rollback(self):
        record = self.capture()
        self.set_env("false")
        with self.assertRaises(guard.GuardError):
            guard.activate(self.root, self.env, record)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.old)
        self.set_env("true")
        guard.activate(self.root, self.env, record)
        self.set_env("false")
        with self.assertRaises(guard.GuardError):
            guard.rollback(self.root, self.env, record)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.new)

    def test_concurrent_or_corrupt_binary_is_preserved(self):
        record = self.capture()
        self.next.write_bytes(b"bad upload")
        with self.assertRaises(guard.GuardError):
            guard.activate(self.root, self.env, record)
        self.next.write_bytes(self.new)
        guard.activate(self.root, self.env, record)
        (self.root / "mail-server").write_bytes(b"other deployment")
        with self.assertRaises(guard.GuardError):
            guard.rollback(self.root, self.env, record)
        self.assertEqual((self.root / "mail-server").read_bytes(), b"other deployment")

    def test_configuration_is_literal_private_and_unambiguous(self):
        for flag in ["TRUE", "yes", "$(echo true)", "'true false'", "true\nMAIL_ID_ACCESS_ENABLED=false"]:
            self.set_env(flag)
            with self.assertRaises(guard.GuardError):
                guard.configuration(self.env)
        self.set_env("'true' # owned comment")
        self.assertTrue(guard.configuration(self.env)[1])
        self.env.chmod(0o644)
        with self.assertRaises(guard.GuardError):
            guard.configuration(self.env)
        self.env.unlink()
        target = self.root / "other.env"
        target.write_text("MAIL_ID_ACCESS_ENABLED=true\n")
        self.env.symlink_to(target)
        with self.assertRaises(guard.GuardError):
            guard.configuration(self.env)

    def test_actual_cli_capture_activation_health_and_rollback(self):
        command = ["python3", str(Path(__file__).with_name("deploy-guard.py")), "--root", str(self.root), "--env-file", str(self.env), "--health-url", self.url, "--key", self.key]

        def run(action, *args):
            result = subprocess.run(command + [action, *args], capture_output=True, text=True, timeout=5)
            self.assertNotIn("eval-owned-credential", result.stdout + result.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)

        run("capture", "--version", "456abcd", "--digest", hashlib.sha256(self.new).hexdigest())
        run("activate")
        self.live["version"] = "456abcd"
        run("verify")
        run("rollback")
        self.live["version"] = "123abcd"
        run("verify-previous")

    def run_driver(self, failure=""):
        # Execute the actual deploy.sh, including its ERR trap, against an owned
        # SSH/SCP/service fixture. These executables cannot reach a remote host.
        local = self.root / "checkout"
        scripts, web, fake = local / "scripts", local / "web", self.root / "fake-bin"
        for path in (scripts, web, fake):
            path.mkdir(parents=True)
        for name in ("deploy.sh", "deploy-guard.py"):
            shutil.copy2(Path(__file__).with_name(name), scripts / name)
        (scripts / "test-owned-mongo.sh").write_text('#!/bin/bash\n"$@"\n')
        (scripts / "test_deploy_guard.py").write_text("import unittest\nclass OwnedBuildGate(unittest.TestCase):\n def test_gate(self): self.assertTrue(True)\n")
        (scripts / "check-sync-parity.py").write_text("raise SystemExit(1)\n")
        self.live_path.write_text(json.dumps(self.live))
        version = secrets.token_hex(4)
        common = '#!/usr/bin/env python3\nimport json,os,pathlib,subprocess,sys,shutil\nr=pathlib.Path(os.environ["EVAL_DEPLOY_ROOT"])\n'
        programs = {
            "git": 'a=sys.argv[1:]\nif a==["branch","--show-current"]:print("main")\nelif a[:1]==["rev-parse"]:print(os.environ["EVAL_DEPLOY_VERSION"])\n',
            "go": 'a=sys.argv[1:]\nif "-o" in a:pathlib.Path(a[a.index("-o")+1]).write_bytes(b"owned new binary")\n',
            "npm": 'pass\n',
            "sleep": 'pass\n',
            "ss": 'print("ESTAB mail-server :993")\n',
            "curl": 'print("{}")\n',
            "scp": 'source,dest=sys.argv[1:]\ndest=dest.removeprefix("oracle-vm:").replace("/home/snowbear/ci/mail",str(r))\nshutil.copy2(source,dest)\n',
            "ssh": '''a=sys.argv[2:]
body=sys.stdin.read()
def replace(v):
 return v.replace("/home/snowbear/.config/smdctl/env/mail.env",str(r/"mail.env")).replace("/home/snowbear/ci/mail",str(r))
if a[:2]==["python3","-"]:
 a=[replace(v) for v in a]+["--health-url",os.environ["EVAL_DEPLOY_HEALTH"]]
else:
 body=replace(body).replace("--env-file "+str(r/"mail.env"),"--env-file "+str(r/"mail.env")+" --health-url "+os.environ["EVAL_DEPLOY_HEALTH"])
result=subprocess.run(a,input=body,text=True)
raise SystemExit(result.returncode)
''',
            "smdctl": '''if sys.argv[1]=="status":print("Status:  active (running)")
elif sys.argv[1]=="restart":
 new=(r/"mail-server").read_bytes()==b"owned new binary"
 failure=os.environ.get("EVAL_DEPLOY_FAILURE")
 if new and failure=="restart":raise SystemExit(1)
 health={"status":"ok","version":os.environ["EVAL_DEPLOY_VERSION"] if new else "123abcd","access_enforced":not(new and failure=="mode")}
 (r/"health.json").write_text(json.dumps(health))
''',
        }
        for name, body in programs.items():
            target = fake / name
            target.write_text(common + body)
            target.chmod(0o755)
        env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ["PATH"], EVAL_DEPLOY_ROOT=str(self.root), EVAL_DEPLOY_VERSION=version, EVAL_DEPLOY_HEALTH=self.url, EVAL_DEPLOY_FAILURE=failure, MAIL_DEPLOY_SKIP_PARITY="0" if failure == "parity" else "1", ICLOUD_EMAIL="eval@example.test", ICLOUD_PASSWORD="eval-owned-password")
        self.addCleanup(lambda: Path("/tmp/mail-server-" + version).unlink(missing_ok=True))
        result = subprocess.run(["bash", str(scripts / "deploy.sh")], cwd=local, env=env, capture_output=True, text=True, timeout=15)
        self.assertNotIn("eval-owned-credential", result.stdout + result.stderr)
        self.assertNotIn("eval-owned-password", result.stdout + result.stderr)
        return result

    def test_actual_driver_succeeds_with_mode_preserved(self):
        result = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.new)
        self.assertTrue(json.loads(self.live_path.read_text())["access_enforced"])

    def test_actual_driver_rolls_back_failed_restart(self):
        result = self.run_driver("restart")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.old)
        self.assertEqual(len(list(self.root.glob("mail-server.failed-*"))), 1)
        self.assertTrue(json.loads(self.live_path.read_text())["access_enforced"])

    def test_actual_driver_rolls_back_wrong_enforcement(self):
        result = self.run_driver("mode")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.old)
        self.assertEqual(len(list(self.root.glob("mail-server.failed-*"))), 1)
        self.assertTrue(json.loads(self.live_path.read_text())["access_enforced"])

    def test_actual_driver_rolls_back_exhausted_parity(self):
        result = self.run_driver("parity")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "mail-server").read_bytes(), self.old)
        self.assertEqual(len(list(self.root.glob("mail-server.failed-*"))), 1)
        self.assertTrue(json.loads(self.live_path.read_text())["access_enforced"])


if __name__ == "__main__":
    unittest.main()
