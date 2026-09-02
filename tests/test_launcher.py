from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

import launcher
from openrsc import __main__ as openrsc_main


TUNNEL_ID = "4ebad8db-43f9-4ce7-8ddf-aa56b89b3cab"


class LauncherValidationTests(unittest.TestCase):
    def test_windows_release_asset_and_published_checksum(self) -> None:
        self.assertEqual(
            launcher.cloudflared_asset_name("Windows", "AMD64"),
            "cloudflared-windows-amd64.exe",
        )
        digest = "ab" * 32
        body = "notes\ncloudflared-windows-amd64.exe: %s\n" % digest
        self.assertEqual(
            launcher.extract_release_checksum(body, "cloudflared-windows-amd64.exe"), digest
        )
        with self.assertRaises(launcher.LauncherError):
            launcher.extract_release_checksum("no checksum", "cloudflared-windows-amd64.exe")

    def test_hostname_and_tunnel_name_validation(self) -> None:
        self.assertEqual(launcher.validate_hostname("Panel.Example.COM."), "panel.example.com")
        self.assertEqual(launcher.sanitize_tunnel_name("OFFICE PC #4"), "openrsc-office-pc-4")
        self.assertEqual(launcher.sanitize_tunnel_name("openrsc-office"), "openrsc-office")
        for invalid in ("https://example.com", "example.com:443", "*.example.com", "localhost"):
            with self.subTest(invalid=invalid), self.assertRaises(launcher.LauncherError):
                launcher.validate_hostname(invalid)

    def test_generated_config_is_complete_and_quotes_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credential = root / "credentials" / (TUNNEL_ID + ".json")
            certificate = root / "cert.pem"
            config = root / "config.yml"
            credential.parent.mkdir()
            credential.write_text("{}", encoding="utf-8")
            certificate.write_text("cert", encoding="ascii")
            payload = launcher.write_cloudflared_config(
                config, TUNNEL_ID, credential, "panel.example.com", 9123, certificate
            )
            self.assertEqual(payload, config.read_text(encoding="utf-8"))
            self.assertIn('tunnel: "%s"' % TUNNEL_ID, payload)
            self.assertIn('hostname: "panel.example.com"', payload)
            self.assertIn('service: "http://127.0.0.1:9123"', payload)
            self.assertIn('service: "http_status:404"', payload)
            self.assertIn(json.dumps(str(credential.resolve())), payload)

    def test_startup_payload_is_hidden_and_uses_stable_supervisor_flags(self) -> None:
        with tempfile.TemporaryDirectory(prefix="Open RSC ") as directory:
            root = Path(directory)
            payload = launcher.startup_payload(
                project=root,
                python_executable=root / "Python 3" / "python.exe",
                config=root / "config" / "open rsc.json",
                data=root / "runtime data",
                port=9123,
            )
        self.assertIn('shell.Run "', payload)
        self.assertIn('", 0, False', payload)
        self.assertIn("--supervise", payload)
        self.assertIn("--no-elevate", payload)
        self.assertIn("--no-browser", payload)
        self.assertIn("--no-startup-prompt", payload)
        self.assertIn("9123", payload)
        self.assertNotIn("--reauth-cloudflare", payload)

    def test_recovery_tracker_waits_offline_then_restarts_after_grace(self) -> None:
        tracker = launcher.RecoveryTracker(failure_limit=3, recovery_grace=20, restart_cooldown=300)
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=False, now=0),
            "offline",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=False, now=10),
            "offline",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=True, now=30),
            "network-restored",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=True, now=40),
            "recovery-grace",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=True, now=50),
            "public-retry",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=True, now=60),
            "public-retry",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=False, internet_ok=True, now=70),
            "restart-public",
        )
        self.assertEqual(
            tracker.observe(local_ok=True, public_ok=True, internet_ok=True, now=80),
            "healthy",
        )

    def test_recovery_tracker_restarts_after_three_local_failures(self) -> None:
        tracker = launcher.RecoveryTracker(failure_limit=3)
        self.assertEqual(tracker.observe(local_ok=False, now=0), "local-retry")
        self.assertEqual(tracker.observe(local_ok=False, now=1), "local-retry")
        self.assertEqual(tracker.observe(local_ok=False, now=2), "restart-local")

    def test_startup_install_and_remove_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = {"APPDATA": str(root / "App Data")}
            args = launcher.build_parser().parse_args(
                [
                    "--config", str(root / "config.json"),
                    "--data", str(root / "data"),
                    "--port", "8787",
                ]
            )
            entry = launcher.install_startup(
                args,
                environment=environment,
                python_executable=root / "Python" / "python.exe",
            )
            self.assertTrue(entry.is_file())
            first = entry.read_text(encoding="utf-16")
            self.assertEqual(
                launcher.install_startup(
                    args,
                    environment=environment,
                    python_executable=root / "Python" / "python.exe",
                ),
                entry,
            )
            self.assertEqual(first, entry.read_text(encoding="utf-16"))
            launcher.remove_startup(args, environment=environment)
            launcher.remove_startup(args, environment=environment)
            self.assertFalse(entry.exists())

    @unittest.skipUnless(os.name == "nt", "startup prompt is Windows-only")
    def test_declined_startup_prompt_is_recorded_and_not_asked_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = launcher.build_parser().parse_args(["--data", str(root / "data")])
            entry = root / "Startup" / launcher.STARTUP_ENTRY_NAME
            with mock.patch.object(launcher, "startup_entry_path", return_value=entry):
                launcher.maybe_prompt_startup(args, input_function=lambda _prompt: "n", is_tty=True)
                self.assertTrue((root / "data" / launcher.STARTUP_CHOICE_NAME).is_file())
                launcher.maybe_prompt_startup(
                    args,
                    input_function=lambda _prompt: self.fail("prompt repeated"),
                    is_tty=True,
                )


class LauncherStateTests(unittest.TestCase):
    def _constant_patches(self, root: Path):
        return mock.patch.multiple(
            launcher,
            CLOUDFLARE=root,
            CLOUDFLARED=root / "bin" / ("cloudflared.exe" if os.name == "nt" else "cloudflared"),
            CERT_FILE=root / "cert.pem",
            CONFIG_FILE=root / "config.yml",
            STATE_FILE=root / "state.json",
            RELEASE_FILE=root / "bin" / "release.json",
            PROFILE_DIR=root / "profile",
            CREDENTIALS_DIR=root / "credentials",
        )

    def test_existing_local_state_is_detected_and_origin_port_is_updated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cloudflare"
            credential = root / "credentials" / (TUNNEL_ID + ".json")
            credential.parent.mkdir(parents=True)
            credential.write_text(json.dumps({"TunnelID": TUNNEL_ID}), encoding="utf-8")
            (root / "config.yml").write_text("old\n", encoding="utf-8")
            (root / "state.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "tunnel_id": TUNNEL_ID,
                        "tunnel_name": "openrsc-office",
                        "hostname": "panel.example.com",
                        "origin_port": 8787,
                        "credentials_file": "credentials/%s.json" % TUNNEL_ID,
                        "config_file": "config.yml",
                    }
                ),
                encoding="utf-8",
            )
            with self._constant_patches(root):
                state = launcher.load_cloudflare_state(port=9001)
            self.assertIsNotNone(state)
            self.assertEqual(state["origin_port"], 9001)
            self.assertIn("http://127.0.0.1:9001", (root / "config.yml").read_text(encoding="utf-8"))
            persisted = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertNotIn("credential_path", persisted)

    def test_first_setup_writes_only_project_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "OpenRSC" / "cloudflare"
            credential = root / "credentials" / (TUNNEL_ID + ".json")
            credential.parent.mkdir(parents=True)
            credential.write_text(json.dumps({"TunnelID": TUNNEL_ID}), encoding="utf-8")
            with self._constant_patches(root), mock.patch.object(
                launcher, "_ensure_origin_certificate"
            ) as login, mock.patch.object(
                launcher, "selected_zone_name", return_value="example.com"
            ), mock.patch.object(
                launcher, "_ensure_tunnel", return_value=(TUNNEL_ID, credential)
            ), mock.patch.object(launcher, "_route_dns") as route:
                state = launcher.setup_cloudflare(
                    hostname="panel.example.com", tunnel_name="office", port=8787
                )
            login.assert_called_once_with(force_login=False)
            route.assert_called_once_with(TUNNEL_ID, "panel.example.com", overwrite=False)
            self.assertEqual(state["hostname"], "panel.example.com")
            self.assertTrue((root / "config.yml").is_file())
            persisted = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["credentials_file"], "credentials/%s.json" % TUNNEL_ID)
            self.assertFalse(Path(directory, ".cloudflared").exists())

    def test_cloudflared_management_process_receives_isolated_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cloudflare"
            with self._constant_patches(root), mock.patch.object(
                launcher.subprocess, "run", return_value=mock.Mock(returncode=0)
            ) as run:
                launcher._run_cloudflared(["tunnel", "--help"], check=True)
            environment = run.call_args.kwargs["env"]
            self.assertEqual(environment["HOME"], str((root / "profile").resolve()))
            self.assertEqual(environment["USERPROFILE"], str((root / "profile").resolve()))
            self.assertNotIn("TUNNEL_ORIGIN_CERT", environment)

    def test_empty_cloudflare_tunnel_list_can_be_reported_as_json_null(self) -> None:
        response = mock.Mock(stdout="null\n")
        with mock.patch.object(launcher, "_run_cloudflared", return_value=response):
            self.assertIsNone(launcher._find_named_tunnel("openrsc-office"))

    @unittest.skipUnless(os.name == "nt", "Authenticode is a Windows check")
    def test_authenticode_check_uses_only_windows_powershell_modules(self) -> None:
        response = mock.Mock(
            returncode=0,
            stdout=json.dumps({"Status": "Valid", "Subject": "CN=Cloudflare, Inc."}),
            stderr="",
        )
        with mock.patch.object(launcher.shutil, "which", return_value="powershell.exe"), mock.patch.object(
            launcher.subprocess, "run", return_value=response
        ) as run:
            subject = launcher.verify_authenticode(Path("cloudflared.exe"))
        self.assertEqual(subject, "CN=Cloudflare, Inc.")
        environment = run.call_args.kwargs["env"]
        expected = str(
            Path(environment.get("SystemRoot") or environment.get("WINDIR") or r"C:\Windows")
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "Modules"
        )
        self.assertEqual(environment["PSModulePath"], expected)


class OpenRSCNamedTunnelTests(unittest.TestCase):
    def test_named_tunnel_process_uses_explicit_binary_config_and_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            config = root / "config.yml"
            executable.write_bytes(b"fixture")
            config.write_text("tunnel: fixture\n", encoding="utf-8")
            process = mock.Mock(stdout=None)
            with mock.patch.object(openrsc_main.subprocess, "Popen", return_value=process) as popen:
                returned = openrsc_main._start_tunnel(
                    8787,
                    executable_path=executable,
                    config_file=config,
                    tunnel_id=TUNNEL_ID,
                )
            self.assertIs(returned, process)
            command = popen.call_args.args[0]
            self.assertEqual(
                command,
                [
                    str(executable.resolve()),
                    "tunnel",
                    "--no-autoupdate",
                    "--config",
                    str(config.resolve()),
                    "run",
                    TUNNEL_ID,
                ],
            )

    def test_tunnel_supervisor_respawns_exited_connector_and_stops_replacement(self) -> None:
        class FakeProcess:
            def __init__(self, pid: int, exit_code=None):
                self.pid = pid
                self.exit_code = exit_code
                self.terminated = False

            def poll(self):
                return self.exit_code

            def terminate(self):
                self.terminated = True
                self.exit_code = 0

            def wait(self, timeout=None):
                return self.exit_code

            def kill(self):
                self.terminate()

        first = FakeProcess(101, exit_code=7)
        second = FakeProcess(102)
        processes = [first, second]
        calls = []

        def starter():
            process = processes[min(len(calls), len(processes) - 1)]
            calls.append(process.pid)
            return process

        supervisor = openrsc_main.TunnelSupervisor(
            starter,
            check_interval=0.005,
            minimum_backoff=0.005,
            maximum_backoff=0.01,
        )
        supervisor.start()
        deadline = time.monotonic() + 1
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        supervisor.stop()
        self.assertEqual(calls[:2], [101, 102])
        self.assertTrue(second.terminated)
        time.sleep(0.02)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
