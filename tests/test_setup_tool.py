from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import launcher
import setup_openrsc
from openrsc.config import build_config, load_config, verify_password, write_config


class SetupSettingsTests(unittest.TestCase):
    def test_settings_round_trip_keeps_every_setup_toggle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "setup.json"
            root = Path(directory) / "workspace"
            root.mkdir()
            settings = setup_openrsc.SetupSettings(
                port=9123,
                tunnel_enabled=False,
                hostname="",
                tunnel_name="office pc",
                recovery_enabled=False,
                startup_enabled=True,
                open_browser=False,
                roots=[str(root)],
                max_terminals=12,
                terminal_idle_hours=24,
                session_hours=12,
            ).validate()
            setup_openrsc.save_settings(settings, target)
            restored = setup_openrsc.detected_settings(settings_path=target, config_path=Path(directory) / "missing.json")
            self.assertEqual(restored.to_mapping(), settings.to_mapping())
            self.assertEqual(restored.tunnel_name, "openrsc-office-pc")

    def test_validation_rejects_invalid_runtime_limits(self) -> None:
        with self.assertRaises(setup_openrsc.SetupError):
            setup_openrsc.SetupSettings(port=0).validate(require_roots=False)
        with self.assertRaises(setup_openrsc.SetupError):
            setup_openrsc.SetupSettings(max_terminals=17).validate(require_roots=False)
        with self.assertRaises(setup_openrsc.SetupError):
            setup_openrsc.SetupSettings(session_hours=0).validate(require_roots=False)


class SetupApplicationTests(unittest.TestCase):
    def test_apply_updates_runtime_config_without_rotating_existing_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            root.mkdir()
            config_path = base / "openrsc.json"
            original = build_config("original-password-for-tests", roots=[str(root)], port=8787)
            write_config(config_path, original)
            settings = setup_openrsc.SetupSettings(
                port=9001,
                tunnel_enabled=False,
                roots=[str(root)],
                max_terminals=10,
                terminal_idle_hours=18,
                session_hours=14,
            )
            setup_openrsc.apply_openrsc_config(settings, config_path=config_path)
            changed = load_config(config_path)
            self.assertEqual((changed.port, changed.files["roots"]), (9001, [str(root)]))
            self.assertEqual(changed.terminal["max_sessions"], 10)
            self.assertEqual(changed.terminal["idle_seconds"], 18 * 3600)
            self.assertEqual(changed.security["session_ttl_seconds"], 14 * 3600)
            self.assertEqual(changed.raw["security"]["session_secret"], original["security"]["session_secret"])
            self.assertTrue(verify_password("original-password-for-tests", changed.security["password"]))

    def test_apply_can_create_config_and_manage_startup_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "Open RSC"
            project.mkdir()
            root = base / "root"
            root.mkdir()
            config_path = project / "config" / "openrsc.json"
            settings_path = project / "config" / "setup.json"
            data_path = project / "data"
            environment = {"APPDATA": str(base / "AppData")}
            settings = setup_openrsc.SetupSettings(
                port=9444,
                tunnel_enabled=False,
                recovery_enabled=True,
                startup_enabled=True,
                open_browser=False,
                roots=[str(root)],
            )
            result = setup_openrsc.apply_all(
                settings,
                password="fresh-password-for-tests",
                settings_path=settings_path,
                config_path=config_path,
                data_path=data_path,
                environment=environment,
                python_executable=base / "Python" / "python.exe",
            )
            self.assertTrue(result["config"].is_file())
            self.assertTrue(result["settings"].is_file())
            self.assertTrue(result["startup"].is_file())
            payload = result["startup"].read_text(encoding="utf-16")
            self.assertIn("--supervise", payload)
            self.assertIn("--no-tunnel", payload)
            self.assertIn("9444", payload)
            settings.startup_enabled = False
            setup_openrsc.apply_startup(settings, environment=environment, data_path=data_path)
            self.assertFalse(result["startup"].exists())

    def test_launch_command_maps_tunnel_and_recovery_choices(self) -> None:
        settings = setup_openrsc.SetupSettings(
            port=9555,
            tunnel_enabled=False,
            recovery_enabled=True,
            roots=[str(Path.cwd())],
        )
        command = setup_openrsc.build_launch_command(settings, python_executable="python-test")
        self.assertEqual(command[0], "python-test")
        self.assertIn("--supervise", command)
        self.assertIn("--no-tunnel", command)
        self.assertIn("--no-startup-prompt", command)
        settings.recovery_enabled = False
        direct = setup_openrsc.build_launch_command(settings, python_executable="python-test")
        self.assertNotIn("--supervise", direct)

    def test_startup_payload_supports_start_without_supervision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = launcher.startup_payload(
                project=root,
                python_executable=root / "python.exe",
                config=root / "config.json",
                data=root / "data",
                supervise=False,
            )
            self.assertNotIn("--supervise", payload)
            self.assertIn("--no-browser", payload)


if __name__ == "__main__":
    unittest.main()
