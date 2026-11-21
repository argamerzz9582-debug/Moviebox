import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from rex.detectors.target_detector import detect_target  # noqa: E402
from rex.minecraft.analyzer import inspect_minecraft_artifact  # noqa: E402


class TestDetectionAndMinecraft(unittest.TestCase):
    def test_detect_elf_and_gguf_and_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            elf = d / "sample.bin"
            elf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HH", 2, 0x3E) + b"\x00" * 44)
            cls_elf = detect_target(str(elf))
            self.assertEqual(cls_elf.primary_type, "elf_binary")
            self.assertIn("x86_64", cls_elf.architecture)

            gguf = d / "model.dat"
            gguf.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 12, 5) + b"\x00" * 32)
            cls_gguf = detect_target(str(gguf))
            self.assertEqual(cls_gguf.primary_type, "ai_model_gguf")

            unk = d / "mystery.dat"
            unk.write_bytes(bytes(range(256)))
            cls_unk = detect_target(str(unk))
            self.assertEqual(cls_unk.primary_type, "unknown_binary")
            self.assertEqual(cls_unk.confidence, "Unverified")

    def test_minecraft_bukkit_plugin_and_fabric_mod(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            # 1. Spigot/Paper plugin JAR
            plugin_jar = d / "ZyroxCore.jar"
            with zipfile.ZipFile(plugin_jar, "w") as zf:
                zf.writestr(
                    "plugin.yml",
                    "name: ZyroxCore\nversion: 1.2.0\nmain: dev.zyrox.core.ZyroxPlugin\napi-version: '1.21'\n"
                    "depend: [Vault]\n"
                    "commands:\n  zyrox:\n    description: Main command\n    permission: zyrox.admin\n"
                    "permissions:\n  zyrox.admin:\n    default: op\n",
                )
                zf.writestr("dev/zyrox/core/ZyroxPlugin.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41org/bukkit/event/EventHandler")

            cls = detect_target(str(plugin_jar))
            self.assertEqual(cls.primary_type, "minecraft_bukkit_plugin")
            self.assertIn("rex-minecraft", cls.recommended_skills)

            mc = inspect_minecraft_artifact(plugin_jar)
            self.assertEqual(mc["metadata"]["name"], "ZyroxCore")
            self.assertEqual(mc["metadata"]["main"], "dev.zyrox.core.ZyroxPlugin")
            self.assertEqual(mc["commands"][0]["command"], "zyrox")
            self.assertEqual(mc["permissions"][0]["permission"], "zyrox.admin")
            self.assertIn("dev.zyrox.core.ZyroxPlugin", mc["metadata"]["detected_event_listeners"])

            # 2. Fabric mod JAR
            mod_jar = d / "nexa-hud.jar"
            with zipfile.ZipFile(mod_jar, "w") as zf:
                zf.writestr(
                    "fabric.mod.json",
                    json.dumps({
                        "id": "nexahud",
                        "name": "NexaHUD",
                        "version": "2.0.0",
                        "environment": "client",
                        "entrypoints": {"client": ["dev.nexa.hud.NexaHudClient"]},
                        "mixins": ["nexahud.mixins.json"],
                        "depends": {"fabricloader": ">=0.16.0", "minecraft": "~1.21.4"},
                    }),
                )
                zf.writestr("nexahud.mixins.json", json.dumps({"package": "dev.nexa.hud.mixin", "client": ["InGameHudMixin"]}))

            cls_mod = detect_target(str(mod_jar))
            self.assertEqual(cls_mod.primary_type, "minecraft_fabric_mod")
            mc_mod = inspect_minecraft_artifact(mod_jar)
            self.assertEqual(mc_mod["metadata"]["id"], "nexahud")
            self.assertIn("dev.nexa.hud.mixin.InGameHudMixin", mc_mod["mixins"])


if __name__ == "__main__":
    unittest.main()
