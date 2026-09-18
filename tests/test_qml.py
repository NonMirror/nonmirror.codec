"""Exercise the actual Quickshell stdin bridge without opening a desktop UI."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("quickshell"), "Quickshell is needed for the QML integration test")
class QmlTests(unittest.TestCase):
    def test_bridge_reuse_limits_and_cancellation(self):
        with tempfile.TemporaryDirectory(prefix="codec-qml-") as directory:
            tmp = Path(directory)
            for name in ("BoundedProcess.qml", "Codec.qml", "Algorithms.js", "codec_runner.py"):
                (tmp / name).symlink_to(ROOT / name)
            # qs imports resolve relative to the test's config root.
            stock = Path("/usr/share/omarchy/shell")
            if stock.exists():
                for source in stock.iterdir():
                    if source.is_dir() and not (tmp / source.name).exists():
                        (tmp / source.name).symlink_to(source, target_is_directory=True)
            (tmp / "shell.qml").write_text('''import Quickshell
import QtQuick
ShellRoot {
  id: root
  property int count: 0
  function check(value, message) {
    if (!value) { console.error("TEST_FAILED", message); Qt.quit(); return false }
    return true
  }
  BoundedProcess {
    id: p
    onCompleted: function(ok, data, message) {
      if (root.count === 2) {
        if (!root.check(!ok && data === "", "Cancelled result was published")) return
        console.log("QML_SECURITY_PASS")
        Qt.quit()
        return
      }
      if (!root.check(ok && data === "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=", message)) return
      root.count++
      if (root.count === 2) {
        Qt.callLater(function() {
          p.start('{"id":"sha256","data":"aGVsbG8=","params":{}}')
          p.cancel("Test cancellation")
        })
      } else {
        Qt.callLater(function() { p.start('{"id":"sha256","data":"aGVsbG8=","params":{}}') })
      }
    }
  }
  BoundedProcess { id: collector }
  Component.onCompleted: {
    collector.busy = true
    collector.collect("A".repeat(349528), false)
    if (!root.check(collector.output.length === 349528, "Exact limit rejected")) return
    collector.collect("A", false)
    if (!root.check(collector.output === "" && collector.rejection !== "", "Overflow appended")) return
    collector.rejection = ""
    collector.collect("E".repeat(4097), true)
    if (!root.check(collector.errorOutput === "" && collector.rejection !== "", "stderr overflow appended")) return
    collector.busy = false
    p.start('{"id":"sha256","data":"aGVsbG8=","params":{}}')
  }
  Timer { interval: 15000; running: true; onTriggered: { console.error("TEST_FAILED timeout"); Qt.quit() } }
}
''')
            result = subprocess.run(["quickshell", "--no-color", "-p", str(tmp / "shell.qml")],
                                    env=dict(os.environ, QT_QPA_PLATFORM="offscreen"),
                                    capture_output=True, text=True, timeout=20)
            log = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, log)
            self.assertIn("QML_SECURITY_PASS", log)
            self.assertNotIn("TEST_FAILED", log)
            self.assertNotIn("ERROR", log)


if __name__ == "__main__":
    unittest.main()
