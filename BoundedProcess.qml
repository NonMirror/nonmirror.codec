import Quickshell.Io
import QtQuick

// Only codec_runner.py may produce output here. Its stdout is bounded base64
// and its stderr contains fixed ASCII diagnostics, never child error text.
Process {
  id: proc
  property string mode: "step"
  property string request: ""
  property string output: ""
  property string errorOutput: ""
  property string rejection: ""
  property bool busy: false
  signal completed(bool ok, string data, string message)
  command: ["/usr/bin/python3", "-I", decodeURIComponent(Qt.resolvedUrl("codec_runner.py").toString().replace(/^file:\/\//, "")), mode]

  function start(payload) {
    if (busy) return false
    request = payload
    output = ""
    errorOutput = ""
    rejection = ""
    busy = true
    stdinEnabled = true
    deadline.restart()
    running = true
    return true
  }

  function cancel(message) {
    if (!busy) return
    rejection = message || "Operation cancelled"
    request = ""
    output = ""
    errorOutput = ""
    // The helper handles TERM by killing and reaping the entire worker group.
    signal(15)
  }

  function collect(chunk, isError) {
    if (rejection) return
    var current = isError ? errorOutput : output
    var limit = isError ? 4096 : 349528  // base64 of 256 KiB
    // Check BEFORE concatenation. Empty split markers never buffer a line.
    if (chunk.length > limit - current.length) {
      cancel("Process output exceeds the size limit")
      return
    }
    if (isError) errorOutput = current + chunk
    else output = current + chunk
  }

  stdout: SplitParser { splitMarker: ""; onRead: data => proc.collect(data, false) }
  stderr: SplitParser { splitMarker: ""; onRead: data => proc.collect(data, true) }
  onStarted: {
    if (rejection) { signal(15); return }
    write(request)
    request = ""
    stdinEnabled = false
  }
  onExited: function(exitCode, exitStatus) {
    deadline.stop()
    var ok = !rejection && exitCode === 0 && exitStatus === 0
    var data = ok ? output : ""
    var message = rejection || errorOutput.trim() || "Could not start or complete the operation"
    request = ""
    output = ""
    errorOutput = ""
    busy = false
    completed(ok, data, message)
  }
  property Timer deadline: Timer {
    interval: 12000
    onTriggered: {
      proc.cancel("Operation timed out")
      // A failed exec emits no exited signal in some Quickshell versions.
      if (!proc.running) {
        proc.busy = false
        proc.completed(false, "", proc.rejection)
      }
    }
  }
  Component.onDestruction: if (busy) signal(15)
}
