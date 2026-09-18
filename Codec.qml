import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "Algorithms.js" as Codec

// Codec: build a pipeline of encode/decode/crypto steps, run it with Enter,
// and copy the result with a second Enter. Encoding, radix and text steps run
// natively in the QML engine; AES, RSA, hashes and gzip shell out to openssl
// or gzip. Steps that need a key, IV or key file prompt for it when they are
// added to the pipeline, and the values can be edited from the pipeline chips.
// Summon with `omarchy-shell shell toggle nonmirror.codec` (Ctrl+Shift+C).
Item {
  id: root

  property string omarchyPath: Quickshell.env("OMARCHY_PATH")
  property var shell: null
  property var manifest: null

  property bool opened: false
  property string phase: "edit"        // edit | params | running | result
  property string focusArea: "input"   // input | algo
  property string inputText: ""
  property string algoQuery: ""
  property var chain: []               // [{ id, params: { name: value } }]
  property int algoIndex: 0
  property var filteredAlgos: []
  property string flashText: ""
  property string errorText: ""
  property bool cursorVisible: true

  // Parameters prompt for the algorithm being added or edited.
  property string pendingAlgoId: ""
  property var pendingParams: ({})
  property int paramIndex: 0
  property int editingIndex: -1
  property string paramError: ""

  // Pipeline execution state. `working` is the byte array between steps.
  property var working: []
  property var steps: []
  property int stepIndex: 0
  property string resultText: ""
  property bool resultBinary: false
  readonly property int maxDataBytes: 262144
  readonly property int maxParamBytes: 4096
  property int session: 0

  // Live number/equation recognition for the current input. Shown as a preview
  // only while the pipeline is empty, so it never competes with a real run.
  readonly property var calc: Codec.evaluateEquation(root.inputText)
  readonly property bool calcReady: root.phase === "edit" && root.chain.length === 0 && root.calc !== null
  readonly property bool previewVisible: root.phase === "result" || root.calcReady
  readonly property string previewText: root.phase === "result" ? root.resultText : (root.calcReady ? root.calc.primary : "")
  readonly property string previewLabel: root.phase === "result"
    ? (root.resultBinary ? "RESULT  ·  binary, shown as hex  ·  Enter to copy" : "RESULT  ·  Enter to copy")
    : ("EQUATION  ·  " + (root.calc ? root.calc.detail : "") + "  ·  Enter to copy")

  // Same [menu] surface tokens the command menu uses, so themes style both.
  property color background: Color.menu.background
  property color foreground: Color.menu.text
  property color border: Color.menu.border
  property var borderSpec: Border.surfaceSpec("menu", "border", border, Math.max(1, Style.space(2)))
  property color scrim: Color.menu.scrim
  property color selectedBackground: Color.menu.selectedBackground
  property color selectedText: Color.menu.selectedText
  property color faint: Util.alpha(foreground, 0.5)
  property color hairline: Util.alpha(foreground, 0.16)
  property color danger: "#e06c75"
  property string fontFamily: Style.font.menuFamily
  readonly property int cornerRadius: Style.cornerRadius
  property int contentMargin: Style.spacing.panelPadding
  property int contentSpacing: Style.spacing.md
  property int fieldHeight: Math.max(Style.space(38), Style.font.body + Style.spacing.controlPaddingY * 2)
  property int algoRowHeight: Math.max(Style.space(34), Style.font.body + Style.spacing.controlPaddingY * 2)
  property int cardWidth: Math.min(Style.space(580), panel.width - Style.gapsOut * 2)
  property int cardHeight: Math.min(Style.space(486), panel.height - Style.gapsOut * 2)

  // --------------------------------------------------------------- lifecycle

  function open(payloadJson) {
    root.cancelOperations()
    root.opened = true
    root.phase = "edit"
    root.focusArea = "input"
    root.inputText = ""
    root.algoQuery = ""
    root.chain = []
    root.algoIndex = 0
    root.errorText = ""
    root.flashText = ""
    root.resultText = ""
    root.resultBinary = false
    root.pendingAlgoId = ""
    root.pendingParams = ({})
    root.editingIndex = -1
    root.paramError = ""
    root.rebuildAlgos()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function close() {
    root.cancelOperations()
    root.opened = false
  }

  function dismiss() {
    root.cancelOperations()
    root.opened = false
    if (root.shell && typeof root.shell.hide === "function")
      root.shell.hide((root.manifest && root.manifest.id) || "nonmirror.codec")
  }

  function toggle() {
    if (root.opened) root.dismiss()
    else root.open("{}")
  }

  // Ctrl+V reads the clipboard into whichever field has focus. Pasting is
  // explicit: the last thing on the clipboard is often unrelated to what you
  // mean to transform, and silently prefilling it made every open start from
  // stale text.
  function requestPaste() {
    if (pasteProc.busy || root.phase === "running") return
    pasteProc.session = root.session
    pasteProc.targetPhase = root.phase
    pasteProc.targetParam = root.currentParam() ? root.currentParam().name : ""
    pasteProc.targetAlgo = root.pendingAlgoId
    pasteProc.start("")
  }

  function cancelOperations() {
    root.session++
    pasteProc.cancel("Operation cancelled")
    cliProc.cancel("Operation cancelled")
    copyProc.payload = ""
    if (copyProc.running) copyProc.signal(15)
    root.working = []
    root.steps = []
  }

  // Check code units first to avoid allocating a huge UTF-8 array to measure
  // an already oversized field; then enforce the actual byte limit.
  function fitsText(text, limit) {
    return text.length <= limit && Codec.textToBytes(text).length <= limit
  }

  function setInput(value) {
    if (!root.fitsText(value, root.maxDataBytes)) {
      root.errorText = "Input exceeds 256 KiB"
      return
    }
    root.inputText = value
  }

  // ------------------------------------------------------------- picker state

  function rebuildAlgos() {
    var all = Codec.catalog()
    // Every whitespace-separated term must appear somewhere in the row, so
    // "aes enc" finds "AES-256 Encrypt" (the 256- in the middle would defeat
    // a plain substring match on the whole query).
    var terms = root.algoQuery.trim().toLowerCase().split(/\s+/)
    var out = []
    for (var i = 0; i < all.length; i++) {
      var a = all[i]
      var haystack = (a.name + " " + a.group + " " + a.id).toLowerCase()
      var matched = true
      for (var t = 0; t < terms.length; t++) {
        if (terms[t] && haystack.indexOf(terms[t]) < 0) {
          matched = false
          break
        }
      }
      if (matched) out.push(a)
    }
    root.filteredAlgos = out
    if (out.length === 0) root.algoIndex = 0
    else if (root.algoIndex >= out.length) root.algoIndex = out.length - 1
    else if (root.algoIndex < 0) root.algoIndex = 0
    revealAlgo()
  }

  function revealAlgo() {
    Qt.callLater(function() {
      if (root.filteredAlgos.length > 0) algoList.positionViewAtIndex(root.algoIndex, ListView.Contain)
    })
  }

  function moveAlgo(delta) {
    var count = root.filteredAlgos.length
    if (count === 0) return
    root.algoIndex = (root.algoIndex + delta + count) % count
    root.revealAlgo()
  }

  function algorithmName(id) {
    var a = Codec.byId(id)
    return a ? a.name : id
  }

  function algorithmHasParams(id) {
    var a = Codec.byId(id)
    return !!(a && a.params && a.params.length > 0)
  }

  function flash(message) {
    root.flashText = message
    flashTimer.restart()
  }

  // Enter on a picker row: open the parameter prompt whenever the algorithm
  // has any (the base table is one of them), otherwise add it straight away.
  // The prompt confirms on Enter, so accepting the default costs one key.
  function selectAlgo(index) {
    if (index < 0 || index >= root.filteredAlgos.length) return
    var picked = root.filteredAlgos[index]
    var algo = Codec.byId(picked.id)
    var params = algo && algo.params ? algo.params : []
    if (params.length === 0) {
      root.appendStep({ id: picked.id, params: ({}) })
      return
    }
    root.beginParams(picked.id, -1)
  }

  function appendStep(step) {
    if (root.chain.length >= 32) { root.errorText = "At most 32 steps are allowed"; return }
    root.chain = root.chain.concat([step])
    flash(root.algorithmName(step.id) + " added")
    root.algoQuery = ""
    root.rebuildAlgos()
  }

  function removeChainAt(index) {
    var next = []
    for (var i = 0; i < root.chain.length; i++) {
      if (i !== index) next.push(root.chain[i])
    }
    root.chain = next
  }

  function removeLastStep() {
    if (root.chain.length === 0) return
    root.chain = root.chain.slice(0, root.chain.length - 1)
  }

  // ------------------------------------------------------------- params state

  function pendingParamList() {
    var a = Codec.byId(root.pendingAlgoId)
    return a && a.params ? a.params : []
  }

  function pendingAlgoName() {
    return root.algorithmName(root.pendingAlgoId)
  }

  function beginParams(algoId, editingIndex) {
    pasteProc.cancel("Paste cancelled after changing fields")
    var algo = Codec.byId(algoId)
    var list = algo && algo.params ? algo.params : []
    var existing = editingIndex >= 0 && editingIndex < root.chain.length
      ? (root.chain[editingIndex].params || {})
      : {}
    var values = ({})
    for (var i = 0; i < list.length; i++) {
      values[list[i].name] = existing[list[i].name] !== undefined ? String(existing[list[i].name]) : ""
    }
    root.pendingAlgoId = algoId
    root.pendingParams = values
    root.paramIndex = 0
    root.editingIndex = editingIndex
    root.paramError = ""
    root.phase = "params"
  }

  function editChainStep(index) {
    if (index < 0 || index >= root.chain.length) return
    var step = root.chain[index]
    if (!root.algorithmHasParams(step.id)) {
      flash(root.algorithmName(step.id) + " has no parameters")
      return
    }
    root.beginParams(step.id, index)
  }

  function currentParam() {
    var list = root.pendingParamList()
    if (root.paramIndex < 0 || root.paramIndex >= list.length) return null
    return list[root.paramIndex]
  }

  function currentParamValue() {
    var param = root.currentParam()
    if (!param) return ""
    var value = root.pendingParams[param.name]
    return value === undefined || value === null ? "" : String(value)
  }

  // pendingParams is reassigned rather than mutated: an in-place write into a
  // QML `var` object is occasionally dropped by the engine, and a lost
  // keystroke in a password field is exactly the kind of thing you notice.
  function setCurrentParamValue(value) {
    if (!root.fitsText(value, root.maxParamBytes)) {
      root.paramError = "Parameter exceeds 4 KiB"
      return
    }
    var param = root.currentParam()
    if (!param) return
    var next = ({})
    for (var k in root.pendingParams) next[k] = root.pendingParams[k]
    next[param.name] = value
    root.pendingParams = next
    root.paramError = ""
  }

  function moveParam(delta) {
    pasteProc.cancel("Paste cancelled after changing fields")
    var list = root.pendingParamList()
    if (list.length === 0) return
    root.paramIndex = (root.paramIndex + delta + list.length) % list.length
  }

  function cancelParams() {
    pasteProc.cancel("Paste cancelled after changing fields")
    root.phase = "edit"
    root.pendingAlgoId = ""
    root.pendingParams = ({})
    root.paramIndex = 0
    root.editingIndex = -1
    root.paramError = ""
  }

  function submitParams() {
    var list = root.pendingParamList()
    for (var i = 0; i < list.length; i++) {
      var param = list[i]
      var value = String(root.pendingParams[param.name] || "")
      if (param.required && !value.trim()) {
        root.paramError = param.label + " is required"
        root.paramIndex = i
        return
      }
      if (param.alphabetSize && value !== "") {
        if (value.length !== param.alphabetSize && value.length !== param.alphabetSize + 1) {
          root.paramError = param.label + " must be " + param.alphabetSize
            + " characters (or " + (param.alphabetSize + 1) + " with a padding character)"
          root.paramIndex = i
          return
        }
      }
    }
    var step = { id: root.pendingAlgoId, params: root.pendingParams }
    var wasEditing = root.editingIndex
    if (wasEditing >= 0 && wasEditing < root.chain.length) {
      var next = root.chain.slice()
      next[wasEditing] = step
      root.chain = next
      flash(root.algorithmName(step.id) + " updated")
    } else {
      root.appendStep(step)
    }
    root.cancelParams()
  }

  // ------------------------------------------------------------------- keys

  function singleLine(text) {
    return String(text).replace(/\n/g, "⏎").replace(/\t/g, "⇥")
  }

  function isPrintable(event) {
    return event.text && event.text.length === 1
      && event.text.charCodeAt(0) >= 32 && event.text.charCodeAt(0) !== 127
      && (event.modifiers === Qt.NoModifier || event.modifiers === Qt.ShiftModifier)
  }

  // Tab and the arrow keys walk the two focusable rows in a ring.
  function cycleFocus(delta) {
    pasteProc.cancel("Paste cancelled after changing fields")
    var areas = ["input", "algo"]
    var at = areas.indexOf(root.focusArea)
    if (at < 0) at = 0
    root.focusArea = areas[(at + delta + areas.length) % areas.length]
  }

  function handleKey(event) {
    if (root.phase === "params") {
      root.handleParamsKey(event)
      return
    }

    var key = event.key
    var mods = event.modifiers

    if (key === Qt.Key_Escape) {
      if (root.phase !== "edit") {
        root.cancelOperations()
        root.phase = "edit"
        root.errorText = ""
      } else if (root.focusArea === "algo" && root.algoQuery) {
        root.algoQuery = ""
        root.rebuildAlgos()
      } else {
        root.dismiss()
      }
      event.accepted = true
      return
    }

    if (root.phase === "result") {
      if (key === Qt.Key_Return || key === Qt.Key_Enter) root.copyResult()
      else root.phase = "edit"
      event.accepted = true
      return
    }

    if (root.phase === "running") {
      event.accepted = true
      return
    }

    if (key === Qt.Key_Tab) {
      root.cycleFocus(mods & Qt.ShiftModifier ? -1 : 1)
      event.accepted = true
      return
    }

    if ((key === Qt.Key_Return || key === Qt.Key_Enter) && (mods & Qt.ControlModifier)) {
      root.runChain()
      event.accepted = true
      return
    }

    // Ctrl+E reopens the last step's parameter prompt without the mouse.
    if (key === Qt.Key_E && (mods & Qt.ControlModifier) && root.chain.length > 0) {
      root.editChainStep(root.chain.length - 1)
      event.accepted = true
      return
    }

    if (key === Qt.Key_V && (mods & Qt.ControlModifier)) {
      root.requestPaste()
      event.accepted = true
      return
    }

    // Alt+J / Alt+K move the picker selection from any focus area (the menu's
    // own selection chords). Enter then opens or adds the highlighted row.
    if ((key === Qt.Key_J || key === Qt.Key_K) && (mods & Qt.AltModifier)) {
      if (root.focusArea !== "algo") root.focusArea = "algo"
      root.moveAlgo(key === Qt.Key_J ? 1 : -1)
      event.accepted = true
      return
    }

    if (root.focusArea !== "algo") {
      if (key === Qt.Key_Down) {
        root.cycleFocus(1)
        event.accepted = true
        return
      }
      if (key === Qt.Key_Up) {
        root.cycleFocus(-1)
        event.accepted = true
        return
      }
    }

    if (root.focusArea === "input") {
      if (key === Qt.Key_Return || key === Qt.Key_Enter) {
        if (root.calcReady) root.copyText(root.calc.primary)
        else root.runChain()
      } else if (Util.editsFilter(event, root.inputText)) {
        root.setInput(Util.editedFilter(event, root.inputText))
      } else if (root.isPrintable(event)) {
        root.setInput(root.inputText + event.text)
      } else {
        return
      }
      event.accepted = true
      return
    }

    // Algorithm picker
    if (key === Qt.Key_Down) {
      root.moveAlgo(1)
    } else if (key === Qt.Key_Up) {
      root.moveAlgo(-1)
    } else if (key === Qt.Key_Return || key === Qt.Key_Enter) {
      root.selectAlgo(root.algoIndex)
    } else if (key === Qt.Key_Backspace && !root.algoQuery) {
      root.removeLastStep()
    } else if (Util.editsFilter(event, root.algoQuery)) {
      root.algoQuery = Util.editedFilter(event, root.algoQuery)
      root.algoIndex = 0
      root.rebuildAlgos()
    } else if (root.isPrintable(event)) {
      root.algoQuery = root.algoQuery + event.text
      root.algoIndex = 0
      root.rebuildAlgos()
    } else {
      return
    }
    event.accepted = true
  }

  function handleParamsKey(event) {
    var key = event.key
    var mods = event.modifiers
    if (key === Qt.Key_Escape) {
      root.cancelParams()
    } else if (key === Qt.Key_Tab) {
      root.moveParam(mods & Qt.ShiftModifier ? -1 : 1)
    } else if (key === Qt.Key_Down) {
      root.moveParam(1)
    } else if (key === Qt.Key_Up) {
      root.moveParam(-1)
    } else if (key === Qt.Key_Return || key === Qt.Key_Enter) {
      root.submitParams()
    } else if (key === Qt.Key_V && (mods & Qt.ControlModifier)) {
      root.requestPaste()
    } else if (Util.editsFilter(event, root.currentParamValue())) {
      root.setCurrentParamValue(Util.editedFilter(event, root.currentParamValue()))
    } else if (root.isPrintable(event)) {
      root.setCurrentParamValue(root.currentParamValue() + event.text)
    }
    event.accepted = true
  }

  // ---------------------------------------------------------------- pipeline

  function runChain() {
    if (cliProc.busy || pasteProc.busy) { root.errorText = "Wait for the current operation to stop"; return }
    if (!root.fitsText(root.inputText, root.maxDataBytes)) { root.errorText = "Input exceeds 256 KiB"; return }
    if (root.chain.length === 0) {
      root.errorText = "Add at least one algorithm with Tab"
      return
    }
    var prepared = []
    for (var i = 0; i < root.chain.length; i++) {
      var algo = Codec.byId(root.chain[i].id)
      if (!algo) {
        root.errorText = "Unknown algorithm: " + root.chain[i].id
        return
      }
      prepared.push({ algo: algo, params: root.chain[i].params || ({}) })
    }
    root.steps = prepared
    root.stepIndex = 0
    root.working = Codec.bytesForInput(root.inputText, root.calc)
    if (root.working.length > root.maxDataBytes) { root.failRun("Input exceeds 256 KiB"); return }
    root.errorText = ""
    root.flashText = ""
    root.resultText = ""
    root.resultBinary = false
    root.phase = "running"
    runNext()
  }

  function expandPath(value) {
    var path = String(value === undefined || value === null ? "" : value)
    var home = Quickshell.env("HOME") || ""
    if (path === "~") return home
    if (path.indexOf("~/") === 0) return home + path.slice(1)
    return path
  }

  function runNext() {
    if (root.phase !== "running") return
    if (root.stepIndex >= root.steps.length) {
      finishRun()
      return
    }
    var step = root.steps[root.stepIndex]
    var algo = step.algo

    if (algo.engine !== "cli") {
      var next
      try {
        // Base58/radix conversion is quadratic; keep it off large buffers in
        // the persistent QML thread. Other native transforms have fixed growth.
        if (/^base58-|^number-/.test(algo.id) && root.working.length > 4096)
          throw new Error("This conversion is limited to 4 KiB")
        next = algo.run(root.working, step.params)
        if (next.length > root.maxDataBytes) throw new Error("Output exceeds 256 KiB")
      } catch (e) {
        failRun(algo.name + ": " + ((e && e.message) ? e.message : String(e)))
        return
      }
      root.working = next
      root.stepIndex = root.stepIndex + 1
      runNext()
      return
    }

    // The entire request goes over stdin. Arguments contain only the fixed
    // helper pathname and operation mode, including in descendant processes.
    var params = ({})
    var list = algo.params || []
    for (var i = 0; i < list.length; i++) {
      var value = String(step.params[list[i].name] || "")
      if (list[i].path) value = root.expandPath(value)
      if (!root.fitsText(value, root.maxParamBytes)) { root.failRun("Parameter exceeds 4 KiB"); return }
      params[list[i].name] = value
    }
    cliProc.session = root.session
    var request = JSON.stringify({ id: algo.id, data: Codec.bytesToBase64(root.working), params: params })
    if (!root.fitsText(request, 393216)) { root.failRun("Request exceeds 384 KiB"); return }
    cliProc.start(request)
  }

  function finishRun() {
    var last = root.steps.length > 0 ? root.steps[root.steps.length - 1] : null
    if (last && last.algo && last.algo.hash) {
      // A trailing hash reads as its digest text, not as opaque bytes, so it is
      // rendered here instead of through prettyBytes' spaced-hex fallback.
      root.resultText = Codec.formatHash(root.working, last.params ? last.params.separator : "")
      root.resultBinary = false
    } else {
      root.resultText = Codec.prettyBytes(root.working)
      root.resultBinary = Codec.isBinary(root.working)
    }
    root.phase = "result"
  }

  function failRun(message) {
    root.working = []
    root.steps = []
    root.errorText = String(message)
    root.phase = "edit"
  }

  function copyText(text) {
    if (copyProc.running) return
    if (!root.fitsText(String(text), 3 * root.maxDataBytes)) { root.errorText = "Copy exceeds 768 KiB"; return }
    copyProc.payload = String(text)
    copyProc.session = root.session
    copyProc.stdinEnabled = true
    copyProc.running = true
  }

  function copyResult() {
    root.copyText(root.previewText)
  }

  Timer {
    id: flashTimer
    interval: 1400
    onTriggered: root.flashText = ""
  }

  Timer {
    interval: 530
    repeat: true
    running: root.opened && (root.phase === "edit" || root.phase === "params")
    onTriggered: root.cursorVisible = !root.cursorVisible
  }

  // Reads the clipboard on demand (Ctrl+V) into the focused input or param.
  BoundedProcess {
    id: pasteProc
    mode: "paste"
    property int session: 0
    property string targetPhase: ""
    property string targetParam: ""
    property string targetAlgo: ""
    onCompleted: function(ok, data, message) {
      if (!root.opened || session !== root.session) return
      if (!ok) { root.errorText = message; return }
      if (targetPhase !== root.phase) return
      var pasted = Codec.bytesToText(Codec.base64ToBytes(data))
      if (pasted === "") return
      if (root.phase === "params") {
        if (!root.currentParam() || root.currentParam().name !== targetParam || root.pendingAlgoId !== targetAlgo) return
        if (!root.fitsText(pasted, root.maxParamBytes - Codec.textToBytes(root.currentParamValue()).length)) {
          root.paramError = "Parameter exceeds 4 KiB"
          return
        }
        root.setCurrentParamValue(root.currentParamValue() + pasted)
      } else if (root.focusArea === "input") {
        if (!root.fitsText(pasted, root.maxDataBytes - Codec.textToBytes(root.inputText).length)) {
          root.errorText = "Input exceeds 256 KiB"
          return
        }
        root.setInput(root.inputText + pasted)
      }
    }
  }

  // One CLI step at a time: the chain is strictly sequential, so a single
  // process is enough. Input and output travel base64-encoded, which keeps
  // binary results (AES blocks, RSA ciphertext, digests, gzip) exact.
  BoundedProcess {
    id: cliProc
    property int session: 0
    onCompleted: function(ok, data, message) {
      if (root.phase !== "running" || session !== root.session) return
      if (!ok) {
        root.failRun(message)
        return
      }
      var bytes
      try {
        bytes = Codec.base64ToBytes(data)
        if (bytes.length > root.maxDataBytes) throw new Error("Output exceeds 256 KiB")
      } catch (e) {
        root.failRun("The step produced unexpected output")
        return
      }
      root.working = bytes
      root.stepIndex = root.stepIndex + 1
      // Deferred so the process has settled before the next step sets a new
      // command on it (a change while it is still finishing is dropped).
      Qt.callLater(runNext)
    }
  }

  // Copy through a process we can watch, then close once the clipboard has
  // actually taken the text, rather than firing and dismissing immediately.
  Process {
    id: copyProc
    property string payload: ""
    property int session: 0
    // wl-copy's successful handoff intentionally leaves its clipboard owner
    // alive. Bound the initial handoff without putting the copied text in argv.
    command: ["/usr/bin/timeout", "--kill-after=1s", "3s", "/usr/bin/wl-copy", "--type", "text/plain"]
    onStarted: {
      if (session !== root.session) { payload = ""; stdinEnabled = false; signal(15); return }
      write(payload)
      payload = ""
      stdinEnabled = false
    }
    onExited: function(exitCode, exitStatus) {
      payload = ""
      if (session !== root.session) return
      if (exitCode === 0 && exitStatus === 0) root.dismiss()
      else root.errorText = "Could not copy the result"
    }
  }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "omarchy-codec"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    Rectangle {
      anchors.fill: parent
      color: root.scrim
    }

    MouseArea {
      anchors.fill: parent
      onClicked: root.dismiss()
    }

    BorderSurface {
      id: card
      width: root.cardWidth
      height: root.cardHeight
      anchors.centerIn: parent
      radius: root.cornerRadius
      color: root.background
      borderSpec: root.borderSpec
      padding: root.contentMargin

      MouseArea { anchors.fill: parent; onClicked: {} }

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true

        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function(event) { root.handleKey(event) }
      }

      ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.bottomMargin: card.contentBottomInset
        anchors.leftMargin: card.contentLeftInset
        spacing: Style.spacing.sm

        // ---------------------------------------------------------- heading
        RowLayout {
          Layout.fillWidth: true
          spacing: Style.spacing.sm

          Text {
            textFormat: Text.PlainText
            text: "Codec"
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
            font.weight: Font.Medium
          }

          Item { Layout.fillWidth: true }

          Text {
            textFormat: Text.PlainText
            visible: root.phase === "running"
            text: "Working…"
            color: root.faint
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            textFormat: Text.PlainText
            text: root.flashText
            visible: root.flashText !== ""
            color: root.selectedText
            opacity: 0.85
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        // ------------------------------------------------------------ input
        RowLayout {
          Layout.fillWidth: true
          spacing: Style.spacing.sm

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: "INPUT"
            color: root.faint
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.letterSpacing: 1
          }

          Text {
            textFormat: Text.PlainText
            text: "0x 0o 0b  ·  bin() oct() hex()"
            color: root.faint
            opacity: 0.7
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        Rectangle {
          Layout.fillWidth: true
          Layout.preferredHeight: root.fieldHeight
          radius: root.cornerRadius
          color: "transparent"
          border.width: Style.spacing.hairline
          border.color: (root.focusArea === "input" && root.phase === "edit") ? root.border : root.hairline

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.IBeamCursor
            onClicked: root.focusArea = "input"
          }

          Text {
            textFormat: Text.PlainText
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Style.spacing.sm
            anchors.rightMargin: Style.spacing.sm
            text: root.inputText === ""
              ? "Type or Ctrl+V to paste…"
              : root.singleLine(root.inputText) + ((root.focusArea === "input" && root.phase === "edit" && root.cursorVisible) ? "▏" : "")
            color: root.inputText === "" ? root.faint : root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            elide: Text.ElideLeft
          }
        }

        // --------------------------------------------------------- pipeline
        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: "PIPELINE" + (root.chain.length > 0 ? "  ·  click to edit params  ·  right-click to remove" : "")
          color: root.faint
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.letterSpacing: 1
        }

        Rectangle {
          Layout.fillWidth: true
          Layout.preferredHeight: Math.max(root.fieldHeight, chainFlow.implicitHeight + Style.spacing.sm)
          radius: root.cornerRadius
          color: root.chain.length > 0 ? Util.alpha(root.selectedBackground, 0.35) : "transparent"
          border.width: Style.spacing.hairline
          border.color: root.hairline

          Text {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Style.spacing.sm
            anchors.rightMargin: Style.spacing.sm
            textFormat: Text.PlainText
            visible: root.chain.length === 0
            text: "No steps yet — press Tab and pick algorithms in order"
            color: root.faint
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            elide: Text.ElideRight
          }

          Flow {
            id: chainFlow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Style.spacing.sm
            anchors.rightMargin: Style.spacing.sm
            spacing: Style.spacing.xs

            Repeater {
              model: root.chain

              delegate: Rectangle {
                required property var modelData
                required property int index

                readonly property bool needsParams: root.algorithmHasParams(modelData.id)

                height: chipText.implicitHeight + Style.spacing.xs * 2
                width: chipText.implicitWidth + Style.spacing.sm * 2
                radius: root.cornerRadius
                color: root.selectedBackground

                Text {
                  id: chipText
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: root.algorithmName(modelData.id) + (needsParams ? "  ·  params" : "")
                  color: root.selectedText
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.title
                }

                MouseArea {
                  anchors.fill: parent
                  acceptedButtons: Qt.LeftButton | Qt.RightButton
                  cursorShape: Qt.PointingHandCursor
                  onClicked: function(mouse) {
                    if (mouse.button === Qt.RightButton) root.removeChainAt(index)
                    else root.editChainStep(index)
                  }
                }
              }
            }
          }
        }

        // ----------------------------------------------------------- result
        Rectangle {
          Layout.fillWidth: true
          Layout.preferredHeight: Math.min(Style.space(160), Math.max(root.fieldHeight, resultTextItem.implicitHeight + Style.spacing.md))
          visible: root.previewVisible
          radius: root.cornerRadius
          color: Util.alpha(root.selectedBackground, 0.45)
          border.width: Style.spacing.hairline
          border.color: root.border

          ColumnLayout {
            anchors.fill: parent
            anchors.margins: Style.spacing.sm
            spacing: Style.spacing.xxs

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              text: root.previewLabel
              color: root.faint
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.letterSpacing: 1
            }

            Flickable {
              Layout.fillWidth: true
              Layout.fillHeight: true
              clip: true
              contentWidth: width
              contentHeight: resultTextItem.implicitHeight
              boundsBehavior: Flickable.StopAtBounds

              Text {
                id: resultTextItem
                width: parent.width
                textFormat: Text.PlainText
                text: root.previewText
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WrapAnywhere
              }
            }
          }
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          visible: root.errorText !== ""
          text: root.errorText
          color: root.danger
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // ------------------------------------------- algorithm / parameters
        RowLayout {
          Layout.fillWidth: true
          visible: root.phase !== "params"
          spacing: Style.spacing.sm

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            elide: Text.ElideRight
            text: root.focusArea === "algo"
              ? "ALGORITHM  ·  Ctrl+E edits last"
              : "ALGORITHM  ·  Tab or Alt+J/K to select"
            color: root.focusArea === "algo" ? root.foreground : root.faint
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.letterSpacing: 1
          }

          // Live echo of the algorithm filter. The list narrows as you type,
          // but once the matches no longer contain the typed text there is
          // nothing else on screen that says what the filter is.
          Rectangle {
            visible: root.focusArea === "algo" || root.algoQuery !== ""
            Layout.preferredWidth: Math.min(Style.space(280), algoQueryText.implicitWidth + Style.spacing.sm * 2)
            Layout.preferredHeight: Math.max(Style.space(22), algoQueryText.implicitHeight + Style.spacing.xs * 2)
            radius: root.cornerRadius
            color: Util.alpha(root.foreground, 0.08)
            border.width: Style.spacing.hairline
            border.color: root.hairline

            Text {
              id: algoQueryText
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.spacing.sm
              anchors.rightMargin: Style.spacing.sm
              textFormat: Text.PlainText
              text: "󰈉  " + (root.algoQuery !== "" ? root.algoQuery : "filter…")
              color: root.algoQuery !== "" ? root.foreground : root.faint
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideLeft
            }
          }
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          visible: root.phase === "params"
          text: "PARAMETERS  ·  " + root.pendingAlgoName()
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.letterSpacing: 1
        }

        Item {
          Layout.fillWidth: true
          Layout.fillHeight: true

          ListView {
            id: algoList
            anchors.fill: parent
            visible: root.phase !== "params"
            model: root.filteredAlgos
            clip: true
            spacing: Style.spacing.xxs
            boundsBehavior: Flickable.StopAtBounds

            delegate: Rectangle {
              required property var modelData
              required property int index

              readonly property bool hasCursor: root.focusArea === "algo" && index === root.algoIndex

              width: ListView.view.width
              height: root.algoRowHeight
              radius: root.cornerRadius
              color: hasCursor ? root.selectedBackground : "transparent"

              Text {
                textFormat: Text.PlainText
                anchors.left: parent.left
                anchors.leftMargin: Style.spacing.sm
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.name
                color: hasCursor ? root.selectedText : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.subtitle
              }

              Text {
                textFormat: Text.PlainText
                anchors.right: parent.right
                anchors.rightMargin: Style.spacing.sm
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.group + (modelData.params.length > 0 ? "  ·  params" : "")
                color: hasCursor ? root.selectedText : root.faint
                opacity: 0.75
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onEntered: root.algoIndex = index
                onClicked: {
                  root.focusArea = "algo"
                  root.algoIndex = index
                  root.selectAlgo(index)
                }
              }
            }

            Text {
              anchors.centerIn: parent
              textFormat: Text.PlainText
              visible: root.filteredAlgos.length === 0
              text: "No algorithm matches “" + root.algoQuery + "”"
              color: root.faint
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          ColumnLayout {
            anchors.fill: parent
            visible: root.phase === "params"
            spacing: Style.spacing.sm

            Repeater {
              model: root.pendingParamList()

              delegate: Rectangle {
                required property var modelData
                required property int index

                readonly property string value: {
                  var v = root.pendingParams[modelData.name]
                  return v === undefined || v === null ? "" : String(v)
                }

                Layout.fillWidth: true
                Layout.preferredHeight: root.fieldHeight
                radius: root.cornerRadius
                color: "transparent"
                border.width: Style.spacing.hairline
                border.color: index === root.paramIndex ? root.border : root.hairline

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.IBeamCursor
                  onClicked: root.paramIndex = index
                }

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.spacing.sm
                  anchors.rightMargin: Style.spacing.sm
                  spacing: Style.spacing.sm

                  Text {
                    Layout.preferredWidth: Style.space(160)
                    textFormat: Text.PlainText
                    text: modelData.label + (modelData.required ? " *" : " (optional)")
                    color: modelData.required ? root.foreground : root.faint
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                  }

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: value === ""
                      ? (modelData.placeholder || "")
                      : root.singleLine(value) + ((index === root.paramIndex && root.phase === "params" && root.cursorVisible) ? "▏" : "")
                    color: value === "" ? root.faint : root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                  }
                }
              }
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              visible: root.paramError !== ""
              text: root.paramError
              color: root.danger
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Item { Layout.fillHeight: true }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              text: "Enter confirms  ·  Esc cancels  ·  Tab or ↑/↓ moves  ·  * required"
              color: root.faint
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }
      }
    }
  }
}
