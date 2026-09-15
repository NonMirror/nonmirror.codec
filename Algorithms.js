.pragma library

// ---------------------------------------------------------------------------
// Codec algorithm engine.
//
// Every step of a pipeline is a function from a byte array to a byte array.
// Byte arrays (plain arrays of 0-255) keep binary data exact: a decode that
// produces a PNG, an AES block, or a gzip stream never has to survive a UTF-8
// round-trip through a QML string.
//
// Encoding, radix and text transforms run natively in the QML JS engine with
// no process spawn. Cryptographic primitives shell out to openssl through a
// spec: the bytes go in and come out base64-encoded on the command line, so
// the pipeline still only ever moves bytes.
// ---------------------------------------------------------------------------

var B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
var B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
var B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
var DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"

// --------------------------------------------------------------- byte helpers

function byteAt(bytes, i) {
  var v = bytes[i]
  return v < 0 ? 0 : (v > 255 ? 255 : v)
}

// UTF-8 encode a QML string into bytes. Surrogate pairs become four bytes;
// lone surrogates become U+FFFD, matching what a text editor would show.
function textToBytes(text) {
  var s = String(text === undefined || text === null ? "" : text)
  var out = []
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i)
    if (c < 0x80) {
      out.push(c)
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      var c2 = s.charCodeAt(i + 1)
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00)
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63))
        i++
      } else {
        out.push(0xef, 0xbf, 0xbd)
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      out.push(0xef, 0xbf, 0xbd)
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    }
  }
  return out
}

// UTF-8 decode, replacing anything malformed with U+FFFD. The replacement
// character is also the signal prettyBytes()/isBinary() use to decide that a
// result is data rather than text.
function bytesToText(bytes) {
  var out = []
  var i = 0
  var n = bytes ? bytes.length : 0
  while (i < n) {
    var b = byteAt(bytes, i)
    var cp, need
    if (b < 0x80) {
      out.push(String.fromCharCode(b))
      i++
      continue
    } else if ((b & 0xe0) === 0xc0) {
      cp = b & 0x1f
      need = 1
    } else if ((b & 0xf0) === 0xe0) {
      cp = b & 0x0f
      need = 2
    } else if ((b & 0xf8) === 0xf0) {
      cp = b & 0x07
      need = 3
    } else {
      out.push("\ufffd")
      i++
      continue
    }
    if (i + need >= n) {
      out.push("\ufffd")
      i++
      continue
    }
    var valid = true
    for (var k = 1; k <= need; k++) {
      var bb = byteAt(bytes, i + k)
      if ((bb & 0xc0) !== 0x80) {
        valid = false
        break
      }
      cp = (cp << 6) | (bb & 0x3f)
    }
    if (!valid || (need === 1 && cp < 0x80) || (need === 2 && cp < 0x800)
        || (need === 3 && cp < 0x10000) || (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) {
      out.push("\ufffd")
      i++
      continue
    }
    if (cp >= 0x10000) {
      cp -= 0x10000
      out.push(String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff)))
    } else {
      out.push(String.fromCharCode(cp))
    }
    i += need + 1
  }
  return out.join("")
}

function isBinary(bytes) {
  var text = bytesToText(bytes)
  if (text.indexOf("\ufffd") >= 0) return true
  for (var i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i)
    if (c === 9 || c === 10 || c === 13) continue
    if (c < 32) return true
  }
  return false
}

function bytesToHexSpaced(bytes) {
  var parts = []
  for (var i = 0; i < bytes.length; i++) {
    var h = byteAt(bytes, i).toString(16)
    parts.push(h.length < 2 ? "0" + h : h)
  }
  return parts.join(" ")
}

// What the result pane shows: text when the bytes are text, spaced hex when
// they are data. The clipboard copy uses the same string.
function prettyBytes(bytes) {
  if (!bytes || bytes.length === 0) return ""
  if (isBinary(bytes)) return bytesToHexSpaced(bytes)
  return bytesToText(bytes)
}

function repeatChar(ch, count) {
  var out = ""
  for (var i = 0; i < count; i++) out += ch
  return out
}

// A base-N alphabet is 64, 58 or 32 characters, optionally followed by one
// more for the padding character. Empty means "use the default table".
function resolveAlphabet(value, size, fallback, name) {
  var alphabet = String(value === undefined || value === null ? "" : value)
  if (alphabet === "") return fallback
  if (alphabet.length !== size && alphabet.length !== size + 1) {
    throw new Error(name + " alphabet must be " + size + " characters"
      + " (or " + (size + 1) + " with a padding character)")
  }
  var seen = ({})
  for (var i = 0; i < alphabet.length; i++) {
    var ch = alphabet.charAt(i)
    if (seen[ch]) throw new Error(name + " alphabet repeats '" + ch + "'")
    seen[ch] = true
  }
  return alphabet
}

// ------------------------------------------------------------------- base64

// All three share one shape: the first `size` characters are the digits and an
// optional (size + 1)th character is the pad. A custom table therefore covers
// base64url (-_), base32hex (0-9A-V), Crockford and Flickr/Ripple base58
// without shipping each as its own algorithm.

function bytesToBase64(bytes, alphabet) {
  var table = String(!alphabet ? B64_STD : alphabet)
  var data = table.slice(0, 64)
  var pad = table.length > 64 ? table.charAt(64) : "="
  var out = []
  var n = bytes ? bytes.length : 0
  for (var i = 0; i < n; i += 3) {
    var b0 = byteAt(bytes, i)
    var b1 = i + 1 < n ? byteAt(bytes, i + 1) : 0
    var b2 = i + 2 < n ? byteAt(bytes, i + 2) : 0
    var triple = (b0 << 16) | (b1 << 8) | b2
    out.push(data.charAt((triple >> 18) & 63))
    out.push(data.charAt((triple >> 12) & 63))
    out.push(i + 1 < n ? data.charAt((triple >> 6) & 63) : pad)
    out.push(i + 2 < n ? data.charAt(triple & 63) : pad)
  }
  return out.join("")
}

function base64ToBytes(value, alphabet) {
  var table = String(!alphabet ? B64_STD : alphabet)
  var data = table.slice(0, 64)
  var pad = table.length > 64 ? table.charAt(64) : "="
  var s = String(value === undefined || value === null ? "" : value).replace(/[\s\r\n\t]/g, "")
  // The stock table still tolerates the URL-safe pair, which is the common
  // case for a table nobody typed in.
  if (data === B64_STD) s = s.replace(/-/g, "+").replace(/_/g, "/")
  if (pad !== "=") s = s.split(pad).join("")
  s = s.replace(/=+$/, "")
  var out = []
  var buffer = 0
  var bits = 0
  for (var i = 0; i < s.length; i++) {
    var v = data.indexOf(s.charAt(i))
    if (v < 0) throw new Error("'" + s.charAt(i) + "' is not in the alphabet")
    buffer = (buffer << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((buffer >> bits) & 0xff)
    }
  }
  return out
}

// ------------------------------------------------------------------- base58

function bytesToBase58(bytes, alphabet) {
  var table = String(!alphabet ? B58_ALPHABET : alphabet)
  var n = bytes ? bytes.length : 0
  if (n === 0) return ""
  var zeros = 0
  while (zeros < n && byteAt(bytes, zeros) === 0) zeros++

  var digits = [0]
  for (var i = zeros; i < n; i++) {
    var carry = byteAt(bytes, i)
    for (var j = 0; j < digits.length; j++) {
      var t = (digits[j] << 8) + carry
      digits[j] = t % 58
      carry = Math.floor(t / 58)
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = Math.floor(carry / 58)
    }
  }

  // A leading zero byte is the alphabet's own zero digit, not always "1".
  var out = repeatChar(table.charAt(0), zeros)
  for (var k = digits.length - 1; k >= 0; k--) out += table.charAt(digits[k])
  return out
}

function base58ToBytes(value, alphabet) {
  var table = String(!alphabet ? B58_ALPHABET : alphabet)
  var s = String(value === undefined || value === null ? "" : value).replace(/[\s\r\n\t]/g, "")
  if (!s) return []
  var zeroChar = table.charAt(0)
  var zeros = 0
  while (zeros < s.length && s.charAt(zeros) === zeroChar) zeros++

  var bytes = [0]
  for (var i = zeros; i < s.length; i++) {
    var idx = table.indexOf(s.charAt(i))
    if (idx < 0) throw new Error("'" + s.charAt(i) + "' is not in the alphabet")
    var carry = idx
    for (var j = 0; j < bytes.length; j++) {
      var t = bytes[j] * 58 + carry
      bytes[j] = t & 0xff
      carry = t >> 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }

  var out = []
  for (var z = 0; z < zeros; z++) out.push(0)
  for (var k = bytes.length - 1; k >= 0; k--) out.push(bytes[k])
  return out
}

// ------------------------------------------------------------------- base32

function bytesToBase32(bytes, alphabet) {
  var table = String(!alphabet ? B32_ALPHABET : alphabet)
  var data = table.slice(0, 32)
  var pad = table.length > 32 ? table.charAt(32) : "="
  var out = []
  var value = 0
  var bits = 0
  var n = bytes ? bytes.length : 0
  for (var i = 0; i < n; i++) {
    value = (value << 8) | byteAt(bytes, i)
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out.push(data.charAt((value >> bits) & 31))
    }
    value &= (1 << bits) - 1
  }
  if (bits > 0) out.push(data.charAt((value << (5 - bits)) & 31))
  var text = out.join("")
  while (text.length % 8 !== 0) text += pad
  return text
}

function base32ToBytes(value, alphabet) {
  var table = String(!alphabet ? B32_ALPHABET : alphabet)
  var data = table.slice(0, 32)
  var pad = table.length > 32 ? table.charAt(32) : "="
  // Accept either case so a table typed in lowercase still decodes.
  var lookup = ({})
  for (var i = 0; i < data.length; i++) {
    lookup[data.charAt(i)] = i
    lookup[data.charAt(i).toUpperCase()] = i
    lookup[data.charAt(i).toLowerCase()] = i
  }
  var s = String(value === undefined || value === null ? "" : value).replace(/[\s\r\n\t]/g, "")
  if (pad !== "=") s = s.split(pad).join("")
  s = s.replace(/=+$/, "")
  var out = []
  var acc = 0
  var bits = 0
  for (var j = 0; j < s.length; j++) {
    var v = lookup[s.charAt(j)]
    if (v === undefined) throw new Error("'" + s.charAt(j) + "' is not in the alphabet")
    acc = (acc << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
    acc &= (1 << bits) - 1
  }
  return out
}

// ---------------------------------------------------------------------- hex

function bytesToHex(bytes, upper) {
  var out = []
  for (var i = 0; i < bytes.length; i++) {
    var h = byteAt(bytes, i).toString(16)
    if (h.length < 2) h = "0" + h
    out.push(upper ? h.toUpperCase() : h)
  }
  return out.join("")
}

// A digest is bytes; when it ends the pipeline it should read as a hash, not as
// opaque data. Continuous lowercase hex by default, or joined by a user
// separator (a space, colon, dash, ...) when one was supplied.
function formatHash(bytes, separator) {
  var sep = String(separator === undefined || separator === null ? "" : separator)
  if (sep === "") return bytesToHex(bytes, false)
  var parts = []
  for (var i = 0; i < bytes.length; i++) {
    var h = byteAt(bytes, i).toString(16)
    if (h.length < 2) h = "0" + h
    parts.push(h)
  }
  return parts.join(sep)
}

function hexToBytes(value) {
  var s = String(value === undefined || value === null ? "" : value)
    .replace(/0x/gi, "")
    .replace(/[\s\r\n\t,:_-]/g, "")
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error("input is not hexadecimal")
  if (s.length % 2 !== 0) throw new Error("hex needs an even number of digits")
  var out = []
  for (var i = 0; i < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16))
  return out
}

// ------------------------------------------------------------- byte radixes

function bytesToBinary(bytes) {
  var out = []
  for (var i = 0; i < bytes.length; i++) {
    var h = byteAt(bytes, i).toString(2)
    out.push(h.length < 8 ? repeatChar("0", 8 - h.length) + h : h)
  }
  return out.join(" ")
}

function binaryToBytes(value) {
  var bits = String(value === undefined || value === null ? "" : value).replace(/[\s\r\n\t_]/g, "")
  if (!/^[01]*$/.test(bits)) throw new Error("input is not binary")
  if (bits.length % 8 !== 0) throw new Error("binary needs a multiple of 8 bits")
  var out = []
  for (var i = 0; i < bits.length; i += 8) out.push(parseInt(bits.substr(i, 8), 2))
  return out
}

function bytesToAscii(bytes) {
  var out = []
  for (var i = 0; i < bytes.length; i++) out.push(String(byteAt(bytes, i)))
  return out.join(" ")
}

function asciiToBytes(value) {
  var s = String(value === undefined || value === null ? "" : value).trim()
  if (!s) return []
  var parts = s.split(/[^0-9]+/)
  var out = []
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue
    var n = Number(parts[i])
    if (!isFinite(n) || n < 0 || n > 255 || Math.floor(n) !== n)
      throw new Error("'" + parts[i] + "' is not a byte value")
    out.push(n)
  }
  return out
}

// ------------------------------------------------------------- text helpers

function rot13(bytes) {
  var text = bytesToText(bytes)
  var out = []
  for (var i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i)
    if (c >= 65 && c <= 90) out.push(String.fromCharCode(((c - 65 + 13) % 26) + 65))
    else if (c >= 97 && c <= 122) out.push(String.fromCharCode(((c - 97 + 13) % 26) + 97))
    else out.push(text.charAt(i))
  }
  return textToBytes(out.join(""))
}

function reverseCodePoints(bytes) {
  var text = bytesToText(bytes)
  var chars = []
  for (var i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      chars.push(text.substr(i, 2))
      i++
    } else {
      chars.push(text.charAt(i))
    }
  }
  chars.reverse()
  return textToBytes(chars.join(""))
}

function upperBytes(bytes) { return textToBytes(bytesToText(bytes).toUpperCase()) }
function lowerBytes(bytes) { return textToBytes(bytesToText(bytes).toLowerCase()) }

function urlEncode(bytes) { return textToBytes(encodeURIComponent(bytesToText(bytes))) }
function urlDecode(bytes) { return textToBytes(decodeURIComponent(bytesToText(bytes))) }

// ---------------------------------------------------------------- number base

// Non-negative integer conversion over arbitrary length strings, so a 4096-bit
// value converts without BigInt. Digits run through base 36.
function convertBaseString(value, fromBase, toBase) {
  var s = String(value).trim().toLowerCase().replace(/[\s_,]/g, "")
  if (!s) throw new Error("the input is empty")
  var out = [0]
  for (var i = 0; i < s.length; i++) {
    var d = DIGITS.indexOf(s.charAt(i))
    if (d < 0 || d >= fromBase) throw new Error("'" + s.charAt(i) + "' is not a base-" + fromBase + " digit")
    var carry = d
    for (var j = 0; j < out.length; j++) {
      var t = out[j] * fromBase + carry
      out[j] = t % toBase
      carry = Math.floor(t / toBase)
    }
    while (carry > 0) {
      out.push(carry % toBase)
      carry = Math.floor(carry / toBase)
    }
  }
  while (out.length > 1 && out[out.length - 1] === 0) out.pop()
  var res = []
  for (var k = out.length - 1; k >= 0; k--) res.push(DIGITS.charAt(out[k]))
  return res.join("")
}

function detectBase(value) {
  var s = String(value).trim().toLowerCase().replace(/[\s_,]/g, "")
  if (s.indexOf("0x") === 0) return { base: 16, value: s.slice(2) }
  if (s.indexOf("0b") === 0) return { base: 2, value: s.slice(2) }
  if (s.indexOf("0o") === 0) return { base: 8, value: s.slice(2) }
  return { base: 10, value: s }
}

function numberToRadix(bytes, radix) {
  var detected = detectBase(bytesToText(bytes))
  return textToBytes(convertBaseString(detected.value, detected.base, radix))
}

// ---------------------------------------------------------------- calculator

// Number-system recognition and a small integer calculator. Values are plain
// JS doubles, so they stay exact up to Number.MAX_SAFE_INTEGER; the byte form
// is built through the arbitrary-precision base converter below, so a literal
// that fits in a double still yields its exact bytes.
var FORMAT_BASES = { "bin": 2, "oct": 8, "hex": 16, "dec": 10 }
var FORMAT_PREFIX = { "bin": "0b", "oct": "0o", "hex": "0x", "dec": "" }

function isQuoted(value) {
  var s = String(value === undefined || value === null ? "" : value).trim()
  if (s.length < 2) return false
  var first = s.charAt(0)
  if (first !== "\"" && first !== "'") return false
  return s.charAt(s.length - 1) === first
}

function unquote(value) {
  var s = String(value === undefined || value === null ? "" : value).trim()
  return isQuoted(s) ? s.slice(1, -1) : String(value)
}

function formatBaseNumber(value, prefix, base) {
  var v = (value && value.__format) ? value.value : value
  if (typeof v !== "number" || !isFinite(v)) return null
  var negative = v < 0
  var text = Math.abs(v).toString(base)
  return (negative ? "-" : "") + prefix + text
}

function tokenizeEquation(input) {
  var s = String(input)
  var tokens = []
  var i = 0
  while (i < s.length) {
    var c = s.charAt(i)
    if (c === " " || c === "\t" || c === "\n" || c === "\r") {
      i++
      continue
    }
    if (c >= "0" && c <= "9") {
      var numberMatch = /^(0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|[0-9][0-9_]*)/.exec(s.slice(i))
      if (!numberMatch) throw new Error("bad number")
      tokens.push({ type: "number", value: numberMatch[0] })
      i += numberMatch[0].length
      continue
    }
    if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_") {
      var nameMatch = /^[a-zA-Z_][a-zA-Z0-9_]*/.exec(s.slice(i))
      tokens.push({ type: "name", value: nameMatch[0] })
      i += nameMatch[0].length
      continue
    }
    var pair = s.substr(i, 2)
    if (pair === "**" || pair === "<<" || pair === ">>") {
      tokens.push({ type: "operator", value: pair })
      i += 2
      continue
    }
    if ("+-*/%()~^&|".indexOf(c) >= 0) {
      tokens.push({ type: "operator", value: c })
      i++
      continue
    }
    throw new Error("unexpected character '" + c + "'")
  }
  return tokens
}

// Returns { value, valueText, primary, detail } when the input is a number
// literal, a bin/oct/hex/dec call, or an expression built from them, and null
// when it is ordinary text. Quoted input is always text.
function evaluateEquation(input) {
  var trimmed = String(input === undefined || input === null ? "" : input).trim()
  if (trimmed === "" || isQuoted(trimmed)) return null

  var tokens
  try {
    tokens = tokenizeEquation(trimmed)
  } catch (e) {
    return null
  }
  if (tokens.length === 0) return null

  var pos = 0
  var sawOperator = false
  var sawFunction = false
  var sawPrefix = false

  function peek() { return pos < tokens.length ? tokens[pos] : null }
  function advance() { return tokens[pos++] }
  function asValue(v) { return (v && v.__format) ? v.value : v }

  function primary() {
    var token = peek()
    if (token === null) throw new Error("unexpected end")
    if (token.type === "number") {
      advance()
      if (/^0[xX]/.test(token.value) || /^0[oO]/.test(token.value)
          || /^0[bB]/.test(token.value)) sawPrefix = true
      var value = Number(String(token.value).replace(/_/g, ""))
      if (isNaN(value)) throw new Error("bad number")
      return value
    }
    if (token.type === "operator" && token.value === "(") {
      advance()
      var inner = expression()
      var close = advance()
      if (!close || close.type !== "operator" || close.value !== ")") throw new Error("missing )")
      return inner
    }
    if (token.type === "name") {
      advance()
      var name = token.value.toLowerCase()
      if (!(name in FORMAT_BASES)) throw new Error("unknown name")
      var open = peek()
      if (!open || open.type !== "operator" || open.value !== "(") throw new Error("expected (")
      advance()
      var argument = expression()
      var end = advance()
      if (!end || end.type !== "operator" || end.value !== ")") throw new Error("missing )")
      sawFunction = true
      var prefix = FORMAT_PREFIX[name]
      var text = formatBaseNumber(argument, prefix, FORMAT_BASES[name])
      if (text === null) throw new Error("cannot format")
      return { __format: true, value: asValue(argument), primary: text }
    }
    throw new Error("unexpected token")
  }

  function unary() {
    var token = peek()
    if (token && token.type === "operator" && (token.value === "-" || token.value === "+" || token.value === "~")) {
      advance()
      var v = asValue(unary())
      if (token.value === "-") return -v
      if (token.value === "~") return ~v
      return v
    }
    return power()
  }

  function power() {
    var base = primary()
    var token = peek()
    if (token && token.type === "operator" && token.value === "**") {
      advance()
      sawOperator = true
      return Math.pow(asValue(base), asValue(unary()))
    }
    // No exponent: hand the value back untouched so a top-level bin/oct/hex
    // call keeps its formatted result instead of collapsing to a number.
    return base
  }

  function multiplicative() {
    var v = unary()
    while (true) {
      var token = peek()
      if (!token || token.type !== "operator" || "*/%".indexOf(token.value) < 0) return v
      advance()
      sawOperator = true
      var right = asValue(unary())
      var left = asValue(v)
      if (token.value === "*") v = left * right
      else if (token.value === "/") v = left / right
      else v = left % right
    }
  }

  function additive() {
    var v = multiplicative()
    while (true) {
      var token = peek()
      if (!token || token.type !== "operator" || (token.value !== "+" && token.value !== "-")) return v
      advance()
      sawOperator = true
      var right = asValue(multiplicative())
      var left = asValue(v)
      v = token.value === "+" ? left + right : left - right
    }
  }

  function shifts() {
    var v = additive()
    while (true) {
      var token = peek()
      if (!token || token.type !== "operator" || (token.value !== "<<" && token.value !== ">>")) return v
      advance()
      sawOperator = true
      var right = asValue(additive())
      var left = asValue(v)
      // JS shifts are 32-bit; mask to keep the result a plain integer.
      v = token.value === "<<" ? (left << (right & 31)) : (left >> (right & 31))
    }
  }

  function bitAnd() {
    var v = shifts()
    while (true) {
      var token = peek()
      if (!token || token.type !== "operator" || token.value !== "&") return v
      advance()
      sawOperator = true
      v = asValue(v) & asValue(shifts())
    }
  }

  function bitXor() {
    var v = bitAnd()
    while (true) {
      var token = peek()
      if (!token || token.type !== "operator" || token.value !== "^") return v
      advance()
      sawOperator = true
      v = asValue(v) ^ asValue(bitAnd())
    }
  }

  function bitOr() {
    var v = bitXor()
    while (true) {
      var token = peek()
      if (!token || token.type !== "operator" || token.value !== "|") return v
      advance()
      sawOperator = true
      v = asValue(v) | asValue(bitXor())
    }
  }

  function expression() { return bitOr() }

  var result
  try {
    result = expression()
    if (pos !== tokens.length) return null
  } catch (e) {
    return null
  }

  // A bare decimal like 42 is just text; only a prefix, a format function or
  // an operator makes the input an equation.
  if (!sawOperator && !sawFunction && !sawPrefix) return null

  var value = (result && result.__format) ? result.value : result
  if (typeof value !== "number" || !isFinite(value)) return null
  var primary = (result && result.__format) ? result.primary : formatBaseNumber(value, "", 10)
  if (primary === null) return null

  var detail = "dec " + formatBaseNumber(value, "", 10)
    + "   hex " + formatBaseNumber(value, "0x", 16)
    + "   bin " + formatBaseNumber(value, "0b", 2)
    + "   oct " + formatBaseNumber(value, "0o", 8)

  return {
    value: value,
    valueText: value.toString(10),
    primary: primary,
    detail: detail,
    exact: Math.abs(value) <= Number.MAX_SAFE_INTEGER
  }
}

// Decimal text -> minimal big-endian bytes, via the arbitrary-precision
// converter so the byte form is exact even past Number.MAX_SAFE_INTEGER.
function integerBytesFromDecimal(decimal) {
  var s = String(decimal).trim()
  if (!/^[0-9]+$/.test(s)) return null
  if (s === "0") return [0]
  var hex = convertBaseString(s, 10, 16)
  if (hex.length % 2 !== 0) hex = "0" + hex
  return hexToBytes(hex)
}

// Bytes the pipeline should actually process: a recognised (unquoted) number
// becomes its numeric bytes, quoted text is unwrapped, everything else is the
// literal UTF-8 of the input.
function bytesForInput(text, calc) {
  if (isQuoted(text)) return textToBytes(unquote(text))
  if (calc && calc.valueText) {
    var bytes = integerBytesFromDecimal(calc.valueText)
    if (bytes) return bytes
    return textToBytes(calc.primary)
  }
  return textToBytes(text)
}

// ------------------------------------------------------------------ registry

function build() {
  return [
    // Encoding ------------------------------------------------------------
    { id: "base64-encode", name: "Base64 Encode", group: "Encoding",
      params: [{ name: "alphabet", label: "Alphabet", alphabetSize: 64, required: false, placeholder: "default: A-Za-z0-9+/" }],
      run: function(b, p) { return textToBytes(bytesToBase64(b, resolveAlphabet(p && p.alphabet, 64, B64_STD, "Base64"))) } },
    { id: "base64-decode", name: "Base64 Decode", group: "Encoding",
      params: [{ name: "alphabet", label: "Alphabet", alphabetSize: 64, required: false, placeholder: "default: A-Za-z0-9+/" }],
      run: function(b, p) { return base64ToBytes(bytesToText(b), resolveAlphabet(p && p.alphabet, 64, B64_STD, "Base64")) } },
    { id: "base58-encode", name: "Base58 Encode", group: "Encoding",
      params: [{ name: "alphabet", label: "Alphabet", alphabetSize: 58, required: false, placeholder: "default: 1-9A-HJ-NP-Za-km-z" }],
      run: function(b, p) { return textToBytes(bytesToBase58(b, resolveAlphabet(p && p.alphabet, 58, B58_ALPHABET, "Base58"))) } },
    { id: "base58-decode", name: "Base58 Decode", group: "Encoding",
      params: [{ name: "alphabet", label: "Alphabet", alphabetSize: 58, required: false, placeholder: "default: 1-9A-HJ-NP-Za-km-z" }],
      run: function(b, p) { return base58ToBytes(bytesToText(b), resolveAlphabet(p && p.alphabet, 58, B58_ALPHABET, "Base58")) } },
    { id: "base32-encode", name: "Base32 Encode", group: "Encoding",
      params: [{ name: "alphabet", label: "Alphabet", alphabetSize: 32, required: false, placeholder: "default: A-Z2-7" }],
      run: function(b, p) { return textToBytes(bytesToBase32(b, resolveAlphabet(p && p.alphabet, 32, B32_ALPHABET, "Base32"))) } },
    { id: "base32-decode", name: "Base32 Decode", group: "Encoding",
      params: [{ name: "alphabet", label: "Alphabet", alphabetSize: 32, required: false, placeholder: "default: A-Z2-7" }],
      run: function(b, p) { return base32ToBytes(bytesToText(b), resolveAlphabet(p && p.alphabet, 32, B32_ALPHABET, "Base32")) } },
    { id: "hex-encode", name: "Hex Encode", group: "Encoding",
      run: function(b) { return textToBytes(bytesToHex(b, false)) } },
    { id: "hex-decode", name: "Hex Decode", group: "Encoding",
      run: function(b) { return hexToBytes(bytesToText(b)) } },
    { id: "binary-encode", name: "Binary Encode", group: "Encoding",
      run: function(b) { return textToBytes(bytesToBinary(b)) } },
    { id: "binary-decode", name: "Binary Decode", group: "Encoding",
      run: function(b) { return binaryToBytes(bytesToText(b)) } },
    { id: "ascii-encode", name: "ASCII Encode", group: "Encoding",
      run: function(b) { return textToBytes(bytesToAscii(b)) } },
    { id: "ascii-decode", name: "ASCII Decode", group: "Encoding",
      run: function(b) { return asciiToBytes(bytesToText(b)) } },
    { id: "url-encode", name: "URL Encode", group: "Encoding",
      run: function(b) { return urlEncode(b) } },
    { id: "url-decode", name: "URL Decode", group: "Encoding",
      run: function(b) { return urlDecode(b) } },

    // Numbers -------------------------------------------------------------
    { id: "number-decimal", name: "Number → Decimal", group: "Number",
      run: function(b) { return numberToRadix(b, 10) } },
    { id: "number-hex", name: "Number → Hex", group: "Number",
      run: function(b) { return numberToRadix(b, 16) } },
    { id: "number-binary", name: "Number → Binary", group: "Number",
      run: function(b) { return numberToRadix(b, 2) } },
    { id: "number-octal", name: "Number → Octal", group: "Number",
      run: function(b) { return numberToRadix(b, 8) } },

    // Text ----------------------------------------------------------------
    { id: "rot13", name: "ROT13", group: "Text",
      run: function(b) { return rot13(b) } },
    { id: "reverse", name: "Reverse", group: "Text",
      run: function(b) { return reverseCodePoints(b) } },
    { id: "upper", name: "Uppercase", group: "Text",
      run: function(b) { return upperBytes(b) } },
    { id: "lower", name: "Lowercase", group: "Text",
      run: function(b) { return lowerBytes(b) } },

    // Crypto (openssl) ----------------------------------------------------
    // A CLI step may declare params. The values are appended to the command
    // line in declaration order after the base64 input, so $1 is always the
    // input and $2, $3, ... are the params. The overlay collects them from the
    // user when the step is added (or clicked in the pipeline).
    { id: "aes-encrypt", name: "AES-256 Encrypt", group: "Crypto",
      params: [{ name: "password", label: "Password", required: true, secret: true, placeholder: "passphrase" }],
      engine: "cli",
      script: 'printf %s "$1" | base64 -d | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass "pass:$2" | base64 -w0' },
    { id: "aes-decrypt", name: "AES-256 Decrypt", group: "Crypto",
      params: [{ name: "password", label: "Password", required: true, secret: true, placeholder: "passphrase" }],
      engine: "cli",
      script: 'printf %s "$1" | base64 -d | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass "pass:$2" | base64 -w0' },
    { id: "aes-key-encrypt", name: "AES-256 Encrypt (key + IV)", group: "Crypto",
      params: [{ name: "key", label: "Key (hex)", required: true, placeholder: "64 hex chars / 32 bytes" },
               { name: "iv", label: "IV (hex)", required: true, placeholder: "32 hex chars / 16 bytes" }],
      engine: "cli",
      script: 'printf %s "$1" | base64 -d | openssl enc -aes-256-cbc -K "$2" -iv "$3" -nosalt | base64 -w0' },
    { id: "aes-key-decrypt", name: "AES-256 Decrypt (key + IV)", group: "Crypto",
      params: [{ name: "key", label: "Key (hex)", required: true, placeholder: "64 hex chars / 32 bytes" },
               { name: "iv", label: "IV (hex)", required: true, placeholder: "32 hex chars / 16 bytes" }],
      engine: "cli",
      script: 'printf %s "$1" | base64 -d | openssl enc -d -aes-256-cbc -K "$2" -iv "$3" -nosalt | base64 -w0' },
    { id: "rsa-encrypt", name: "RSA Encrypt", group: "Crypto",
      params: [{ name: "pubkey", label: "Public key file", required: true, path: true, placeholder: "~/.keys/public.pem" }],
      engine: "cli",
      script: 'printf %s "$1" | base64 -d | openssl pkeyutl -encrypt -pubin -inkey "$2" | base64 -w0' },
    { id: "rsa-decrypt", name: "RSA Decrypt", group: "Crypto",
      params: [{ name: "privkey", label: "Private key file", required: true, path: true, placeholder: "~/.keys/private.pem" }],
      engine: "cli",
      script: 'printf %s "$1" | base64 -d | openssl pkeyutl -decrypt -inkey "$2" | base64 -w0' },
    { id: "xor", name: "XOR", group: "Crypto",
      params: [{ name: "key", label: "Key", required: true, placeholder: "keystream" }],
      run: function(b, params) {
        var k = textToBytes(params && params.key ? params.key : "")
        if (k.length === 0) throw new Error("XOR needs a key")
        var out = []
        for (var i = 0; i < b.length; i++) out.push(byteAt(b, i) ^ k[i % k.length])
        return out
      } },
    { id: "sha256", name: "SHA-256", group: "Crypto", engine: "cli", hash: true,
      params: [{ name: "separator", label: "Hex separator", required: false, placeholder: "none — continuous hex" }],
      script: 'printf %s "$1" | base64 -d | openssl dgst -sha256 -binary | base64 -w0' },
    { id: "sha512", name: "SHA-512", group: "Crypto", engine: "cli", hash: true,
      params: [{ name: "separator", label: "Hex separator", required: false, placeholder: "none — continuous hex" }],
      script: 'printf %s "$1" | base64 -d | openssl dgst -sha512 -binary | base64 -w0' },
    { id: "sha1", name: "SHA-1", group: "Crypto", engine: "cli", hash: true,
      params: [{ name: "separator", label: "Hex separator", required: false, placeholder: "none — continuous hex" }],
      script: 'printf %s "$1" | base64 -d | openssl dgst -sha1 -binary | base64 -w0' },
    { id: "md5", name: "MD5", group: "Crypto", engine: "cli", hash: true,
      params: [{ name: "separator", label: "Hex separator", required: false, placeholder: "none — continuous hex" }],
      script: 'printf %s "$1" | base64 -d | openssl dgst -md5 -binary | base64 -w0' },
    { id: "gzip", name: "Gzip", group: "Crypto", engine: "cli",
      script: 'printf %s "$1" | base64 -d | gzip -9 | base64 -w0' },
    { id: "gunzip", name: "Gunzip", group: "Crypto", engine: "cli",
      script: 'printf %s "$1" | base64 -d | gzip -d | base64 -w0' }
  ]
}

var _registry = null

function list() {
  if (!_registry) {
    _registry = build()
    // Native entries omit `engine`; stamp it once so consumers can branch on
    // engine without treating undefined as anything special.
    for (var i = 0; i < _registry.length; i++) {
      if (_registry[i].engine === undefined) _registry[i].engine = "native"
    }
  }
  return _registry
}

function byId(id) {
  var all = list()
  for (var i = 0; i < all.length; i++) if (all[i].id === id) return all[i]
  return null
}

// Plain metadata for the picker list: no functions go into a ListView model.
function catalog() {
  var all = list()
  var out = []
  for (var i = 0; i < all.length; i++) {
    out.push({
      id: all[i].id,
      name: all[i].name,
      group: all[i].group,
      engine: all[i].engine,
      params: all[i].params || []
    })
  }
  return out
}
