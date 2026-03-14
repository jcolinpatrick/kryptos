/**
 * kryptosbot.com — Workbench: client-side K4 cipher experimentation
 * All computation runs in the browser. No data is sent to any server.
 */
(function () {
  "use strict";

  // --- Constants ---
  var CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR";
  var AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ";

  // Known cribs (0-indexed): positions 21-33 = EASTNORTHEAST, 63-73 = BERLINCLOCK
  var CRIBS = {};
  var ENE = "EASTNORTHEAST";
  var BC = "BERLINCLOCK";
  for (var i = 0; i < ENE.length; i++) CRIBS[21 + i] = ENE[i];
  for (var j = 0; j < BC.length; j++) CRIBS[63 + j] = BC[j];

  // W positions that bracket the cribs
  var W_POSITIONS = [20, 36, 48, 58, 74];

  // Bean constraints: k[27] = k[65], plus variant-independent inequalities.
  var BEAN_EQ = [27, 65];
  var BEAN_INEQ = (function () {
    var positions = Object.keys(CRIBS).map(Number).sort(function (a, b) { return a - b; });
    var pairs = [];
    for (var i = 0; i < positions.length; i++) {
      for (var j = i + 1; j < positions.length; j++) {
        var a = positions[i], b = positions[j];
        var ca = CT.charCodeAt(a) - 65, pa = CRIBS[a].charCodeAt(0) - 65;
        var cb = CT.charCodeAt(b) - 65, pb = CRIBS[b].charCodeAt(0) - 65;
        var vigEq = ((ca - pa + 26) % 26) === ((cb - pb + 26) % 26);
        var beauEq = ((ca + pa) % 26) === ((cb + pb) % 26);
        var vbEq = ((pa - ca + 26) % 26) === ((pb - cb + 26) % 26);
        if (!vigEq && !beauEq && !vbEq) pairs.push([a, b]);
      }
    }
    return pairs;
  })();

  // --- Elimination data ---
  var ELIMINATIONS = {
    "none:vigenere":     { severity: "proven", msg: "Single-layer Vigen\u00e8re on raw 97 chars is mathematically eliminated (key conflicts at all periods 1\u201326)." },
    "none:beaufort":     { severity: "proven", msg: "Single-layer Beaufort on raw 97 chars is mathematically eliminated (key conflicts at all periods 1\u201326)." },
    "none:varbeaufort":  { severity: "proven", msg: "Single-layer Variant Beaufort on raw 97 chars is mathematically eliminated (key conflicts at all periods 1\u201326)." },
    "none:autokey-vig":  { severity: "exhausted", msg: "Autokey Vigen\u00e8re on raw 97 chars: exhaustively tested (156 single-letter + 1M dictionary keys). Zero crib hits." },
    "none:autokey-beau": { severity: "exhausted", msg: "Autokey Beaufort on raw 97 chars: exhaustively tested. Zero crib hits." },
    "none:caesar":       { severity: "proven", msg: "Caesar (monoalphabetic shift) is a special case of Vigen\u00e8re period 1 \u2014 mathematically eliminated." },
    "none:atbash":       { severity: "proven", msg: "Atbash is a fixed monoalphabetic substitution \u2014 mathematically eliminated." },
    "columnar:vigenere":   { severity: "exhausted", msg: "Columnar \u00d7 periodic Vigen\u00e8re: 47M+ configs tested across all widths and periods 1\u201313. Best: 9/24 (noise)." },
    "columnar:beaufort":   { severity: "exhausted", msg: "Columnar \u00d7 periodic Beaufort: 47M+ configs tested. Best: 9/24 (noise)." },
    "columnar:varbeaufort": { severity: "exhausted", msg: "Columnar \u00d7 periodic Variant Beaufort: 47M+ configs tested. Best: 9/24 (noise)." },
    "columnar:autokey-vig":  { severity: "open", msg: "Columnar + autokey Vigen\u00e8re: partially tested but large keyspace remains. Productive territory." },
    "columnar:autokey-beau": { severity: "open", msg: "Columnar + autokey Beaufort: partially tested. Productive territory." },
    "railfence:vigenere":    { severity: "open", msg: "Rail fence + Vigen\u00e8re: open territory. Non-standard transposition not exhaustively tested." },
    "railfence:beaufort":    { severity: "open", msg: "Rail fence + Beaufort: open territory." },
    "serpentine:vigenere":   { severity: "open", msg: "Serpentine + Vigen\u00e8re: open territory. Boustrophedon reading not yet tested with substitution." },
    "serpentine:beaufort":   { severity: "open", msg: "Serpentine + Beaufort: open territory." },
    "spiral:vigenere":       { severity: "open", msg: "Spiral + Vigen\u00e8re: open territory. Spiral transposition not yet tested." },
    "spiral:beaufort":       { severity: "open", msg: "Spiral + Beaufort: open territory." },
    "myszkowski:vigenere":   { severity: "open", msg: "Myszkowski + Vigen\u00e8re: open territory. Tied-column transposition not exhaustively tested." },
    "myszkowski:beaufort":   { severity: "open", msg: "Myszkowski + Beaufort: open territory." },
    "none:quagmire-ii":      { severity: "exhausted", msg: "Quagmire II (sculpture tableau) on raw 97: all periods 1\u201326 eliminated. Cross-alphabet key conflicts at all periods." },
    "none:quagmire-ii-autokey": { severity: "exhausted", msg: "Q2 autokey on raw 97: 390 indicator/keyword/variant configs tested (2026-03-14). Best 13/24 with null mask." },
    "columnar:quagmire-ii":  { severity: "open", msg: "Columnar + Q2: KOMPASS:vig+col7 reached 14/24. Below DEFECTOR:AZ_beau+col7 (15/24). Partially explored." },
    "columnar:quagmire-ii-autokey": { severity: "open", msg: "Columnar + Q2 autokey: open territory." },
    "none:four-square":      { severity: "proven", msg: "Four-Square on raw 97: eliminated. SA 200\u00d780K configs, ceiling 23/24 (never 24). Digraphic IC=1.66 (random)." },
    "columnar:four-square":  { severity: "open", msg: "Columnar + Four-Square: open territory." },
    "none:porta":            { severity: "proven", msg: "Porta cipher: eliminated analytically (2026-03-13). Key conflicts at all periods." },
    "none:gronsfeld":        { severity: "proven", msg: "Gronsfeld: eliminated analytically (2026-03-13). Special case of Vigen\u00e8re with digits 0\u20139." },
    "none:affine":           { severity: "proven", msg: "Affine cipher on 97 chars: all 9,312 (a,b) pairs tested exhaustively. Best 8/24 (noise)." },
    "none:rot13":            { severity: "proven", msg: "ROT13: special case of Caesar shift 13 \u2014 mathematically eliminated." }
  };

  // --- Top 50 English trigrams for text quality scoring ---
  var TOP_TRIGRAMS = [
    "THE", "AND", "ING", "ION", "TIO", "ENT", "ERE", "HER", "ATE", "VER",
    "TER", "THA", "ATI", "HAT", "FOR", "EST", "ALL", "INT", "ITH", "HIS",
    "OFT", "STH", "NOT", "RES", "ORT", "WAS", "ARE", "ONE", "OUR", "OUT",
    "HAS", "AVE", "MAN", "PRO", "ERS", "COM", "NTH", "STI", "TED", "OTH",
    "ITI", "ERA", "ECT", "NDE", "IST", "OME", "NGT", "NCE", "ANT", "DER"
  ];
  var TRIGRAM_SET = {};
  for (var ti = 0; ti < TOP_TRIGRAMS.length; ti++) TRIGRAM_SET[TOP_TRIGRAMS[ti]] = true;

  // --- Session history ---
  var sessionHistory = [];

  // --- DOM Elements ---
  var ctDisplay = document.getElementById("ct-display");
  var transMethod = document.getElementById("trans-method");
  var transColumnar = document.getElementById("trans-opts-columnar");
  var transRailfence = document.getElementById("trans-opts-railfence");
  var transSerpentine = document.getElementById("trans-opts-serpentine");
  var transSpiral = document.getElementById("trans-opts-spiral");
  var transMyszkowski = document.getElementById("trans-opts-myszkowski");
  var transManual = document.getElementById("trans-opts-manual");
  var subMethod = document.getElementById("sub-method");
  var subKey = document.getElementById("sub-key");
  var subKeyGroup = document.getElementById("sub-key-group");
  var subCaesarGroup = document.getElementById("sub-caesar-group");
  var subShift = document.getElementById("sub-shift");
  var subAlphabet = document.getElementById("sub-alphabet");
  var resultsEmpty = document.getElementById("results-empty");
  var resultsPanel = document.getElementById("results-panel");
  var transResult = document.getElementById("trans-result");
  var transposedCt = document.getElementById("transposed-ct");
  var ptDisplay = document.getElementById("plaintext-display");
  var scoreCrib = document.getElementById("score-crib");
  var scoreEne = document.getElementById("score-ene");
  var scoreBc = document.getElementById("score-bc");
  var scoreIc = document.getElementById("score-ic");
  var scoreBean = document.getElementById("score-bean");
  var scoreFree = document.getElementById("score-free");
  var keystreamDetail = document.getElementById("keystream-detail");
  var keystreamAnalysis = document.getElementById("keystream-analysis");
  var wHighlight = document.getElementById("w-highlight");
  var wSegments = document.getElementById("w-segments");
  var nullMode = document.getElementById("null-mode");
  var nullManualGroup = document.getElementById("null-manual-group");
  var nullPositionsInput = document.getElementById("null-positions");
  var nullCribModel = document.getElementById("null-crib-model");
  var nullExtractedDiv = document.getElementById("null-extracted");
  var nullExtractedCt = document.getElementById("null-extracted-ct");
  var nullExtractedLen = document.getElementById("null-extracted-len");
  var nullCountSpan = document.getElementById("null-count");
  var eliminationWarning = document.getElementById("elimination-warning");
  var scoreTrigram = document.getElementById("score-trigram");
  var gridViewCheckbox = document.getElementById("grid-view");
  var gridViewContainer = document.getElementById("grid-view-container");
  var gridViewPre = document.getElementById("grid-view-pre");
  var historyCount = document.getElementById("history-count");
  var historyLog = document.getElementById("history-log");

  // --- Render CT display with crib and W highlighting ---
  function renderCT(text, container, opts) {
    opts = opts || {};
    var showW = opts.showW || false;
    var nullPositions = opts.nullPositions || {};
    var cribs = opts.cribs || CRIBS;

    var html = "";
    for (var i = 0; i < text.length; i++) {
      var classes = [];
      if (cribs[i] !== undefined) classes.push("crib");
      if (showW && text[i] === "W" && W_POSITIONS.indexOf(i) >= 0) classes.push("w-marker");
      if (nullPositions[i]) classes.push("null-char");

      if (classes.length > 0) {
        html += '<span class="' + classes.join(" ") + '">' + text[i] + "</span>";
      } else {
        html += text[i];
      }
    }
    container.innerHTML = html;
    container.classList.add("text-mono");
  }

  renderCT(CT, ctDisplay);

  // --- Alphabet helpers ---
  function getAlphabet() {
    return subAlphabet.value === "KA" ? KA : AZ;
  }

  function alphaIndex(ch, alpha) {
    return alpha.indexOf(ch.toUpperCase());
  }

  function mod(n, m) {
    return ((n % m) + m) % m;
  }

  // --- Null mask helpers ---
  function getNullPositions() {
    var mode = nullMode.value;
    if (mode === "disabled") return [];
    if (mode === "w-only") return W_POSITIONS.slice();
    // manual
    var str = nullPositionsInput.value.trim();
    if (!str) return [];
    return str.split(",").map(function (s) { return parseInt(s.trim()); })
      .filter(function (n) { return !isNaN(n) && n >= 0 && n < CT.length; });
  }

  function extractCT(text, nullPos) {
    var posSet = {};
    for (var i = 0; i < nullPos.length; i++) posSet[nullPos[i]] = true;
    var result = "";
    for (var j = 0; j < text.length; j++) {
      if (!posSet[j]) result += text[j];
    }
    return result;
  }

  function remapCribs(nullPos) {
    // Model A: after removing nulls, crib positions shift
    var posSet = {};
    for (var i = 0; i < nullPos.length; i++) posSet[nullPos[i]] = true;

    var remapped = {};
    var newIdx = 0;
    for (var j = 0; j < CT.length; j++) {
      if (!posSet[j]) {
        if (CRIBS[j] !== undefined) {
          remapped[newIdx] = CRIBS[j];
        }
        newIdx++;
      }
    }
    return remapped;
  }

  // --- Keyword to column order ---
  function keywordToOrder(keyword, width) {
    var kw = keyword.toUpperCase().replace(/[^A-Z]/g, "").substring(0, width);
    if (kw.length < width) return null;
    var indexed = [];
    for (var i = 0; i < kw.length; i++) indexed.push([kw[i], i]);
    indexed.sort(function (a, b) {
      if (a[0] < b[0]) return -1;
      if (a[0] > b[0]) return 1;
      return a[1] - b[1];
    });
    var order = new Array(width);
    for (var rank = 0; rank < indexed.length; rank++) {
      order[indexed[rank][1]] = rank;
    }
    return order;
  }

  // --- Transposition implementations ---
  function applyTransposition(text) {
    var method = transMethod.value;
    if (method === "none") return text;
    if (method === "columnar") return columnarTranspose(text);
    if (method === "railfence") return railfenceTranspose(text);
    if (method === "serpentine") return serpentineTranspose(text);
    if (method === "spiral") return spiralTranspose(text);
    if (method === "myszkowski") return myszkowskiTranspose(text);
    if (method === "manual") return manualTranspose(text);
    return text;
  }

  function columnarTranspose(text) {
    var width = parseInt(document.getElementById("trans-width").value) || 10;

    // Check for keyword-derived column order first
    var kwInput = document.getElementById("trans-keyword").value.trim();
    var orderStr = document.getElementById("trans-colorder").value.trim();
    var n = text.length;
    var rows = Math.ceil(n / width);

    var colOrder;
    if (kwInput) {
      colOrder = keywordToOrder(kwInput, width);
      if (!colOrder) return text; // keyword too short
    } else if (orderStr) {
      colOrder = orderStr.split(",").map(function (s) { return parseInt(s.trim()); });
      if (colOrder.length !== width) return text;
    } else {
      colOrder = [];
      for (var c = 0; c < width; c++) colOrder.push(c);
    }

    // Read off columns in the given order to undo columnar transposition
    var fullCols = n % width || width;
    var result = new Array(n);
    var pos = 0;

    for (var ci = 0; ci < width; ci++) {
      var col = colOrder[ci];
      var colLen = col < (n % width || width) ? rows : rows - (n % width === 0 ? 0 : 1);
      if (n % width === 0) colLen = rows;
      for (var r = 0; r < colLen; r++) {
        result[r * width + col] = text[pos++];
      }
    }
    return result.join("");
  }

  function railfenceTranspose(text) {
    var depth = parseInt(document.getElementById("trans-depth").value) || 3;
    var n = text.length;
    if (depth <= 1 || depth >= n) return text;

    var railLens = new Array(depth).fill(0);
    var rail = 0, dir = 1;
    for (var i = 0; i < n; i++) {
      railLens[rail]++;
      if (rail === 0) dir = 1;
      else if (rail === depth - 1) dir = -1;
      rail += dir;
    }

    var rails = [];
    var pos = 0;
    for (var r = 0; r < depth; r++) {
      rails.push(text.substring(pos, pos + railLens[r]));
      pos += railLens[r];
    }

    var result = "";
    var indices = new Array(depth).fill(0);
    rail = 0; dir = 1;
    for (var k = 0; k < n; k++) {
      result += rails[rail][indices[rail]++];
      if (rail === 0) dir = 1;
      else if (rail === depth - 1) dir = -1;
      rail += dir;
    }
    return result;
  }

  // Generate a permutation and undo it (inverse apply)
  function undoPermutation(text, perm) {
    if (perm.length !== text.length) return text;
    // perm is the read-off order: CT[i] = original[perm[i]]
    // To undo: original[perm[i]] = CT[i]
    var result = new Array(text.length);
    for (var i = 0; i < perm.length; i++) {
      result[perm[i]] = text[i];
    }
    return result.join("");
  }

  function serpentineTranspose(text) {
    var width = parseInt(document.getElementById("trans-serp-width").value) || 10;
    var vertical = document.getElementById("trans-serp-vertical").checked;
    var n = text.length;
    var rows = Math.ceil(n / width);

    var perm = [];
    if (!vertical) {
      for (var r = 0; r < rows; r++) {
        if (r % 2 === 0) {
          for (var c = 0; c < width; c++) {
            var pos = r * width + c;
            if (pos < n) perm.push(pos);
          }
        } else {
          for (var c2 = width - 1; c2 >= 0; c2--) {
            var pos2 = r * width + c2;
            if (pos2 < n) perm.push(pos2);
          }
        }
      }
    } else {
      for (var c3 = 0; c3 < width; c3++) {
        if (c3 % 2 === 0) {
          for (var r2 = 0; r2 < rows; r2++) {
            var pos3 = r2 * width + c3;
            if (pos3 < n) perm.push(pos3);
          }
        } else {
          for (var r3 = rows - 1; r3 >= 0; r3--) {
            var pos4 = r3 * width + c3;
            if (pos4 < n) perm.push(pos4);
          }
        }
      }
    }
    return undoPermutation(text, perm);
  }

  function spiralTranspose(text) {
    var width = parseInt(document.getElementById("trans-spiral-width").value) || 10;
    var ccw = document.getElementById("trans-spiral-ccw").checked;
    var n = text.length;
    var rows = Math.ceil(n / width);

    var visited = [];
    for (var ri = 0; ri < rows; ri++) {
      visited.push(new Array(width).fill(false));
    }

    var dirs = ccw
      ? [[1, 0], [0, 1], [-1, 0], [0, -1]]
      : [[0, 1], [1, 0], [0, -1], [-1, 0]];

    var perm = [];
    var r = 0, c = 0, d = 0;
    for (var step = 0; step < rows * width; step++) {
      var pos = r * width + c;
      if (pos < n) perm.push(pos);
      visited[r][c] = true;

      var nr = r + dirs[d][0], nc = c + dirs[d][1];
      if (nr >= 0 && nr < rows && nc >= 0 && nc < width && !visited[nr][nc]) {
        r = nr; c = nc;
      } else {
        d = (d + 1) % 4;
        nr = r + dirs[d][0]; nc = c + dirs[d][1];
        if (nr >= 0 && nr < rows && nc >= 0 && nc < width && !visited[nr][nc]) {
          r = nr; c = nc;
        } else {
          break;
        }
      }
    }
    return undoPermutation(text, perm);
  }

  function myszkowskiTranspose(text) {
    var keyword = (document.getElementById("trans-mysz-keyword").value || "").toUpperCase().replace(/[^A-Z]/g, "");
    if (!keyword) return text;
    var width = keyword.length;
    var n = text.length;
    var rows = Math.ceil(n / width);

    // Rank letters: tied letters get the same rank
    var uniqueSorted = [];
    var seen = {};
    var kwArr = keyword.split("").slice();
    kwArr.sort();
    for (var s = 0; s < kwArr.length; s++) {
      if (!seen[kwArr[s]]) { uniqueSorted.push(kwArr[s]); seen[kwArr[s]] = true; }
    }
    var letterRank = {};
    for (var u = 0; u < uniqueSorted.length; u++) letterRank[uniqueSorted[u]] = u;
    var colRanks = [];
    for (var k = 0; k < keyword.length; k++) colRanks.push(letterRank[keyword[k]]);

    // Group columns by rank
    var rankToCols = {};
    for (var ci = 0; ci < colRanks.length; ci++) {
      var rk = colRanks[ci];
      if (!rankToCols[rk]) rankToCols[rk] = [];
      rankToCols[rk].push(ci);
    }

    // Build column contents
    var cols = {};
    for (var p = 0; p < n; p++) {
      var col = p % width;
      if (!cols[col]) cols[col] = [];
      cols[col].push(p);
    }

    // Build perm: read ranks in order, tied columns row-by-row
    var perm = [];
    var sortedRanks = Object.keys(rankToCols).map(Number).sort(function (a, b) { return a - b; });
    for (var ri = 0; ri < sortedRanks.length; ri++) {
      var tiedCols = rankToCols[sortedRanks[ri]];
      if (tiedCols.length === 1) {
        var colPositions = cols[tiedCols[0]] || [];
        for (var cp = 0; cp < colPositions.length; cp++) perm.push(colPositions[cp]);
      } else {
        for (var row = 0; row < rows; row++) {
          for (var tc = 0; tc < tiedCols.length; tc++) {
            var pos = row * width + tiedCols[tc];
            if (pos < n) perm.push(pos);
          }
        }
      }
    }
    return undoPermutation(text, perm);
  }

  function manualTranspose(text) {
    var permStr = document.getElementById("trans-perm").value.trim();
    if (!permStr) return text;
    var perm = permStr.split(",").map(function (s) { return parseInt(s.trim()); });
    if (perm.length !== text.length) return text;
    // output[i] = input[perm[i]] (gather convention)
    var result = "";
    for (var i = 0; i < perm.length; i++) {
      var idx = perm[i];
      if (idx < 0 || idx >= text.length) return text;
      result += text[idx];
    }
    return result;
  }

  // --- Substitution implementations ---
  function applySubstitution(text) {
    var method = subMethod.value;
    var alpha = getAlphabet();

    if (method === "none") return text;
    if (method === "atbash") return atbash(text, alpha);
    if (method === "caesar") {
      var shift = parseInt(subShift.value) || 0;
      return caesar(text, shift, alpha);
    }

    var key = subKey.value.toUpperCase().replace(/[^A-Z]/g, "");
    if (!key) return null;

    if (method === "vigenere") return vigenere(text, key, alpha);
    if (method === "beaufort") return beaufort(text, key, alpha);
    if (method === "varbeaufort") return varBeaufort(text, key, alpha);
    if (method === "autokey-vig") return autokeyVig(text, key, alpha);
    if (method === "autokey-beau") return autokeyBeau(text, key, alpha);
    if (method === "quagmire-ii") {
      var ind = (document.getElementById("sub-indicator").value || "K").toUpperCase();
      return quagmireII(text, key, ind);
    }
    if (method === "quagmire-ii-autokey") {
      var ind2 = (document.getElementById("sub-indicator").value || "K").toUpperCase();
      return quagmireIIAutokey(text, key, ind2);
    }
    if (method === "four-square") {
      var key2 = (document.getElementById("sub-key2").value || "").toUpperCase().replace(/[^A-Z]/g, "");
      if (!key2) return null;
      return fourSquare(text, key, key2);
    }
    if (method === "porta") return porta(text, key);
    if (method === "gronsfeld") return gronsfeld(text, key);
    if (method === "affine") {
      var parts = key.split(/[^0-9]+/).filter(Boolean);
      if (parts.length < 2) return null;
      return affine(text, parseInt(parts[0]), parseInt(parts[1]));
    }
    if (method === "rot13") return rot13(text);
    return text;
  }

  function vigenere(ct, key, alpha) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      pt += alpha[mod(c - k, 26)];
    }
    return pt;
  }

  function beaufort(ct, key, alpha) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      pt += alpha[mod(k - c, 26)];
    }
    return pt;
  }

  function varBeaufort(ct, key, alpha) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      pt += alpha[mod(c + k, 26)];
    }
    return pt;
  }

  function autokeyVig(ct, key, alpha) {
    var pt = "";
    var fullKey = key.split("");
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(fullKey[i], alpha);
      var p = mod(c - k, 26);
      pt += alpha[p];
      fullKey.push(alpha[p]);
    }
    return pt;
  }

  function autokeyBeau(ct, key, alpha) {
    var pt = "";
    var fullKey = key.split("");
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(fullKey[i], alpha);
      var p = mod(k - c, 26);
      pt += alpha[p];
      fullKey.push(alpha[p]);
    }
    return pt;
  }

  function caesar(ct, shift, alpha) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      pt += alpha[mod(c - shift, 26)];
    }
    return pt;
  }

  function atbash(ct, alpha) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      pt += alpha[25 - c];
    }
    return pt;
  }

  // --- Quagmire II (sculpture tableau) ---
  // The Kryptos sculpture IS a Quagmire II tableau: KA body, AZ edges.
  // K1-K3 used Quagmire III (KA everywhere). The Q2 tableau may be for K4.
  // CT = KA[(AZ.index(key) + KA.index(PT) - indicator_pos) % 26]
  // Decrypt: PT = KA[(KA.index(CT) - AZ.index(key) + indicator_pos) % 26]
  function quagmireII(ct, key, indicator) {
    var indPos = KA.indexOf(indicator.charAt(0));
    if (indPos < 0) indPos = 0;
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = KA.indexOf(ct[i]);
      var k = AZ.indexOf(key.charAt(i % key.length));
      pt += KA[mod(c - k + indPos, 26)];
    }
    return pt;
  }

  // Quagmire II Autokey: PT-feedback with AZ key indexing
  function quagmireIIAutokey(ct, key, indicator) {
    var indPos = KA.indexOf(indicator.charAt(0));
    if (indPos < 0) indPos = 0;
    var pt = "";
    var fullKey = key.split("");
    for (var i = 0; i < ct.length; i++) {
      var c = KA.indexOf(ct[i]);
      var k = AZ.indexOf(fullKey[i]);
      var pIdx = mod(c - k + indPos, 26);
      var pChar = KA[pIdx];
      pt += pChar;
      fullKey.push(pChar); // PT-feedback: next key letter = PT letter
    }
    return pt;
  }

  // --- Four-Square cipher ---
  // Digraphic cipher using two 5x5 keyed grids.
  // Since K4 uses all 26 letters, we use 6x5=30 grid (no J/Q merge needed).
  // But classic Four-Square uses 5x5 with I=J. We implement both:
  // Standard 5x5 (I=J merged) since that's the historical form.
  function buildFourSquareGrid(keyword) {
    var seen = {};
    var grid = [];
    // Add keyword letters first (skip J, treat as I)
    for (var i = 0; i < keyword.length; i++) {
      var ch = keyword[i] === "J" ? "I" : keyword[i];
      if (!seen[ch] && ch >= "A" && ch <= "Z") {
        seen[ch] = true;
        grid.push(ch);
      }
    }
    // Fill remaining (skip J)
    for (var c = 0; c < 26; c++) {
      var ch = String.fromCharCode(65 + c);
      if (ch === "J") continue;
      if (!seen[ch]) {
        seen[ch] = true;
        grid.push(ch);
      }
    }
    return grid; // 25 chars
  }

  function fourSquare(ct, key1, key2) {
    var plain = buildFourSquareGrid(""); // standard A-Z (no J)
    var grid1 = buildFourSquareGrid(key1);
    var grid2 = buildFourSquareGrid(key2);
    // Normalize CT: replace J with I
    var text = ct.replace(/J/g, "I");
    // Pad to even length
    if (text.length % 2 !== 0) text += "X";
    var pt = "";
    for (var i = 0; i < text.length; i += 2) {
      // Find positions in keyed grids
      var idx1 = grid1.indexOf(text[i]);
      var idx2 = grid2.indexOf(text[i + 1]);
      if (idx1 < 0 || idx2 < 0) { pt += text[i] + text[i + 1]; continue; }
      var r1 = Math.floor(idx1 / 5), c1 = idx1 % 5;
      var r2 = Math.floor(idx2 / 5), c2 = idx2 % 5;
      // Decrypt: swap columns between grids, read from plain grids
      pt += plain[r1 * 5 + c2];
      pt += plain[r2 * 5 + c1];
    }
    return pt;
  }

  // --- Porta cipher ---
  // Reciprocal cipher: 13 alphabets, period = key length
  function porta(ct, key) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = ct.charCodeAt(i) - 65;
      var k = Math.floor((key.charCodeAt(i % key.length) - 65) / 2); // 0-12
      var p;
      if (c < 13) {
        p = (c + k) % 13 + 13;
      } else {
        p = (c - 13 - k + 13) % 13;
      }
      pt += String.fromCharCode(p + 65);
    }
    return pt;
  }

  // --- Affine cipher ---
  // P = a_inv * (C - b) mod 26
  function affine(ct, a, b) {
    // Find modular inverse of a mod 26
    var aInv = -1;
    for (var i = 1; i < 26; i++) {
      if ((a * i) % 26 === 1) { aInv = i; break; }
    }
    if (aInv < 0) return null; // a not coprime to 26
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = ct.charCodeAt(i) - 65;
      pt += String.fromCharCode(mod(aInv * (c - b), 26) + 65);
    }
    return pt;
  }

  // --- Gronsfeld cipher (numeric key) ---
  function gronsfeld(ct, key) {
    var pt = "";
    var digits = key.replace(/[^0-9]/g, "");
    if (!digits) return null;
    for (var i = 0; i < ct.length; i++) {
      var c = ct.charCodeAt(i) - 65;
      var k = parseInt(digits[i % digits.length]);
      pt += String.fromCharCode(mod(c - k, 26) + 65);
    }
    return pt;
  }

  // --- ROT13 ---
  function rot13(ct) {
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = ct.charCodeAt(i) - 65;
      pt += String.fromCharCode((c + 13) % 26 + 65);
    }
    return pt;
  }

  // --- Scoring ---
  function scoreCribs(pt, cribs) {
    cribs = cribs || CRIBS;
    var eneHits = 0, bcHits = 0;
    var matched = [];
    for (var pos in cribs) {
      if (parseInt(pos) < pt.length && pt[pos] === cribs[pos]) {
        matched.push(parseInt(pos));
        // Determine which crib group this belongs to
        var origPos = parseInt(pos);
        // For remapped cribs, check the expected letter
        if (ENE.indexOf(cribs[pos]) >= 0 && origPos < pt.length) {
          // Heuristic: check if this is an ENE or BC position
          // For standard CRIBS, check position ranges
          if (cribs === CRIBS) {
            if (origPos >= 21 && origPos <= 33) eneHits++;
            else bcHits++;
          } else {
            // For remapped cribs, we track by the original crib letter
            // This is approximate — count by letter membership
            eneHits++; // simplified: assign to ENE by default for remapped
          }
        } else {
          bcHits++;
        }
      }
    }
    // Fix scoring for standard cribs
    if (cribs === CRIBS) {
      eneHits = 0; bcHits = 0;
      for (var pos2 in CRIBS) {
        var p = parseInt(pos2);
        if (p < pt.length && pt[p] === CRIBS[p]) {
          if (p >= 21 && p <= 33) eneHits++;
          else bcHits++;
        }
      }
    }
    return { total: eneHits + bcHits, ene: eneHits, bc: bcHits, matched: matched };
  }

  function calcIC(text) {
    var freq = {};
    for (var i = 0; i < text.length; i++) {
      freq[text[i]] = (freq[text[i]] || 0) + 1;
    }
    var n = text.length;
    var sum = 0;
    for (var ch in freq) {
      sum += freq[ch] * (freq[ch] - 1);
    }
    return n > 1 ? sum / (n * (n - 1)) : 0;
  }

  // Build a mapping from CT97 position to working-text position after null removal
  function buildPositionMap(nullPos) {
    if (!nullPos || nullPos.length === 0) return null;
    var posSet = {};
    for (var i = 0; i < nullPos.length; i++) posSet[nullPos[i]] = true;
    var map = {};
    var newIdx = 0;
    for (var j = 0; j < CT.length; j++) {
      if (!posSet[j]) {
        map[j] = newIdx;
        newIdx++;
      }
    }
    return map;
  }

  function checkBean(ct, pt, alpha, method, nullPos) {
    // When null mask is active (Model A), crib positions shift.
    // We need to map the original CT97 crib positions to positions in the
    // working text. The Bean constraints are defined in CT97 space (positions
    // 27, 65 for equality; pairs from BEAN_INEQ). We must remap them.
    var posMap = buildPositionMap(nullPos);

    var keys = {};
    for (var pos in CRIBS) {
      var origPos = parseInt(pos);
      // Determine the actual position in the working ct/pt
      var workPos = posMap ? posMap[origPos] : origPos;
      if (workPos === undefined || workPos >= ct.length || workPos >= pt.length) continue;
      var c = alphaIndex(ct[workPos], alpha);
      var pv = alphaIndex(pt[workPos], alpha);
      if (method === "beaufort" || method === "autokey-beau") {
        keys[origPos] = mod(c + pv, 26);
      } else if (method === "varbeaufort") {
        keys[origPos] = mod(pv - c, 26);
      } else {
        keys[origPos] = mod(c - pv, 26);
      }
    }

    // Bean equality check uses original CT97 positions
    if (keys[BEAN_EQ[0]] === undefined || keys[BEAN_EQ[1]] === undefined) return null;
    if (keys[BEAN_EQ[0]] !== keys[BEAN_EQ[1]]) return false;

    // Bean inequality checks also use original CT97 positions
    for (var i = 0; i < BEAN_INEQ.length; i++) {
      var a = BEAN_INEQ[i][0], b = BEAN_INEQ[i][1];
      if (keys[a] === undefined || keys[b] === undefined) continue;
      if (keys[a] === keys[b]) return false;
    }
    return true;
  }

  function freeCribSearch(pt) {
    var hits = [];
    var eneIdx = pt.indexOf(ENE);
    if (eneIdx >= 0) hits.push("ENE@" + eneIdx);
    var bcIdx = pt.indexOf(BC);
    if (bcIdx >= 0) hits.push("BC@" + bcIdx);
    if (hits.length === 0) {
      for (var len = 6; len <= ENE.length; len++) {
        for (var start = 0; start <= pt.length - len; start++) {
          var sub = pt.substring(start, start + len);
          if (ENE.indexOf(sub) >= 0 && len >= 6) {
            hits.push(sub + "@" + start);
            break;
          }
        }
        if (hits.length > 0) break;
      }
    }
    return hits.length > 0 ? hits.join(", ") : "None";
  }

  function scoreTrigrams(text) {
    if (text.length < 3) return { hits: 0, total: 0, pct: 0 };
    var total = text.length - 2;
    var hits = 0;
    for (var i = 0; i <= text.length - 3; i++) {
      if (TRIGRAM_SET[text.substring(i, i + 3)]) hits++;
    }
    return { hits: hits, total: total, pct: total > 0 ? (100 * hits / total) : 0 };
  }

  function deriveKeystream(ct, pt, alpha, method, cribs) {
    cribs = cribs || CRIBS;
    var lines = [];
    var positions = Object.keys(cribs).map(Number).sort(function (a, b) { return a - b; });
    for (var i = 0; i < positions.length; i++) {
      var pos = positions[i];
      if (pos >= ct.length || pos >= pt.length) continue;
      var c = alphaIndex(ct[pos], alpha);
      var p = alphaIndex(pt[pos], alpha);
      var kVal;
      if (method === "beaufort" || method === "autokey-beau") {
        kVal = mod(c + p, 26);
      } else if (method === "varbeaufort") {
        kVal = mod(p - c, 26);
      } else {
        kVal = mod(c - p, 26);
      }
      var expected = cribs[pos];
      var match = pt[pos] === expected ? "OK" : "MISS";
      lines.push(
        "pos=" + String(pos).padStart(2) +
        "  CT=" + ct[pos] +
        "  PT=" + pt[pos] +
        "  expected=" + expected +
        "  k=" + String(kVal).padStart(2) +
        " (" + AZ[kVal] + ")  " + match
      );
    }
    return lines.join("\n");
  }

  // --- Keystream period consistency analysis ---
  function analyzeKeystream(ct, pt, alpha, method, cribs) {
    cribs = cribs || CRIBS;
    var positions = Object.keys(cribs).map(Number).sort(function (a, b) { return a - b; });

    // Derive keystream values at crib positions
    var keyVals = {};
    for (var i = 0; i < positions.length; i++) {
      var pos = positions[i];
      if (pos >= ct.length || pos >= pt.length) continue;
      var c = alphaIndex(ct[pos], alpha);
      var p = alphaIndex(pt[pos], alpha);
      if (method === "beaufort" || method === "autokey-beau") {
        keyVals[pos] = mod(c + p, 26);
      } else if (method === "varbeaufort") {
        keyVals[pos] = mod(p - c, 26);
      } else {
        keyVals[pos] = mod(c - p, 26);
      }
    }

    var html = '<table class="keystream-table"><thead><tr><th>Period</th><th>Conflicts</th><th>Verdict</th></tr></thead><tbody>';

    for (var period = 2; period <= 13; period++) {
      // Group crib positions by residue class mod period
      var residueGroups = {};
      for (var j = 0; j < positions.length; j++) {
        var pos2 = positions[j];
        if (keyVals[pos2] === undefined) continue;
        var res = pos2 % period;
        if (!residueGroups[res]) residueGroups[res] = [];
        residueGroups[res].push(keyVals[pos2]);
      }

      // Count conflicts: within each residue group, all values should be equal
      var conflicts = 0;
      for (var res2 in residueGroups) {
        var vals = residueGroups[res2];
        if (vals.length < 2) continue;
        var first = vals[0];
        for (var v = 1; v < vals.length; v++) {
          if (vals[v] !== first) conflicts++;
        }
      }

      var cls = conflicts === 0 ? "conflict-0" : "conflict-high";
      var verdict = conflicts === 0 ? "Consistent" : conflicts + " conflict" + (conflicts > 1 ? "s" : "");
      html += '<tr><td>' + period + '</td><td class="' + cls + '">' + conflicts + '</td><td>' + verdict + '</td></tr>';
    }

    // Self-encrypting positions
    html += '</tbody></table>';
    html += '<p style="margin-top: var(--sp-3); margin-bottom: 0;"><small class="text-muted">';
    html += 'Self-encrypting positions: ';
    var selfEnc = [];
    if (ct.length > 32 && pt.length > 32 && ct[32] === pt[32]) selfEnc.push("32 (CT=PT=" + ct[32] + ")");
    if (ct.length > 73 && pt.length > 73 && ct[73] === pt[73]) selfEnc.push("73 (CT=PT=" + ct[73] + ")");
    html += selfEnc.length > 0 ? selfEnc.join(", ") : "None detected";
    html += '</small></p>';

    return html;
  }

  // --- Grid view (28x31 master grid) ---
  function renderGridView(nullPos) {
    var GRID_WIDTH = 31;
    var nullSet = {};
    for (var i = 0; i < nullPos.length; i++) nullSet[nullPos[i]] = true;
    var html = "";
    for (var i = 0; i < CT.length; i++) {
      if (i > 0 && i % GRID_WIDTH === 0) html += "\n";
      var ch = CT[i];
      if (CRIBS[i] !== undefined) {
        html += '<span class="crib">' + ch + "</span>";
      } else if (nullSet[i]) {
        html += '<span class="null-char">' + ch + "</span>";
      } else {
        html += ch;
      }
    }
    gridViewPre.innerHTML = html;
  }

  function classifyScore(score) {
    if (score >= 24) return "breakthrough";
    if (score >= 18) return "signal";
    if (score >= 10) return "store";
    return "noise";
  }

  // --- Elimination check ---
  function checkElimination() {
    var trans = transMethod.value;
    var sub = subMethod.value;
    var key = trans + ":" + sub;
    var entry = ELIMINATIONS[key];

    if (!entry) {
      eliminationWarning.innerHTML = "";
      eliminationWarning.className = "";
      return;
    }

    var cls = "wb-warning wb-warning-" + entry.severity;
    var label = entry.severity === "proven" ? "PROVEN IMPOSSIBLE"
      : entry.severity === "exhausted" ? "EXHAUSTIVELY TESTED"
      : "OPEN TERRITORY";

    eliminationWarning.className = cls;
    eliminationWarning.innerHTML = "<strong>" + label + "</strong> " + entry.msg;
  }

  // --- Presets ---
  function applyPreset(name) {
    // Reset null mask
    nullMode.value = "disabled";
    nullManualGroup.classList.add("hidden");
    nullExtractedDiv.classList.add("hidden");

    switch (name) {
      case "vig-kryptos":
        transMethod.value = "none";
        subMethod.value = "vigenere";
        subKey.value = "KRYPTOS";
        subAlphabet.value = "AZ";
        break;
      case "beau-kryptos-ka":
        transMethod.value = "none";
        subMethod.value = "beaufort";
        subKey.value = "KRYPTOS";
        subAlphabet.value = "KA";
        break;
      case "col7-vig":
        transMethod.value = "columnar";
        document.getElementById("trans-width").value = "7";
        document.getElementById("trans-keyword").value = "";
        document.getElementById("trans-colorder").value = "";
        subMethod.value = "vigenere";
        subKey.value = "KRYPTOS";
        subAlphabet.value = "AZ";
        break;
      case "rail-beau":
        transMethod.value = "railfence";
        document.getElementById("trans-depth").value = "7";
        subMethod.value = "beaufort";
        subKey.value = "KRYPTOS";
        subAlphabet.value = "AZ";
        break;
      case "serpentine-vig":
        transMethod.value = "serpentine";
        document.getElementById("trans-serp-width").value = "10";
        document.getElementById("trans-serp-vertical").checked = false;
        subMethod.value = "vigenere";
        subKey.value = "KRYPTOS";
        subAlphabet.value = "AZ";
        break;
      case "best-lead":
        // Step 0: Null mask
        nullMode.value = "manual";
        nullPositionsInput.value = "0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96";
        nullCribModel.value = "A";
        updateNullOptions();
        // Step 1: Columnar width 7
        transMethod.value = "columnar";
        document.getElementById("trans-width").value = "7";
        document.getElementById("trans-keyword").value = "";
        document.getElementById("trans-colorder").value = "";
        // Step 2: Autokey Beaufort, DEFECTOR, AZ
        subMethod.value = "autokey-beau";
        subKey.value = "DEFECTOR";
        subAlphabet.value = "AZ";
        break;
      case "blank":
        transMethod.value = "none";
        subMethod.value = "vigenere";
        subKey.value = "";
        subAlphabet.value = "AZ";
        break;
    }

    updateTransOptions();
    updateSubOptions();
    runPipeline();
  }

  // --- UI Logic ---
  function showHide(el, show) {
    if (show) el.classList.remove("hidden");
    else el.classList.add("hidden");
  }

  function updateTransOptions() {
    var m = transMethod.value;
    showHide(transColumnar, m === "columnar");
    showHide(transRailfence, m === "railfence");
    showHide(transSerpentine, m === "serpentine");
    showHide(transSpiral, m === "spiral");
    showHide(transMyszkowski, m === "myszkowski");
    showHide(transManual, m === "manual");
  }

  function updateSubOptions() {
    var m = subMethod.value;
    var needsKey = ["vigenere", "beaufort", "varbeaufort", "autokey-vig", "autokey-beau",
                    "quagmire-ii", "quagmire-ii-autokey", "four-square", "porta", "gronsfeld", "affine"].indexOf(m) >= 0;
    var needsCaesar = m === "caesar";
    var needsKey2 = m === "four-square";
    var needsIndicator = m === "quagmire-ii" || m === "quagmire-ii-autokey";
    showHide(subKeyGroup, needsKey);
    showHide(subCaesarGroup, needsCaesar);
    var key2Group = document.getElementById("sub-key2-group");
    var indGroup = document.getElementById("sub-indicator-group");
    if (key2Group) showHide(key2Group, needsKey2);
    if (indGroup) showHide(indGroup, needsIndicator);
    // Update key label hints
    var keyLabel = document.getElementById("sub-key-label");
    if (keyLabel) {
      if (m === "affine") keyLabel.textContent = "Key (a,b)";
      else if (m === "gronsfeld") keyLabel.textContent = "Key (digits)";
      else keyLabel.textContent = "Key";
    }
  }

  function updateNullOptions() {
    var m = nullMode.value;
    showHide(nullManualGroup, m === "manual");

    var nullPos = getNullPositions();
    if (m !== "disabled" && nullPos.length > 0) {
      var extracted = extractCT(CT, nullPos);
      nullExtractedCt.textContent = extracted;
      nullExtractedLen.textContent = extracted.length;
      nullCountSpan.textContent = nullPos.length;
      showHide(nullExtractedDiv, true);
    } else {
      showHide(nullExtractedDiv, false);
    }

    // Re-render CT display with null highlighting
    var showW = wHighlight.checked;
    var nullSet = {};
    for (var i = 0; i < nullPos.length; i++) nullSet[nullPos[i]] = true;
    renderCT(CT, ctDisplay, { showW: showW, nullPositions: nullSet });

    // Refresh grid view if visible
    if (gridViewCheckbox.checked) {
      renderGridView(nullPos);
    }
  }

  function runPipeline() {
    // Check elimination status
    checkElimination();

    // Step 0: Null mask
    var nullPos = getNullPositions();
    var workingCT = CT;
    var activeCribs = CRIBS;

    if (nullPos.length > 0) {
      var cribModel = nullCribModel.value;
      if (cribModel === "A") {
        // Model A: remove nulls, cribs shift
        workingCT = extractCT(CT, nullPos);
        activeCribs = remapCribs(nullPos);
      }
      // Model B: cribs stay at original positions, pipeline runs on full CT
      // (null positions in PT are garbage — not scored)
    }

    // Step 1: Transposition
    workingCT = applyTransposition(workingCT);
    var showTrans = transMethod.value !== "none";

    if (showTrans) {
      renderCT(workingCT, transposedCt, { cribs: activeCribs });
      showHide(transResult, true);
    } else {
      showHide(transResult, false);
    }

    // Step 2: Substitution
    var pt = applySubstitution(workingCT);
    if (pt === null) {
      showHide(resultsEmpty, true);
      showHide(resultsPanel, false);
      return;
    }

    showHide(resultsEmpty, false);
    showHide(resultsPanel, true);

    // Render plaintext with crib highlighting
    renderCT(pt, ptDisplay, { cribs: activeCribs });

    // Score
    var alpha = getAlphabet();
    var cribResult = scoreCribs(pt, activeCribs);
    var ic = calcIC(pt);
    var bean = checkBean(workingCT, pt, alpha, subMethod.value, nullPos);
    var free = freeCribSearch(pt);
    var trigramResult = scoreTrigrams(pt);
    var cls = classifyScore(cribResult.total);

    scoreCrib.innerHTML = cribResult.total + "/24 <span class=\"score-badge score-badge-" + cls + "\">" + cls + "</span>";
    scoreEne.textContent = cribResult.ene + "/13";
    scoreBc.textContent = cribResult.bc + "/11";
    scoreIc.textContent = ic.toFixed(4);
    scoreTrigram.textContent = trigramResult.hits + "/" + trigramResult.total + " (" + trigramResult.pct.toFixed(1) + "%)";
    scoreBean.textContent = bean === null ? "N/A" : (bean ? "PASS" : "FAIL");
    scoreBean.style.color = bean === true ? "var(--green)" : (bean === false ? "var(--red)" : "");
    scoreFree.textContent = free;

    keystreamDetail.textContent = deriveKeystream(workingCT, pt, alpha, subMethod.value, activeCribs);
    keystreamAnalysis.innerHTML = analyzeKeystream(workingCT, pt, alpha, subMethod.value, activeCribs);

    // Session history
    var methodDesc = transMethod.value !== "none" ? transMethod.value + " + " : "";
    methodDesc += subMethod.value;
    var keyDesc = subKey.value || subShift.value || "--";
    sessionHistory.push({
      attempt: sessionHistory.length + 1,
      method: methodDesc,
      key: keyDesc,
      score: cribResult.total + "/24",
      cls: cls,
      timestamp: new Date().toLocaleTimeString()
    });
    renderHistory();
  }

  // --- Session history rendering ---
  function renderHistory() {
    historyCount.textContent = sessionHistory.length;
    if (sessionHistory.length === 0) {
      historyLog.innerHTML = "";
      return;
    }
    var html = '<table><thead><tr><th>#</th><th>Method</th><th>Key</th><th>Score</th><th>Time</th></tr></thead><tbody>';
    // Show most recent first
    for (var i = sessionHistory.length - 1; i >= 0; i--) {
      var h = sessionHistory[i];
      html += '<tr><td>' + h.attempt + '</td><td>' + h.method + '</td><td>' + h.key +
        '</td><td><span class="score-badge score-badge-' + h.cls + '">' + h.score +
        '</span></td><td>' + h.timestamp + '</td></tr>';
    }
    html += '</tbody></table>';
    historyLog.innerHTML = html;
  }

  // --- Event listeners ---
  transMethod.addEventListener("change", function () {
    updateTransOptions();
    runPipeline();
  });

  subMethod.addEventListener("change", function () {
    updateSubOptions();
    runPipeline();
  });

  // Debounced input handler for all text/number inputs
  var debounce;
  function onInput() {
    clearTimeout(debounce);
    debounce = setTimeout(runPipeline, 300);
  }

  subKey.addEventListener("input", onInput);
  subShift.addEventListener("input", onInput);
  subAlphabet.addEventListener("change", runPipeline);
  document.getElementById("trans-width").addEventListener("input", onInput);
  document.getElementById("trans-keyword").addEventListener("input", onInput);
  document.getElementById("trans-colorder").addEventListener("input", onInput);
  document.getElementById("trans-depth").addEventListener("input", onInput);
  document.getElementById("trans-perm").addEventListener("input", onInput);
  document.getElementById("trans-serp-width").addEventListener("input", onInput);
  document.getElementById("trans-serp-vertical").addEventListener("change", runPipeline);
  document.getElementById("trans-spiral-width").addEventListener("input", onInput);
  document.getElementById("trans-spiral-ccw").addEventListener("change", runPipeline);
  document.getElementById("trans-mysz-keyword").addEventListener("input", onInput);

  // W-highlight toggle
  wHighlight.addEventListener("change", function () {
    showHide(wSegments, wHighlight.checked);
    var nullPos = getNullPositions();
    var nullSet = {};
    for (var i = 0; i < nullPos.length; i++) nullSet[nullPos[i]] = true;
    renderCT(CT, ctDisplay, { showW: wHighlight.checked, nullPositions: nullSet });
  });

  // Grid view toggle
  gridViewCheckbox.addEventListener("change", function () {
    var checked = gridViewCheckbox.checked;
    gridViewContainer.style.display = checked ? "block" : "none";
    if (checked) {
      renderGridView(getNullPositions());
    }
  });

  // Null mask controls
  nullMode.addEventListener("change", function () {
    updateNullOptions();
    runPipeline();
  });
  nullPositionsInput.addEventListener("input", function () {
    clearTimeout(debounce);
    debounce = setTimeout(function () { updateNullOptions(); runPipeline(); }, 300);
  });
  nullCribModel.addEventListener("change", runPipeline);

  // Preset cards
  var presetCards = document.querySelectorAll(".preset-card[data-preset]");
  for (var pi = 0; pi < presetCards.length; pi++) {
    (function (card) {
      card.addEventListener("click", function () {
        applyPreset(card.getAttribute("data-preset"));
      });
    })(presetCards[pi]);
  }

  // Reset button
  document.getElementById("reset-btn").addEventListener("click", function () {
    // Step 0
    nullMode.value = "disabled";
    nullPositionsInput.value = "";
    nullCribModel.value = "A";
    updateNullOptions();
    // Step 1
    transMethod.value = "none";
    document.getElementById("trans-width").value = "7";
    document.getElementById("trans-keyword").value = "";
    document.getElementById("trans-colorder").value = "";
    document.getElementById("trans-depth").value = "3";
    document.getElementById("trans-perm").value = "";
    document.getElementById("trans-serp-width").value = "7";
    document.getElementById("trans-spiral-width").value = "7";
    document.getElementById("trans-mysz-keyword").value = "";
    updateTransOptions();
    // Step 2
    subMethod.value = "vigenere";
    subKey.value = "";
    subShift.value = "0";
    subAlphabet.value = "AZ";
    var key2 = document.getElementById("sub-key2");
    var ind = document.getElementById("sub-indicator");
    if (key2) key2.value = "";
    if (ind) ind.value = "K";
    updateSubOptions();
    // Clear results
    showHide(document.getElementById("results-panel"), false);
    showHide(document.getElementById("results-empty"), true);
    // Reset CT display
    wHighlight.checked = false;
    gridViewCheckbox.checked = false;
    gridViewContainer.style.display = "none";
    renderCT(CT, ctDisplay, { showW: false, nullPositions: {} });
  });

  // Init
  updateTransOptions();
  updateSubOptions();
})();
