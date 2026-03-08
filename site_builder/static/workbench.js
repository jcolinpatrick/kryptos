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

  // Bean constraints: k[27] = k[65], plus 21 inequalities
  var BEAN_EQ = [27, 65];
  var BEAN_INEQ = [
    [21, 27], [21, 65], [22, 28], [22, 66], [23, 27], [23, 29],
    [23, 65], [23, 67], [24, 28], [24, 30], [24, 66], [24, 68],
    [25, 27], [25, 29], [25, 31], [25, 65], [25, 67], [25, 69],
    [26, 28], [26, 30], [26, 32]
  ];

  // --- DOM Elements ---
  var ctDisplay = document.getElementById("ct-display");
  var transMethod = document.getElementById("trans-method");
  var transColumnar = document.getElementById("trans-opts-columnar");
  var transRailfence = document.getElementById("trans-opts-railfence");
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

  // --- Render CT display with crib highlighting ---
  function renderCT(text, container) {
    var html = "";
    for (var i = 0; i < text.length; i++) {
      if (CRIBS[i] !== undefined) {
        html += '<span class="crib">' + text[i] + "</span>";
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

  // --- Transposition implementations ---
  function applyTransposition(text) {
    var method = transMethod.value;
    if (method === "none") return text;
    if (method === "columnar") return columnarTranspose(text);
    if (method === "railfence") return railfenceTranspose(text);
    if (method === "manual") return manualTranspose(text);
    return text;
  }

  function columnarTranspose(text) {
    var width = parseInt(document.getElementById("trans-width").value) || 10;
    var orderStr = document.getElementById("trans-colorder").value.trim();
    var n = text.length;
    var rows = Math.ceil(n / width);

    // Build column order
    var colOrder;
    if (orderStr) {
      colOrder = orderStr.split(",").map(function (s) { return parseInt(s.trim()); });
      if (colOrder.length !== width) return text; // invalid
    } else {
      colOrder = [];
      for (var c = 0; c < width; c++) colOrder.push(c);
    }

    // Read off columns in the given order to undo columnar transposition
    // (assumes the text was written into a grid by rows and read off by columns)
    var fullCols = n % width || width;
    var result = new Array(n);
    var pos = 0;

    // Inverse: text was produced by reading columns in colOrder
    // To undo: figure out which positions each column contains
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

    // Compute rail lengths
    var railLens = new Array(depth).fill(0);
    var rail = 0, dir = 1;
    for (var i = 0; i < n; i++) {
      railLens[rail]++;
      if (rail === 0) dir = 1;
      else if (rail === depth - 1) dir = -1;
      rail += dir;
    }

    // Assign text to rails
    var rails = [];
    var pos = 0;
    for (var r = 0; r < depth; r++) {
      rails.push(text.substring(pos, pos + railLens[r]));
      pos += railLens[r];
    }

    // Read off in zigzag order
    var result = "";
    var indices = new Array(depth).fill(0);
    rail = 0; dir = 1;
    for (var j = 0; j < n; j++) {
      result += rails[rail][indices[rail]++];
      if (rail === 0) dir = 1;
      else if (rail === depth - 1) dir = -1;
      rail += dir;
    }
    return result;
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
    return text;
  }

  function vigenere(ct, key, alpha) {
    // PT = (CT - K) mod 26
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      pt += alpha[mod(c - k, 26)];
    }
    return pt;
  }

  function beaufort(ct, key, alpha) {
    // PT = (K - CT) mod 26
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      pt += alpha[mod(k - c, 26)];
    }
    return pt;
  }

  function varBeaufort(ct, key, alpha) {
    // Variant Beaufort decrypt: PT = (CT + K) mod 26
    var pt = "";
    for (var i = 0; i < ct.length; i++) {
      var c = alphaIndex(ct[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      pt += alpha[mod(c + k, 26)];
    }
    return pt;
  }

  function autokeyVig(ct, key, alpha) {
    // Autokey Vigenère: key extends with plaintext
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
    // Autokey Beaufort: key extends with plaintext
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

  // --- Scoring ---
  function scoreCribs(pt) {
    var eneHits = 0, bcHits = 0;
    var matched = [];
    for (var pos in CRIBS) {
      if (pt[pos] === CRIBS[pos]) {
        matched.push(parseInt(pos));
        if (pos >= 21 && pos <= 33) eneHits++;
        else bcHits++;
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

  function checkBean(ct, pt, alpha) {
    // Derive keystream values at crib positions
    var keys = {};
    for (var pos in CRIBS) {
      var c = alphaIndex(ct[pos], alpha);
      var p = alphaIndex(pt[pos], alpha);
      // Use Vigenère convention: k = (c - p) mod 26
      keys[pos] = mod(c - p, 26);
    }

    // Check equality
    if (keys[BEAN_EQ[0]] === undefined || keys[BEAN_EQ[1]] === undefined) return null;
    if (keys[BEAN_EQ[0]] !== keys[BEAN_EQ[1]]) return false;

    // Check inequalities
    for (var i = 0; i < BEAN_INEQ.length; i++) {
      var a = BEAN_INEQ[i][0], b = BEAN_INEQ[i][1];
      if (keys[a] === undefined || keys[b] === undefined) continue;
      if (keys[a] === keys[b]) return false;
    }
    return true;
  }

  function freeCribSearch(pt) {
    // Search for EASTNORTHEAST or BERLINCLOCK anywhere in the plaintext
    var hits = [];
    var eneIdx = pt.indexOf(ENE);
    if (eneIdx >= 0) hits.push("ENE@" + eneIdx);
    var bcIdx = pt.indexOf(BC);
    if (bcIdx >= 0) hits.push("BC@" + bcIdx);
    // Also check substrings
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

  function deriveKeystream(ct, pt, alpha) {
    var lines = [];
    var positions = Object.keys(CRIBS).map(Number).sort(function (a, b) { return a - b; });
    for (var i = 0; i < positions.length; i++) {
      var pos = positions[i];
      var c = alphaIndex(ct[pos], alpha);
      var p = alphaIndex(pt[pos], alpha);
      var kVal = mod(c - p, 26);
      var match = pt[pos] === CRIBS[pos] ? "OK" : "MISS";
      lines.push(
        "pos=" + String(pos).padStart(2) +
        "  CT=" + ct[pos] +
        "  PT=" + pt[pos] +
        "  expected=" + CRIBS[pos] +
        "  k=" + String(kVal).padStart(2) +
        " (" + alpha[kVal] + ")  " + match
      );
    }
    return lines.join("\n");
  }

  function classifyScore(score) {
    if (score >= 24) return "breakthrough";
    if (score >= 18) return "signal";
    if (score >= 10) return "store";
    return "noise";
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
    showHide(transManual, m === "manual");
  }

  function updateSubOptions() {
    var m = subMethod.value;
    var needsKey = ["vigenere", "beaufort", "varbeaufort", "autokey-vig", "autokey-beau"].indexOf(m) >= 0;
    var needsCaesar = m === "caesar";
    showHide(subKeyGroup, needsKey);
    showHide(subCaesarGroup, needsCaesar);
  }

  function runPipeline() {
    // Step 1: Transposition
    var workingCT = applyTransposition(CT);
    var showTrans = transMethod.value !== "none";

    if (showTrans) {
      renderCT(workingCT, transposedCt);
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
    renderCT(pt, ptDisplay);

    // Score
    var alpha = getAlphabet();
    var cribResult = scoreCribs(pt);
    var ic = calcIC(pt);
    var bean = checkBean(workingCT, pt, alpha);
    var free = freeCribSearch(pt);
    var cls = classifyScore(cribResult.total);

    scoreCrib.innerHTML = cribResult.total + "/24 <span class=\"score-badge score-badge-" + cls + "\">" + cls + "</span>";
    scoreEne.textContent = cribResult.ene + "/13";
    scoreBc.textContent = cribResult.bc + "/11";
    scoreIc.textContent = ic.toFixed(4);
    scoreBean.textContent = bean === null ? "N/A" : (bean ? "PASS" : "FAIL");
    scoreBean.style.color = bean === true ? "var(--green)" : (bean === false ? "var(--red)" : "");
    scoreFree.textContent = free;

    keystreamDetail.textContent = deriveKeystream(workingCT, pt, alpha);
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
  document.getElementById("trans-colorder").addEventListener("input", onInput);
  document.getElementById("trans-depth").addEventListener("input", onInput);
  document.getElementById("trans-perm").addEventListener("input", onInput);

  // Init
  updateTransOptions();
  updateSubOptions();
})();
