/**
 * kryptosbot.com — VIC Cipher Workbench
 * Full VIC cipher implementation with optional classical layering.
 * All computation runs in the browser. Nothing is sent anywhere unless the
 * visitor explicitly checks the "share promising results" box on the page.
 */
(function () {
  "use strict";

  // =========================================================================
  // Constants
  // =========================================================================
  var CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR";
  var AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ";

  var CRIBS = {};
  var ENE = "EASTNORTHEAST";
  var BC = "BERLINCLOCK";
  for (var i = 0; i < ENE.length; i++) CRIBS[21 + i] = ENE[i];
  for (var j = 0; j < BC.length; j++) CRIBS[63 + j] = BC[j];

  // Top 50 English trigrams
  var TOP_TRIGRAMS = [
    "THE", "AND", "ING", "ION", "TIO", "ENT", "ERE", "HER", "ATE", "VER",
    "TER", "THA", "ATI", "HAT", "FOR", "EST", "ALL", "INT", "ITH", "HIS",
    "OFT", "STH", "NOT", "RES", "ORT", "WAS", "ARE", "ONE", "OUR", "OUT",
    "HAS", "AVE", "MAN", "PRO", "ERS", "COM", "NTH", "STI", "TED", "OTH",
    "ITI", "ERA", "ECT", "NDE", "IST", "OME", "NGT", "NCE", "ANT", "DER"
  ];
  var TRIGRAM_SET = {};
  for (var ti = 0; ti < TOP_TRIGRAMS.length; ti++) TRIGRAM_SET[TOP_TRIGRAMS[ti]] = true;

  // =========================================================================
  // Utility functions
  // =========================================================================
  function mod10(n) { return ((n % 10) + 10) % 10; }
  function mod26(n) { return ((n % 26) + 26) % 26; }

  function sanitize(s) { return s.toUpperCase().replace(/[^A-Z]/g, ""); }
  function sanitizeDigits(s) { return s.replace(/[^0-9]/g, ""); }

  function alphaIndex(ch, alpha) { return alpha.indexOf(ch.toUpperCase()); }

  /** Convert letters to single digits via a mapping scheme.
   *  "az_mod10": A=0,B=1,...,J=9,K=0,...,Z=5
   *  "ka_mod10": KA alphabet positions mod 10
   *  "checkerboard": Use checkerboard encode table (1 or 2 digits per letter)
   */
  function letterToDigits(text, mapping, cb) {
    var digits = [];
    if (mapping === "checkerboard" && cb) {
      return checkerboardEncode(text, cb);
    }
    var alpha = (mapping === "ka_mod10" || mapping === "ka_mod10_1") ? KA : AZ;
    var offset = (mapping === "az_mod10_1" || mapping === "ka_mod10_1") ? 1 : 0;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i].toUpperCase();
      var idx = alpha.indexOf(ch);
      if (idx >= 0) digits.push((idx + offset) % 10);
    }
    return digits;
  }

  /** Sequencing: rank letters/digits, leftmost first for ties. Returns 1-based (0=10). */
  function sequenceLetters(str) {
    var indexed = [];
    for (var i = 0; i < str.length; i++) indexed.push({ ch: str[i], pos: i });
    indexed.sort(function (a, b) {
      if (a.ch < b.ch) return -1;
      if (a.ch > b.ch) return 1;
      return a.pos - b.pos;
    });
    var result = new Array(str.length);
    for (var rank = 0; rank < indexed.length; rank++) {
      result[indexed[rank].pos] = (rank + 1) % 10; // 10 becomes 0
    }
    return result;
  }

  /** Sequencing for digits: rank numerically, leftmost first for ties. 0 counts as 10 (highest). Returns 1-based (10→0). */
  function sequenceDigits(digits) {
    var indexed = [];
    for (var i = 0; i < digits.length; i++) {
      // In VIC, 0 ranks as 10 (highest value)
      indexed.push({ val: digits[i] === 0 ? 10 : digits[i], pos: i });
    }
    indexed.sort(function (a, b) {
      if (a.val !== b.val) return a.val - b.val;
      return a.pos - b.pos;
    });
    var result = new Array(digits.length);
    for (var rank = 0; rank < indexed.length; rank++) {
      result[indexed[rank].pos] = (rank + 1) % 10; // 10 becomes 0
    }
    return result;
  }

  /** Chain addition (VIC-style): add consecutive pairs from position 0 onward, advancing by 1. */
  function chainAdd(digits, count) {
    var result = digits.slice();
    var addPos = 0;
    while (result.length < count) {
      result.push(mod10(result[addPos] + result[addPos + 1]));
      addPos++;
    }
    return result.slice(0, count);
  }

  /** Digit encoding: for each digit d in source, replace with target[d-1] (where 0=10th position). */
  function digitEncode(source, lookupRow) {
    var result = [];
    for (var i = 0; i < source.length; i++) {
      var d = source[i];
      var idx = (d === 0) ? 9 : d - 1; // 0 maps to position 10 (index 9)
      result.push(lookupRow[idx]);
    }
    return result;
  }

  /** Mod-10 addition of two digit arrays. */
  function addDigits(a, b) {
    var result = [];
    for (var i = 0; i < Math.min(a.length, b.length); i++) {
      result.push(mod10(a[i] + b[i]));
    }
    return result;
  }

  /** Mod-10 subtraction: (a - b) mod 10, digit by digit. */
  function subDigits(a, b) {
    var result = [];
    for (var i = 0; i < Math.min(a.length, b.length); i++) {
      result.push(mod10(a[i] - b[i]));
    }
    return result;
  }

  // =========================================================================
  // VIC Key Generation
  // =========================================================================
  function generateVICKeys(phrase, date, personal, keygroup) {
    var steps = {};

    // Line-A: Keygroup (5 digits)
    var lineA = [];
    for (var i = 0; i < 5; i++) lineA.push(parseInt(keygroup[i]));
    steps.lineA = lineA.slice();

    // Line-B: First 5 digits of Date
    var lineB = [];
    for (var i2 = 0; i2 < 5; i2++) lineB.push(parseInt(date[i2]));
    steps.lineB = lineB.slice();

    // Line-C: (Line-A - Line-B) mod 10
    var lineC = subDigits(lineA, lineB);
    steps.lineC = lineC.slice();

    // Line-D: First 20 letters of Phrase
    var lineD = sanitize(phrase).substring(0, 20);
    steps.lineD = lineD;

    // Line-E.1: Sequence first 10 letters of Line-D
    var lineE1 = sequenceLetters(lineD.substring(0, 10));
    steps.lineE1 = lineE1.slice();

    // Line-E.2: Sequence last 10 letters of Line-D
    var lineE2 = sequenceLetters(lineD.substring(10, 20));
    steps.lineE2 = lineE2.slice();

    // Line-F.1: Line-C + chain-add to 10 digits
    var lineF1 = chainAdd(lineC, 10);
    steps.lineF1 = lineF1.slice();

    // Line-G: (Line-E.1 + Line-F.1) mod 10
    var lineG = addDigits(lineE1, lineF1);
    steps.lineG = lineG.slice();

    // Line-H: Encode Line-G using Line-E.2
    // For each digit in G: the digit d (1-10, with 0=10) indexes into E.2
    var lineH = digitEncode(lineG, lineE2);
    steps.lineH = lineH.slice();

    // Line-J: Sequence of Line-H
    var lineJ = sequenceDigits(lineH);
    steps.lineJ = lineJ.slice();

    // Lines K-P: Chain-add Line-H for 50 more digits (5 rows of 10)
    var lineKP = chainAdd(lineH, 60); // H is 10, then 50 more = 60 total
    var lineKPBlock = lineKP.slice(10); // skip H itself, take 50
    steps.lineK = lineKPBlock.slice(0, 10);
    steps.lineL = lineKPBlock.slice(10, 20);
    steps.lineM = lineKPBlock.slice(20, 30);
    steps.lineN = lineKPBlock.slice(30, 40);
    steps.lineP = lineKPBlock.slice(40, 50);

    // Line-S: Sequence of Line-P
    var lineS = sequenceDigits(steps.lineP);
    steps.lineS = lineS.slice();

    // a,b: Last two non-equal digits of Line-P + personal number
    var personalNum = parseInt(personal) || 0;
    var lastTwo = findLastTwoNonEqual(steps.lineP);
    var a_val = mod10(lastTwo[0] + personalNum);
    var b_val = mod10(lastTwo[1] + personalNum);
    // a and b should not be 0; if 0, treat as 10
    if (a_val === 0) a_val = 10;
    if (b_val === 0) b_val = 10;
    steps.a = a_val;
    steps.b = b_val;
    steps.lastTwoRaw = lastTwo.slice();

    // The full K-P block as a flat 50-digit array
    var fullKP = lineKPBlock;

    // Line-Q: First 'a' digits from columnar transposition of K-P block by Line-J
    var lineQ;
    // Take first (a * width) digits from K-P, where width = 10 (Line-J length)
    // But K-P only has 50 digits and a can be up to 10.
    // Rethinking: Line-Q takes first 'a' columns worth from the 50-digit block rearranged
    // Actually per the flowchart: fork 50 digits to CT(Line-J) producing a# and DT producing b#.
    // The 50 digits go through columnar transposition keyed by Line-J, producing (a+b) digits.
    // Then first a digits = Line-Q, next b digits = Line-R.

    // Columnar transposition of 50 digits using Line-J as key
    var transposed50 = columnarReadOff(fullKP, lineJ);
    lineQ = transposed50.slice(0, a_val);
    steps.lineQ = lineQ.slice();

    // Line-R: Next 'b' digits
    var lineR = transposed50.slice(a_val, a_val + b_val);
    steps.lineR = lineR.slice();

    // 6th digit of date (for keygroup insertion position)
    steps.kgInsertDigit = parseInt(date[5]);

    return steps;
  }

  function findLastTwoNonEqual(digits) {
    // Scan from end of the digit array for last two non-equal digits
    for (var i = digits.length - 1; i >= 1; i--) {
      if (digits[i] !== digits[i - 1]) {
        return [digits[i - 1], digits[i]];
      }
    }
    // Fallback: just use last two
    return [digits[digits.length - 2], digits[digits.length - 1]];
  }

  /** Columnar transposition read-off: write digits row-by-row into columns,
   *  read off columns in order given by key (key values 0-9 where 0=10). */
  function columnarReadOff(digits, key) {
    var width = key.length;
    var rows = Math.ceil(digits.length / width);

    // Build grid (row-major)
    var grid = [];
    for (var r = 0; r < rows; r++) {
      var row = [];
      for (var c = 0; c < width; c++) {
        var idx = r * width + c;
        if (idx < digits.length) row.push(digits[idx]);
        else row.push(null);
      }
      grid.push(row);
    }

    // Read off by column in key order (key values are 1-based ranks, 0=10)
    // Sort columns by key value
    var colOrder = [];
    for (var ci = 0; ci < width; ci++) colOrder.push({ col: ci, rank: key[ci] === 0 ? 10 : key[ci] });
    colOrder.sort(function (a, b) { return a.rank - b.rank; });

    var result = [];
    for (var oi = 0; oi < colOrder.length; oi++) {
      var col = colOrder[oi].col;
      for (var ri = 0; ri < rows; ri++) {
        if (grid[ri][col] !== null) result.push(grid[ri][col]);
      }
    }
    return result;
  }

  // =========================================================================
  // Straddling Checkerboard
  // =========================================================================

  /** Build checkerboard from Line-S (column permutation), top-row letters, remaining letters.
   *  Returns { encode: {letter -> digit_string}, decode: {digit_string -> letter}, grid: 3xN array, rowLabels: [null, d1, d2] } */
  function buildCheckerboard(lineS, topRowLetters, remainingLetters) {
    // lineS is 10 digits (1-based ranks, 0=10) defining column header permutation
    // Column headers = lineS values mapped to 0-9 (where 0=10th position)
    var colHeaders = [];
    for (var i = 0; i < 10; i++) {
      colHeaders.push(lineS[i] === 0 ? 0 : lineS[i]); // lineS values are already 0-9 (with 0 = rank 10)
    }
    // Actually the column headers are just 0-9 in the permuted order defined by lineS.
    // lineS[i] = rank of column i. We want column order sorted by rank.
    // Column header at position i = i (digit 0-9). But columns are reordered by lineS.
    // Actually: lineS determines which digit goes in which column position.
    // Position p has digit value corresponding to rank lineS[p].
    // Hmm, let me reconsider:
    // lineS = sequencing of lineP = ranking.
    // The column headers of the checkerboard are the digits 1,2,...,9,0 permuted by lineS.
    // lineS[i] gives the rank of position i. To get headers: position sorted by rank gives digit order.

    // Column header for position i = i itself (0-9). lineS determines column ORDER for reading off.
    // For the checkerboard: column labeled with digit lineS[i]-mapped-to-digit.
    // Standard interpretation: column header at position i = (lineS[i] % 10).
    // No — lineS is the permutation. The column headers are the digits 0-9, placed at the positions
    // determined by lineS. So if lineS = [3,1,5,2,8,4,9,6,7,0], then:
    // Position 0 has column header 3, position 1 has header 1, etc. Wait, 0=10.
    // Actually lineS is the rank: the digit at column position p is whatever makes
    // the column headers a permutation of {1,2,...,9,0}.

    // Standard VIC: lineS is the sequencing of lineP. The column header at position i = lineS[i] % 10.
    // Since sequencing returns 1-10 (with 0=10), we map: lineS[i] where 0 means the digit "0".
    var headers = [];
    for (var h = 0; h < 10; h++) {
      headers.push(lineS[h] % 10); // 0=0, 1=1, ..., 9=9. 10 would be 0 but sequenceDigits returns 0 for rank 10.
    }

    var topRow = sanitize(topRowLetters).substring(0, 8);
    if (topRow.length < 8) {
      // Pad with common letters
      var common = "ASINTOER";
      for (var p = topRow.length; p < 8; p++) topRow += common[p];
    }

    // Find the two blank positions in row 0 (positions NOT filled by topRow letters)
    // The blank positions' column header digits become the row labels for rows 1 and 2
    var filledPositions = [];
    var blankPositions = [];
    var topRowUsed = {};

    // Place top-row letters left to right in the first available positions
    var row0 = new Array(10).fill(null);
    var topIdx = 0;
    for (var pos = 0; pos < 10 && topIdx < topRow.length; pos++) {
      row0[pos] = topRow[topIdx++];
    }
    for (var bp = 0; bp < 10; bp++) {
      if (row0[bp] === null) blankPositions.push(bp);
    }
    // Ensure exactly 2 blanks
    if (blankPositions.length !== 2) {
      // Force: use last two positions as blanks
      blankPositions = [8, 9];
      for (var fx = 0; fx < 8; fx++) row0[fx] = topRow[fx] || "?";
      row0[8] = null; row0[9] = null;
    }

    var rowLabel1 = headers[blankPositions[0]];
    var rowLabel2 = headers[blankPositions[1]];

    // Build remaining letters for rows 1 and 2
    var remaining;
    if (remainingLetters && sanitize(remainingLetters).length >= 18) {
      remaining = sanitize(remainingLetters).substring(0, 20);
    } else {
      // Auto-generate: remaining alphabet letters not in topRow + period + slash
      var usedSet = {};
      for (var ui = 0; ui < topRow.length; ui++) usedSet[topRow[ui]] = true;
      remaining = "";
      for (var ai = 0; ai < 26; ai++) {
        var ch = AZ[ai];
        if (!usedSet[ch]) remaining += ch;
      }
      // VIC traditionally adds period (.) and slash (/) as specials
      // We represent them as digits or skip — for K4 we only need 26 letters
      // Pad to 20 if needed
      remaining += ".."; // placeholders
    }

    var row1 = [];
    var row2 = [];
    for (var ri = 0; ri < 10; ri++) {
      row1.push(ri < remaining.length ? remaining[ri] : ".");
      row2.push((ri + 10) < remaining.length ? remaining[ri + 10] : "/");
    }

    // Build encode/decode maps
    var encode = {};
    var decode = {};

    // Row 0: single-digit encoding
    for (var e0 = 0; e0 < 10; e0++) {
      if (row0[e0] !== null) {
        var digitStr = "" + headers[e0];
        encode[row0[e0]] = digitStr;
        decode[digitStr] = row0[e0];
      }
    }

    // Row 1: two-digit encoding (rowLabel1 + column header)
    for (var e1 = 0; e1 < 10; e1++) {
      var digitStr1 = "" + rowLabel1 + headers[e1];
      encode[row1[e1]] = digitStr1;
      decode[digitStr1] = row1[e1];
    }

    // Row 2: two-digit encoding (rowLabel2 + column header)
    for (var e2 = 0; e2 < 10; e2++) {
      var digitStr2 = "" + rowLabel2 + headers[e2];
      encode[row2[e2]] = digitStr2;
      decode[digitStr2] = row2[e2];
    }

    return {
      encode: encode,
      decode: decode,
      headers: headers,
      row0: row0,
      row1: row1,
      row2: row2,
      rowLabel1: rowLabel1,
      rowLabel2: rowLabel2,
      blankPositions: blankPositions
    };
  }

  /** Encode text to digits using checkerboard. */
  function checkerboardEncode(text, cb) {
    var digits = [];
    for (var i = 0; i < text.length; i++) {
      var ch = text[i].toUpperCase();
      if (cb.encode[ch]) {
        var dStr = cb.encode[ch];
        for (var d = 0; d < dStr.length; d++) digits.push(parseInt(dStr[d]));
      }
    }
    return digits;
  }

  /** Decode digit stream to text using checkerboard. */
  function checkerboardDecode(digits, cb) {
    var text = "";
    var i = 0;
    while (i < digits.length) {
      var d1 = "" + digits[i];
      // Check if this digit is a row label (prefix for 2-digit code)
      if (digits[i] === cb.rowLabel1 || digits[i] === cb.rowLabel2) {
        if (i + 1 < digits.length) {
          var d2 = d1 + digits[i + 1];
          if (cb.decode[d2]) {
            text += cb.decode[d2];
            i += 2;
            continue;
          }
        }
      }
      // Single digit decode
      if (cb.decode[d1]) {
        text += cb.decode[d1];
      }
      i++;
    }
    return text;
  }

  // =========================================================================
  // Columnar Transposition (VIC style — encryption and decryption)
  // =========================================================================

  /** Columnar transposition ENCRYPT: write row-by-row, read off by key column order. */
  function columnarEncrypt(digits, key) {
    return columnarReadOff(digits, key);
  }

  /** Columnar transposition DECRYPT: reverse the columnar encryption.
   *  key is an array of ranks (1-based, 0=10). */
  function columnarDecrypt(digits, key) {
    var width = key.length;
    var n = digits.length;
    var rows = Math.ceil(n / width);
    var remainder = n % width;

    // Sort columns by rank to determine read-off order
    var colOrder = [];
    for (var ci = 0; ci < width; ci++) colOrder.push({ col: ci, rank: key[ci] === 0 ? 10 : key[ci] });
    colOrder.sort(function (a, b) { return a.rank - b.rank; });

    // Determine column lengths
    var colLens = new Array(width);
    for (var cl = 0; cl < width; cl++) {
      // In encryption, each column gets 'rows' entries, except the last row
      // which only fills the first 'remainder' columns (if remainder > 0)
      colLens[cl] = (remainder === 0 || cl < remainder) ? rows : rows - 1;
    }

    // Read digits into columns in key order
    var columns = {};
    var pos = 0;
    for (var oi = 0; oi < colOrder.length; oi++) {
      var col = colOrder[oi].col;
      columns[col] = [];
      var clen = colLens[col];
      for (var ri = 0; ri < clen; ri++) {
        if (pos < n) columns[col].push(digits[pos++]);
      }
    }

    // Read out row by row
    var result = [];
    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < width; c++) {
        if (columns[c] && r < columns[c].length) {
          result.push(columns[c][r]);
        }
      }
    }
    return result;
  }

  // =========================================================================
  // Disrupted Diagonal Transposition (VIC style)
  // =========================================================================

  /** Disrupted diagonal transposition ENCRYPT.
   *  Fill the grid diagonally, but "disrupt" at triangle boundaries. */
  function disruptedDiagEncrypt(digits, key) {
    var width = key.length;
    var n = digits.length;
    var rows = Math.ceil(n / width);

    // Build grid
    var grid = [];
    for (var r = 0; r < rows; r++) {
      grid.push(new Array(width).fill(null));
    }

    // Sort columns by rank
    var colOrder = [];
    for (var ci = 0; ci < width; ci++) colOrder.push({ col: ci, rank: key[ci] === 0 ? 10 : key[ci] });
    colOrder.sort(function (a, b) { return a.rank - b.rank; });
    // Map from original position to sorted rank
    var colSorted = colOrder.map(function (x) { return x.col; });

    // Fill using disrupted diagonal pattern:
    // Process triangles formed by the key order. For each successive column in key order,
    // fill the triangle: rows below the current diagonal, in the columns already seen.
    var pos = 0;
    var filledCols = []; // columns added so far (in key rank order)

    for (var ki = 0; ki < width && pos < n; ki++) {
      var newCol = colSorted[ki];

      // Fill the triangle: for each row from the current "diagonal level" downward,
      // fill across the columns we've already added, then the new column
      // Actually, the standard VIC disrupted diagonal:
      // Write in rows, but within each "block" defined by key order,
      // fill diagonally within the triangular region.
      filledCols.push(newCol);
      filledCols.sort(function (a, b) { return a - b; });

      // Fill the new diagonal: starting from row=ki, col=newCol, going diagonal
      var dr = ki, dc = newCol;
      // Actually, use the simpler standard model:
      // Row ki gets filled at column newCol
      if (dr < rows && pos < n) {
        grid[dr][dc] = digits[pos++];
      }
    }

    // Fill remaining positions row by row
    for (var fr = 0; fr < rows && pos < n; fr++) {
      for (var fc = 0; fc < width && pos < n; fc++) {
        if (grid[fr][fc] === null) {
          grid[fr][fc] = digits[pos++];
        }
      }
    }

    // Read off by columns in key order
    var result = [];
    for (var ro = 0; ro < colOrder.length; ro++) {
      var readCol = colOrder[ro].col;
      for (var rr = 0; rr < rows; rr++) {
        if (grid[rr][readCol] !== null) result.push(grid[rr][readCol]);
      }
    }
    return result;
  }

  /** Disrupted diagonal transposition DECRYPT. */
  function disruptedDiagDecrypt(digits, key) {
    var width = key.length;
    var n = digits.length;
    var rows = Math.ceil(n / width);
    var remainder = n % width;

    // Sort columns by rank
    var colOrder = [];
    for (var ci = 0; ci < width; ci++) colOrder.push({ col: ci, rank: key[ci] === 0 ? 10 : key[ci] });
    colOrder.sort(function (a, b) { return a.rank - b.rank; });

    // Determine column lengths (same logic as columnar)
    var colLens = new Array(width);
    for (var cl = 0; cl < width; cl++) {
      colLens[cl] = (remainder === 0 || cl < remainder) ? rows : rows - 1;
    }

    // Read digits into columns (in key order)
    var columns = {};
    var pos = 0;
    for (var oi = 0; oi < colOrder.length; oi++) {
      var col = colOrder[oi].col;
      columns[col] = [];
      for (var ri = 0; ri < colLens[col]; ri++) {
        if (pos < n) columns[col].push(digits[pos++]);
      }
    }

    // Now reconstruct by reversing the fill order
    // For decryption, we need to figure out which positions were filled in what order.
    // Use same fill pattern as encrypt to determine the mapping.
    var grid = [];
    for (var gr = 0; gr < rows; gr++) {
      grid.push(new Array(width).fill(null));
    }

    // Build fill order (same as encrypt)
    var fillOrder = [];
    var colSorted = colOrder.map(function (x) { return x.col; });
    var addedCols = [];

    for (var ki = 0; ki < width; ki++) {
      var newCol = colSorted[ki];
      addedCols.push(newCol);
      addedCols.sort(function (a, b) { return a - b; });
      if (ki < rows) {
        fillOrder.push([ki, newCol]);
        grid[ki][newCol] = -1; // mark
      }
    }

    // Fill remaining row by row
    for (var fr = 0; fr < rows; fr++) {
      for (var fc = 0; fc < width; fc++) {
        if (grid[fr][fc] === null) {
          var fpos = fr * width + fc;
          if (fpos < n) {
            fillOrder.push([fr, fc]);
            grid[fr][fc] = -1;
          }
        }
      }
    }

    // Now we have fillOrder = the order cells were written during encryption.
    // During encryption, after filling, columns are read off by key order.
    // During decryption, we reverse: read columns back from ciphertext,
    // then read cells in fill order.

    // Place column data back
    var grid2 = [];
    for (var g2r = 0; g2r < rows; g2r++) {
      grid2.push(new Array(width).fill(null));
    }
    var colIndices = {};
    for (var ci2 = 0; ci2 < width; ci2++) colIndices[ci2] = 0;

    // Read out in fill order using columns
    var result = [];
    for (var fi = 0; fi < fillOrder.length; fi++) {
      var cell = fillOrder[fi];
      var cellCol = cell[1];
      var cidx = colIndices[cellCol];
      if (columns[cellCol] && cidx < columns[cellCol].length) {
        result.push(columns[cellCol][cidx]);
        colIndices[cellCol]++;
      }
    }
    return result;
  }

  // =========================================================================
  // Keygroup Insertion/Extraction
  // =========================================================================

  /** Insert keygroup at position P groups from the end. */
  function insertKeygroup(digits, keygroup, insertPos) {
    // insertPos = 6th digit of date, counting 5-digit groups from the end
    var groupCount = Math.floor(digits.length / 5);
    var insertIdx = digits.length - (insertPos * 5);
    if (insertIdx < 0) insertIdx = 0;

    var result = digits.slice(0, insertIdx);
    for (var i = 0; i < keygroup.length; i++) result.push(parseInt(keygroup[i]));
    for (var j = insertIdx; j < digits.length; j++) result.push(digits[j]);
    return result;
  }

  /** Extract keygroup from position P groups from the end. */
  function extractKeygroup(digits, kgLength, insertPos) {
    var totalLen = digits.length;
    var insertIdx = totalLen - kgLength - (insertPos * 5);
    if (insertIdx < 0) insertIdx = 0;

    var before = digits.slice(0, insertIdx);
    var after = digits.slice(insertIdx + kgLength);
    var extracted = digits.slice(insertIdx, insertIdx + kgLength);
    return { digits: before.concat(after), keygroup: extracted };
  }

  // =========================================================================
  // Classical cipher layers
  // =========================================================================

  function vigEncrypt(text, key, alpha) {
    var pt = "";
    for (var i = 0; i < text.length; i++) {
      var c = alphaIndex(text[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      if (c < 0) { pt += text[i]; continue; }
      pt += alpha[mod26(c + k)];
    }
    return pt;
  }

  function vigDecrypt(text, key, alpha) {
    var pt = "";
    for (var i = 0; i < text.length; i++) {
      var c = alphaIndex(text[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      if (c < 0) { pt += text[i]; continue; }
      pt += alpha[mod26(c - k)];
    }
    return pt;
  }

  function beaufortDecrypt(text, key, alpha) {
    var pt = "";
    for (var i = 0; i < text.length; i++) {
      var c = alphaIndex(text[i], alpha);
      var k = alphaIndex(key[i % key.length], alpha);
      if (c < 0) { pt += text[i]; continue; }
      pt += alpha[mod26(k - c)];
    }
    return pt;
  }

  function beaufortEncrypt(text, key, alpha) {
    // Beaufort is self-reciprocal: encrypt = decrypt
    return beaufortDecrypt(text, key, alpha);
  }

  function varBeaufortDecrypt(text, key, alpha) {
    // VB decrypt: PT = (CT - K) mod 26
    return vigDecrypt(text, key, alpha);
  }

  function varBeaufortEncrypt(text, key, alpha) {
    // VB encrypt: CT = (PT + K) mod 26
    return vigEncrypt(text, key, alpha);
  }

  function applyExtraLayer(text, method, key, alpha, isEncrypt) {
    if (method === "none" || !key) return text;
    key = sanitize(key);
    if (!key) return text;

    if (method === "vigenere") {
      return isEncrypt ? vigEncrypt(text, key, alpha) : vigDecrypt(text, key, alpha);
    }
    if (method === "beaufort") {
      return isEncrypt ? beaufortEncrypt(text, key, alpha) : beaufortDecrypt(text, key, alpha);
    }
    if (method === "varbeaufort") {
      return isEncrypt ? varBeaufortEncrypt(text, key, alpha) : varBeaufortDecrypt(text, key, alpha);
    }
    return text;
  }

  // =========================================================================
  // Scoring against K4 cribs
  // =========================================================================

  function scorePlaintext(pt) {
    var eneScore = 0, bcScore = 0;
    for (var pos in CRIBS) {
      if (!CRIBS.hasOwnProperty(pos)) continue;
      var p = parseInt(pos);
      if (p < pt.length && pt[p] === CRIBS[p]) {
        if (p >= 21 && p <= 33) eneScore++;
        else if (p >= 63 && p <= 73) bcScore++;
      }
    }
    var total = eneScore + bcScore;

    // IC
    var freq = new Array(26).fill(0);
    for (var i = 0; i < pt.length; i++) {
      var idx = pt.charCodeAt(i) - 65;
      if (idx >= 0 && idx < 26) freq[idx]++;
    }
    var n = pt.length;
    var ic = 0;
    for (var f = 0; f < 26; f++) ic += freq[f] * (freq[f] - 1);
    ic = n > 1 ? ic / (n * (n - 1)) : 0;

    // Free crib search
    var freeCrib = searchFreeCribs(pt);

    // Classification
    var cls = "noise";
    if (total >= 18) cls = "signal";
    else if (total >= 10) cls = "interesting";
    if (total >= 24) cls = "breakthrough";

    return {
      total: total,
      ene: eneScore,
      bc: bcScore,
      ic: ic,
      freeCrib: freeCrib,
      classification: cls
    };
  }

  function searchFreeCribs(text) {
    var best = 0;
    var targets = [ENE, BC];
    for (var t = 0; t < targets.length; t++) {
      var target = targets[t];
      for (var i = 0; i <= text.length - target.length; i++) {
        var matches = 0;
        for (var j = 0; j < target.length; j++) {
          if (text[i + j] === target[j]) matches++;
        }
        if (matches > best) best = matches;
      }
    }
    return best;
  }

  function deriveKeystream(pt) {
    var lines = [];
    for (var pos in CRIBS) {
      if (!CRIBS.hasOwnProperty(pos)) continue;
      var p = parseInt(pos);
      if (p >= pt.length) continue;
      var c = CT.charCodeAt(p) - 65;
      var ptc = pt.charCodeAt(p) - 65;
      var kVig = mod26(c - ptc);
      var kBeau = mod26(c + ptc);
      var group = (p >= 21 && p <= 33) ? "ENE" : "BC";
      var match = pt[p] === CRIBS[p] ? "MATCH" : "miss";
      lines.push(
        "pos " + String(p).padStart(2) + " (" + group.padEnd(3) + "): " +
        "CT=" + CT[p] + " PT=" + pt[p] + " expected=" + CRIBS[p] + " " + match +
        "  k_vig=" + AZ[kVig] + "(" + kVig + ")" +
        "  k_beau=" + AZ[kBeau] + "(" + kBeau + ")"
      );
    }
    return lines.join("\n");
  }

  // =========================================================================
  // Rendering helpers
  // =========================================================================

  function renderPT(text, container) {
    var html = "";
    for (var i = 0; i < text.length; i++) {
      if (CRIBS[i] !== undefined) {
        var isMatch = text[i] === CRIBS[i];
        var cls = isMatch ? "crib" : "crib-miss";
        var group = (i >= 21 && i <= 33) ? "ENE" : "BC";
        var tip = "pos " + i + " (" + group + "): expected " + CRIBS[i] + ", got " + text[i];
        html += '<span class="' + cls + '" title="' + tip + '">' + text[i] + "</span>";
      } else {
        html += text[i];
      }
    }
    container.innerHTML = html;
    container.classList.add("text-mono");
  }

  function renderCheckerboard(cb, container) {
    var html = '<table class="vic-cb-table"><thead><tr><th></th>';
    for (var h = 0; h < 10; h++) {
      html += "<th>" + cb.headers[h] + "</th>";
    }
    html += "</tr></thead><tbody>";

    // Row 0
    html += "<tr><td></td>";
    for (var c0 = 0; c0 < 10; c0++) {
      var ch = cb.row0[c0];
      var cls = ch === null ? "vic-cb-blank" : "vic-cb-filled";
      html += '<td class="' + cls + '">' + (ch || "\u2022") + "</td>";
    }
    html += "</tr>";

    // Row 1
    html += "<tr><td class='vic-cb-rowlabel'>" + cb.rowLabel1 + "</td>";
    for (var c1 = 0; c1 < 10; c1++) {
      html += "<td>" + cb.row1[c1] + "</td>";
    }
    html += "</tr>";

    // Row 2
    html += "<tr><td class='vic-cb-rowlabel'>" + cb.rowLabel2 + "</td>";
    for (var c2 = 0; c2 < 10; c2++) {
      html += "<td>" + cb.row2[c2] + "</td>";
    }
    html += "</tr>";

    html += "</tbody></table>";

    // Encoding table
    html += '<div class="vic-encode-table"><h5>Encoding</h5><div class="text-mono" style="word-break:break-all;">';
    var sortedKeys = Object.keys(cb.encode).sort();
    for (var si = 0; si < sortedKeys.length; si++) {
      var letter = sortedKeys[si];
      if (letter === "." || letter === "/") continue;
      html += '<span class="vic-encode-pair">' + letter + "=" + cb.encode[letter] + "</span> ";
    }
    html += "</div></div>";

    container.innerHTML = html;
  }

  function renderKeyGen(steps, container) {
    var html = '<div class="vic-keygen-lines">';

    function fmtDigits(arr) {
      return arr.map(function (d) { return d; }).join(" ");
    }

    function line(label, value, desc) {
      var html = '<div class="vic-kg-line"><span class="vic-kg-label">' + label + '</span><span class="vic-kg-value text-mono">' + value + '</span>';
      if (desc) html += '<span class="vic-kg-desc">' + desc + '</span>';
      html += '</div>';
      return html;
    }

    html += line("Line-A", fmtDigits(steps.lineA), "Keygroup");
    html += line("Line-B", fmtDigits(steps.lineB), "First 5 digits of Date");
    html += line("Line-C", fmtDigits(steps.lineC), "(A - B) mod 10");
    html += line("Line-D", steps.lineD, "First 20 letters of Phrase");
    html += line("Line-E.1", fmtDigits(steps.lineE1), "Sequence first 10 of D");
    html += line("Line-E.2", fmtDigits(steps.lineE2), "Sequence last 10 of D");
    html += line("Line-F.1", fmtDigits(steps.lineF1), "C chain-added to 10 digits");
    html += line("Line-G", fmtDigits(steps.lineG), "(E.1 + F.1) mod 10");
    html += line("Line-H", fmtDigits(steps.lineH), "G encoded by E.2");
    html += line("Line-J", fmtDigits(steps.lineJ), "Sequence of H");
    html += line("Line-K", fmtDigits(steps.lineK), "Chain-add row 1");
    html += line("Line-L", fmtDigits(steps.lineL), "Chain-add row 2");
    html += line("Line-M", fmtDigits(steps.lineM), "Chain-add row 3");
    html += line("Line-N", fmtDigits(steps.lineN), "Chain-add row 4");
    html += line("Line-P", fmtDigits(steps.lineP), "Chain-add row 5");
    html += line("Line-S", fmtDigits(steps.lineS), "Sequence of P (checkerboard columns)");
    html += line("a, b", steps.a + ", " + steps.b, "Last 2 non-equal of P (" + steps.lastTwoRaw.join(",") + ") + personal " + (document.getElementById("vic-personal").value || "0"));
    html += line("Line-Q", fmtDigits(steps.lineQ), "Columnar transposition key (a=" + steps.a + " digits)");
    html += line("Line-R", fmtDigits(steps.lineR), "Disrupted diagonal key (b=" + steps.b + " digits)");
    html += line("KG pos", steps.kgInsertDigit, "Keygroup insertion position (6th date digit)");

    html += "</div>";
    container.innerHTML = html;
  }

  function renderTransGrids(digits, key, label, container, append) {
    var width = key.length;
    var rows = Math.ceil(digits.length / width);

    var html = append ? container.innerHTML : "";
    html += '<div class="vic-trans-grid-section">';
    html += "<h5>" + label + " (key: " + key.join("") + ", width " + width + ")</h5>";
    html += '<table class="vic-trans-table"><thead><tr>';

    // Rank-sorted column headers
    var colOrder = [];
    for (var ci = 0; ci < width; ci++) colOrder.push({ col: ci, rank: key[ci] === 0 ? 10 : key[ci] });
    colOrder.sort(function (a, b) { return a.rank - b.rank; });

    for (var h = 0; h < width; h++) {
      html += "<th>" + (key[h] === 0 ? "0" : key[h]) + "</th>";
    }
    html += "</tr></thead><tbody>";

    for (var r = 0; r < rows; r++) {
      html += "<tr>";
      for (var c = 0; c < width; c++) {
        var idx = r * width + c;
        html += "<td>" + (idx < digits.length ? digits[idx] : "") + "</td>";
      }
      html += "</tr>";
    }

    html += "</tbody></table></div>";
    container.innerHTML = html;
  }

  function updateScoreDisplay(score, isK4) {
    var heroEl = document.getElementById("vic-score-hero");
    var heroNum = document.getElementById("vic-score-hero-num");
    var heroBadge = document.getElementById("vic-score-hero-badge");

    var tier = score.classification === "noise" ? "noise" :
      score.classification === "interesting" ? "store" :
      score.classification === "signal" ? "signal" : "breakthrough";

    if (isK4) {
      heroNum.textContent = score.total + "/24";
      heroBadge.textContent = score.classification;
      heroBadge.className = "score-badge score-badge-" + tier;
      document.getElementById("vic-score-ene").textContent = score.ene + "/13";
      document.getElementById("vic-score-bc").textContent = score.bc + "/11";
    } else {
      heroNum.textContent = "";
      heroBadge.textContent = "";
      heroBadge.className = "score-badge";
      document.getElementById("vic-score-ene").textContent = "n/a";
      document.getElementById("vic-score-bc").textContent = "n/a";
    }

    heroEl.className = "vic-score-bar" + (isK4 ? " sc-" + tier : "");
    document.getElementById("vic-score-ic").textContent = score.ic.toFixed(4);
    document.getElementById("vic-score-free").textContent = score.freeCrib;
  }

  // =========================================================================
  // Main pipeline
  // =========================================================================

  function runVICPipeline() {
    try {
      runVICPipelineInner();
    } catch (e) {
      document.getElementById("vic-plaintext-display").innerHTML =
        '<span style="color:var(--red);">Pipeline error: ' + e.message + '</span>';
      console.error("VIC pipeline error:", e);
    }
  }

  function runVICPipelineInner() {
    var phrase = document.getElementById("vic-phrase").value || "";
    var date = sanitizeDigits(document.getElementById("vic-date").value || "");
    var personal = sanitizeDigits(document.getElementById("vic-personal").value || "0");
    var keygroup = sanitizeDigits(document.getElementById("vic-keygroup").value || "");
    var topRow = document.getElementById("vic-toprow").value || "ASINTOER";
    var remainingLetters = document.getElementById("vic-remaining").value || "";
    var ciphertext = document.getElementById("vic-ciphertext").value || "";
    var direction = document.getElementById("vic-direction").value;
    var skipCB = document.getElementById("vic-skip-checkerboard").checked;
    var skipTrans = document.getElementById("vic-skip-transpositions").checked;
    var skipKG = document.getElementById("vic-skip-keygroup-extract").checked;
    var ctIsDigits = document.getElementById("vic-ct-is-digits").checked;
    var letterMappingEl = document.getElementById("vic-letter-mapping");
    var letterMapping = letterMappingEl ? letterMappingEl.value : "checkerboard";
    var altTrans = document.getElementById("vic-alt-trans").value;
    var nullMode = document.getElementById("vic-null-mask-mode").value;
    var nullPositionsStr = document.getElementById("vic-null-positions").value || "";

    // Validate inputs
    function showValidationError(msg) {
      document.getElementById("vic-plaintext-display").innerHTML = '<span class="text-muted">' + msg + '</span>';
      document.getElementById("vic-score-hero").className = "vic-score-bar sc-noise";
      document.getElementById("vic-score-hero-num").textContent = "--";
      document.getElementById("vic-score-hero-badge").textContent = "";
      document.getElementById("vic-score-hero-badge").className = "score-badge score-badge-noise";
      document.getElementById("vic-score-ene").textContent = "--";
      document.getElementById("vic-score-bc").textContent = "--";
      document.getElementById("vic-score-ic").textContent = "--";
      document.getElementById("vic-score-free").textContent = "--";
      document.getElementById("vic-keygen-display").innerHTML = "";
      document.getElementById("vic-checkerboard-display").innerHTML = "";
      document.getElementById("vic-trans-display").innerHTML = "";
      document.getElementById("vic-digit-stream").textContent = "";
      document.getElementById("vic-keystream-detail").textContent = "";
    }
    if (date.length < 6) {
      showValidationError("Date must be 6 digits.");
      return;
    }
    if (keygroup.length < 5) {
      showValidationError("Keygroup must be 5 digits.");
      return;
    }
    if (sanitize(phrase).length < 20) {
      showValidationError("Phrase must be at least 20 letters.");
      return;
    }

    // Generate VIC keys
    var steps = generateVICKeys(phrase, date, personal, keygroup);
    renderKeyGen(steps, document.getElementById("vic-keygen-display"));

    // Build checkerboard
    var cb = buildCheckerboard(steps.lineS, topRow, remainingLetters);
    renderCheckerboard(cb, document.getElementById("vic-checkerboard-display"));

    // Pre-VIC layer
    var preSubMethod = document.getElementById("vic-pre-sub-method").value;
    var preSubKey = document.getElementById("vic-pre-sub-key").value || "";
    var preSubAlpha = document.getElementById("vic-pre-sub-alphabet").value === "KA" ? KA : AZ;

    // Post-VIC layer
    var postSubMethod = document.getElementById("vic-post-sub-method").value;
    var postSubKey = document.getElementById("vic-post-sub-key").value || "";
    var postSubAlpha = document.getElementById("vic-post-sub-alphabet").value === "KA" ? KA : AZ;

    // Null mask
    var nullPositions = [];
    if (nullMode !== "none") {
      nullPositions = nullPositionsStr.split(",").map(function (s) { return parseInt(s.trim()); })
        .filter(function (n) { return !isNaN(n) && n >= 0; });
    }

    var workingText = ciphertext.toUpperCase().replace(/[^A-Z0-9]/g, "");
    var digitStream = [];

    if (direction === "decrypt") {
      // === DECRYPTION PIPELINE ===

      // 1. Pre-null mask removal (if mode = pre)
      if (nullMode === "pre") {
        var nullSet = {};
        for (var ni = 0; ni < nullPositions.length; ni++) nullSet[nullPositions[ni]] = true;
        var cleaned = "";
        for (var ci = 0; ci < workingText.length; ci++) {
          if (!nullSet[ci]) cleaned += workingText[ci];
        }
        workingText = cleaned;
      }

      // 2. Undo post-VIC substitution (applied last during encryption, undo first)
      if (postSubMethod !== "none" && postSubKey) {
        workingText = applyExtraLayer(workingText, postSubMethod, postSubKey, postSubAlpha, false);
      }

      // 3. Convert to digits
      if (ctIsDigits) {
        // Input is already digits — parse directly
        for (var di = 0; di < workingText.length; di++) {
          var d = parseInt(workingText[di]);
          if (!isNaN(d)) digitStream.push(d);
        }
      } else if (skipCB) {
        // Skip checkerboard — convert letters to digits via selected mapping
        // (uses az_mod10 or ka_mod10 since checkerboard is skipped)
        var skipMapping = (letterMapping === "checkerboard") ? "az_mod10" : letterMapping;
        digitStream = letterToDigits(workingText, skipMapping, null);
      } else {
        // DECRYPT MODE with checkerboard: convert CT letters to digits via selected mapping
        digitStream = letterToDigits(workingText, letterMapping, cb);
      }

      if (digitStream.length > 0) {
        // 4. Extract keygroup (if applicable)
        if (!skipKG) {
          var kgResult = extractKeygroup(digitStream, 5, steps.kgInsertDigit);
          digitStream = kgResult.digits;
        }

        // Display digit stream
        var dsLabel = ctIsDigits ? "Parsed digits" : (skipCB ? "Letters \u2192 digits (" + letterMapping + ")" : "Letters \u2192 digits (checkerboard)");
        document.getElementById("vic-digit-stream").textContent =
          dsLabel + ": " + digitStream.join("") +
          "\nLength: " + digitStream.length + " digits";

        // 5. Undo transpositions
        if (!skipTrans) {
          if (altTrans === "none") {
            // Standard VIC: undo disrupted diagonal, then columnar
            var transContainer = document.getElementById("vic-trans-display");
            transContainer.innerHTML = "";

            // Undo disrupted diagonal (Line-R key)
            renderTransGrids(digitStream, steps.lineR, "Disrupted Diagonal (before undo)", transContainer, false);
            digitStream = disruptedDiagDecrypt(digitStream, steps.lineR);

            // Undo columnar (Line-Q key)
            renderTransGrids(digitStream, steps.lineQ, "Columnar (before undo)", transContainer, true);
            digitStream = columnarDecrypt(digitStream, steps.lineQ);
          } else if (altTrans === "columnar") {
            var transContainer2 = document.getElementById("vic-trans-display");
            renderTransGrids(digitStream, steps.lineQ, "Columnar only (Line-Q key, before undo)", transContainer2, false);
            digitStream = columnarDecrypt(digitStream, steps.lineQ);
          } else if (altTrans === "col7") {
            // Columnar width 7, ascending order
            var col7Key = [1, 2, 3, 4, 5, 6, 7];
            var transContainer3 = document.getElementById("vic-trans-display");
            renderTransGrids(digitStream, col7Key, "Columnar width 7 (ascending, before undo)", transContainer3, false);
            digitStream = columnarDecrypt(digitStream, col7Key);
          } else if (altTrans === "railfence") {
            // Use Line-Q length as depth
            var transContainer4 = document.getElementById("vic-trans-display");
            transContainer4.innerHTML = "<p>Rail fence with depth " + steps.lineQ.length + " (on digit stream)</p>";
            digitStream = railfenceDecryptDigits(digitStream, steps.lineQ.length);
          }
        }

        // 6. Decode digits through checkerboard
        if (!skipCB) {
          workingText = checkerboardDecode(digitStream, cb);
        } else {
          // Checkerboard skipped — output raw digits as text
          workingText = digitStream.join("");
        }
      }

      // 7. Apply pre-VIC substitution undo
      if (preSubMethod !== "none" && preSubKey) {
        workingText = applyExtraLayer(workingText, preSubMethod, preSubKey, preSubAlpha, false);
      }

      // 8. Post-null mask removal (if mode = post)
      if (nullMode === "post") {
        var nullSet2 = {};
        for (var ni2 = 0; ni2 < nullPositions.length; ni2++) nullSet2[nullPositions[ni2]] = true;
        var cleaned2 = "";
        for (var ci2 = 0; ci2 < workingText.length; ci2++) {
          if (!nullSet2[ci2]) cleaned2 += workingText[ci2];
        }
        workingText = cleaned2;
      }
    } else {
      // === ENCRYPTION PIPELINE ===

      // 1. Pre-VIC substitution
      if (preSubMethod !== "none" && preSubKey) {
        workingText = applyExtraLayer(workingText, preSubMethod, preSubKey, preSubAlpha, true);
      }

      // 2. Encode through checkerboard
      if (!skipCB) {
        digitStream = checkerboardEncode(workingText, cb);
      } else {
        // If skipping CB, try to parse as digits
        digitStream = [];
        for (var ei = 0; ei < workingText.length; ei++) {
          var ed = parseInt(workingText[ei]);
          if (!isNaN(ed)) digitStream.push(ed);
        }
      }

      if (digitStream.length > 0) {
        // 3. Apply transpositions
        if (!skipTrans) {
          if (altTrans === "none") {
            digitStream = columnarEncrypt(digitStream, steps.lineQ);
            digitStream = disruptedDiagEncrypt(digitStream, steps.lineR);
          } else if (altTrans === "columnar") {
            digitStream = columnarEncrypt(digitStream, steps.lineQ);
          } else if (altTrans === "col7") {
            var col7KeyEnc = [1, 2, 3, 4, 5, 6, 7];
            digitStream = columnarEncrypt(digitStream, col7KeyEnc);
          }
        }

        // 4. Insert keygroup
        if (!skipKG) {
          digitStream = insertKeygroup(digitStream, keygroup, steps.kgInsertDigit);
        }

        // 5. Decode back to text through checkerboard (to get letter CT)
        if (!skipCB) {
          workingText = checkerboardDecode(digitStream, cb);
        } else {
          workingText = digitStream.join("");
        }

        document.getElementById("vic-digit-stream").textContent =
          "Digit stream: " + digitStream.join("") +
          "\nLength: " + digitStream.length + " digits";
      }

      // 6. Post-VIC substitution
      if (postSubMethod !== "none" && postSubKey) {
        workingText = applyExtraLayer(workingText, postSubMethod, postSubKey, postSubAlpha, true);
      }
    }

    // Display results
    var plaintext = sanitize(workingText);
    if (plaintext.length > 0) {
      renderPT(plaintext, document.getElementById("vic-plaintext-display"));
    } else {
      document.getElementById("vic-plaintext-display").innerHTML =
        '<span class="text-muted">No output. Check inputs.</span>';
    }

    // Score — only show K4 crib analysis when input is K4 CT
    var isK4 = (sanitize(ciphertext) === CT);
    var score = scorePlaintext(plaintext);
    updateScoreDisplay(score, isK4);

    // Share promising K4 results (18+) ONLY if the visitor opted in via the
    // page checkbox. Default off: nothing is ever sent without consent.
    var vicShareOptIn = document.getElementById("wb-share-signal");
    if (vicShareOptIn && vicShareOptIn.checked && isK4 && score.total >= 18) {
      var notifyKey = score.total + ":" + score.classification;
      if (!sessionNotified[notifyKey]) {
        sessionNotified[notifyKey] = true;
        var methodParts = ["VIC"];
        if (skipCB) methodParts.push("noCB");
        if (skipTrans) methodParts.push("noTrans");
        if (altTrans !== "none") methodParts.push(altTrans);
        if (preSubMethod !== "none") methodParts.push("pre:" + preSubMethod);
        if (postSubMethod !== "none") methodParts.push("post:" + postSubMethod);
        if (nullMode !== "none") methodParts.push("null:" + nullMode);
        var vicMethod = methodParts.join("+");
        var vicBody = score.total + "/24 " + score.classification.toUpperCase()
          + " | ENE=" + score.ene + " BC=" + score.bc
          + " | " + vicMethod
          + " | phrase=" + sanitize(phrase).substring(0, 12)
          + " date=" + date + " pn=" + personal + " kg=" + keygroup
          + " | PT: " + plaintext.substring(0, 40) + "...";
        try {
          fetch("https://ntfy.sh/kryptosbot-wb-signal", {
            method: "POST", mode: "no-cors",
            headers: {
              "Title": "K4 VIC Workbench: " + score.total + "/24 " + score.classification,
              "Priority": score.total >= 24 ? "5" : "4",
              "Tags": score.total >= 24 ? "rotating_light,trophy" : "chart_with_upwards_trend"
            },
            body: vicBody
          });
        } catch (e) { /* silent */ }
      }
    }

    // Keystream — only meaningful for K4
    document.getElementById("vic-keystream-detail").textContent = isK4 ? deriveKeystream(plaintext) : "(K4 keystream analysis only shown when ciphertext is K4)";

    // Update digit stream display
    if (digitStream && digitStream.length > 0) {
      var dsEl = document.getElementById("vic-digit-stream");
      dsEl.textContent += "\n\nFinal plaintext length: " + plaintext.length + " chars";
    }

    // History
    addToHistory(score, plaintext, steps);
  }

  function railfenceDecryptDigits(digits, depth) {
    var n = digits.length;
    if (depth <= 1 || depth >= n) return digits;

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
      rails.push(digits.slice(pos, pos + railLens[r]));
      pos += railLens[r];
    }

    var result = [];
    var indices = new Array(depth).fill(0);
    rail = 0; dir = 1;
    for (var k = 0; k < n; k++) {
      result.push(rails[rail][indices[rail]++]);
      if (rail === 0) dir = 1;
      else if (rail === depth - 1) dir = -1;
      rail += dir;
    }
    return result;
  }

  // =========================================================================
  // Session history
  // =========================================================================
  var sessionHistory = [];
  var sessionNotified = {};

  function addToHistory(score, plaintext, steps) {
    var entry = {
      time: new Date().toLocaleTimeString(),
      score: score.total,
      ene: score.ene,
      bc: score.bc,
      classification: score.classification,
      phrase: document.getElementById("vic-phrase").value,
      date: document.getElementById("vic-date").value,
      keygroup: document.getElementById("vic-keygroup").value,
      personal: document.getElementById("vic-personal").value,
      pt: plaintext.substring(0, 40) + (plaintext.length > 40 ? "..." : ""),
      lineQ: steps.lineQ.join(""),
      lineR: steps.lineR.join("")
    };
    sessionHistory.unshift(entry);

    var countEl = document.getElementById("vic-history-count");
    countEl.textContent = sessionHistory.length;

    var logEl = document.getElementById("vic-history-log");
    var html = "";
    for (var i = 0; i < Math.min(sessionHistory.length, 50); i++) {
      var e = sessionHistory[i];
      var cls = e.classification === "noise" ? "text-muted" :
                e.classification === "interesting" ? "" :
                e.classification === "signal" ? "text-accent" : "text-green";
      html += '<div class="wb-history-entry">';
      html += '<span class="' + cls + '">' + e.score + '/24</span> ';
      html += '<small class="text-muted">' + e.time + '</small> ';
      html += '<span class="text-mono" style="font-size:var(--text-xs);">';
      html += 'phrase=' + e.phrase.substring(0, 12) + ' date=' + e.date + ' kg=' + e.keygroup;
      html += ' Q=' + e.lineQ + ' R=' + e.lineR;
      html += '</span>';
      html += '<div class="text-mono" style="font-size:var(--text-xs);color:var(--text-tertiary);">' + e.pt + '</div>';
      html += '</div>';
    }
    logEl.innerHTML = html;
  }

  // =========================================================================
  // UI wiring
  // =========================================================================

  function showHide(el, show) {
    if (show) el.classList.remove("hidden");
    else el.classList.add("hidden");
  }

  function wireUI() {
    // Pre-sub key group visibility
    var preSubMethod = document.getElementById("vic-pre-sub-method");
    var preSubGroup = document.getElementById("vic-pre-sub-key-group");
    preSubMethod.addEventListener("change", function () {
      showHide(preSubGroup, preSubMethod.value !== "none");
    });

    // Post-sub key group visibility
    var postSubMethod = document.getElementById("vic-post-sub-method");
    var postSubGroup = document.getElementById("vic-post-sub-key-group");
    postSubMethod.addEventListener("change", function () {
      showHide(postSubGroup, postSubMethod.value !== "none");
    });

    // Null mask group visibility
    var nullMaskMode = document.getElementById("vic-null-mask-mode");
    var nullMaskGroup = document.getElementById("vic-null-mask-group");
    nullMaskMode.addEventListener("change", function () {
      showHide(nullMaskGroup, nullMaskMode.value !== "none");
    });

    // Letter-mapping group: hide when "Input is digit stream" is checked
    var ctIsDigitsCB = document.getElementById("vic-ct-is-digits");
    var letterMappingGroup = document.getElementById("vic-letter-mapping-group");
    if (ctIsDigitsCB && letterMappingGroup) {
      ctIsDigitsCB.addEventListener("change", function () {
        showHide(letterMappingGroup, !ctIsDigitsCB.checked);
      });
    }

    // Run button
    document.getElementById("vic-run-btn").addEventListener("click", function () {
      runVICPipeline();
    });

    // Reset button
    document.getElementById("vic-reset-btn").addEventListener("click", function () {
      document.getElementById("vic-phrase").value = "KRYPTOSABCDEFGHIJLMN";
      document.getElementById("vic-date").value = "091189";
      document.getElementById("vic-personal").value = "5";
      document.getElementById("vic-keygroup").value = "90271";
      document.getElementById("vic-toprow").value = "ASINTOER";
      document.getElementById("vic-remaining").value = "";
      document.getElementById("vic-ciphertext").value = CT;
      document.getElementById("vic-direction").value = "decrypt";
      document.getElementById("vic-skip-checkerboard").checked = false;
      document.getElementById("vic-skip-transpositions").checked = false;
      document.getElementById("vic-skip-keygroup-extract").checked = false;
      document.getElementById("vic-ct-is-digits").checked = false;
      if (document.getElementById("vic-letter-mapping")) {
        document.getElementById("vic-letter-mapping").value = "checkerboard";
      }
      showHide(letterMappingGroup, true);
      document.getElementById("vic-pre-sub-method").value = "none";
      document.getElementById("vic-post-sub-method").value = "none";
      document.getElementById("vic-alt-trans").value = "none";
      document.getElementById("vic-null-mask-mode").value = "none";
      document.getElementById("vic-null-positions").value = "";
      document.getElementById("vic-pre-sub-key").value = "";
      document.getElementById("vic-post-sub-key").value = "";
      showHide(preSubGroup, false);
      showHide(postSubGroup, false);
      showHide(nullMaskGroup, false);
      runVICPipeline();
    });

    // Auto-run on significant input changes
    var autoRunInputs = [
      "vic-phrase", "vic-date", "vic-personal", "vic-keygroup",
      "vic-toprow", "vic-remaining", "vic-direction",
      "vic-pre-sub-method", "vic-pre-sub-key", "vic-pre-sub-alphabet",
      "vic-post-sub-method", "vic-post-sub-key", "vic-post-sub-alphabet",
      "vic-alt-trans", "vic-null-mask-mode", "vic-null-positions",
      "vic-letter-mapping"
    ];
    var debounceTimer = null;
    function debouncedRun() {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(runVICPipeline, 300);
    }

    for (var ai = 0; ai < autoRunInputs.length; ai++) {
      var el = document.getElementById(autoRunInputs[ai]);
      if (el) {
        el.addEventListener("input", debouncedRun);
        el.addEventListener("change", debouncedRun);
      }
    }

    // Checkboxes trigger immediate run
    var checkboxes = [
      "vic-skip-checkerboard", "vic-skip-transpositions",
      "vic-skip-keygroup-extract", "vic-ct-is-digits"
    ];
    for (var ci = 0; ci < checkboxes.length; ci++) {
      var cbEl = document.getElementById(checkboxes[ci]);
      if (cbEl) cbEl.addEventListener("change", runVICPipeline);
    }
  }

  // =========================================================================
  // Inline styles for VIC-specific components
  // =========================================================================
  function injectStyles() {
    var style = document.createElement("style");
    style.textContent = [
      /* ---- Layout: single-column stacked, side-by-side only on very wide screens ---- */
      ".vic-workspace { flex-direction: column; }",
      "@media (min-width: 1280px) {",
      "  .vic-workspace { flex-direction: row; }",
      "  .vic-controls { flex: 1 1 400px; max-width: 460px; }",
      "  .vic-results { flex: 1 1 480px; }",
      "}",

      /* ---- Compact score bar (replaces oversized hero) ---- */
      ".vic-score-bar { display: flex; align-items: center; gap: var(--sp-3); padding: var(--sp-2) var(--sp-3); border-radius: var(--radius-md); border: 1px solid var(--border-default); background: var(--bg-surface); margin: var(--sp-2) 0; flex-wrap: wrap; }",
      ".vic-score-bar-num { font-family: var(--font-mono); font-size: var(--text-xl); font-weight: 700; line-height: 1; color: var(--text-tertiary); white-space: nowrap; }",
      ".vic-score-bar-stats { display: flex; gap: var(--sp-3); flex-wrap: wrap; margin-left: auto; }",
      ".vic-score-bar-stat { font-size: var(--text-xs); color: var(--text-tertiary); white-space: nowrap; }",
      ".vic-score-bar-stat b { color: var(--text-secondary); font-family: var(--font-mono); }",
      ".vic-score-bar.sc-noise .vic-score-bar-num { color: var(--text-tertiary); }",
      ".vic-score-bar.sc-store { border-color: var(--amber-border); }",
      ".vic-score-bar.sc-store .vic-score-bar-num { color: var(--amber); }",
      ".vic-score-bar.sc-signal { border-color: rgba(56,189,248,0.3); box-shadow: 0 0 12px rgba(56,189,248,0.06); }",
      ".vic-score-bar.sc-signal .vic-score-bar-num { color: var(--accent); }",
      ".vic-score-bar.sc-breakthrough { border-color: rgba(34,197,94,0.4); box-shadow: 0 0 16px rgba(34,197,94,0.1); }",
      ".vic-score-bar.sc-breakthrough .vic-score-bar-num { color: var(--green); }",

      /* ---- Details panels: tight, no excess padding ---- */
      ".vic-results details { margin-bottom: 2px; }",
      ".vic-results details summary { font-size: var(--text-xs); font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; padding: var(--sp-1) 0; cursor: pointer; user-select: none; }",
      ".vic-results details summary:hover { color: var(--accent); }",
      ".vic-results details[open] summary { color: var(--accent); }",
      ".vic-results details > div, .vic-results details > pre { padding: var(--sp-1) 0 var(--sp-2); }",

      /* ---- Checkerboard table ---- */
      ".vic-cb-table { border-collapse: collapse; margin: var(--sp-1) 0; font-family: var(--font-mono); font-size: var(--text-xs); width: 100%; table-layout: fixed; }",
      ".vic-cb-table th, .vic-cb-table td { border: 1px solid var(--border-default); padding: 2px 4px; text-align: center; }",
      ".vic-cb-table th { background: var(--bg-elevated); color: var(--accent); font-weight: 600; }",
      ".vic-cb-table td { background: var(--bg-surface); }",
      ".vic-cb-blank { background: var(--bg-hover) !important; color: var(--text-tertiary); }",
      ".vic-cb-filled { color: var(--green); font-weight: 600; }",
      ".vic-cb-rowlabel { background: var(--bg-elevated) !important; color: var(--accent); font-weight: 600; }",

      /* ---- Encode pairs: compact inline flow ---- */
      ".vic-encode-table { margin-top: var(--sp-1); }",
      ".vic-encode-table h5 { font-size: 10px; text-transform: uppercase; color: var(--text-tertiary); letter-spacing: 0.06em; margin-bottom: 2px; }",
      ".vic-encode-pair { display: inline-block; margin-right: 6px; margin-bottom: 1px; color: var(--text-secondary); font-size: var(--text-xs); }",

      /* ---- Key generation: compact two-column grid ---- */
      ".vic-keygen-lines { font-size: var(--text-xs); }",
      ".vic-kg-line { display: grid; grid-template-columns: 52px 1fr; gap: 4px; padding: 2px 0; border-bottom: 1px solid var(--border-subtle); align-items: baseline; }",
      ".vic-kg-label { font-weight: 600; color: var(--accent); font-size: 10px; text-transform: uppercase; white-space: nowrap; }",
      ".vic-kg-value { letter-spacing: 0.08em; color: var(--text-primary); }",
      ".vic-kg-desc { grid-column: 1 / -1; color: var(--text-tertiary); font-size: 10px; padding-left: 56px; margin-top: -2px; padding-bottom: 1px; }",

      /* ---- Transposition grids ---- */
      ".vic-trans-grid-section { margin: var(--sp-1) 0; }",
      ".vic-trans-grid-section h5 { font-size: 10px; text-transform: uppercase; color: var(--text-tertiary); letter-spacing: 0.06em; margin-bottom: 2px; }",
      ".vic-trans-table { border-collapse: collapse; font-family: var(--font-mono); font-size: 11px; }",
      ".vic-trans-table th, .vic-trans-table td { border: 1px solid var(--border-default); padding: 1px 4px; text-align: center; min-width: 1.4em; }",
      ".vic-trans-table th { background: var(--bg-elevated); color: var(--accent); }",
      ".vic-trans-table td { background: var(--bg-surface); color: var(--text-secondary); }",

      /* ---- History ---- */
      ".wb-history-scroll { max-height: 200px; overflow-y: auto; }",
      ".wb-history-entry { padding: 2px 0; border-bottom: 1px solid var(--border-subtle); font-size: var(--text-xs); }",
      ".text-accent { color: var(--accent); }",
      ".text-green { color: var(--green); font-weight: 600; }",

      /* ---- Grid display containers ---- */
      ".vic-grid-display { overflow-x: auto; max-width: 100%; }",

      /* ---- Plaintext display ---- */
      ".vic-results .ct-display-compact { font-size: var(--text-xs); padding: var(--sp-2); line-height: 1.5; word-break: break-all; }",

      /* ---- Result heading ---- */
      ".vic-results .wb-result-heading { font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-tertiary); margin: var(--sp-2) 0 var(--sp-1); }"
    ].join("\n");
    document.head.appendChild(style);
  }

  // =========================================================================
  // Init
  // =========================================================================
  injectStyles();
  wireUI();
  // Run once on load
  runVICPipeline();

})();
