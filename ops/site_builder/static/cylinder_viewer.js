// ── DATA ───────────────────────────────────────────────────────────────
// Full cipher panel: 868 chars in 28 rows of 31 (squeezed ? removed, remaining ? kept)
// Source: strategies.py FULL_CORRECTED_CT / sculpture_path_search _FULL_CT_869
var PANEL_ROWS = [
  "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   // 0   K1
  "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   // 1   K1
  "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   // 2   K1 ends col 0, K2 starts col 1
  "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   // 3   K2
  "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",    // 4   K2
  "QZGZLECGYUXUEENJTBJLBQCRTBJDFHR",    // 5   K2
  "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",    // 6   K2
  "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",    // 7   K2
  "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",    // 8   K2
  "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",    // 9   K2  (squeezed ? removed)
  "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",    // 10  K2
  "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",    // 11  K2
  "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",    // 12  K2
  "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",    // 13  K2 ends
  "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",    // 14  K3
  "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",    // 15  K3
  "TPRNGATIHNRARPESLNNELEBLPIIACAE",     // 16  K3
  "WMTWNDITEENRAHCTENEUDRETNHAEOET",     // 17  K3
  "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",     // 18  K3
  "EIFTBRSPAMHHEWENATAMATEGYEERLBT",     // 19  K3
  "EEFOASFIOTUETUAEOTOARMAEERTNRTI",     // 20  K3
  "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",    // 21  K3
  "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",     // 22  K3
  "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",    // 23  K3
  "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",    // 24  K3 ends, K4 starts col 27
  "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",    // 25  K4
  "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",    // 26  K4
  "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",    // 27  K4 ends
];

var WINDOW = 31;
var NULL_PALETTE = { B:1, G:1, I:1, K:1, O:1, W:1, Z:1 };

// Section boundaries (sculpture row ranges)
var SECTIONS = [
  { label: 'K1', startRow: 0, endRow: 2 },
  { label: 'K2', startRow: 2, endRow: 14 },
  { label: 'K3', startRow: 14, endRow: 25 },
  { label: 'K4', startRow: 24, endRow: 28 },
];

// K4 starts at global position 771 (row 24 col 27)
// K4 CT positions 0-96 map to global positions 771-867
var K4_GLOBAL_START = 24 * 31 + 27;  // = 771

// K4 crib positions (0-indexed within K4)
var K4_CRIBS = [
  { start: 21, len: 13, cls: 'crib-ene' },   // EASTNORTHEAST
  { start: 63, len: 11, cls: 'crib-bcl' },   // BERLINCLOCK
];

// Build global-position crib map
var cribGlobalMap = {};
K4_CRIBS.forEach(function(c) {
  for (var i = 0; i < c.len; i++) {
    cribGlobalMap[K4_GLOBAL_START + c.start + i] = c.cls;
  }
});

// ── STATE ──────────────────────────────────────────────────────────────
var showNullPalette = true;
var showPositions = false;
var offsets = new Array(28).fill(0);

// ── HELPERS ────────────────────────────────────────────────────────────
function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function isK4Global(globalPos) {
  return globalPos >= K4_GLOBAL_START && globalPos < K4_GLOBAL_START + 97;
}

// ── RENDER ─────────────────────────────────────────────────────────────
function render() {
  var panel = document.getElementById('panel');
  clearChildren(panel);

  // Column numbers header
  var colNums = document.createElement('div');
  colNums.className = 'col-numbers';
  for (var c = 0; c < WINDOW; c++) {
    var cn = document.createElement('div');
    cn.className = 'col-num';
    cn.textContent = String(c);
    colNums.appendChild(cn);
  }
  panel.appendChild(colNums);

  var sectionIdx = 0;
  var shownSections = {};

  for (var ri = 0; ri < 28; ri++) {
    // Section separator labels
    for (var si = 0; si < SECTIONS.length; si++) {
      var sec = SECTIONS[si];
      if (sec.startRow === ri && !shownSections[sec.label]) {
        shownSections[sec.label] = true;
        var sep = document.createElement('div');
        sep.className = 'section-sep';
        var line1 = document.createElement('div');
        line1.className = 'sep-line';
        var lbl = document.createElement('span');
        lbl.className = 'sep-label';
        lbl.textContent = sec.label;
        var line2 = document.createElement('div');
        line2.className = 'sep-line';
        sep.appendChild(line1);
        sep.appendChild(lbl);
        sep.appendChild(line2);
        panel.appendChild(sep);
      }
    }

    var row = PANEL_ROWS[ri];
    var n = row.length;
    var offset = offsets[ri];

    var container = document.createElement('div');
    container.className = 'row-container';

    // Row number
    var rowNum = document.createElement('div');
    rowNum.className = 'row-num';
    rowNum.textContent = String(ri);
    container.appendChild(rowNum);

    // Left arrow
    var leftBtn = document.createElement('button');
    leftBtn.className = 'arrow-btn';
    leftBtn.textContent = '\u25C0';
    leftBtn.title = 'Rotate left';
    leftBtn.dataset.row = String(ri);
    leftBtn.addEventListener('click', (function(r) {
      return function() { rotate(r, -1); };
    })(ri));
    container.appendChild(leftBtn);

    // Cells
    var cellsEl = document.createElement('div');
    cellsEl.className = 'row-cells';
    cellsEl.dataset.row = String(ri);

    for (var col = 0; col < WINDOW; col++) {
      var srcIdx = ((col - offset) % n + n) % n;
      var ch = row[srcIdx];
      var globalPos = ri * 31 + srcIdx;

      var cell = document.createElement('div');
      cell.className = 'cell';

      // Crib highlighting
      if (cribGlobalMap[globalPos]) {
        cell.classList.add(cribGlobalMap[globalPos]);
      }

      // Null palette (K4 chars only)
      if (showNullPalette && NULL_PALETTE[ch] && isK4Global(globalPos)) {
        cell.classList.add('null-palette');
      }

      // ? marks
      if (ch === '?') {
        cell.classList.add('q-mark');
      }

      cell.textContent = ch;

      // Position labels (K4 only)
      if (showPositions && isK4Global(globalPos)) {
        var posLabel = document.createElement('span');
        posLabel.className = 'pos-label';
        posLabel.textContent = String(globalPos - K4_GLOBAL_START);
        cell.appendChild(posLabel);
      }

      cellsEl.appendChild(cell);
    }

    setupDrag(cellsEl, ri);
    container.appendChild(cellsEl);

    // Right arrow
    var rightBtn = document.createElement('button');
    rightBtn.className = 'arrow-btn';
    rightBtn.textContent = '\u25B6';
    rightBtn.title = 'Rotate right';
    rightBtn.addEventListener('click', (function(r) {
      return function() { rotate(r, 1); };
    })(ri));
    container.appendChild(rightBtn);

    // Offset badge
    var badge = document.createElement('div');
    badge.className = 'offset-badge';
    if (offset === 0) {
      badge.classList.add('zero');
      badge.textContent = '0';
    } else if (offset > 0) {
      badge.classList.add('positive');
      badge.textContent = '+' + offset;
    } else {
      badge.classList.add('negative');
      badge.textContent = String(offset);
    }
    container.appendChild(badge);

    panel.appendChild(container);
  }
}

// ── ROTATION ───────────────────────────────────────────────────────────
function rotate(ri, delta) {
  var lockAll = document.getElementById('lock-all').checked;
  if (lockAll) {
    for (var i = 0; i < 28; i++) offsets[i] += delta;
  } else {
    offsets[ri] += delta;
  }
  render();
}

function resetAll() {
  for (var i = 0; i < 28; i++) offsets[i] = 0;
  render();
}

// ── DRAG SUPPORT ───────────────────────────────────────────────────────
function setupDrag(cellsEl, ri) {
  var startX = null;
  var accumulated = 0;
  var threshold = 28;

  function onStart(x) {
    startX = x;
    accumulated = 0;
  }

  function onMove(x) {
    if (startX === null) return;
    var dx = x - startX;
    var steps = Math.trunc(dx / threshold);
    if (steps !== accumulated) {
      var delta = steps - accumulated;
      accumulated = steps;
      rotate(ri, delta);
    }
  }

  function onEnd() {
    startX = null;
    accumulated = 0;
  }

  cellsEl.addEventListener('mousedown', function(e) {
    e.preventDefault();
    onStart(e.clientX);
    function moveHandler(e2) { onMove(e2.clientX); }
    function upHandler() {
      document.removeEventListener('mousemove', moveHandler);
      document.removeEventListener('mouseup', upHandler);
      onEnd();
    }
    document.addEventListener('mousemove', moveHandler);
    document.addEventListener('mouseup', upHandler);
  });

  cellsEl.addEventListener('touchstart', function(e) {
    if (e.touches.length === 1) onStart(e.touches[0].clientX);
  }, { passive: true });

  cellsEl.addEventListener('touchmove', function(e) {
    if (e.touches.length === 1) onMove(e.touches[0].clientX);
  }, { passive: true });

  cellsEl.addEventListener('touchend', function() { onEnd(); });
  cellsEl.addEventListener('touchcancel', function() { onEnd(); });
}

// ── TOGGLES ────────────────────────────────────────────────────────────
function toggleNullHighlight() {
  showNullPalette = !showNullPalette;
  document.getElementById('btn-show-null').textContent =
    'Null Palette: ' + (showNullPalette ? 'ON' : 'OFF');
  document.getElementById('btn-show-null').classList.toggle('active', showNullPalette);
  render();
}

function togglePositions() {
  showPositions = !showPositions;
  document.getElementById('btn-show-pos').textContent =
    'Positions: ' + (showPositions ? 'ON' : 'OFF');
  document.getElementById('btn-show-pos').classList.toggle('active', showPositions);
  render();
}

// ── INIT ───────────────────────────────────────────────────────────────
// Attach listeners (CSP blocks inline onclick; standalone fallback via onclick attrs)
var _btnReset = document.getElementById('btn-reset');
var _btnNull  = document.getElementById('btn-show-null');
var _btnPos   = document.getElementById('btn-show-pos');
if (_btnReset) _btnReset.addEventListener('click', resetAll);
if (_btnNull)  _btnNull.addEventListener('click', toggleNullHighlight);
if (_btnPos)   _btnPos.addEventListener('click', togglePositions);

if (_btnNull) _btnNull.classList.add('active');
render();
