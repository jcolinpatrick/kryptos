/* k3_jefferson_viewer.js — K3 Jefferson Cipher Viewer */
(function() {
'use strict';

// K3 DATA
var GRID = [
  "ILNTAYESTATHCW","BLHMHEHAROIEEH","ISIWNTHONRSLEO","OLTETYMFTEHMHD",
  "ELAAEOAERIILUV","TSGCRIPEEPEKET","PDNADESTEWCRFR","CLRIUARBAELTMT",
  "OUPIEHBLMTIIFT","EYTPNNTRRSHRGS","HEELEEFEAMDOMS","RRNBTWIEOTDLHL",
  "SNMECIEYTTTDON","LTXLHTRGOHCYEH","NHWEADCEEAERNE","HCRNREYTAAADPM",
  "OAMNNSAAUIBDDI","RISLELTMTNESRE","HAOSEOCAEDFOAF","ANNETFNTUDWAHP",
  "YHSPITEATEEEDI","DSHRDEENOSIOTR","NYOANOHEIBRGGM","EDNRWEQWFIGEAD",
];
var COLS = 14, ROWS = 24;

var NDYAHR_ROWS = {
  23: { letter:'E', dir:'\u00B7', shift:0,  kryptos:'K', cls:'anchor-cell' },
  22: { letter:'N', dir:'\u2190', shift:-1, kryptos:'R', cls:'ndyahr' },
  21: { letter:'D', dir:'\u2193', shift:+1, kryptos:'Y', cls:'ndyahr' },
  20: { letter:'Y', dir:'\u2191', shift:-1, kryptos:'P', cls:'ndyahr' },
  19: { letter:'A', dir:'\u2191', shift:-1, kryptos:'T', cls:'ndyahr' },
  18: { letter:'H', dir:'\u2192', shift:+1, kryptos:'O', cls:'ndyahr' },
  17: { letter:'R', dir:'\u2191', shift:-1, kryptos:'S', cls:'ndyahr' },
};

var K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED" +
  "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY" +
  "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE" +
  "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER" +
  "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN" +
  "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ";

var PT_GRID = [];
for (var r = 0; r < ROWS; r++) {
  var ptRow = "";
  for (var c = 0; c < COLS; c++) {
    var ctPos = c * 24 + (23 - r);
    ptRow += (ctPos < K3_PT.length) ? K3_PT[ctPos] : "?";
  }
  PT_GRID.push(ptRow);
}

// STATE
var offsets = new Array(ROWS).fill(0);
var readBottomUp = true;
var showPT = false;
var hoveredCol = -1;

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function render() {
  var panel = document.getElementById('panel');
  while (panel.firstChild) panel.removeChild(panel.firstChild);

  var colNums = el('div', 'col-nums');
  for (var c = 0; c < COLS; c++) colNums.appendChild(el('div', 'col-n', String(c+1)));
  panel.appendChild(colNums);

  for (var ri = 0; ri < ROWS; ri++) {
    var rowStr = GRID[ri];
    var n = rowStr.length;
    var off = offsets[ri];

    var row = el('div', 'row');
    row.appendChild(el('div', 'row-num', String(ri+1)));

    var la = el('button', 'arrow', '\u25C0');
    la.addEventListener('click', (function(r){return function(){rotate(r,-1)};})(ri));
    row.appendChild(la);

    var cells = el('div', 'cells');
    cells.dataset.row = ri;

    for (var col = 0; col < COLS; col++) {
      var srcIdx = ((col - off) % n + n) % n;
      var ch = rowStr[srcIdx];
      var cell = el('div', 'cell', ch);
      cell.dataset.col = col;

      if (col === 0 && NDYAHR_ROWS[ri] && srcIdx === 0) {
        cell.classList.add(NDYAHR_ROWS[ri].cls);
        var da = el('span', 'disp-arrow', NDYAHR_ROWS[ri].dir);
        cell.appendChild(da);
      }

      if (showPT) {
        var origPt = PT_GRID[ri][srcIdx];
        cell.classList.add('k3pt-on');
        var pts = el('span', 'pt-char', origPt);
        cell.appendChild(pts);
      }

      if (col === hoveredCol) cell.classList.add('col-highlight');

      cell.addEventListener('mouseenter', function() {
        var c = parseInt(this.dataset.col);
        if (hoveredCol !== c) { hoveredCol = c; highlightCol(); }
      });

      cells.appendChild(cell);
    }

    setupDrag(cells, ri);
    row.appendChild(cells);

    var ra = el('button', 'arrow', '\u25B6');
    ra.addEventListener('click', (function(r){return function(){rotate(r,1)};})(ri));
    row.appendChild(ra);

    var badge = el('div', 'offset');
    if (off === 0) { badge.classList.add('zero'); badge.textContent = '0'; }
    else if (off > 0) { badge.classList.add('pos'); badge.textContent = '+'+off; }
    else { badge.classList.add('neg'); badge.textContent = String(off); }
    row.appendChild(badge);

    panel.appendChild(row);
  }
  updateReadout();
}

function highlightCol() {
  document.querySelectorAll('.jv-page .cell').forEach(function(c) {
    c.classList.toggle('col-highlight', parseInt(c.dataset.col) === hoveredCol);
  });
}

function updateReadout() {
  var container = document.getElementById('readout');
  while (container.firstChild) container.removeChild(container.firstChild);

  // Horizontal readout: each column = one row showing "Col N: LETTERS..."
  for (var c = 0; c < COLS; c++) {
    var numDiv = el('div', 'readout-col-num', 'Col ' + (c+1));
    var textDiv = el('div', 'readout-col-text');
    var colStr = '';
    for (var r = 0; r < ROWS; r++) {
      var ri = readBottomUp ? (ROWS-1-r) : r;
      var off = offsets[ri];
      var srcIdx = ((c - off) % COLS + COLS) % COLS;
      colStr += GRID[ri][srcIdx];
    }
    textDiv.textContent = colStr;

    // Wrap in a .readout-col container (CSS display:contents makes it flow into grid)
    var colDiv = el('div', 'readout-col');
    colDiv.appendChild(numDiv);
    colDiv.appendChild(textDiv);
    container.appendChild(colDiv);
  }

  document.getElementById('readout-dir-label').textContent =
    readBottomUp ? '\u2191 bottom to top' : '\u2193 top to bottom';
}

function rotate(ri, delta) {
  if (document.getElementById('lock-all').checked) {
    for (var i = 0; i < ROWS; i++) offsets[i] += delta;
  } else {
    offsets[ri] += delta;
  }
  render();
}

function resetAll() {
  offsets = new Array(ROWS).fill(0);
  document.getElementById('btn-ndyahr').classList.remove('active');
  render();
}

function applyNDYAHR() {
  offsets = new Array(ROWS).fill(0);
  for (var ri in NDYAHR_ROWS) offsets[parseInt(ri)] = NDYAHR_ROWS[ri].shift;
  document.getElementById('btn-ndyahr').classList.add('active');
  render();
}

function toggleDir() {
  readBottomUp = !readBottomUp;
  var btn = document.getElementById('btn-dir');
  btn.textContent = readBottomUp ? 'Read: \u2191 Bottom-Up' : 'Read: \u2193 Top-Down';
  btn.classList.toggle('active', !readBottomUp);
  updateReadout();
}

function togglePT() {
  showPT = !showPT;
  var btn = document.getElementById('btn-pt');
  btn.textContent = 'Plaintext: ' + (showPT ? 'ON' : 'OFF');
  btn.classList.toggle('active', showPT);
  render();
}

function setupDrag(cellsEl, ri) {
  var startX = null, accumulated = 0, threshold = 30;
  cellsEl.addEventListener('mousedown', function(e) {
    e.preventDefault();
    startX = e.clientX; accumulated = 0;
    function onMove(e2) {
      var steps = Math.trunc((e2.clientX - startX) / threshold);
      if (steps !== accumulated) { rotate(ri, steps - accumulated); accumulated = steps; }
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
  cellsEl.addEventListener('touchstart', function(e) {
    if (e.touches.length === 1) { startX = e.touches[0].clientX; accumulated = 0; }
  }, { passive: true });
  cellsEl.addEventListener('touchmove', function(e) {
    if (e.touches.length === 1 && startX !== null) {
      var steps = Math.trunc((e.touches[0].clientX - startX) / threshold);
      if (steps !== accumulated) { rotate(ri, steps - accumulated); accumulated = steps; }
    }
  }, { passive: true });
  cellsEl.addEventListener('touchend', function() { startX = null; });
}

// Wire buttons (CSP: no inline onclick)
document.getElementById('btn-reset').addEventListener('click', resetAll);
document.getElementById('btn-ndyahr').addEventListener('click', applyNDYAHR);
document.getElementById('btn-dir').addEventListener('click', toggleDir);
document.getElementById('btn-pt').addEventListener('click', togglePT);

render();
})();
