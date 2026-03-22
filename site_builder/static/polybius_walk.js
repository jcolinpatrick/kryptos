/* polybius_walk.js — K4 Keystream Polybius Grid Walk */
(function() {
'use strict';

var KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ';
var KEYSTREAM = 'JLJODEGKUKKKLOCGGBGOKTRU';
var CRIB_LABELS = ['E','A','S','T','N','O','R','T','H','E','A','S','T','B','E','R','L','I','N','C','L','O','C','K'];
var CRIB_POS = [21,22,23,24,25,26,27,28,29,30,31,32,33,63,64,65,66,67,68,69,70,71,72,73];
var AP_LETTERS = new Set(['G','K','O']);
var ROW_COLORS = ['#82aaff','#7fdbca','#ffcb6b','#f78c6c','#c792ea','#666'];
var ROW_BG = ['#1a2332','#1a3322','#332a1a','#33221a','#2a1a33','#1a1a1a'];

var gridPos = {};
for (var i = 0; i < KA.length; i++) gridPos[KA[i]] = [Math.floor(i/5), i%5];

var freq = {};
KEYSTREAM.split('').forEach(function(c) { freq[c] = (freq[c]||0) + 1; });

var ksData = KEYSTREAM.split('').map(function(ch, i) {
  return {
    letter: ch, index: i, row: gridPos[ch][0], col: gridPos[ch][1],
    cribPos: CRIB_POS[i], cribLetter: CRIB_LABELS[i], isAP: AP_LETTERS.has(ch)
  };
});

// Stats Bar
var statsData = [
  {val:'10/23', lbl:'Same-row pairs (2.3x)', cls:'significant'},
  {val:'8/23', lbl:'Same-col pairs (1.7x)', cls:'not-sig'},
  {val:'p=0.0057', lbl:'Row clustering MC', cls:'significant'},
  {val:'p=0.075', lbl:'Col clustering MC', cls:'not-sig'},
  {val:'12/24', lbl:'Distinct key values', cls:''}
];
var statsBar = document.getElementById('statsBar');
statsData.forEach(function(s) {
  var d = document.createElement('div');
  d.className = 'stat ' + s.cls;
  var v = document.createElement('div'); v.className = 'val'; v.textContent = s.val;
  var l = document.createElement('div'); l.className = 'lbl'; l.textContent = s.lbl;
  d.appendChild(v); d.appendChild(l); statsBar.appendChild(d);
});

// Legend
var legendBar = document.getElementById('legendBar');
for (var r = 0; r < 5; r++) {
  var item = document.createElement('div'); item.className = 'legend-item';
  var sw = document.createElement('div'); sw.className = 'legend-swatch';
  sw.style.background = ROW_BG[r]; sw.style.border = '1px solid ' + ROW_COLORS[r];
  var txt = document.createTextNode('Row ' + r);
  item.appendChild(sw); item.appendChild(txt); legendBar.appendChild(item);
}

// Row Labels
var rowLabels = document.getElementById('rowLabels');
for (var r = 0; r < 6; r++) {
  var lbl = document.createElement('div'); lbl.className = 'row-label';
  lbl.textContent = 'R' + r; rowLabels.appendChild(lbl);
}

// Polybius Grid
var gridEl = document.getElementById('polybiusGrid');
for (var i = 0; i < 30; i++) {
  var r = Math.floor(i/5), c = i%5;
  var cell = document.createElement('div');
  var letter = i < KA.length ? KA[i] : '';
  cell.className = 'grid-cell row' + r + (AP_LETTERS.has(letter) ? ' ap' : '');
  if (i >= KA.length) { cell.style.opacity = '0.15'; }
  cell.id = letter ? 'gcell-' + letter : '';
  var span = document.createElement('span'); span.textContent = letter;
  cell.appendChild(span);
  if (letter && freq[letter]) {
    var cnt = document.createElement('span'); cnt.className = 'count';
    cnt.textContent = freq[letter]; cell.appendChild(cnt);
  }
  gridEl.appendChild(cell);
}

// Timeline
var timelineEl = document.getElementById('timeline');
ksData.forEach(function(d, i) {
  if (i === 13) {
    var div = document.createElement('div'); div.className = 'crib-divider';
    div.textContent = '|'; timelineEl.appendChild(div);
  }
  var cell = document.createElement('div');
  cell.className = 'ks-cell';
  cell.style.background = ROW_BG[d.row];
  cell.style.border = '1px solid ' + ROW_COLORS[d.row] + '40';
  if (i < 23 && ksData[i+1].row === d.row) cell.classList.add('same-row-next');
  cell.id = 'ks-' + i;

  var lt = document.createElement('span'); lt.className = 'letter';
  lt.style.color = ROW_COLORS[d.row]; lt.textContent = d.letter;
  var rn = document.createElement('span'); rn.className = 'rownum';
  rn.style.color = ROW_COLORS[d.row] + '60'; rn.textContent = 'R' + d.row;
  var ps = document.createElement('span'); ps.className = 'pos';
  ps.textContent = d.cribLetter + '@' + d.cribPos;

  cell.appendChild(lt); cell.appendChild(rn); cell.appendChild(ps);
  cell.addEventListener('mouseenter', (function(idx) {
    return function() { highlightStep(idx); };
  })(i));
  timelineEl.appendChild(cell);
});

// Row Sequence Bars
function buildSeqBars(container, getData, sameCheck, shadowColor, prefix) {
  ksData.forEach(function(d, i) {
    var bar = document.createElement('div'); bar.className = 'row-bar';
    var val = getData(d);
    var h = 10 + val * 14;
    var sameNext = i < 23 && sameCheck(d, ksData[i+1]);

    var rl = document.createElement('span');
    rl.style.cssText = 'font-size:0.7em;margin-bottom:2px;color:' + ROW_COLORS[d.row];
    rl.textContent = d.letter;
    var b = document.createElement('div'); b.className = 'bar';
    b.style.cssText = 'width:24px;border-radius:3px 3px 0 0;height:' + h + 'px;background:' + ROW_COLORS[d.row] + (sameNext ? ';box-shadow:3px 0 0 ' + shadowColor : '');
    var lb = document.createElement('span');
    lb.style.cssText = 'font-size:0.6em;color:#555;margin-top:2px';
    lb.textContent = prefix + val;

    bar.appendChild(rl); bar.appendChild(b); bar.appendChild(lb);
    container.appendChild(bar);
  });
}
function getRow(d) { return d.row; }
function getCol(d) { return d.col; }
buildSeqBars(document.getElementById('rowSeq'), getRow, function(a,b){return a.row===b.row;}, '#ff5370', 'R');
buildSeqBars(document.getElementById('colSeq'), getCol, function(a,b){return a.col===b.col;}, '#5370ff', 'C');

// Walk SVG
var svg = document.getElementById('walkSvg');
var ns = 'http://www.w3.org/2000/svg';
var CW = 52, CH = 52, PAD = 14, GAP = 3;

var bgRect = document.createElementNS(ns, 'rect');
bgRect.setAttribute('width', 300); bgRect.setAttribute('height', 340);
bgRect.setAttribute('fill', '#0d0d15'); bgRect.setAttribute('rx', 8);
svg.appendChild(bgRect);

for (var i = 0; i < 30; i++) {
  var r = Math.floor(i/5), c = i%5;
  if (r === 5 && c > 0) continue;
  var x = PAD + c*(CW+GAP), y = PAD + r*(CH+GAP);
  var rect = document.createElementNS(ns, 'rect');
  rect.setAttribute('x', x); rect.setAttribute('y', y);
  rect.setAttribute('width', CW); rect.setAttribute('height', CH);
  rect.setAttribute('rx', 6); rect.setAttribute('fill', ROW_BG[r]);
  rect.setAttribute('stroke', ROW_COLORS[r]); rect.setAttribute('stroke-opacity', 0.3);
  svg.appendChild(rect);
  if (i < KA.length) {
    var txt = document.createElementNS(ns, 'text');
    txt.setAttribute('x', x+CW/2); txt.setAttribute('y', y+CH/2+5);
    txt.setAttribute('fill', ROW_COLORS[r]); txt.setAttribute('fill-opacity', 0.4);
    txt.setAttribute('text-anchor', 'middle'); txt.setAttribute('font-size', 14);
    txt.setAttribute('font-family', 'monospace'); txt.textContent = KA[i];
    svg.appendChild(txt);
  }
}

var walkGroup = document.createElementNS(ns, 'g'); walkGroup.id = 'walkLines'; svg.appendChild(walkGroup);
var walkDot = document.createElementNS(ns, 'circle');
walkDot.setAttribute('r', 8); walkDot.setAttribute('fill', '#fff');
walkDot.setAttribute('stroke', '#ff5370'); walkDot.setAttribute('stroke-width', 2);
walkDot.setAttribute('visibility', 'hidden'); walkDot.id = 'walkDot'; svg.appendChild(walkDot);

function gridCenter(r, c) { return { x: PAD + c*(CW+GAP) + CW/2, y: PAD + r*(CH+GAP) + CH/2 }; }

var currentStep = -1, playing = false, playTimer = null;

function highlightStep(idx) {
  document.querySelectorAll('.pw-page .grid-cell').forEach(function(c) { c.classList.remove('active'); });
  var cell = document.getElementById('gcell-' + ksData[idx].letter);
  if (cell) cell.classList.add('active');
}

function drawWalkTo(step) {
  var group = document.getElementById('walkLines');
  while (group.firstChild) group.removeChild(group.firstChild);
  for (var i = 0; i <= step && i < ksData.length; i++) {
    var d = ksData[i], p = gridCenter(d.row, d.col);
    if (i > 0) {
      var prev = ksData[i-1], pp = gridCenter(prev.row, prev.col);
      var sameRow = prev.row === d.row;
      var line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', pp.x); line.setAttribute('y1', pp.y);
      line.setAttribute('x2', p.x); line.setAttribute('y2', p.y);
      line.setAttribute('stroke', sameRow ? '#ff5370' : '#ffffff30');
      line.setAttribute('stroke-width', sameRow ? 2.5 : 1);
      if (!sameRow) line.setAttribute('stroke-dasharray', '4,3');
      group.appendChild(line);
    }
    var txt = document.createElementNS(ns, 'text');
    txt.setAttribute('x', p.x + ((i%3)-1)*6); txt.setAttribute('y', p.y - 12);
    txt.setAttribute('fill', ROW_COLORS[d.row]); txt.setAttribute('text-anchor', 'middle');
    txt.setAttribute('font-size', 9); txt.setAttribute('font-family', 'monospace');
    txt.textContent = i + 1; group.appendChild(txt);
  }
  if (step >= 0 && step < ksData.length) {
    var d = ksData[step], p = gridCenter(d.row, d.col);
    walkDot.setAttribute('cx', p.x); walkDot.setAttribute('cy', p.y);
    walkDot.setAttribute('fill', ROW_COLORS[d.row]); walkDot.setAttribute('visibility', 'visible');
  }
  currentStep = step;
  document.getElementById('stepDisplay').textContent = 'Step ' + (step+1) + '/24';
  var scrubber = document.getElementById('scrubber');
  if (scrubber) scrubber.value = step;
  highlightStep(Math.max(0, step));
}

function stepForward() { if (currentStep < 23) drawWalkTo(currentStep + 1); }
function stepBack() { if (currentStep > 0) drawWalkTo(currentStep - 1); }
function resetWalk() {
  stopPlay(); currentStep = -1;
  var g = document.getElementById('walkLines'); while (g.firstChild) g.removeChild(g.firstChild);
  walkDot.setAttribute('visibility', 'hidden');
  document.querySelectorAll('.pw-page .grid-cell').forEach(function(c) { c.classList.remove('active'); });
  document.getElementById('stepDisplay').textContent = 'Step 0/24';
}
function togglePlay() {
  if (playing) return stopPlay();
  playing = true;
  document.getElementById('btnPlay').classList.add('active');
  document.getElementById('btnPlay').textContent = '\u275A\u275A Pause';
  if (currentStep >= 23) resetWalk();
  tick();
}
function stopPlay() {
  playing = false; clearTimeout(playTimer);
  document.getElementById('btnPlay').classList.remove('active');
  document.getElementById('btnPlay').textContent = '\u25B6 Play';
}
function tick() {
  if (!playing) return;
  stepForward();
  if (currentStep >= 23) return stopPlay();
  playTimer = setTimeout(tick, 750);
}

// Wire up buttons (CSP: no inline onclick)
document.getElementById('btnPlay').addEventListener('click', togglePlay);
document.getElementById('btnReset').addEventListener('click', resetWalk);
document.getElementById('btnStepFwd').addEventListener('click', stepForward);
document.getElementById('btnStepBack').addEventListener('click', stepBack);

// Scrubber — drag to any step like a video timeline
var scrubberEl = document.getElementById('scrubber');
if (scrubberEl) {
  scrubberEl.addEventListener('input', function() {
    stopPlay();
    drawWalkTo(parseInt(this.value));
  });
}

drawWalkTo(23);
})();
