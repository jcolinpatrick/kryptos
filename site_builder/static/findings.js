// findings.js — Position readout for ciphertext display
(function() {
  var vis = document.getElementById('ct-visual');
  var readout = document.getElementById('ct-readout');
  if (!vis || !readout) return;

  vis.addEventListener('mouseover', function(e) {
    var t = e.target;
    if (!t.classList.contains('ct-char')) return;
    var pos = t.getAttribute('data-pos');
    var ch = t.getAttribute('data-char');
    var isNull = t.hasAttribute('data-null');
    var label = 'Position ' + pos + ': ' + ch;
    if (isNull) label += ' (null)';
    readout.textContent = label;
  });

  vis.addEventListener('mouseleave', function() {
    readout.textContent = 'Position \u2014';
  });
})();
