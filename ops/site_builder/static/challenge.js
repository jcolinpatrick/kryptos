/* Challenge page verification — client-side SHA-256 hash check */
(function() {
  'use strict';

  var EXPECTED_HASH = 'ab491ee62d455cf627859b836591c355643b7da738ce4f6a55aacf6743fdae51';
  var MIN_LENGTH = 10;
  var MAX_LENGTH = 200;

  function sha256(text) {
    var buf = new TextEncoder().encode(text);
    return crypto.subtle.digest('SHA-256', buf).then(function(hb) {
      return Array.from(new Uint8Array(hb)).map(function(b) {
        return b.toString(16).padStart(2, '0');
      }).join('');
    });
  }

  function logAttempt(len, correct) {
    /* Server-side: fire and forget */
    try {
      fetch('/api/challenge/attempt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({length: len, correct: correct, ts: Date.now()})
      });
    } catch (e) { /* ignore */ }
  }

  function checkAnswer() {
    var input = document.getElementById('ch-answer');
    var r = document.getElementById('ch-result');
    var btn = document.getElementById('ch-btn');

    if (!input || !r || !btn) return;

    var raw = input.value.trim();

    /* Reset */
    r.className = 'ch-result';

    if (raw.length === 0) {
      r.className = 'ch-result wrn';
      r.textContent = 'Please enter a plaintext guess using letters A\u2013Z.';
      return;
    }

    /* Check for non-letter characters and inform the user */
    var hadSpaces = /\s/.test(raw);
    var hadDigits = /\d/.test(raw);
    var hadPunctuation = /[^A-Za-z\s\d]/.test(raw);

    /* Strip to uppercase letters only for hashing */
    var cleaned = raw.toUpperCase().replace(/[^A-Z]/g, '');

    if (cleaned.length === 0) {
      r.className = 'ch-result wrn';
      r.textContent = 'No letters found. The plaintext uses only A\u2013Z.';
      return;
    }

    if (cleaned.length < MIN_LENGTH) {
      r.className = 'ch-result wrn';
      r.textContent = 'Too short (' + cleaned.length + ' letters after removing non-letters). The plaintext is longer.';
      return;
    }

    if (cleaned.length > MAX_LENGTH) {
      r.className = 'ch-result wrn';
      r.textContent = 'Too long. Maximum ' + MAX_LENGTH + ' characters.';
      return;
    }

    /* Build a note about what was stripped */
    var notes = [];
    if (hadSpaces) notes.push('spaces removed');
    if (hadDigits) notes.push('digits removed');
    if (hadPunctuation) notes.push('punctuation removed');
    var strippedNote = notes.length > 0
      ? ' (' + notes.join(', ') + '; checking ' + cleaned.length + ' letters)'
      : '';

    btn.disabled = true;
    btn.textContent = 'Checking\u2026';

    sha256(cleaned).then(function(hash) {
      var correct = hash === EXPECTED_HASH;

      /* Track attempt (best-effort, no personal data) */
      logAttempt(cleaned.length, correct);

      if (correct) {
        r.className = 'ch-result ok';
        r.innerHTML = 'Correct! Congratulations. Please email '
          + '<a href="mailto:contact@kryptosbot.com">contact@kryptosbot.com</a>'
          + ' with subject \u201cChallenge Solution\u201d describing both methods'
          + ' and keys for credit on\u00a0this\u00a0page.';
        /* Best-effort server notification */
        try {
          fetch('/api/challenge/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({answer: cleaned})
          });
        } catch (e) { /* ignore */ }
      } else {
        r.className = 'ch-result no';
        r.textContent = 'Not correct.' + strippedNote + ' Keep trying.';
      }

      btn.disabled = false;
      btn.textContent = 'Verify';
    });
  }

  /* Bind after DOM ready */
  var btn = document.getElementById('ch-btn');
  var input = document.getElementById('ch-answer');

  if (btn) {
    btn.addEventListener('click', checkAnswer);
  }
  if (input) {
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        checkAnswer();
      }
    });
  }
})();
