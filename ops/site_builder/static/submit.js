/**
 * kryptosbot.com — Theory submission form handler
 * Posts to /api/classify, displays classification result.
 */
(function () {
  "use strict";

  var form = document.getElementById("submit-form");
  var textarea = document.getElementById("theory-input");
  var counter = document.getElementById("char-counter");
  var submitBtn = document.getElementById("submit-btn");
  var resultBox = document.getElementById("submit-result");

  var clearBtn = document.getElementById("clear-btn");

  var MIN_CHARS = 10;
  var MAX_CHARS = 2000;

  if (!form || !textarea) return;

  // Character counter + clear button visibility
  function updateCounter() {
    var len = textarea.value.length;
    counter.textContent = len + " / " + MAX_CHARS;

    if (len > MAX_CHARS) {
      counter.className = "char-counter over-limit";
      submitBtn.disabled = true;
    } else if (len < MIN_CHARS) {
      counter.className = "char-counter";
      submitBtn.disabled = true;
    } else {
      counter.className = "char-counter";
      submitBtn.disabled = false;
    }

    clearBtn.style.display = len > 0 ? "" : "none";
  }

  textarea.addEventListener("input", updateCounter);
  updateCounter();

  // Clear button
  clearBtn.addEventListener("click", function () {
    textarea.value = "";
    hideResult();
    updateCounter();
    textarea.focus();
  });

  // Form submission
  form.addEventListener("submit", function (e) {
    e.preventDefault();

    var theory = textarea.value.trim();
    if (theory.length < MIN_CHARS || theory.length > MAX_CHARS) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span>Classifying...';
    hideResult();

    fetch("/api/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ theory: theory }),
    })
      .then(function (res) {
        if (res.status === 429) {
          showResult("ratelimit", "Rate limit reached. Please try again in a few minutes.");
          return null;
        }
        if (!res.ok) throw new Error("Server error: " + res.status);
        return res.json();
      })
      .then(function (data) {
        if (!data) return;

        if (data.status === "matched") {
          var html = "<strong>This theory has already been tested.</strong><br><br>";
          html += escapeHtml(data.title || "Matched elimination") + "<br>";
          if (data.summary) {
            html += escapeHtml(data.summary) + "<br><br>";
          }
          html += '<a href="' + escapeHtml(data.url || "#") + '">View full elimination details &rarr;</a>';
          showResult("matched", html);
        } else if (data.status === "novel") {
          var html = "<strong>This theory appears to be novel and feasible!</strong><br><br>";
          if (data.summary) {
            html += escapeHtml(data.summary) + "<br><br>";
          }
          html += "Your submission has been queued for review. ";
          html += "We will evaluate it against our testing framework.";
          if (data.queue_position) {
            html += "<br><br>Queue position: <strong>#" + data.queue_position + "</strong>";
          }
          if (data.token) {
            var statusUrl = "/status/?t=" + encodeURIComponent(data.token);
            html += '<br><br><strong>Bookmark this link to check your results:</strong><br>';
            html += '<a href="' + statusUrl + '">' + escapeHtml(window.location.origin + statusUrl) + '</a>';
            html += '<br><span style="font-size:0.85em;opacity:0.7">This is your only way to check back &mdash; save it now.</span>';
          }
          showResult("novel", html);
        } else if (data.status === "rejected") {
          var feas = data.feasibility || "unknown";
          var html = "";
          if (feas === "infeasible") {
            html += "<strong>This theory has too many possibilities to test.</strong><br><br>";
            html += escapeHtml(data.reason || "There are more combinations to try than a computer could check in a lifetime.");
            html += "<br><br>Try narrowing it down &mdash; a specific key word, a specific method, or a specific starting point helps us actually run the test.";
          } else if (feas === "impossible") {
            html += "<strong>This theory can't work on K4.</strong><br><br>";
            html += escapeHtml(data.reason || "It conflicts with something we know for certain about how K4 is constructed.");
          } else if (feas === "untestable") {
            html += "<strong>Interesting idea, but we need something more concrete to test.</strong><br><br>";
            html += escapeHtml(data.reason || "We can only test theories that translate into a step-by-step procedure a computer can follow.");
            html += "<br><br>The key question is: <em>could someone follow your instructions and get a single, definite answer?</em> Narrative ideas (\"the answer is hidden in the shadows\") are interesting but we need a mechanical process &mdash; which cipher, which key, which order of operations.";
          } else {
            html += "<strong>We couldn't evaluate this one.</strong><br><br>";
            html += escapeHtml(data.reason || "Try rephrasing with a bit more detail about the method you have in mind.");
          }
          showResult("error", html);
        } else if (data.status === "error") {
          showResult("error", escapeHtml(data.message || "An error occurred."));
        } else {
          showResult("error", "Unexpected response from server.");
        }
      })
      .catch(function (err) {
        showResult("error", "Could not reach the server. Please try again later.");
        console.error("Submit error:", err);
      })
      .finally(function () {
        submitBtn.disabled = false;
        submitBtn.textContent = "Classify Theory";
        updateCounter();
      });
  });

  function showResult(type, html) {
    resultBox.className = "result-box result-" + type;
    resultBox.innerHTML = html;
    resultBox.style.display = "block";
    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function hideResult() {
    resultBox.style.display = "none";
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function formatNumber(n) {
    if (n == null) return "N/A";
    return Number(n).toLocaleString();
  }
})();
