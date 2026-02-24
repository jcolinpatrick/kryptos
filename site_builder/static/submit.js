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

  var MIN_CHARS = 10;
  var MAX_CHARS = 2000;

  if (!form || !textarea) return;

  // Character counter
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
  }

  textarea.addEventListener("input", updateCounter);
  updateCounter();

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
          showResult("novel", html);
        } else if (data.status === "rejected") {
          var feas = data.feasibility || "unknown";
          var html = "";
          if (feas === "infeasible") {
            html += "<strong>This theory is computationally infeasible.</strong><br><br>";
            html += escapeHtml(data.reason || "The search space is too large to test in any practical timeframe.");
            html += "<br><br>Consider narrowing your theory to a specific, smaller parameter space.";
          } else if (feas === "impossible") {
            html += "<strong>This theory violates known mathematical constraints.</strong><br><br>";
            html += escapeHtml(data.reason || "The approach is structurally incompatible with K4.");
          } else if (feas === "untestable") {
            html += "<strong>This theory needs more specificity.</strong><br><br>";
            html += escapeHtml(data.reason || "Please describe the specific cipher method, key source, and parameters.");
            html += "<br><br>For example, instead of \"maybe a substitution cipher\", try: \"Vigen&egrave;re cipher with keyword BERLIN and period 6, applied after a columnar transposition with width 9.\"";
          } else {
            html += "<strong>This theory could not be evaluated.</strong><br><br>";
            html += escapeHtml(data.reason || "Please try rephrasing with more detail.");
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
