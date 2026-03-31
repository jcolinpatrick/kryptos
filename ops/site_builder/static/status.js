/**
 * internal.com — Submission status checker
 * Fetches /api/status/<token> and displays the result.
 */
(function () {
  "use strict";

  var form = document.getElementById("status-form");
  var input = document.getElementById("token-input");
  var btn = document.getElementById("status-btn");
  var resultBox = document.getElementById("status-result");

  if (!form || !input) return;

  // Auto-fill from ?t= query parameter
  var params = new URLSearchParams(window.location.search);
  var prefilledToken = params.get("t");
  if (prefilledToken) {
    input.value = prefilledToken;
    // Auto-submit after a short delay so the user sees the page first
    setTimeout(function () { form.dispatchEvent(new Event("submit")); }, 200);
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();

    var token = input.value.trim().toLowerCase();
    if (!token || token.length !== 32 || !/^[0-9a-f]+$/.test(token)) {
      showResult("error", "Please enter a valid 32-character token.");
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Checking...';
    hideResult();

    fetch("/api/status/" + encodeURIComponent(token))
      .then(function (res) {
        if (res.status === 404) {
          showResult("error", "No submission found for this token. Please double-check and try again.");
          return null;
        }
        if (!res.ok) throw new Error("Server error: " + res.status);
        return res.json();
      })
      .then(function (data) {
        if (!data) return;

        var html = "";
        var type = "matched";

        if (data.status === "pending") {
          type = "novel";
          html += "<strong>Your submission is in the queue.</strong><br><br>";
          html += "We haven't gotten to it yet, but it's on the list. Check back later.";
        } else if (data.status === "testing") {
          type = "novel";
          html += "<strong>Your theory is currently being tested!</strong><br><br>";
          html += "We're running it through our framework now. Check back soon for results.";
        } else if (data.status === "published") {
          type = "novel";
          html += "<strong>Your theory has been tested and published.</strong><br><br>";
          if (data.note) {
            html += escapeHtml(data.note);
          } else {
            html += "Results have been added to the elimination database.";
          }
        } else if (data.status === "rejected") {
          type = "error";
          html += "<strong>This theory was reviewed and could not be tested.</strong><br><br>";
          if (data.note) {
            html += escapeHtml(data.note);
          } else {
            html += "Unfortunately this one didn't make it through review.";
          }
        }

        html += "<br><br><span style='font-size:0.85em;opacity:0.7'>";
        html += "Submitted: " + escapeHtml(data.submitted || "unknown");
        if (data.theory_preview) {
          html += "<br>Theory: " + escapeHtml(data.theory_preview);
        }
        html += "</span>";

        showResult(type, html);
      })
      .catch(function (err) {
        showResult("error", "Could not reach the server. Please try again later.");
        console.error("Status check error:", err);
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = "Check Status";
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
})();
