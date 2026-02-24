/**
 * kryptosbot.com — Search functionality using Lunr.js
 * Assumes `lunr` is available globally via a <script> tag.
 */
(function () {
  "use strict";

  var index = null;
  var documents = {};
  var searchInput = document.getElementById("search-input");
  var resultsContainer = document.getElementById("search-results");
  var statusEl = document.getElementById("search-status");

  if (!searchInput || !resultsContainer) return;

  // Load search index
  function loadIndex() {
    setStatus("Loading search index...");
    fetch("/static/search-index.json")
      .then(function (res) {
        if (!res.ok) throw new Error("Failed to load search index");
        return res.json();
      })
      .then(function (data) {
        // Store documents keyed by id
        data.documents.forEach(function (doc) {
          documents[doc.id] = doc;
        });

        // Build Lunr index
        index = lunr(function () {
          this.ref("id");
          this.field("title", { boost: 10 });
          this.field("description", { boost: 5 });
          this.field("category", { boost: 3 });
          this.field("tags", { boost: 2 });
          this.field("cipher_type");
          this.field("key_model");
          this.field("transposition_family");

          var self = this;
          data.documents.forEach(function (doc) {
            self.add(doc);
          });
        });

        setStatus("");
        searchInput.disabled = false;
        searchInput.placeholder = "Search eliminations...";
        searchInput.focus();
      })
      .catch(function (err) {
        setStatus("Failed to load search index. Try refreshing the page.");
        console.error("Search index load error:", err);
      });
  }

  // Perform search
  function doSearch(query) {
    if (!index) return;

    query = query.trim();
    if (query.length < 2) {
      resultsContainer.innerHTML = "";
      setStatus("");
      return;
    }

    var results;
    try {
      results = index.search(query);
    } catch (e) {
      // If the query has syntax errors, try a simpler search
      try {
        results = index.search(query.replace(/[:\*\~\^]/g, ""));
      } catch (e2) {
        results = [];
      }
    }

    if (results.length === 0) {
      setStatus('No results found for "' + escapeHtml(query) + '"');
      resultsContainer.innerHTML = "";
      return;
    }

    setStatus(results.length + " result" + (results.length !== 1 ? "s" : "") + " found");

    var html = "";
    results.forEach(function (result) {
      var doc = documents[result.ref];
      if (!doc) return;

      var verdictClass = "verdict-" + (doc.verdict || "noise").toLowerCase();
      var scoreClass = getScoreClass(doc.best_score);

      html += '<div class="search-result">';
      html += '<h3><a href="/elimination/' + escapeHtml(doc.id) + '/">' + escapeHtml(doc.title) + "</a></h3>";
      html += '<div class="meta">';
      html += '<span class="verdict ' + verdictClass + '">' + escapeHtml(doc.verdict || "NOISE") + "</span> ";
      html += '<span>Score: <strong class="' + scoreClass + '">' + (doc.best_score != null ? doc.best_score + "/24" : "N/A") + "</strong></span> ";
      html += "<span>" + formatNumber(doc.configs_tested) + " configs</span> ";
      if (doc.category) {
        html += "<span>" + escapeHtml(doc.category) + "</span>";
      }
      html += "</div>";
      if (doc.description) {
        html += '<p style="font-size:0.9375rem;color:var(--color-muted);margin:0.25rem 0 0">' + escapeHtml(truncate(doc.description, 150)) + "</p>";
      }
      html += "</div>";
    });

    resultsContainer.innerHTML = html;
  }

  // Debounced search
  var debounceTimer;
  searchInput.addEventListener("input", function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      doSearch(searchInput.value);
    }, 200);
  });

  // Handle enter key
  searchInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      clearTimeout(debounceTimer);
      doSearch(searchInput.value);
    }
  });

  // Helpers
  function setStatus(msg) {
    if (statusEl) statusEl.textContent = msg;
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function truncate(str, len) {
    if (str.length <= len) return str;
    return str.substring(0, len) + "...";
  }

  function formatNumber(n) {
    if (n == null) return "N/A";
    return Number(n).toLocaleString();
  }

  function getScoreClass(score) {
    if (score == null) return "";
    if (score >= 24) return "score-breakthrough";
    if (score >= 18) return "score-signal";
    if (score >= 7) return "score-store";
    return "score-noise";
  }

  // Init
  searchInput.disabled = true;
  searchInput.placeholder = "Loading...";
  loadIndex();
})();
