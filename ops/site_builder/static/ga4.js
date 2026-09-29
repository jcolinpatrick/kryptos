/* GA4 bootstrap. The measurement ID comes from the rendered page's data
 * attribute so it remains environment configuration rather than a source
 * constant. This file is external to comply with the site's strict CSP. */
(function () {
  "use strict";
  var script = document.currentScript;
  var measurementId = script && script.dataset.measurementId;
  if (!measurementId) return;

  var loader = document.createElement("script");
  loader.async = true;
  loader.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(measurementId);
  document.head.appendChild(loader);

  window.dataLayer = window.dataLayer || [];
  window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };
  window.gtag("js", new Date());

  // gtag sends document.location.href as page_location by default. The status
  // page URL is "/status/?t=<32-hex submission token>", which the Terms
  // describe as a bearer credential, so the default behaviour transmits that
  // credential to Google on every visit. Strip that one parameter and leave
  // everything else, so utm_* campaign attribution still works.
  var pageLocation = window.location.href;
  try {
    var url = new URL(window.location.href);
    if (url.searchParams.has("t")) {
      url.searchParams.delete("t");
      pageLocation = url.toString();
    }
  } catch (e) {
    // Very old browsers lack URL(); fall back to a plain string cut rather
    // than risk sending the token because a constructor was unavailable.
    pageLocation = window.location.origin + window.location.pathname;
  }
  window.gtag("config", measurementId, { page_location: pageLocation });
}());
