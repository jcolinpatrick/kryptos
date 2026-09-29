/* Respect prefers-reduced-motion for autoplaying video. CSS cannot pause a
   <video>, so this is the one place the site needs script for it. Same-origin
   file: the CloudFront CSP allows script-src 'self' and nothing inline. */
(function () {
  'use strict';
  if (!window.matchMedia || !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }
  var videos = document.querySelectorAll('video[autoplay]');
  for (var i = 0; i < videos.length; i++) {
    var v = videos[i];
    v.removeAttribute('autoplay');
    v.removeAttribute('loop');
    try { v.pause(); } catch (e) { /* not started yet */ }
  }
})();
