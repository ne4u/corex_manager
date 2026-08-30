/**
 * Page Protect Asset Beacon
 *
 * Injected into HTML responses by HAProxy's resp_transform filter when
 * Page Protect beacon injection is enabled. Collects all resources loaded
 * by the page using the Resource Timing API and POSTs them to the beacon
 * endpoint so the backend can build a complete asset inventory regardless
 * of CSP mode (enforce or monitor).
 *
 * Self-contained, no dependencies. ~1KB minified.
 */
(function () {
  'use strict';

  var BEACON_URL = '/_asset-beacon';
  var BEACON_SCRIPT_URL = '/_asset-beacon.js';
  var collected = {};
  var sent = false;

  // Map PerformanceResourceTiming.initiatorType to Page Protect resource_type
  function mapType(initiatorType) {
    if (!initiatorType) return 'other';
    var t = initiatorType.toLowerCase();
    if (t === 'script') return 'script';
    if (t === 'link' || t === 'css') return 'style';
    if (t === 'img' || t === 'image') return 'img';
    if (t === 'fetch' || t === 'xmlhttprequest') return 'connect';
    if (t === 'xmlhttprequest') return 'connect';
    if (t === 'font') return 'font';
    if (t === 'iframe' || t === 'frame') return 'frame';
    if (t === 'object' || t === 'embed') return 'object';
    return 'other';
  }

  function collectEntries(entries) {
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e.name) continue;
      // Skip the beacon endpoint, beacon script, and data/blob URIs
      if (e.name === BEACON_URL || e.name === BEACON_SCRIPT_URL ||
          e.name.indexOf(BEACON_SCRIPT_URL) !== -1 ||
          e.name.indexOf('data:') === 0 || e.name.indexOf('blob:') === 0) continue;
      // Deduplicate by URL
      if (collected[e.name]) continue;
      try {
        var url = new URL(e.name, location.href);
        collected[e.name] = {
          url: e.name,
          resource_type: mapType(e.initiatorType),
          domain: url.hostname || null,
        };
      } catch (_) {
        collected[e.name] = {
          url: e.name,
          resource_type: mapType(e.initiatorType),
          domain: null,
        };
      }
    }
  }

  function sendBeacon() {
    if (sent) return;
    sent = true;
    var resources = [];
    for (var key in collected) {
      if (collected.hasOwnProperty(key)) resources.push(collected[key]);
    }
    if (resources.length === 0) return;
    var payload = JSON.stringify({
      page: location.href,
      resources: resources,
      ts: Date.now(),
    });
    // Use sendBeacon for reliability (survives page unload)
    if (navigator.sendBeacon) {
      navigator.sendBeacon(BEACON_URL, payload);
    } else {
      // Fallback to fetch with keepalive
      try {
        fetch(BEACON_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          keepalive: true,
        }).catch(function () {});
      } catch (_) {}
    }
  }

  // Collect existing resource entries
  if (performance && performance.getEntriesByType) {
    try {
      collectEntries(performance.getEntriesByType('resource'));
    } catch (_) {}
  }

  // Observe dynamically loaded resources
  if (typeof PerformanceObserver !== 'undefined') {
    try {
      var observer = new PerformanceObserver(function (list) {
        collectEntries(list.getEntries());
      });
      observer.observe({ type: 'resource', buffered: true });
    } catch (_) {}
  }

  // Send on pagehide (most reliable for capturing late-loaded resources)
  if ('addEventListener' in window) {
    window.addEventListener('pagehide', sendBeacon, { once: true });
    // Also send on visibilitychange (mobile backgrounding)
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') sendBeacon();
    }, { once: true });
  }
})();
