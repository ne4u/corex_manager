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

  // Derive the POST endpoint and script URL from this script's own src tag
  // so they stay in sync with whatever path is configured in Page Protect
  // settings (HAProxy injects <script src="/_cx-assets.js?v=..."></script>).
  // Falls back to defaults if detection fails.
  var BEACON_SCRIPT_URL = '/_cx-assets.js';
  var BEACON_URL = '/_cx-assets';
  try {
    var currentScript = document.currentScript || (function () {
      var scripts = document.getElementsByTagName('script');
      return scripts[scripts.length - 1];
    })();
    if (currentScript && currentScript.src) {
      var srcUrl = new URL(currentScript.src, location.href);
      BEACON_SCRIPT_URL = srcUrl.pathname;
      BEACON_URL = BEACON_SCRIPT_URL.replace(/\.js$/, '');
    }
  } catch (_) {}
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

  // Read the cxid from the Server-Timing response header via the Resource
  // Timing API's serverTiming property (the only response header readable by
  // JS). HAProxy inserts "Server-Timing: total;dur=<ms>,cxid;desc="<uuid>""
  // on HTML responses. The cxid proves the IP received a real response and
  // is validated by HAProxy on the beacon POST to prevent spoofing.
  function getCxid() {
    try {
      var entries = performance.getEntries ? performance.getEntries() : [];
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        if (e.serverTiming) {
          for (var j = 0; j < e.serverTiming.length; j++) {
            if (e.serverTiming[j].name === 'cxid' && e.serverTiming[j].description) {
              return e.serverTiming[j].description;
            }
          }
        }
      }
    } catch (_) {}
    return null;
  }

  function sendBeacon() {
    if (sent) return;
    sent = true;
    var resources = [];
    for (var key in collected) {
      if (collected.hasOwnProperty(key)) resources.push(collected[key]);
    }
    var cxid = getCxid();
    // Skip only if there's nothing to send at all — no resources AND no cxid.
    // The cxid must be submitted even when the resource list is empty so the
    // IP can be beacon-trusted regardless of whether the page loaded assets.
    if (resources.length === 0 && !cxid) return;
    var payload = JSON.stringify({
      page: location.href,
      resources: resources,
      ts: Date.now(),
      cxid: cxid,
    });
    // Use sendBeacon for reliability (survives page unload).
    // Check the return value — sendBeacon returns false when the payload
    // exceeds the browser's ~64KB limit, in which case fall back to fetch.
    if (navigator.sendBeacon) {
      try {
        if (navigator.sendBeacon(BEACON_URL, payload)) return;
      } catch (_) {}
    }
    // Fallback to fetch with keepalive (also used when sendBeacon returns false)
    try {
      fetch(BEACON_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true,
      }).catch(function () {});
    } catch (_) {}
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
  // Also send after a delay in case the user stays on the page (pagehide
  // may not fire for a while). The sent flag prevents duplicate sends.
  setTimeout(sendBeacon, 5000);
})();
