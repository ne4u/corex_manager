"""Embedded Page Protect beacon JavaScript.

This module contains the beacon JS as a string constant so the backend can
write it to the shared data volume during ``write_config`` without needing
the ``haproxy/`` source directory (which is only present in the HAProxy
build context, not the backend container).

The source of truth is ``haproxy/page-protect-beacon.js`` in the repo root.
The minified version is ``haproxy/page-protect-beacon.min.js``.
If you edit either file, copy the content here too.
"""

BEACON_JS = """\
/*! Page Protect Asset Beacon */
!function(){"use strict";var S="/_cx-assets.js",B="/_cx-assets";try{var cs=document.currentScript||function(){var s=document.getElementsByTagName("script");return s[s.length-1]}();if(cs&&cs.src){var u=new URL(cs.src,location.href);S=u.pathname,B=S.replace(/\\.js$/,"")}}catch(e){}var c={},s=!1;function m(t){if(!t)return"other";var n=t.toLowerCase();return"script"===n?"script":"link"===n||"css"===n?"style":"img"===n||"image"===n?"img":"fetch"===n||"xmlhttprequest"===n?"connect":"font"===n?"font":"iframe"===n||"frame"===n?"frame":"object"===n||"embed"===n?"object":"other"}function a(e){for(var t=0;t<e.length;t++){var n=e[t];if(n.name&&n.name!==B&&n.name!==S&&-1===n.name.indexOf(S)&&0!==n.name.indexOf("data:")&&0!==n.name.indexOf("blob:")&&!c[n.name]){try{var r=new URL(n.name,location.href);c[n.name]={url:n.name,resource_type:m(n.initiatorType),domain:r.hostname||null}}catch(t){c[n.name]={url:n.name,resource_type:m(n.initiatorType),domain:null}}}}}function g(){try{var e=performance.getEntries?performance.getEntries():[];for(var t=0;t<e.length;t++){var n=e[t];if(n.serverTiming)for(var r=0;r<n.serverTiming.length;r++)if("cxid"===n.serverTiming[r].name&&n.serverTiming[r].description)return n.serverTiming[r].description}}catch(e){}return null}function f(){if(!s){s=!0;var e=[];for(var t in c)c.hasOwnProperty(t)&&e.push(c[t]);var x=g();if(e.length||x){var n=JSON.stringify({page:location.href,resources:e,ts:Date.now(),cxid:x});if(navigator.sendBeacon){try{if(navigator.sendBeacon(B,n))return}catch(t){}}try{fetch(B,{method:"POST",headers:{"Content-Type":"application/json"},body:n,keepalive:!0}).catch(function(){})}catch(t){}}}}performance&&performance.getEntriesByType&&a(performance.getEntriesByType("resource")),"undefined"!=typeof PerformanceObserver&&new PerformanceObserver(function(e){a(e.getEntries())}).observe({type:"resource",buffered:!0}),"addEventListener"in window&&(window.addEventListener("pagehide",f,{once:!0}),document.addEventListener("visibilitychange",function(){"hidden"===document.visibilityState&&f()},{once:!0})),setTimeout(f,5e3)}();
"""
