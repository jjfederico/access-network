// Minimal service worker — enables "Add to Home Screen" / install on Android Chrome.
// Intentionally does NOT cache, so members always get the latest AXESS (no stale app).
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch', e => { /* passthrough to network */ });
