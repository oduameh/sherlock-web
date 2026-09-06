// The app no longer uses a service worker (it caused stale-UI bugs and offers no
// value for a live, server-backed tool). Proactively remove any worker a browser
// still has registered, and clear its caches, so every client loads fresh code.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.getRegistrations()
    .then(function (regs) { regs.forEach(function (r) { r.unregister(); }); })
    .catch(function () {});
  if (window.caches && caches.keys) {
    caches.keys().then(function (keys) {
      keys.forEach(function (k) { caches.delete(k); });
    }).catch(function () {});
  }
}
