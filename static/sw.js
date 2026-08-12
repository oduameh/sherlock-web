// Kill-switch service worker.
//
// sherlock-web is a live, server-backed tool with no useful offline mode, and a
// cached app shell kept causing stale-UI bugs (a page that looks loaded but runs
// old code — e.g. "Start investigation does nothing" after a deploy). So the app
// no longer uses a service worker at all.
//
// This file exists only to UN-install any worker a browser still has. Browsers
// re-fetch sw.js on their own update check (it is served no-cache), bypassing any
// old worker's cache; installing this version runs the activate handler below,
// which purges every cache, unregisters itself, and reloads open tabs so they
// drop service-worker control. After that the app always loads fresh from the
// network. index.html also unregisters on load, so either path self-heals.
self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
      await self.registration.unregister();
      const clients = await self.clients.matchAll({ type: "window" });
      for (const client of clients) {
        try { client.navigate(client.url); } catch (e) { /* best effort */ }
      }
    })()
  );
});

// No fetch handler: every request goes straight to the network.
