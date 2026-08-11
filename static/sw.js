// Sherlock Web service worker.
// HTML is network-first so deploys show up immediately (cache is only a
// fallback when offline). Icons/manifest are cache-first — they rarely change
// and the cache name bump below evicts stale copies.
// API requests (including the SSE stream) always go to the network.
const CACHE = "sherlock-web-shell-v2";
const STATIC_ASSETS = [
  "/manifest.webmanifest",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Never touch API/SSE traffic or non-GET requests.
  if (event.request.method !== "GET" || url.pathname.startsWith("/api/")) return;
  // HTML navigations: network-first, fall back to cache when offline.
  if (event.request.mode === "navigate") {
    event.respondWith(
      fetch(event.request)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((cache) => cache.put("/", copy));
          return res;
        })
        .catch(() => caches.match("/"))
    );
    return;
  }
  // Static assets (icons, manifest): cache-first.
  event.respondWith(
    caches.match(event.request).then((hit) => hit || fetch(event.request))
  );
});
