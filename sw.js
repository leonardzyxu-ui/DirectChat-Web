const CACHE_NAME = "directchat-shell-v5";
const SCOPE_PATH = new URL(self.registration.scope).pathname;
const SHELL_URLS = ["./", "./pwa-192.png", "./pwa-512.png", "./pwa-192.svg", "./pwa-512.svg"].map(path => new URL(path, self.registration.scope).toString());

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL_URLS)));
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))))
  );
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") {
    return;
  }
  const url = new URL(request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith(`${SCOPE_PATH}assets/`)) {
    event.respondWith(
      caches.match(request).then(cached => {
        const fresh = fetch(request).then(response => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
          return response;
        });
        return cached || fresh;
      })
    );
    return;
  }
  event.respondWith(
    fetch(request)
      .then(response => {
        const copy = response.clone();
        if (url.origin === self.location.origin) {
          caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request).then(response => response || caches.match(new URL("./", self.registration.scope).toString())))
  );
});

self.addEventListener("push", event => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = {};
  }
  event.waitUntil(
    self.registration.showNotification(payload.title || "DirectChat", {
      body: payload.body || "New DirectChat message.",
      icon: new URL("./pwa-192.png", self.registration.scope).toString(),
      badge: new URL("./pwa-192.png", self.registration.scope).toString(),
      tag: "directchat-message",
      renotify: true,
      requireInteraction: false,
      data: { url: payload.url || self.registration.scope }
    })
  );
});

self.addEventListener("notificationclick", event => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(clients => {
      for (const client of clients) {
        if ("focus" in client) {
          client.focus();
          return;
        }
      }
      return self.clients.openWindow(event.notification.data?.url || self.registration.scope);
    })
  );
});
