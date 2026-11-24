'use strict';

const scope = self.registration.scope;
const prefix = 'aes-rsa:' + scope + ':';
const cacheName = prefix + 'v1';
const shell = ['./', './index.html', './app.js', './manifest.webmanifest', './icon-192.png', './icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(cacheName).then(cache => cache.addAll(shell)));
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith(prefix) && key !== cacheName).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET' || !event.request.url.startsWith(scope)) return;
  event.respondWith((async () => {
    const cache = await caches.open(cacheName);
    if (event.request.mode === 'navigate') {
      try {
        return await fetch(event.request);
      } catch {
        return cache.match(new URL('./index.html', scope));
      }
    }
    return (await cache.match(event.request)) || fetch(event.request);
  })());
});
