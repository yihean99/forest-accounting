// 森系记账本 Service Worker（仅用于满足注册，不做缓存）
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
