// Signet Passkeys: bridge between the page and the service worker.
//
// Runs in the extension's isolated world of the top-level document. It
// forwards a passkey call from page.js to the service worker over its own
// connection, shows a notice while the phone is being asked, and returns the
// answer. It adds nothing the page says about itself: the origin is attached
// by the service worker.
(() => {
  'use strict';
  if (window.top !== window) return;
  const CHANNEL = 'signet-passkey';
  const KINDS = ['create', 'get', 'status'];
  const calls = new Map(); // id -> { port, notice }

  const toPage = (id, body) =>
    window.postMessage({ channel: CHANNEL, to: 'page', id, ...body }, window.location.origin);

  function end(id, reply) {
    const call = calls.get(id);
    if (!call) return;
    calls.delete(id);
    if (call.notice) call.notice.remove();
    try {
      call.port.disconnect();
    } catch {
      // Already closed.
    }
    if (reply) toPage(id, { reply });
  }

  // A small notice in the corner, so the person at the computer knows why
  // nothing is happening on this screen. Text only, in a closed shadow root.
  function notice(id, phone) {
    const call = calls.get(id);
    if (!call || call.notice) return;
    const host = document.createElement('div');
    host.style.cssText = 'all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    const box = document.createElement('div');
    box.setAttribute('role', 'status');
    box.style.cssText =
      'font: 14px/1.4 system-ui, sans-serif; background: #16181d; color: #fff; padding: 12px 14px;' +
      'border-radius: 10px; box-shadow: 0 4px 18px rgba(0,0,0,.35); max-width: 340px;' +
      'display: flex; gap: 12px; align-items: center;';
    const text = document.createElement('span');
    text.textContent = `Signet: approve this on ${phone || 'your phone'}.`;
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    cancel.style.cssText =
      'font: inherit; color: #fff; background: #3a3f4b; border: 0; border-radius: 6px; padding: 6px 10px; cursor: pointer;';
    cancel.addEventListener('click', () =>
      end(id, { result: 'error', name: 'NotAllowedError', message: 'Cancelled.' }));
    box.append(text, cancel);
    root.append(box);
    (document.body || document.documentElement).append(host);
    call.notice = host;
  }

  window.addEventListener('message', event => {
    if (event.source !== window || event.origin !== window.location.origin) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || data.to !== 'bridge' || typeof data.id !== 'string') return;
    if (data.type === 'cancel') return end(data.id, null);
    if (!KINDS.includes(data.type) || calls.has(data.id)) return;

    // Tell page.js this script is alive. Without this it hands the call to
    // the browser, which is what should happen if the extension was removed
    // or reloaded under an open page.
    toPage(data.id, { received: true });
    const unavailable = { result: 'native', reason: 'the extension is not available' };
    let port;
    try {
      port = chrome.runtime.connect({ name: CHANNEL });
    } catch {
      return toPage(data.id, { reply: unavailable });
    }
    calls.set(data.id, { port, notice: null });
    port.onMessage.addListener(message => {
      if (message && message.result === 'pending') return notice(data.id, message.phone);
      end(data.id, message || unavailable);
    });
    port.onDisconnect.addListener(() => end(data.id, unavailable));
    port.postMessage({ type: data.type, options: data.options, mediation: data.mediation });
  });
})();
