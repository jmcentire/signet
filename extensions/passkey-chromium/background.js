// Signet Passkeys: service worker.
//
// The only part of the extension that can start the local program, and the
// only part that knows the page's origin from the browser instead of from the
// page. A content script opens one connection per passkey call. This worker
// attaches the origin the browser reports for that connection, starts the
// native-messaging host, and passes its replies back.
'use strict';

const HOST = 'io.github.jmcentire.signet_passkey';
const CHANNEL = 'signet-passkey';
const KINDS = ['create', 'get', 'status'];

function browserName() {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  const known = ['Google Chrome', 'Microsoft Edge', 'Brave', 'Chromium'];
  for (const name of known) {
    if (brands.some(brand => brand.brand === name)) return name;
  }
  return 'Chromium browser';
}

// The page origin, or null when the connection is not from the top-level
// document of a tab. Passkey calls inside frames are left to the browser.
function topLevelOrigin(sender) {
  if (!sender || !sender.tab || sender.frameId !== 0) return null;
  if (typeof sender.origin !== 'string' || typeof sender.url !== 'string') return null;
  try {
    return new URL(sender.url).origin === sender.origin ? sender.origin : null;
  } catch {
    return null;
  }
}

chrome.runtime.onConnect.addListener(port => {
  if (port.name !== CHANNEL) return;
  const origin = topLevelOrigin(port.sender);
  let host = null;
  let finished = false;

  const finish = message => {
    if (finished) return;
    finished = true;
    try {
      port.postMessage(message);
    } catch {
      // The page went away.
    }
    if (host) host.disconnect();
  };
  const native = reason => finish({ result: 'native', reason });

  // The page cancelled, navigated or closed: closing the host's input tells
  // it to stop waiting.
  port.onDisconnect.addListener(() => {
    finished = true;
    if (host) host.disconnect();
  });

  port.onMessage.addListener(message => {
    if (host || finished) return; // one request per connection
    if (!origin) return native('not a top-level page');
    if (!message || !KINDS.includes(message.type)) return native('unknown request');
    try {
      host = chrome.runtime.connectNative(HOST);
    } catch {
      return native('the Signet program is not installed');
    }
    host.onMessage.addListener(reply => {
      if (reply && reply.result === 'pending') {
        try {
          port.postMessage(reply);
        } catch {
          // The page went away.
        }
        return;
      }
      finish(reply || { result: 'native', reason: 'empty reply' });
    });
    host.onDisconnect.addListener(() => {
      void chrome.runtime.lastError; // read it so Chrome does not log it
      native('the Signet program is not available');
    });
    host.postMessage({
      v: 1,
      id: crypto.randomUUID(),
      type: message.type,
      origin,
      options: message.options,
      mediation: message.mediation,
      browser: browserName(),
    });
  });
});
