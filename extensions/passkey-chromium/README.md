# Signet Passkeys (Chromium extension)

Sends a page's passkey calls to the owner's phone, wherever the phone is, or
hands them back to the browser. It is one part of
[remote passkey approval](../../docs/remote-passkey.md) and does nothing without
the `signet-passkey` program paired with a phone.

Status: a tested reference, loaded unpacked. It is not packaged, signed or
published. The phone app it is meant to talk to does not exist yet; tests use a
simulator.

## Parts

| File | Where it runs | What it does |
|---|---|---|
| `page.js` | The page's own world, top-level document | Stands in front of `navigator.credentials.create` and `.get`. Returns the phone's result as a standard credential object, or calls the browser's implementation with the page's original arguments. |
| `bridge.js` | The extension's isolated world | Carries each call to the service worker and shows a notice while the phone is being asked. |
| `background.js` | Service worker | Attaches the page's origin as the browser reports it and starts the local program over native messaging. |

The script in the page shares a world with the page, so nothing it says is
trusted. The origin a request is made for comes from the browser, in the service
worker.

## Permissions

`nativeMessaging`, to start the local program, and content scripts on `https`
pages and `http://localhost`. It reads no page content and makes no network
requests of its own.

## Loading it

1. Open the browser's extensions page, switch on developer mode, choose "Load
   unpacked" and pick this folder. Note the 32-letter id shown.
2. Run `signet-passkey browser install --extension-id <id>`.

`make passkey-e2e` does this in a throwaway profile and checks the whole chain.
