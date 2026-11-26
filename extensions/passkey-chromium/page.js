// Signet Passkeys: the page side.
//
// Runs in the page's own world, before any page script, in the top-level
// document only. It stands in front of navigator.credentials.create and .get.
// For each call it asks the extension whether the phone handles it. If so it
// returns what the phone signed, shaped like the object the browser would
// return. If not, it calls the browser's own implementation with the page's
// original arguments, exactly as if this script were not here.
//
// This script decides nothing about trust. It shares a world with the page,
// so anything it says could be said by the page. The origin a request is made
// for is taken from the browser by the service worker, and the phone shows it
// to the owner.
(() => {
  'use strict';
  if (window.top !== window) return;
  if (typeof CredentialsContainer !== 'function' || typeof PublicKeyCredential !== 'function') return;

  const CHANNEL = 'signet-passkey';
  // How long the bridge has to say it is there before a call is left to the
  // browser.
  const BRIDGE_MS = 1500;
  const browser = {
    create: CredentialsContainer.prototype.create,
    get: CredentialsContainer.prototype.get,
    platformAvailable: PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable,
  };
  const waiting = new Map(); // id -> { settle, timer }
  let serial = 0;

  window.addEventListener('message', event => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || data.to !== 'page') return;
    const call = waiting.get(data.id);
    if (!call) return;
    if (data.received) {
      clearTimeout(call.timer);
      return;
    }
    waiting.delete(data.id);
    clearTimeout(call.timer);
    call.settle(data.reply);
  });

  // Ask the extension. Resolves with its reply; a missing extension counts as
  // "leave it to the browser".
  function ask(type, body, signal) {
    return new Promise((resolve, reject) => {
      const id = `${Date.now()}-${++serial}-${Math.random().toString(36).slice(2)}`;
      const post = message =>
        window.postMessage({ channel: CHANNEL, to: 'bridge', id, ...message }, window.location.origin);
      const timer = setTimeout(() => {
        if (waiting.delete(id)) resolve({ result: 'native', reason: 'no answer from the extension' });
      }, BRIDGE_MS);
      waiting.set(id, { settle: resolve, timer });
      if (signal) {
        const abort = () => {
          if (!waiting.delete(id)) return;
          clearTimeout(timer);
          post({ type: 'cancel' });
          reject(signal.reason !== undefined
            ? signal.reason
            : new DOMException('The operation was aborted.', 'AbortError'));
        };
        if (signal.aborted) return abort();
        signal.addEventListener('abort', abort, { once: true });
      }
      post({ type, ...body });
    });
  }

  function bytesOf(source) {
    if (ArrayBuffer.isView(source)) {
      return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    }
    if (Object.prototype.toString.call(source) === '[object ArrayBuffer]') {
      return new Uint8Array(source);
    }
    throw new TypeError('not a buffer');
  }

  function encode(source) {
    let raw = '';
    for (const byte of bytesOf(source)) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decode(text) {
    const padded = text.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    return Uint8Array.from(raw, c => c.charCodeAt(0)).buffer;
  }

  const descriptors = list =>
    Array.from(list || [], item => ({ type: item.type, id: encode(item.id), transports: item.transports }));

  // The standard JSON form of the page's options. Throws on anything
  // unexpected, and the caller then leaves the call to the browser, which
  // reports the error the page should see.
  function creationJSON(options) {
    const selection = options.authenticatorSelection;
    return {
      rp: { id: options.rp.id, name: options.rp.name },
      user: {
        id: encode(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      challenge: encode(options.challenge),
      pubKeyCredParams: Array.from(options.pubKeyCredParams, p => ({ type: p.type, alg: p.alg })),
      timeout: options.timeout,
      excludeCredentials: descriptors(options.excludeCredentials),
      authenticatorSelection: selection && {
        authenticatorAttachment: selection.authenticatorAttachment,
        residentKey: selection.residentKey,
        requireResidentKey: selection.requireResidentKey,
        userVerification: selection.userVerification,
      },
      attestation: options.attestation,
      extensions: options.extensions && options.extensions.credProps ? { credProps: true } : undefined,
    };
  }

  function requestJSON(options) {
    return {
      challenge: encode(options.challenge),
      timeout: options.timeout,
      rpId: options.rpId,
      allowCredentials: descriptors(options.allowCredentials),
      userVerification: options.userVerification,
    };
  }

  // An object a page cannot tell from the browser's own result by the means
  // pages use: instanceof, the standard properties, and the standard methods.
  function credentialFrom(json, created) {
    const fields = json.response;
    const response = created
      ? {
          clientDataJSON: decode(fields.clientDataJSON),
          attestationObject: decode(fields.attestationObject),
          getAuthenticatorData: () => decode(fields.authenticatorData),
          getPublicKey: () => (fields.publicKey ? decode(fields.publicKey) : null),
          getPublicKeyAlgorithm: () => fields.publicKeyAlgorithm,
          getTransports: () => Array.from(fields.transports || []),
        }
      : {
          clientDataJSON: decode(fields.clientDataJSON),
          authenticatorData: decode(fields.authenticatorData),
          signature: decode(fields.signature),
          userHandle: fields.userHandle ? decode(fields.userHandle) : null,
        };
    Object.setPrototypeOf(
      response,
      (created ? AuthenticatorAttestationResponse : AuthenticatorAssertionResponse).prototype
    );
    const credential = {
      id: json.id,
      rawId: decode(json.rawId),
      type: 'public-key',
      authenticatorAttachment: json.authenticatorAttachment || null,
      response,
      getClientExtensionResults: () => structuredClone(json.clientExtensionResults || {}),
      toJSON: () => structuredClone(json),
    };
    Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
    return credential;
  }

  async function handle(type, container, args) {
    const fallback = () => browser[type].apply(container, args);
    const options = args[0];
    const publicKey = options && options.publicKey;
    // Not a passkey call, or sign-in through the browser's autofill list.
    if (!publicKey || options.mediation === 'conditional') return fallback();
    // A page nobody has interacted with does not get to reach the phone.
    if (type === 'create' && !(navigator.userActivation && navigator.userActivation.hasBeenActive)) {
      return fallback();
    }
    let json;
    try {
      json = type === 'create' ? creationJSON(publicKey) : requestJSON(publicKey);
    } catch {
      return fallback();
    }
    const reply = await ask(type, { options: json, mediation: options.mediation }, options.signal);
    if (reply && reply.result === 'credential') {
      try {
        return credentialFrom(reply.credential, type === 'create');
      } catch {
        throw new DOMException('The answer from the phone could not be used.', 'UnknownError');
      }
    }
    if (reply && reply.result === 'error') {
      throw new DOMException(reply.message || 'The request was not completed.', reply.name || 'NotAllowedError');
    }
    return fallback();
  }

  // Defined as methods so `this` is checked the way the originals check it.
  const wrapped = {
    create(...args) {
      if (!(this instanceof CredentialsContainer)) return browser.create.apply(this, args);
      return handle('create', this, args);
    },
    get(...args) {
      if (!(this instanceof CredentialsContainer)) return browser.get.apply(this, args);
      return handle('get', this, args);
    },
  };
  CredentialsContainer.prototype.create = wrapped.create;
  CredentialsContainer.prototype.get = wrapped.get;

  // Sites often hide their passkey option unless the device reports a built-in
  // authenticator. A computer paired with a phone has one, in effect.
  if (typeof browser.platformAvailable === 'function') {
    let status;
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = function () {
      status = status || ask('status', {}).catch(() => null);
      return status.then(reply =>
        reply && reply.result === 'status' && reply.paired && reply.new_passkeys
          ? true
          : browser.platformAvailable.call(PublicKeyCredential)
      );
    };
  }
})();
