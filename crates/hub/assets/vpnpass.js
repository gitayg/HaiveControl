// VPN pass, browser side. The hub (vpn.rs) issues a pass for a client PUBLIC key
// and returns the rest of the WireGuard config; the keypair, the .conf and the QR
// code are made here, so the client's private key never leaves the browser.
// Needs assets/x25519.js (fallback keygen) and assets/qrcode.js (QR) loaded first.
(function(root) {
'use strict';

function b64(u8) {
  var s = '';
  for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function unb64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var b = atob(s), u = new Uint8Array(b.length);
  for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}

// Curve25519 clamping, as `wg genkey` does. X25519 clamps anyway, so the public key
// is the same either way; clamped keys just look like every other WireGuard key.
function clamp(sk) {
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  return sk;
}

function webcrypto() {
  return root.crypto;
}

// The vendored TweetNaCl X25519 (x25519.js), for browsers without WebCrypto X25519
// and for pages served over plain http, where crypto.subtle does not exist.
function viaTweetnacl() {
  var c = webcrypto();
  if (!c || !c.getRandomValues) throw new Error('this browser has no secure random number generator');
  if (typeof root.x25519Base !== 'function') throw new Error('the X25519 fallback (x25519.js) is not loaded');
  var sk = clamp(c.getRandomValues(new Uint8Array(32)));
  return { privateKey: b64(sk), publicKey: b64(root.x25519Base(sk)), via: 'tweetnacl' };
}

// Resolves { privateKey, publicKey, via } in base64. `noWebCrypto` forces the fallback.
function vpnKeypair(noWebCrypto) {
  var c = webcrypto(), subtle = c && c.subtle;
  if (!subtle || noWebCrypto) return Promise.resolve().then(viaTweetnacl);
  return subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])
    .then(function(k) {
      return Promise.all([subtle.exportKey('jwk', k.privateKey), subtle.exportKey('raw', k.publicKey)]);
    })
    .then(function(r) {
      var d = unb64url(r[0].d), pub = new Uint8Array(r[1]);
      if (d.length !== 32 || pub.length !== 32) throw new Error('unexpected X25519 key size');
      return { privateKey: b64(clamp(d)), publicKey: b64(pub), via: 'webcrypto' };
    })
    // No X25519 in this WebCrypto (NotSupportedError): use the vendored one.
    .catch(viaTweetnacl);
}

function line(v) {
  return String(v).replace(/[\r\n]/g, ' ');
}

// The client's .conf: `w` is the `wireguard` object of the hub's pass response.
function vpnConf(name, privateKey, w) {
  return '# IT-AI VPN — ' + line(name) + '\n' +
    '[Interface]\n' +
    'PrivateKey = ' + line(privateKey) + '\n' +
    'Address = ' + line(w.address) + '\n' +
    'DNS = ' + line(w.dns) + '\n' +
    'MTU = ' + line(w.mtu) + '\n' +
    '\n' +
    '[Peer]\n' +
    'PublicKey = ' + line(w.serverPublicKey) + '\n' +
    'PresharedKey = ' + line(w.presharedKey) + '\n' +
    'Endpoint = ' + line(w.endpoint) + '\n' +
    'AllowedIPs = ' + line(w.allowedIps) + '\n' +
    'PersistentKeepalive = ' + line(w.persistentKeepalive) + '\n';
}

// SVG QR code of `text`, UTF-8 encoded (qrcode.js's default keeps only the low
// byte of each char, so hand it one char per UTF-8 byte).
function vpnQrSvg(text) {
  var u = new TextEncoder().encode(text), bin = '';
  for (var i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  var q = root.qrcode(0, 'M');
  q.addData(bin, 'Byte');
  q.make();
  return q.createSvgTag({ cellSize: 4, margin: 16, scalable: true });
}

var api = { vpnKeypair: vpnKeypair, vpnConf: vpnConf, vpnQrSvg: vpnQrSvg };
if (typeof module === 'object' && module.exports) module.exports = api;
else for (var k in api) root[k] = api[k];
})(typeof self !== 'undefined' ? self : globalThis);
