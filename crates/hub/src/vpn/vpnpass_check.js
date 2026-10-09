// Runs the dashboard's VPN pass code (assets/vpnpass.js) under node >= 20, which
// has WebCrypto X25519. Checks each keygen path against OpenSSL's X25519, and the
// .conf built from a real /x/vpn/pass response. Run by the vpn::http_tests test
// `the_dashboard_builds_the_pass_in_the_browser`, or by hand:
//   node crates/hub/src/vpn/vpnpass_check.js [pass-response.json]
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const assets = path.join(__dirname, '..', '..', 'assets');
globalThis.x25519Base = require(path.join(assets, 'x25519.js')).x25519Base;
globalThis.qrcode = require(path.join(assets, 'qrcode.js'));
const { vpnKeypair, vpnConf, vpnQrSvg } = require(path.join(assets, 'vpnpass.js'));

const unb64 = (s) => Buffer.from(s, 'base64');

// X25519(sk, basepoint) by OpenSSL, independent of both code paths under test.
function opensslPublic(sk) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), sk]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
}

function checkPair(kp, via) {
  assert.strictEqual(kp.via, via, `expected the ${via} path, got ${kp.via}`);
  const sk = unb64(kp.privateKey), pk = unb64(kp.publicKey);
  assert.strictEqual(sk.length, 32, 'private key length');
  assert.strictEqual(pk.length, 32, 'public key length');
  assert.strictEqual(kp.privateKey.length, 44);
  assert.strictEqual(sk[0] & 7, 0, 'clamped low bits');
  assert.strictEqual(sk[31] & 0xc0, 0x40, 'clamped high bits');
  assert.deepStrictEqual(pk, opensslPublic(sk), `${via}: public key != X25519(private, 9)`);
}

function parseConf(text) {
  const sections = {};
  let cur = null;
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#')) continue;
    const m = /^\[(\w+)\]$/.exec(l);
    if (m) {
      assert.ok(!sections[m[1]], `duplicate [${m[1]}]`);
      cur = sections[m[1]] = {};
      continue;
    }
    const kv = /^(\w+) = (.+)$/.exec(l);
    assert.ok(kv && cur, `stray line: ${JSON.stringify(raw)}`);
    assert.ok(!(kv[1] in cur), `duplicate ${kv[1]}`);
    cur[kv[1]] = kv[2];
  }
  return sections;
}

(async () => {
  // RFC 7748 section 6.1 (Alice), for the vendored fallback.
  const alice = x25519Base(new Uint8Array(Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex')));
  assert.strictEqual(Buffer.from(alice).toString('hex'), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'x25519.js fails RFC 7748');

  const seen = new Set();
  for (let i = 0; i < 25; i++) {
    for (const [force, via] of [[false, 'webcrypto'], [true, 'tweetnacl']]) {
      const kp = await vpnKeypair(force);
      checkPair(kp, via);
      assert.ok(!seen.has(kp.privateKey), 'a private key repeated');
      seen.add(kp.privateKey);
    }
  }

  // Without crypto.subtle (a page over plain http), the fallback is used.
  Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });
  checkPair(await vpnKeypair(), 'tweetnacl');
  // And when subtle exists but has no X25519.
  Object.defineProperty(globalThis.crypto, 'subtle', { value: { generateKey: () => Promise.reject(new Error('NotSupportedError')) }, configurable: true });
  checkPair(await vpnKeypair(), 'tweetnacl');
  delete globalThis.crypto.subtle;
  assert.ok(globalThis.crypto.subtle && globalThis.crypto.subtle.generateKey.length !== 0, 'the real crypto.subtle is back');

  // The .conf, from a real pass response if one is given.
  const resp = process.argv[2]
    ? JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
    : { pass: { name: 'iPhone\nInjected = 1' }, wireguard: { address: '10.77.0.2/32', dns: '1.1.1.1, 1.0.0.1', mtu: 1380, serverPublicKey: Buffer.alloc(32, 1).toString('base64'), presharedKey: Buffer.alloc(32, 2).toString('base64'), endpoint: 'vpn.example:31820', allowedIps: '0.0.0.0/0, ::/0', persistentKeepalive: 25 } };
  const w = resp.wireguard;
  const kp = await vpnKeypair();
  const conf = vpnConf(resp.pass.name + '\r\nPrivateKey = injected', kp.privateKey, w);
  const c = parseConf(conf);
  assert.deepStrictEqual(Object.keys(c), ['Interface', 'Peer']);
  assert.deepStrictEqual(c.Interface, { PrivateKey: kp.privateKey, Address: w.address, DNS: w.dns, MTU: String(w.mtu) });
  assert.deepStrictEqual(c.Peer, {
    PublicKey: w.serverPublicKey,
    PresharedKey: w.presharedKey,
    Endpoint: w.endpoint,
    AllowedIPs: '0.0.0.0/0, ::/0',
    PersistentKeepalive: '25',
  });
  assert.match(c.Interface.Address, /^10\.77\.0\.\d+\/32$/);
  assert.strictEqual(c.Interface.MTU, '1380');
  for (const k of [c.Peer.PublicKey, c.Peer.PresharedKey]) assert.strictEqual(unb64(k).length, 32);
  assert.deepStrictEqual(opensslPublic(unb64(c.Interface.PrivateKey)), unb64(kp.publicKey), 'the .conf key is not the one whose public half was sent');

  const svg = vpnQrSvg(conf);
  assert.ok(svg.startsWith('<svg') && svg.includes('<path d="M'), 'no QR code');

  console.log(`ok: ${seen.size} keypairs (webcrypto + tweetnacl) match OpenSSL X25519; fallback without subtle and without X25519; RFC 7748 vector; .conf [Interface]/[Peer] from ${process.argv[2] ? 'a real pass response' : 'a sample response'}; QR ${svg.length} bytes`);
})().catch((e) => {
  console.error(e && e.stack || e);
  process.exit(1);
});
