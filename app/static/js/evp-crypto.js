/* EVP - the cryptography that runs ON THE VOTER'S DEVICE.
 *
 * R5  sealBallot(): the ballot is locked in the browser with the election PUBLIC key (fresh AES-256-GCM key,
 *     wrapped with RSA-OAEP-SHA256). The election id is bound in as GCM additional data. Same format as
 *     app/ballot/r05_crypto.py seal_ballot(), so the count (with 3 of 5 key shares) can open it.
 * R1  blind / unblind: the voting pass is blinded before it is sent to the issuer, so the issuer signs it
 *     without ever seeing it. Same maths as app/ballot/r01_blind.py (full-domain hash, textbook blind RSA).
 *
 * Works in the browser (window.EVPCrypto) and in Node 20+ (module.exports) so it can be tested against Python.
 */
(function (root) {
  "use strict";
  var cryptoApi = (typeof globalThis !== "undefined" && globalThis.crypto) ? globalThis.crypto : null;
  var subtle = cryptoApi.subtle;
  var enc = new TextEncoder();

  function b64(bytes) {
    var s = ""; bytes = new Uint8Array(bytes);
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function unb64(text) {
    var s = atob(text), out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function concat(a, b) { var out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; }
  function bytesToBig(bytes) { var h = ""; bytes.forEach(function (x) { h += x.toString(16).padStart(2, "0"); }); return h ? BigInt("0x" + h) : 0n; }
  function randomBytes(n) { var b = new Uint8Array(n); cryptoApi.getRandomValues(b); return b; }
  function hex(bytes) { return Array.from(bytes, function (x) { return x.toString(16).padStart(2, "0"); }).join(""); }

  function modPow(base, exp, mod) {
    var result = 1n; base %= mod;
    while (exp > 0n) { if (exp & 1n) result = (result * base) % mod; base = (base * base) % mod; exp >>= 1n; }
    return result;
  }
  function egcd(a, b) { var x0 = 1n, x1 = 0n; while (b) { var q = a / b; [a, b] = [b, a % b]; [x0, x1] = [x1, x0 - q * x1]; } return [a, x0]; }
  function modInv(a, m) { var r = egcd(((a % m) + m) % m, m); if (r[0] !== 1n) throw new Error("not invertible"); return ((r[1] % m) + m) % m; }
  function bitLength(n) { return n.toString(2).length; }

  // ---------------------------------------------------------------- R1 blind signature (voter side)
  async function fullDomainHash(electionId, token, n) {
    var width = Math.ceil(bitLength(n) / 8);
    var seed = concat(concat(enc.encode(electionId), enc.encode("|")), token);
    var out = new Uint8Array(0), counter = 0;
    while (out.length < width) {
      var c = new Uint8Array([(counter >>> 24) & 255, (counter >>> 16) & 255, (counter >>> 8) & 255, counter & 255]);
      out = concat(out, new Uint8Array(await subtle.digest("SHA-256", concat(seed, c))));
      counter++;
    }
    return bytesToBig(out.slice(0, width)) % n;
  }

  function blind(m, n, e) {
    var width = Math.ceil(bitLength(n) / 8) + 8;
    while (true) {
      var r = bytesToBig(randomBytes(width)) % n;
      if (r < 2n) continue;
      if (egcd(r, n)[0] !== 1n) continue;
      return { blinded: (m * modPow(r, e, n)) % n, r: r };
    }
  }

  function unblind(blindSig, r, n) { return (blindSig * modInv(r, n)) % n; }
  function verify(m, sig, n, e) { return sig > 0n && sig < n && modPow(sig, e, n) === m; }

  async function newPass(electionId, nHex, e) {
    var n = BigInt("0x" + nHex), E = BigInt(e);
    var token = randomBytes(32);
    var m = await fullDomainHash(electionId, token, n);
    var b = blind(m, n, E);
    return { token: token, tokenHex: hex(token), m: m, n: n, e: E, r: b.r, blindedHex: b.blinded.toString(16) };
  }

  function finishPass(pass, blindSigHex) {
    var sig = unblind(BigInt("0x" + blindSigHex), pass.r, pass.n);
    if (!verify(pass.m, sig, pass.n, pass.e)) throw new Error("The voting pass signature is not valid.");
    return sig.toString(16);
  }

  // ---------------------------------------------------------------- R5 sealing (voter side)
  async function sealBallot(publicPem, electionId, ballot) {
    var der = unb64(publicPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
    var rsa = await subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    var aes = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    var rawAes = new Uint8Array(await subtle.exportKey("raw", aes));
    var nonce = randomBytes(12);
    var plain = enc.encode(JSON.stringify(ballot));
    var locked = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(electionId) }, aes, plain);
    var ek = await subtle.encrypt({ name: "RSA-OAEP" }, rsa, rawAes);
    rawAes.fill(0);
    return JSON.stringify({ v: 1, ek: b64(ek), n: b64(nonce), c: b64(locked) });
  }

  var exported = { newPass: newPass, finishPass: finishPass, sealBallot: sealBallot,
                   fullDomainHash: fullDomainHash, blind: blind, unblind: unblind, verify: verify };
  if (typeof module !== "undefined" && module.exports) module.exports = exported;
  else root.EVPCrypto = exported;
})(typeof window !== "undefined" ? window : globalThis);
