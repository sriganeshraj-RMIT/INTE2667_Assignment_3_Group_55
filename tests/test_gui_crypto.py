"""GUI - the browser-side cryptography (static/js/evp-crypto.js) must match the server exactly:
a ballot sealed in the browser opens at the count (R5), and a pass blinded and unblinded in the browser verifies
at the checker (R1). Runs the real JavaScript with Node; skipped where Node is not installed."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.ballot import r01_blind as blind
from app.ballot.r05_crypto import open_ballot

NODE = shutil.which("node")
JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "evp-crypto.js"
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

RUNNER = r"""
const C = require(process.argv[1]);
let input = ""; process.stdin.on("data", d => input += d).on("end", async () => {
  const a = JSON.parse(input);
  if (a.step === "prepare") {
    const p = await C.newPass(a.election, a.n, a.e);
    const sealed = await C.sealBallot(a.pem, a.election, a.ballot);
    console.log(JSON.stringify({blinded: p.blindedHex, token: p.tokenHex, r: p.r.toString(16), m: p.m.toString(16), sealed}));
  } else {
    const p = {r: BigInt("0x" + a.r), n: BigInt("0x" + a.n), e: BigInt(a.e), m: BigInt("0x" + a.m)};
    try { console.log(JSON.stringify({sig: C.finishPass(p, a.bs)})); } catch (e) { console.log(JSON.stringify({error: e.message})); }
  }
});"""


def node(payload):
    out = subprocess.run([NODE, "-e", RUNNER, str(JS)], input=json.dumps(payload), capture_output=True, text=True,
                         check=True, timeout=60)
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def keys():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return k, pem


def test_browser_sealed_ballot_opens_at_the_count_and_only_for_its_election(keys):
    k, pem = keys
    n = k.public_key().public_numbers().n
    out = node({"step": "prepare", "election": "e1", "n": format(n, "x"), "e": 65537, "pem": pem,
                "ballot": {"c1": 2, "c2": 1, "c3": 3}})
    assert open_ballot(k, "e1", out["sealed"]) == {"c1": 2, "c2": 1, "c3": 3}
    assert open_ballot(k, "e2", out["sealed"]) is None                     # bound to its election
    assert "c1" not in out["sealed"]                                       # nothing readable in the sealed text


def test_browser_blinded_pass_verifies_at_the_checker(keys):
    k, _ = keys
    n, d = k.public_key().public_numbers().n, k.private_numbers().d
    out = node({"step": "prepare", "election": "e1", "n": format(n, "x"), "e": 65537, "pem": keys[1], "ballot": {}})
    token = bytes.fromhex(out["token"])
    assert int(out["m"], 16) == blind.full_domain_hash("e1", token, n)     # same full-domain hash as Python
    assert int(out["blinded"], 16) != int(out["m"], 16)                    # the issuer never sees the pass itself
    blind_sig = blind.sign_blinded(int(out["blinded"], 16), d, n)
    done = node({"step": "finish", "r": out["r"], "n": format(n, "x"), "e": 65537, "m": out["m"], "bs": format(blind_sig, "x")})
    assert blind.verify(blind.full_domain_hash("e1", token, n), int(done["sig"], 16), n)


def test_browser_refuses_a_wrong_signature_from_the_issuer(keys):
    k, _ = keys
    n = k.public_key().public_numbers().n
    out = node({"step": "prepare", "election": "e1", "n": format(n, "x"), "e": 65537, "pem": keys[1], "ballot": {}})
    done = node({"step": "finish", "r": out["r"], "n": format(n, "x"), "e": 65537, "m": out["m"], "bs": "1234"})
    assert "not valid" in done["error"]
