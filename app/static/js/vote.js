/* Voting, all on the voter's device:
 *   1. check the ballot is formal (every candidate numbered 1..n once) - the server checks again at the count;
 *   2. seal it with the election public key (R5)            - done BEFORE asking for the pass, so a failure here
 *                                                              never uses up the voter's one vote;
 *   3. blind a fresh voting pass and have it signed (R1, R3 marks the voter off);
 *   4. cast the sealed ballot with the pass WITHOUT the sign-in cookie (credentials: "omit"), so the ballot box
 *      cannot tell who sent it (R1, R4);
 *   5. show the signed receipt (R6).
 * If casting fails after the pass was issued, the pass is kept in memory and the button retries with it.
 */
(function () {
  "use strict";
  var box = document.getElementById("ballot");
  if (!box) return;
  var electionId = box.dataset.election;
  var form = document.getElementById("ballot-form");
  var errorBox = document.getElementById("ballot-error");
  var statusBox = document.getElementById("vote-status");
  var pending = null;                         // {token, sig, sealed} once a pass was issued but not yet used

  function step(name, state) {
    var li = document.querySelector('#steps [data-step="' + name + '"]');
    if (!li) return;
    li.classList.remove("text-success", "text-danger", "fw-bold");
    li.classList.add(state === "done" ? "text-success" : state === "fail" ? "text-danger" : "fw-bold");
  }
  function fail(msg) { errorBox.textContent = msg; errorBox.classList.remove("hidden"); }

  function readBallot() {
    var inputs = Array.from(form.querySelectorAll("input[data-candidate]"));
    var n = inputs.length, seen = {}, ballot = {};
    for (var i = 0; i < inputs.length; i++) {
      var v = inputs[i].value.trim();
      if (!/^\d+$/.test(v)) throw new Error("Number every box from 1 to " + n + ".");
      var p = parseInt(v, 10);
      if (p < 1 || p > n) throw new Error("Use only the numbers 1 to " + n + ".");
      if (seen[p]) throw new Error("Each number can be used only once (" + p + " is used twice).");
      seen[p] = true;
      ballot[inputs[i].dataset.candidate] = p;
    }
    return ballot;
  }

  async function cast(p) {
    step("cast", "busy");
    var res = await EVP.api("POST", "/ballot/" + encodeURIComponent(electionId) + "/cast",
      { token: p.token, signature: p.sig, sealed_ballot: p.sealed }, { anonymous: true });
    if (!res.ok) { step("cast", "fail"); throw Object.assign(new Error(res.data.message || "Casting failed."), { retry: res.status >= 500 }); }
    step("cast", "done"); step("receipt", "done");
    pending = null;
    showReceipt(res.data);
  }

  function showReceipt(r) {
    form.querySelectorAll("input, button").forEach(function (el) { el.disabled = true; });
    document.getElementById("receipt-code").textContent = r.confirmation_code;
    var keep = { election_id: r.election_id, confirmation_code: r.confirmation_code, ballot_hash: r.ballot_hash,
                 signature: r.signature, public_key: r.public_key };
    var blob = new Blob([JSON.stringify(keep, null, 2)], { type: "application/json" });
    document.getElementById("receipt-download").href = URL.createObjectURL(blob);
    document.getElementById("receipt-card").classList.remove("hidden");
    statusBox.replaceChildren();
  }

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    errorBox.classList.add("hidden");
    var btn = document.getElementById("cast-btn");
    btn.disabled = true;
    try {
      if (!pending) {
        var ballot = readBallot();
        if (!window.confirm("Cast this vote? You can vote only once.")) { btn.disabled = false; return; }
        step("seal", "busy");
        var pub = await EVP.api("GET", "/ballot/" + encodeURIComponent(electionId) + "/public-key");
        if (!pub.ok) { step("seal", "fail"); throw new Error(pub.data.message || "The election key is not available."); }
        var sealed = await EVPCrypto.sealBallot(pub.data.public_key_pem, electionId, ballot);
        step("seal", "done");

        step("pass", "busy");
        var key = await EVP.api("GET", "/ballot/" + encodeURIComponent(electionId) + "/pass-key");
        if (!key.ok) { step("pass", "fail"); throw new Error(key.data.message || "The pass key is not available."); }
        var pass = await EVPCrypto.newPass(electionId, key.data.n, key.data.e);
        var issued = await EVP.api("POST", "/ballot/" + encodeURIComponent(electionId) + "/pass", { blinded: pass.blindedHex });
        if (!issued.ok) { step("pass", "fail"); throw new Error(issued.data.message || "A voting pass could not be issued."); }
        pending = { token: pass.tokenHex, sig: EVPCrypto.finishPass(pass, issued.data.blind_signature), sealed: sealed };
        step("pass", "done");
      }
      await cast(pending);
    } catch (e) {
      fail(e.message + (pending ? " Your voting pass is kept on this page: press the button again to retry." : ""));
      btn.disabled = false;
    }
  });
})();
