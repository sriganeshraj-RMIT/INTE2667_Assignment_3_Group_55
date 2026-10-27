/* Paste a saved receipt file to fill the form. */
(function () {
  "use strict";
  var paste = document.getElementById("paste");
  if (!paste) return;
  paste.addEventListener("input", function () {
    try {
      var r = JSON.parse(paste.value);
      if (r.ballot_hash) document.getElementById("ballot_hash").value = r.ballot_hash;
      if (r.signature) document.getElementById("signature").value = r.signature;
      if (r.election_id) document.getElementById("election_id").value = r.election_id;
    } catch (e) { /* not JSON yet */ }
  });
})();
