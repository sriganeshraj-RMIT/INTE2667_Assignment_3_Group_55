/* Split the chosen "election|candidate" into the two fields the API expects. */
(function () {
  "use strict";
  var pick = document.getElementById("candidate_pick");
  if (!pick) return;
  function sync() {
    var parts = (pick.value || "|").split("|");
    document.getElementById("election_id").value = parts[0];
    document.getElementById("candidate_id").value = parts[1];
  }
  pick.addEventListener("change", sync);
  sync();
})();
