/* Audit page: copy the chosen election into the election forms; draw alerts with an acknowledge button. */
(function () {
  "use strict";
  var pick = document.getElementById("a-election");
  function sync() {
    document.querySelectorAll(".election-form input[name=election_id]").forEach(function (el) { el.value = pick ? pick.value : ""; });
  }
  if (pick) { pick.addEventListener("change", sync); sync(); }

  function cell(row, text) { var td = document.createElement("td"); td.textContent = text; row.appendChild(td); return td; }

  document.addEventListener("evp:result", function (ev) {
    if (ev.detail.form.id !== "alerts-form") return;
    var box = document.getElementById("alerts");
    box.replaceChildren();
    var res = ev.detail.res;
    if (!res.ok) { EVP.show(box, res); return; }
    if (!res.data.length) { box.textContent = "No alerts."; return; }
    var table = document.createElement("table");
    table.className = "table table-sm small";
    var head = table.createTHead().insertRow();
    ["Severity", "Rule", "Account", "When (UTC)", "Status", ""].forEach(function (h) { cell(head, h); });
    var body = table.createTBody();
    res.data.forEach(function (a) {
      var row = body.insertRow();
      var sev = cell(row, a.severity);
      sev.className = a.severity === "CRITICAL" ? "text-danger fw-bold" : a.severity === "HIGH" ? "text-danger" : "";
      cell(row, a.rule); cell(row, a.actor_id); cell(row, a.created_at); cell(row, a.status);
      var act = cell(row, "");
      if (a.status === "OPEN") {
        var b = document.createElement("button");
        b.className = "btn btn-sm btn-outline-secondary"; b.textContent = "Acknowledge"; b.type = "button";
        b.addEventListener("click", async function () {
          var r = await EVP.api("POST", "/audit/alerts/" + encodeURIComponent(a.id) + "/acknowledge");
          if (r.ok) { b.replaceWith(document.createTextNode("acknowledged")); } else { EVP.show(act, r); }
        });
        act.appendChild(b);
      }
    });
    box.appendChild(table);
  });
  // the alerts form already showed a JSON result box; hide it so the table is the main view
  var form = document.getElementById("alerts-form");
  if (form) form.dataset.result = "#alerts-json";
})();
