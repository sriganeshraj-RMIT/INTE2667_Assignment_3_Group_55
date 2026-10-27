/* After a correct password, go to the second step (R12). */
document.addEventListener("evp:result", function (ev) {
  var form = ev.detail.form;
  if (form.id !== "login-form" || !ev.detail.res.ok) return;
  var next = form.dataset.next;
  window.location.assign("/mfa" + (next ? "?next=" + encodeURIComponent(next) : ""));
});
