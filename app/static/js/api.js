/* EVP - shared helpers for every page.
 *  - api(): fetch() to the REST API with the CSRF token (R18) from <meta name="csrf-token">.
 *  - <form data-api="/path/{field}" data-method="POST|GET"> forms are sent as JSON automatically.
 *    Inputs: data-type="int" | "list" (one value per line or comma) ; empty optional fields are left out.
 *    data-result="#id" shows the answer, data-reload="1" reloads the page after success,
 *    data-redirect="/page" goes there after success, data-confirm="text" asks first.
 *  - Every value is written with textContent, never innerHTML, so API data cannot inject markup (XSS).
 */
(function () {
  "use strict";

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute("content") : "";
  }

  async function api(method, path, body, opts) {
    opts = opts || {};
    var init = { method: method, headers: { "Accept": "application/json" },
                 credentials: opts.anonymous ? "omit" : "same-origin" };
    if (method !== "GET") {
      init.headers["Content-Type"] = "application/json";
      if (!opts.anonymous) init.headers["X-CSRF-Token"] = csrf();
      init.body = JSON.stringify(body || {});
    }
    var resp = await fetch(path, init);
    var data = null;
    try { data = await resp.json(); } catch (e) { data = { error: "BAD_RESPONSE", message: "The server sent an unexpected answer." }; }
    return { ok: resp.ok, status: resp.status, data: data };
  }

  function show(target, res, okText) {
    var box = typeof target === "string" ? document.querySelector(target) : target;
    if (!box) return;
    box.replaceChildren();
    var alert = document.createElement("div");
    alert.className = "alert mb-2 " + (res.ok ? "alert-success" : "alert-danger");
    var msg = res.ok ? (okText || "Done.") : ((res.data && res.data.message) || "Request failed.") +
      (res.data && res.data.error ? " (" + res.data.error + ")" : "");
    alert.textContent = msg;
    box.appendChild(alert);
    if (res.data && (res.ok || !res.data.message)) {
      var pre = document.createElement("pre");
      pre.className = "result-box bg-light p-2 border rounded";
      pre.textContent = JSON.stringify(res.data, null, 2);
      box.appendChild(pre);
    }
  }

  function formBody(form) {
    var body = {};
    form.querySelectorAll("input[name], select[name], textarea[name]").forEach(function (el) {
      if (el.type === "checkbox") { body[el.name] = el.checked; return; }
      var v = el.value.trim();
      if (v === "" && !el.required) return;
      var t = el.dataset.type;
      if (t === "int") v = parseInt(v, 10);
      else if (t === "list") v = v.split(/[\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
      body[el.name] = v;
    });
    return body;
  }

  function fillPath(path, body) {
    return path.replace(/\{(\w+)\}/g, function (_, key) {
      var v = body[key]; delete body[key];
      return encodeURIComponent(v == null ? "" : v);
    });
  }

  document.addEventListener("submit", async function (ev) {
    var form = ev.target;
    if (!form.matches("form[data-api]")) return;
    ev.preventDefault();
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) return;
    var button = form.querySelector("[type=submit]");
    if (button) button.disabled = true;
    try {
      var body = formBody(form);
      var method = (form.dataset.method || "POST").toUpperCase();
      var path = fillPath(form.dataset.api, body);
      if (method === "GET" && Object.keys(body).length) path += "?" + new URLSearchParams(body).toString();
      var res = await api(method, path, method === "GET" ? null : body);
      show(form.dataset.result || form.querySelector(".form-result"), res, form.dataset.ok);
      document.dispatchEvent(new CustomEvent("evp:result", { detail: { form: form, res: res } }));
      if (res.ok && form.dataset.redirect) window.location.assign(form.dataset.redirect);
      else if (res.ok && form.dataset.reload) setTimeout(function () { window.location.reload(); }, 900);
    } finally {
      if (button) button.disabled = false;
    }
  });

  // Sign out (navigation bar)
  document.addEventListener("click", async function (ev) {
    var el = ev.target.closest("[data-logout]");
    if (!el) return;
    ev.preventDefault();
    await api("POST", "/auth/logout");
    window.location.assign("/");
  });

  window.EVP = Object.assign(window.EVP || {}, { api: api, show: show, csrf: csrf });
})();
