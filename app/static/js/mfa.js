/* R12 second step: set up the authenticator app (staff) or ask for an emailed code (voters). */
(function () {
  "use strict";
  var setupBtn = document.getElementById("setup-btn");
  if (setupBtn) {
    setupBtn.addEventListener("click", async function () {
      setupBtn.disabled = true;
      var res = await EVP.api("POST", "/auth/mfa/setup");
      if (!res.ok) { EVP.show("#setup-box", res); return; }
      document.getElementById("secret").textContent = res.data.secret;
      var img = document.getElementById("qr");
      if (window.qrcode) {
        var qr = qrcode(0, "M"); qr.addData(res.data.otpauth_uri); qr.make();
        img.src = qr.createDataURL(5, 2);
      } else { img.classList.add("hidden"); }
      document.getElementById("setup-result").classList.remove("hidden");
      setupBtn.classList.add("hidden");
    });
  }
  var emailBtn = document.getElementById("email-btn");
  if (emailBtn) {
    emailBtn.addEventListener("click", async function () {
      emailBtn.disabled = true;
      var res = await EVP.api("POST", "/auth/mfa/email-code");
      EVP.show("#email-result", res, "A code was sent to your email address. It expires in 5 minutes.");
      setTimeout(function () { emailBtn.disabled = false; }, 30000);
    });
  }
})();
