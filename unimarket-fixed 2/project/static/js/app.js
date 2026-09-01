document.addEventListener("submit", (event) => {
  const form = event.target;
  const price = form.querySelector("input[name='price'], input[name='amount']");
  const password = form.querySelector("input[name='password']");
  const confirmation = form.querySelector("input[name='password2']");

  if (price && Number(price.value) < 0) {
    event.preventDefault();
    price.focus();
  }

  if (confirmation && password && confirmation.value !== password.value) {
    event.preventDefault();
    confirmation.setCustomValidity("Passwords do not match.");
    confirmation.reportValidity();
    return;
  }
  if (confirmation) confirmation.setCustomValidity("");
});

document.addEventListener("click", (event) => {
  const toggle = event.target.closest(".password-toggle");
  if (!toggle) return;

  const field = toggle.closest(".password-field")?.querySelector("input");
  if (!field) return;

  const showing = field.type === "text";
  field.type = showing ? "password" : "text";
  toggle.textContent = showing ? "Show" : "Hide";
  toggle.setAttribute("aria-label", `${showing ? "Show" : "Hide"} password`);
});

/* ===== OTP countdown timer ===== */
(function() {
  var el = document.getElementById('otp-countdown');
  if (!el) return;
  var secs = parseInt(el.dataset.seconds, 10) || 0;
  if (secs <= 0) { el.textContent = 'Expired'; el.classList.add('expired'); return; }
  function tick() {
    if (secs <= 0) { el.textContent = 'Expired — request a new code'; el.classList.add('expired'); return; }
    var m = Math.floor(secs / 60), s = secs % 60;
    el.textContent = m + ':' + (s < 10 ? '0' : '') + s;
    secs--;
    setTimeout(tick, 1000);
  }
  tick();
})();
