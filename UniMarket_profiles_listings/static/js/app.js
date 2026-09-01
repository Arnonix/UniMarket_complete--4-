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
