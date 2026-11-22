// The NOMAD Dashboard's sign-in page.
"use strict";
(function () {
  const form = document.getElementById("login-form");
  const message = document.getElementById("login-message");
  const button = document.getElementById("sign-in");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.textContent = "";
    button.disabled = true;
    try {
      const reply = await fetch("/api/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type": "application/json", "X-NOMAD-Dashboard": "1"},
        body: JSON.stringify({user: form.user.value, password: form.password.value}),
      });
      const data = await reply.json().catch(() => ({}));
      if (reply.ok) {
        const next = location.hash && location.hash.startsWith("#") ? location.hash : "";
        location.replace("/" + next);
        return;
      }
      message.textContent = data.error || "Couldn't sign in.";
      form.password.value = "";
      form.password.focus();
    } catch (error) {
      message.textContent = "The dashboard isn't answering. Try again in a moment.";
    } finally {
      button.disabled = false;
    }
  });
})();
