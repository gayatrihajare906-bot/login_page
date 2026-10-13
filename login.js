const loginForm = document.getElementById("loginForm");
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const message = document.getElementById("message");

// Show or hide password
togglePassword.addEventListener("click", function () {
  const isPassword = passwordInput.type === "password";

  passwordInput.type = isPassword ? "text" : "password";
  togglePassword.textContent = isPassword ? "◎" : "◉";
  togglePassword.setAttribute(
    "aria-label",
    isPassword ? "Hide password" : "Show password",
  );
});

// Forgot password

// Login form
loginForm.addEventListener("submit", async function (event) {
  event.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = passwordInput.value;
  const remember = document.getElementById("remember").checked;

  message.style.color = "#ffffff";
  message.textContent = "Checking login details...";

  try {
    // Connects to your Flask backend
    const response = await fetch("http://127.0.0.1:5000/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",

      body: JSON.stringify({
        email: email,
        password: password,
        remember: remember,
      }),
    });

    const data = await response.json();

    if (response.ok && data.success) {
      message.style.color = "#baffc9";
      message.textContent = "Login successful!";

      // Use the redirect URL returned by Flask
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
      }
    } else {
      message.style.color = "#ffd0d0";
      message.textContent = data.message || "Invalid email or password.";
    }
  } catch (error) {
    message.style.color = "#ffd0d0";
    message.textContent =
      "Cannot connect to the server. Start your Flask backend.";
  }
});
