const registerForm = document.getElementById("registerForm");
const message = document.getElementById("message");

registerForm.addEventListener("submit", function(event) {
const password = document.getElementById("password").value;
const confirmPassword =
document.getElementById("confirmPassword").value;

if (password.length < 8) {
    event.preventDefault();
    message.textContent =
        "Password must contain at least 8 characters.";
    return;
}

if (password !== confirmPassword) {
    event.preventDefault();
    message.textContent = "Passwords do not match.";
    return;
}

message.textContent = "Creating your account...";

});