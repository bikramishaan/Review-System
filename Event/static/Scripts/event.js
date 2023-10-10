window.onload = function() {
  var formField = document.getElementById("number");
  formField.value = '';
  
}

function copyText(inputId) {
/* Get the text field */
var copyText = document.getElementById(inputId);

/* Select the text field */
copyText.select();
copyText.setSelectionRange(0, 99999); /* For mobile devices */

/* Copy the text inside the text field */
document.execCommand("copy");

/* Alert the copied text */
alert("Copied the text: " + copyText.value);

var buttonId = "copyButton" + inputId.slice(-1);
var button = document.getElementById(buttonId);
button.style.backgroundColor = "green";
button.innerHTML = 'Link copied'

}

// Function to display the message for a specified duration
function flashMessage(message, duration) {
  const flashDiv = document.getElementById("flash-message");
  flashDiv.innerText = message;
  flashDiv.style.display = "block";
  setTimeout(function () {
    flashDiv.style.display = "none";
  }, duration);
}

// Example usage
flashMessage("You are now logged in as " + role, 3000); // Display for 5 seconds (5000 milliseconds)