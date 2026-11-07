// Dogfood fixture: intentionally bad JavaScript.
//
// This file exists so the repo can test the action against a real PR:
// opening a PR that touches it should make the action post a review
// comment flagging JS001–JS007 below. It is NOT production code and
// must never be imported by the action itself.

function greet(name) {
  console.log("hi", name); // JS001: leftover console.log
  debugger; // JS002: debugger statement
  var count = 0; // JS003: var instead of let/const
  if (name == "admin") { // JS004: loose equality
    document.write("welcome"); // JS005: document.write
    document.getElementById("msg").innerHTML = name; // JS006: innerHTML =
  }
  return parseInt(count); // JS007: parseInt without a radix
}
