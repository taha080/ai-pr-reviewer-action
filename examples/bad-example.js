// Dogfood fixture: intentionally bad JavaScript.
//
// This file exists so the repo can test the action against a real PR:
// opening a PR that touches it should make the action post a review
// comment flagging JS001-JS018 below. It is NOT production code and
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

// JS011-JS013: complexity rules (Day 3). This function is deliberately
// too long (over 50 lines), takes too many parameters (6) and nests
// too deep (4 levels).
function tooComplex(a, b, c, d, e, f) { // JS012: 6 parameters
  const total = a + b + c + d + e + f;
  const v1 = 1;
  const v2 = 2;
  const v3 = 3;
  const v4 = 4;
  const v5 = 5;
  const v6 = 6;
  const v7 = 7;
  const v8 = 8;
  const v9 = 9;
  const v10 = 10;
  const v11 = 11;
  const v12 = 12;
  const v13 = 13;
  const v14 = 14;
  const v15 = 15;
  const v16 = 16;
  const v17 = 17;
  const v18 = 18;
  const v19 = 19;
  const v20 = 20;
  const v21 = 21;
  const v22 = 22;
  const v23 = 23;
  const v24 = 24;
  const v25 = 25;
  const v26 = 26;
  const v27 = 27;
  const v28 = 28;
  const v29 = 29;
  const v30 = 30;
  const v31 = 31;
  const v32 = 32;
  const v33 = 33;
  const v34 = 34;
  const v35 = 35;
  const v36 = 36;
  const v37 = 37;
  const v38 = 38;
  const v39 = 39;
  const v40 = 40;
  const v41 = 41;
  const v42 = 42;
  const v43 = 43;
  const v44 = 44;
  const v45 = 45;
  const v46 = 46;
  const v47 = 47;
  const v48 = 48;
  if (total) { // JS013: nesting level 1
    if (total) { // level 2
      if (total) { // level 3
        if (total) { // level 4
          return total;
        }
      }
    }
  }
  return total;
}

// JS014-JS018: dangerous-API rules (Day 4).
function dangerous(userInput) {
  eval(userInput); // JS014: eval() executes a string
  setTimeout("dangerous()", 100); // JS015: string timer
  with (userInput) { return name; } // JS016: with statement
  const token = document.cookie; // JS017: direct cookie access
  const ordered = [3, 10, 2].sort(); // JS018: sort() without comparator
  return token + ordered.length;
}
