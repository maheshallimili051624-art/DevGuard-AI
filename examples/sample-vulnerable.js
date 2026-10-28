const express = require("express");
const app = express();

// Example only: review untrusted output before rendering in a browser.
app.get("/hello", (req, res) => {
  const name = req.query.name;
  res.send("Hello " + name);
});

app.listen(3000, () => console.log("Server started"));
