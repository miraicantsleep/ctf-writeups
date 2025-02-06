const express = require("express");
const https = require("https");
const fs = require("fs");
const app = express();
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const nunjucks = require("nunjucks");
const routes = require("./routes");
const Database = require("./database");

const db = new Database("party.db");

const privateKey = fs.readFileSync("/tmp/server.key", "utf8");
const certificate = fs.readFileSync("/tmp/server.cert", "utf8");
const credentials = { key: privateKey, cert: certificate };

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

nunjucks.configure("views", {
  autoescape: true,
  express: app,
});

app.set("views", "./views");
app.use("/static", express.static("./static"));

app.use(routes(db));

app.all("*", (req, res) => {
  return res.status(404).send({
    message: "404 page not found",
  });
});

app.use(function (err, req, res, next) {
  res.status(500).json({ message: "Something went wrong!" });
});

(async () => {
  await db.connect();
  await db.migrate();

  https.createServer(credentials, app).listen(1337, "0.0.0.0", () => {
    console.log("HTTPS Server listening on port 1337");
  });
})();
