var express = require("express");
var router = express.Router();
var debug = require("debug")("csc-signature-app:server:redirect");

router.get("/", async function (req, res, next) {
  debug("========== /redirect ==========");
  state = req.query["state"];
  code = req.query["code"];

  if (!code) {
    debug("ERROR: No code from server");
    res.send("ERROR: No code from server");
    return;
  }
  debug("/redirect: got code from server: " + code);

  if (state.startsWith("service-")) {
    req.app.set("csc.service_code", code);
    res.redirect("/service_authz");
  } else if (state.startsWith("credential-")) {
    req.app.set("csc.credential_code", code);
    res.redirect("/sign");
  } else {
    debug("ERROR: unknown scope: %0", state);
    res.send("ERROR: unknown scope");
  }
});

module.exports = router;
