var express = require("express");
var router = express.Router();
// var app = require("../app");

var jwt_vc = require("../signatures/jwt_vc.js");
var VC = new jwt_vc.JWT_VC(null);
var dtbs = VC.VC;
// app.set("dtbs", dtbs);

const PageParams = {
  title: "Sign",
  currentURL: "/sign",
  dtbs: null,
  jws: null,
  credentialAuthzCode: null,
  credentialAuthzToken: null,
};

router.get("/", function (req, res, next) {
  PageParams.credentialAuthzCode = req.app.get("csc.credential_code");
  PageParams.credentialAuthzToken = req.app.get("csc.credential_token");
  PageParams.dtbs = JSON.stringify(VC.getVC(), null, 4);
  PageParams.jws = req.app.get("jws");
  res.render("sign", PageParams);
});

module.exports = router;
