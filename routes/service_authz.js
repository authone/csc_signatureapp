var express = require("express");
var router = express.Router();

const PageParams = {
  title: "Service Authorization",
  currentURL: "/service_authz",
  serviceAuthzCode: null,
  cscServiceAuthzRequest: null,
  authorization_token: null,
};

router.get("/", function (req, res, next) {
  PageParams.serviceAuthzCode = req.app.get("csc.service_code");
  PageParams.authorization_token = req.app.get("csc.service_token");
  // if (PageParams.authorization_token) {
  //   PageParams.authorization_token = PageParams.authorization_token.replaceAll(
  //     ".",
  //     ".\n"
  //   );
  // }
  res.render("service_authz", PageParams);
});

module.exports = router;
