var express = require("express");
var router = express.Router();

const PageParams = {
  title: "Server Info",
  currentURL: "/",
  cscInfo: null,
};

router.get("/", function (req, res, next) {
  if (req.app.get("csc.serverInfo")) {
    cscServerInfo = req.app.get("csc.serverInfo");
    PageParams.cscInfo = JSON.stringify(cscServerInfo, null, 4);
    PageParams.cscInfoLogo = cscServerInfo.logo;
  }
  res.render("index", PageParams);
});

module.exports = router;
