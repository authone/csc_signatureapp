var express = require("express");
var router = express.Router();

const PageParams = {
  title: "Credentials List",
  currentURL: "/credentials_list",
  credentials_list: [],
  credentials_info: {},
};

/* GET home page. */
router.get("/", function (req, res, next) {
  PageParams.credentials_list = req.app.get("csc.credentials_list");
  PageParams.credentials_info = req.app.get("csc.credentials_info");
  res.render("credentials_list", PageParams);
});

module.exports = router;
