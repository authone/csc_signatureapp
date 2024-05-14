var express = require("express");
var router = express.Router();
var config = require("config");
var debug = require("debug")("csc-signature-app:csc");
const { default: base64url } = require("base64url");

var pplsClient = require("../rest_client/ppls_rest_client.js");
var cscClient = new pplsClient.PplsRestClient(config.get("paperless.url"));

var jwt_vc = require("../signatures/jwt_vc.js");
var VC = new jwt_vc.JWT_VC(null);

/*
  == app set(s) ==
csc.serverInfo
csc.lastState
csc.service_code
csc.credential_code
csc.credentials_list
csc.credentials_info
dtbs
*/

var onRestClientError = function (res, error, url) {
  debugMsg = `ERROR on ${url} call: ${error.code} [${error.response.status} ${error.response.statusText}]: \n ${error.stack}`;
  debug(debugMsg);

  res
    .status(error.response.status)
    .send(`${error.response.status} ${error.response.statusText}`);
};

router.get("/info", async function (req, res, next) {
  debug("========== /csc/info ==========");

  await cscClient.info();
  debug(`csc info done: ${cscClient.ServerInfo}`);
  req.app.set("csc.serverInfo", cscClient.ServerInfo);
  debug("Server INFO: " + JSON.stringify(cscClient.ServerInfo, null, 2));
  res.send(cscClient.ServerInfo);
});

router.get("/authorize_service", async function (req, res, next) {
  debug("========== /csc/authorize_service ==========");
  serverInfo = req.app.get("csc.serverInfo");
  if (!serverInfo) {
    error = "No ServerInfo saved in app context found";
    debug(error);
    res.status(404).send(error);
    return;
  }
  response = cscClient.constructServiceAuthorizationUrl(
    serverInfo.oauth2,
    config.get("paperless.oauth_client_id"),
    config.get("paperless.redirect_uri")
  );
  req.app.set("csc.lastState", response.state);
  res.send(response);
});

router.get("/authorize_credential", async function (req, res, next) {
  debug("========== /csc/authorize_credential ==========");
  credentials_list = req.app.get("csc.credentials_list");
  credentials_info = req.app.get("csc.credentials_info");

  if (!credentials_list || !credentials_info) {
    error = "No credentials found";
    debug(error);
    res.status(404).send(error);
    return;
  }
  response = cscClient.constructCredentialAuthorizationUrl(
    serverInfo.oauth2,
    config.get("paperless.oauth_client_id"),
    config.get("paperless.redirect_uri"),
    credentials_list[0],
    [VC.getDtbsRepresentation()]
  );
  debug("/csc/authorize_credential Authorization URL: " + response.url);
  req.app.set("csc.lastState", response.state);
  res.send(response);
});

router.get("/authz_token_service", async function (req, res, next) {
  debug("========== /csc/authz_token_service ==========");
  code = req.app.get("csc.service_code");
  if (code) {
    var resp = await cscClient
      .oauth2_token(
        config.get("paperless.oauth_client_id"),
        config.get("paperless.oauth_client_secret"),
        config.get("paperless.redirect_uri"),
        code
      )
      .then((result) => {
        if (result.status == 200 && result.data && result.data.access_token) {
          req.app.set("csc.service_token", result.data.access_token);
          req.app.set("csc.service_code", null);
          res.send(200);
        } else {
          error =
            "/csc/authz_token_service ERROR: no authorization_token found";
          debug(error);
          res.status(404).send(error);
        }
      })
      .catch((error) => {
        debug("/csc/authz_token_service ERROR: %0", error);
        res.status(404).send(error);
      });
  } else {
    error = "/csc/authz_token_service ERROR: No code from server";
    debug(error);
    res.status(404).send(error);
  }
});

router.get("/authz_token_credential", async function (req, res, next) {
  debug("========== /csc/authz_token_credential ==========");
  code = req.app.get("csc.credential_code");
  if (!code) {
    error = "/csc/authz_token_credential ERROR: No code found";
    debug(error);
    res.status(404).send(error);
    return;
  }

  var resp = await cscClient
    .oauth2_token(
      config.get("paperless.oauth_client_id"),
      config.get("paperless.oauth_client_secret"),
      config.get("paperless.redirect_uri"),
      code
    )
    .then((result) => {
      if (result.status == 200 && result.data && result.data.access_token) {
        req.app.set("csc.credential_token", result.data.access_token);
        req.app.set("csc.credential_code", null);
        res.send(200);
      } else {
        error =
          "/csc/authz_token_credential ERROR: no credential authorization token found";
        debug(error);
        res.status(404).send(error);
      }
    })
    .catch((error) => {
      debug("/csc/authz_token_credential ERROR: %0", error);
      res.status(404).send(error);
    });
});

router.get("/credentials_list", async function (req, res, next) {
  debug("========== /csc/credentials_list ==========");
  const authz_token = req.app.get("csc.service_token");
  var resp = await cscClient
    .credentials_list(authz_token)
    .then((result) => {
      req.app.set("csc.credentials_list", result.data.credentialIDs);
      debug("Credentials List: %O", result.data);
      res.send(200);
    })
    .catch((error) => {
      debug("/csc/credentials_list ERROR: %0", error);
      res.status(404).send(error);
    });
});

router.get("/credentials_info", async function (req, res, next) {
  debug("========== /csc/credentials_info ==========");
  const authz_token = req.app.get("csc.service_token");
  const credentials = req.app.get("csc.credentials_list");
  if (credentials && credentials.length > 0) {
    var resp = await cscClient
      .credentials_info(credentials[0], authz_token)
      .then((result) => {
        debug("Credentials Info: %O", result.data);
        app_credentials_info = req.app.get("csc.credentials_info");
        if (!app_credentials_info) {
          app_credentials_info = {};
        }

        app_credentials_info[`${credentials[0]}`] = result.data;
        req.app.set("csc.credentials_info", app_credentials_info);

        res.send(result.data);
      })
      .catch((error) => {
        onRestClientError(res, error, "/csc/sign_data");
      });
  } else {
    res.send("No credentials");
  }
});

router.get("/sign_data", async function (req, res, next) {
  debug("========== /csc/sign_data ==========");
  const credentials = req.app.get("csc.credentials_list");
  const credential_token = req.app.get("csc.credential_token");
  const authzToken = req.app.get("csc.service_token");
  if (!credentials || !credential_token || !authzToken) {
    res.status(400).send("No credentials found");
    return;
  }

  var hashes = [VC.getDtbsRepresentation()];

  debug(
    "/csc/sign_data credential=" +
      credentials[0] +
      " hashes= " +
      JSON.stringify(hashes, null, "  ") +
      "credentialToken=" +
      credential_token
  );

  await cscClient
    .signatures_signHash(
      credentials[0],
      hashes,
      jwt_vc.JWA_OID_MAP["RS256"],
      credential_token,
      authzToken
    )
    .then((result) => {
      debug("/csc/sign_data: got signature: ", result.data);
      signatures = result.data.signatures;
      VC.setSignature(signatures[0]);
      req.app.set("jws", VC.getJws());
      res.send("OK");
    })
    .catch((error) => {
      onRestClientError(res, error, "/csc/sign_data");
    });
});

module.exports = router;
