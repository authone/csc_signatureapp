#!/usr/bin/env node
var rest_client = require("./axios-rest-client.js");
var jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { default: base64url } = require("base64url");
// const b64url = require("base64url");
const qs = require("qs");

class PplsRestClient extends rest_client.RestClient {
  constructor(baseURL) {
    super(baseURL);
  }

  //#region /info
  /**
   * ************************************************************************************
   * Calls:
   *    curl -i -X POST -H "Content-Type: application/json" -d '{}' /info
   *  @returns info {}
   * ************************************************************************************
   */
  async info() {
    var resp = await this.post("/info");
    this.ServerInfo = resp.data;
    if (this.ServerInfo.oauth2) {
      this.AuthzClient = new rest_client.RestClient(this.ServerInfo.oauth2);
    }
  }
  //#endregion

  //#region /oauth2/token
  /**
   * ************************************************************************************
   * Calls:
   *    	curl -i -X POST -H "Content-Type: application/json"
   *        -d "{\"grant_type\":\"authorization_code\",\"client_id\":\"<CLIENT_ID>\",\"client_secret\":\"<CLIENT_SECRET>\",
   *             \"redirect_uri\":\"<REDIRECT_URI>\",\"code\":\"<AUTHORIZATION_CODE>\"}"
   *        https://<SERVICE_BASE_URI>/csc/v0/oauth2/token
   *  @returns authorization token
   * ************************************************************************************
   */
  async oauth2_token(clientId, clientSecret, redirUri, code) {
    const params = {
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirUri,
      code: code,
    };
    var resp = await this.AuthzClient.post(
      "/oauth2/token",
      qs.stringify(params),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );
    return resp;
  }
  //#endregion

  //#region /credentials/list
  /**
   * ************************************************************************************
   * Calls:
   *    	curl -i -X POST
   *          -H "Authorization: Bearer <AUTH_TOKEN>"
   *          -H "Content-Type: application/json"
   *          -d "{\"pageToken\":null}"
   *        https://<SERVICE_BASE_URI>/csc/v0/credentials/list
   *  @returns credentials_list {}
   * ************************************************************************************
   */
  async credentials_list(authzToken) {
    return this.post("/credentials/list", JSON.stringify({}), {
      headers: { Authorization: "Bearer: " + authzToken },
    });
  }
  //#endregion

  //#region /credentials/info
  /**
   * ************************************************************************************
   * Calls:
   *    	curl -i -X POST
   *          -H "Authorization: Bearer <AUTH_TOKEN>"
   *          -H "Content-Type: application/json"
   *          -d "{\"credentialID\":\"<CREDENTIAL_ID>\",\"certificates\":\"chain\",\"authInfo\":true,\"certInfo\":true,\"lang\":\"en-US\",\"clientData\":null}"
   *        https://<SERVICE_BASE_URI>/csc/v0/credentials/info
   *  @returns credentials_info {}
   * ************************************************************************************
   */
  async credentials_info(credentialId, authzToken) {
    var data = {
      credentialID: credentialId,
      certificates: "chain",
      certInfo: true,
      authInfo: true,
      lang: "en",
    };
    return this.post("/credentials/info", data, {
      headers: { Authorization: "Bearer: " + authzToken },
    });
  }
  //#endregion

  //#region /signatures/signHash
  /**
   * ************************************************************************************
   * signatures/signHash
   * Calls:
   *      curl -i -X POST
   *          -H "Authorization: Bearer <AUTH_TOKEN>"
   *          -H "Content-Type: application/json"
   *          -d "{\"credentialID\":\"<CREDENTIAL_ID>\",\"SAD\":\"<SAD>\",\"hash\":[\"<SHA256_HASH>\"],\"signAlgo\":\"1.2.840.113549.1.1.11\"}"
   *        https://<SERVICE_BASE_URI>/csc/v0/signatures/signHash
   * ************************************************************************************
   */

  async signatures_signHash(credentialId, dataHash, signAlgo, sad, authzToken) {
    var data = {
      credentialID: credentialId,
      SAD: sad,
      hash: dataHash,
      signAlgo: signAlgo,
    };
    return this.post("/signatures/signHash", data, {
      headers: { Authorization: "Bearer: " + authzToken },
    });
  }
  //#endregion

  /**
   * ************************************************************************************
   account_token = 
    base64UrlEncode(<JWT_Header>) + "." +
    base64UrlEncode(<JWT_Payload>) + "." +
    base64UrlEncode(<JWT_Signature>)

    <JWT_Header> = {
        "typ": "JWT",
        "alg": "HS256"
    }
    <JWT_Payload> = {
        "sub": <Account_ID>, //Account ID
        "iat": <Unix_Epoch_Time>, //Issued At Time
        "jti": <Token_Unique_Identifier>, //JWT ID
        "iss": <Signature_Application_Name>, //Issuer
        "azp": <OAuth2_client_id> //Authorized presenter
    }
    <JWT_Signature> = HMACSHA256(
        base64UrlEncode(<JWT_Header>) + "." +
        base64UrlEncode(<JWT_Payload>),
        SHA256(<OAuth2_client_secret>)
    )
   * ************************************************************************************
   */
  create_account_token(accountId, clientId, clientSecret) {
    const str_jwt_header = JSON.stringify({
      typ: "JWT",
      alg: "HS256",
    });
    const str_jwt_body = JSON.stringify({
      sub: accountId,
      iat: Date.now() / 1000,
      jti: crypto.randomBytes(16).toString("base64"),
      iss: "test_client",
      azp: clientId,
    });
    const payload =
      base64url.encode(str_jwt_header) + "." + base64url.encode(str_jwt_body);

    const clientSecretHash = crypto
      .createHash("sha256")
      .update(clientSecret)
      .digest();

    const jwt_signature = jwt.sign(payload, clientSecretHash, {
      algorithm: "HS256",
    });

    const bearer =
      base64url.encode(str_jwt_header) +
      "." +
      base64url.encode(str_jwt_body) +
      "." +
      base64url.encode(jwt_signature);

    return bearer;
  }

  //#region constructAuthzURL
  /**
   * ************************************************************************************
   * Url like:
   * curl -i -X GET -H "Content-Type: application/json" -d '{}'
   *        /oauth2/authorize?response_type=code&client_id=123&scope=service
   *  @returns authorization code
   * ************************************************************************************
   **/
  constructServiceAuthorizationUrl(baseUrl, clientId, redirUri) {
    const url_params = {
      client_id: clientId,
      response_type: "code",
      redirect_uri: redirUri,
      scope: "service",
      state: "service-" + crypto.randomBytes(16).toString("base64"),
      culture: "en",
    };

    var cscUrlWithParams = new URL(baseUrl);
    cscUrlWithParams.pathname = cscUrlWithParams.pathname + "oauth2/authorize";

    for (const key in url_params) {
      cscUrlWithParams.searchParams.append(key, url_params[key]);
    }
    return { url: cscUrlWithParams.href, state: url_params.state };
  }

  /**
   * ************************************************************************************
   * Url like:
   * curl -i -X GET -H "Content-Type: application/json" -d '{}'
   *        /oauth2/authorize?response_type=code&client_id=123&scope=credential
   *  @returns authorization code
   * ************************************************************************************
   **/
  constructCredentialAuthorizationUrl(
    baseUrl,
    clientId,
    redirUri,
    credentialId,
    hashes
  ) {
    var url_params = {
      client_id: clientId,
      response_type: "code",
      redirect_uri: redirUri,
      scope: "credential",
      state: "credential-" + crypto.randomBytes(16).toString("base64"),
      culture: "en",
      credentialID: credentialId,
      hash: hashes,
      numSignatures: hashes.length,
    };

    var cscUrlWithParams = new URL(baseUrl);
    cscUrlWithParams.pathname = cscUrlWithParams.pathname + "oauth2/authorize";

    for (var key in url_params) {
      cscUrlWithParams.searchParams.append(key, url_params[key]);
    }
    return { url: cscUrlWithParams.href, state: url_params.state };
  }
}
//#endregion

exports.PplsRestClient = PplsRestClient;
