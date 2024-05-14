var config = require("config");
var jwt = require("jsonwebtoken");
const { default: base64url } = require("base64url");
const crypto = require("crypto");

/**
 * ---------------- JWT header ---------------
{
  "alg": "ES256",
  "typ": "JWT"
}
--------------- JWT payload ---------------
// NOTE: The example below uses a valid VC-JWT serialization
//       that duplicates the iss, nbf, jti, and sub fields in the
//       Verifiable Credential (vc) field.
{
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": "http://example.edu/credentials/3732",
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ],
    "issuer": "https://example.edu/issuers/565049",
    "issuanceDate": "2010-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    }
  },
  "iss": "https://example.edu/issuers/565049",
  "nbf": 1262304000,
  "jti": "http://example.edu/credentials/3732",
  "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21"
}
--------------- JWT ---------------
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3
d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L
2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRl
bnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eUR
lZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLz
U2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhb
FN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEi
LCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFN
jaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNT
Y1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVud
GlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMy
MSJ9.giMDNtWUgKbvWL4pteSpSkrh-lhgkhJUZ_gatHdRvEFs9_kB4G9neABvTuuQKfwERzi2KF
Qz3X0nzF-jrOO-5w

 */

const OID_JWA_MAP = {
  "1.2.840.113549.1.1.1": "RSA", // ?
  "1.2.840.113549.1.1.11": "RS256", // RSASSA-PKCS1-v1_5 using SHA-256
  "1.2.840.113549.1.1.13": "RS512", // RSASSA-PKCS1-v1_5 using SHA-512
};
const JWA_OID_MAP = {
  RSA: "1.2.840.113549.1.1.1", // ?
  RS256: "1.2.840.113549.1.1.11", // RSASSA-PKCS1-v1_5 using SHA-256
  RS512: "1.2.840.113549.1.1.13", // RSASSA-PKCS1-v1_5 using SHA-512
};

const DocumentToBeSigned = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  id: "urn:uuid:6a9c92a9-2530-4e2b-9776-530467e9bbe0",
  type: ["VerifiableCredential", "ExampleAlumniCredential"],
  issuer: "https://certsign.ro/issuers/565049",
  validFrom: "2020-01-01T12:31:42Z",
  issuanceDate: "2020-01-01T12:31:42Z",
  credentialSubject: {
    id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
    alumniOf: {
      id: "did:example:c276e12ec21ebfeb1f712ebc6f1",
      name: "certSIGN Academy",
    },
  },
};

const JwtHeader = {
  alg: "RS256",
  typ: "JWT",
};

class JWT_VC {
  constructor(claims) {
    // this.VC = claims;
    this.setJwtHeader(JwtHeader);
    this.setVC(DocumentToBeSigned, config.get("credentials.context"));
    // this.body = DocumentToBeSigned;
    // this.VC["@context"] = config.get("credentials.context");
    // this.proof = {};
    this.dtbsRepresentation = null;
  }

  setJwtHeader(header) {
    this.jwtHeader = header;
    this.jwtHeaderStr = JSON.stringify(this.jwtHeader);
  }

  setJwtBody(body) {
    this.jwtBody = body;
    this.jwtBodyStr = JSON.stringify(this.jwtBody);
  }

  setVC(vc, context) {
    var bdy = vc;
    bdy["@context"] = context;
    this.setJwtBody(bdy);
  }

  setSignature(rawSignature) {
    this.jwtSignature = rawSignature;
  }

  getVC() {
    return this.jwtBody;
  }

  // return JWS representation using JWS Compact Serialization
  getJws() {
    return (
      base64url.encode(this.jwtHeaderStr) +
      "." +
      base64url.encode(this.jwtBodyStr) +
      "." +
      base64url.encode(this.jwtSignature)
    );
  }

  getDtbsRepresentation() {
    if (!this.dtbsRepresentation) {
      const str_jwt_body = JSON.stringify(this.VC);
      const payload =
        base64url.encode(this.jwtHeaderStr) +
        "." +
        base64url.encode(this.jwtBodyStr);

      this.dtbsRepresentation = crypto
        .createHash("sha256")
        .update(payload)
        .digest("base64");
    }
    return this.dtbsRepresentation;
  }
}
exports.JWT_VC = JWT_VC;
exports.OID_JWA_MAP = OID_JWA_MAP;
exports.JWA_OID_MAP = JWA_OID_MAP;
