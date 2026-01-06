/* -*- mode: javascript; tab-width: 8; indent-tabs-mode: nil; js-indent-level: 2 -*- */

import express from "express";
import fetch from "node-fetch";

const PORT = process.env.PORT || 3000;
const HTTP_STATUS_BAD_REQUEST = 400;
const HTTP_STATUS_UNAUTHORIZED = 401
const HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;
const HTTP_STATUS_SERVICE_UNAVAILABLE = 503;


let authzSrv = {
  dropbox: {
    accessTokenURL: "https://api.dropboxapi.com/oauth2/token",
  },
  googledrive: {
    accessTokenURL: "https://oauth2.googleapis.com/token",
  },
  onedrive: {
    accessTokenURL: "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
  },
};


let app = express();

// Needed to process form data in POST requests.
app.use(express.urlencoded({extended: true}));

// Allow CORS.
app.all(["/readnext/*"], (aRequest, aResponse, aFnNext) => {
  aResponse.set("Access-Control-Allow-Origin", "*");
  aFnNext();
});


app.get("/", (aRequest, aResponse) => {
  aResponse.send('<html><head><meta http-equiv="Refresh" content="0; URL=https://aecreations.io/"></head></html>');
});


// Simple health check.
app.get("/ping", (aRequest, aResponse) => {
  aResponse.json({status: "ok"});
});


// Get API key for the given cloud storage backend.
app.get("/readnext/apikey", (aRequest, aResponse) => {
  getAPIKey("readnext", aRequest, aResponse);
});


// Get access token.
app.post("/readnext/token", (aRequest, aResponse) => {
  getAccessToken("readnext", aRequest, aResponse);
});


function getAPIKey(aAppName, aRequest, aResponse)
{
  let backnd;
  if ("svc" in aRequest.query) {
    backnd = aRequest.query["svc"];
  }

  if (! backnd) {
    aResponse.status(HTTP_STATUS_BAD_REQUEST).json({
      error: {
        name: "ReferenceError",
        message: "Missing svc"
      }
    });
    return;
  }
  
  let apiKey;
  if (isValidService(backnd)) {
    apiKey = process.env[`${aAppName.toUpperCase()}_CLIENT_KEY_${backnd.toUpperCase()}`];
  }
  else {
    aResponse.status(HTTP_STATUS_BAD_REQUEST).json({
      error: {
        name: "RangeError",
        message: `Unsupported value of svc: '${backnd}'`
      }
    });
    return;
  }

  if (typeof apiKey == "string") {
    aResponse.json({api_key: apiKey});
  }
  else {
    aResponse.sendStatus(HTTP_STATUS_INTERNAL_SERVER_ERROR);
  }
}


async function getAccessToken(aAppName, aRequest, aResponse)
{
  let backnd;
  if ("svc" in aRequest.body) {
    backnd = aRequest.body["svc"];
  }

  let grantType = "authorization_code";
  if ("grant_type" in aRequest.body) {
    grantType = aRequest.body["grant_type"];
  }

  if (!backnd || !grantType) {
    aResponse.status(HTTP_STATUS_BAD_REQUEST).json({
      error: {
        name: "ReferenceError",
        message: "Missing svc and/or grant_type"
      }
    });
    return;
  }

  if (! isValidService(backnd)) {
    aResponse.sendStatus(HTTP_STATUS_BAD_REQUEST);
    return;
  }
  
  let requestParams;
  let requestOpts = {
    method: "POST",
  };

  requestParams = new URLSearchParams({
    client_id: process.env[`${aAppName.toUpperCase()}_CLIENT_KEY_${backnd.toUpperCase()}`],
    client_secret: process.env[`${aAppName.toUpperCase()}_CLIENT_SECRET_${backnd.toUpperCase()}`],
  });

  if (grantType == "authorization_code") {
    let authzCode, redirectURI;
    "code" in aRequest.body && (authzCode = aRequest.body["code"]);
    "redirect_uri" in aRequest.body && (redirectURI = aRequest.body["redirect_uri"]);
    if (!authzCode || !redirectURI) {
      aResponse.status(HTTP_STATUS_BAD_REQUEST).json({
        error: {
          name: "ReferenceError",
          message: `Missing code and/or redirect_uri (grant_type: '${grantType}')`
        }
      });
      return;
    }

    requestParams.set("grant_type", "authorization_code");
    requestParams.set("code", authzCode);
    requestParams.set("redirect_uri", redirectURI);
  }
  else if (grantType == "refresh_token") {
    let refreshToken;
    "refresh_token" in aRequest.body && (refreshToken = aRequest.body["refresh_token"]);
    if (! refreshToken) {
      aResponse.status(HTTP_STATUS_BAD_REQUEST).json({
        error: {
          name: "ReferenceError",
          message: "Missing refresh_token"
        }
      });
      return;
    }

    requestParams.set("grant_type", "refresh_token");
    requestParams.set("refresh_token", refreshToken);
  }

  if (backnd == "onedrive") {
    requestParams.delete("client_secret");  // Not required for native apps
    requestParams.set("scope", "User.Read Files.ReadWrite.AppFolder offline_access");
  }

  requestOpts.body = requestParams;

  let tokenURL = authzSrv[backnd].accessTokenURL;
  let resp;  
  try {
    resp = await fetch(tokenURL, requestOpts);
  }
  catch (e) {
    // An error may occur if the request to the authz server timed out.
    console.log("getAccessToken(): Exception thrown by fetch(): " + e);

    aResponse.status(HTTP_STATUS_SERVICE_UNAVAILABLE).json({
      error: {
        name: "ServerError",
        message: "${e.name}: ${e.message}",
        source: tokenURL,
      }
    });
    return;
  }

  if (resp.ok) {
    let respBody = await resp.json();
    let outResp;

    if (grantType == "authorization_code") {
      outResp = {
        access_token: respBody["access_token"],
        refresh_token: respBody["refresh_token"],
      };
    }
    else if (grantType == "refresh_token") {
      outResp = {
        access_token: respBody["access_token"],
      };

      if ("refresh_token" in respBody) {
        // Include new refresh token issued by authz server.
        outResp.refresh_token = respBody["refresh_token"];
      }
    }

    // Google Drive: Also include the scopes returned from the access token
    // request in order to confirm that all the necessary permissions were
    // granted by the user.
    if (backnd == "googledrive") {
      outResp.scope = respBody.scope;
    }
    
    aResponse.json(outResp);
  }
  else {
    // Dropbox and Google Drive will return HTTP status 400 and the following
    // JSON in the response if the refresh token is expired:
    // {
    //   "error": "invalid_grant",
    //   "error_description": "Token has been expired or revoked."
    // }
    //
    // Per RFC 6749, section 5.2:
    // "The provided authorization grant (e.g., authorization
    // code, resource owner credentials) or refresh token is
    // invalid, expired, revoked, does not match the redirection
    // URI used in the authorization request, or was issued to
    // another client."
    // - Source: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
    //
    // MS OneDrive will also return HTTP status 400 and the same value for
    // "error".
    if (resp.status == HTTP_STATUS_BAD_REQUEST) {
      let errRespBody = await resp.json();
      aResponse.status(HTTP_STATUS_BAD_REQUEST).json({
        error: {
          name: "AuthorizationError",
          message: `${errRespBody.error}: ${errRespBody.error_description}`,
          source: tokenURL,
          error: errRespBody.error,
          errorDescription: errRespBody.error_description,
        }
      });
    }
    else {
      let errRespCnt = await resp.text();
      console.log(`aeOAPS /token: HTTP status ${resp.status} returned from ${tokenURL}`);
      console.log(errRespCnt);

      aResponse.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json({
        error: {
          name: "HTTPResponseError",
          message: resp.statusText,
          source: tokenURL,
          statusCode: resp.status,
        }
      });
    }
  }  
}


function isValidService(aAuthzSrvKey)
{
  let rv = ["dropbox", "onedrive", "googledrive"].includes(aAuthzSrvKey);

  return rv;
}


app.listen(PORT, () => console.log(`OAuth Proxy Server started, listening on port ${PORT}`));
