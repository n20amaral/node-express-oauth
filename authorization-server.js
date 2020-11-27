const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const {
  randomString,
  containsAll,
  decodeAuthCredentials,
  timeout,
} = require("./utils");

const config = {
  port: 9001,
  privateKey: fs.readFileSync("assets/private_key.pem"),

  clientId: "my-client",
  clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
  redirectUri: "http://localhost:9000/callback",

  authorizationEndpoint: "http://localhost:9001/authorize",
};

const clients = {
  "my-client": {
    name: "Sample Client",
    clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
    scopes: ["permission:name", "permission:date_of_birth"],
  },
  "test-client": {
    name: "Test Client",
    clientSecret: "TestSecret",
    scopes: ["permission:name"],
  },
};

const users = {
  user1: "password1",
  john: "appleseed",
};

const requests = {};
const authorizationCodes = {};

let state = "";

const app = express();
app.set("view engine", "ejs");
app.set("views", "assets/authorization-server");
app.use(timeout);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/*
Your code here
*/
app.get("/authorize", (req, res) => {
  const clientId = req.query["client_id"];

  if (!clientId || !clients[clientId]) {
    res.status(401).end();
    return;
  }

  const requestScopes = req.query.scope.split(" ");
  const clientScopes = clients[clientId].scopes;

  if (!containsAll(clientScopes, requestScopes)) {
    res.status(401).end();
    return;
  }

  const requestId = randomString();
  requests[requestId] = req.query;

  res.status(200).render("login", {
    client: clients[clientId],
    scope: req.query.scope,
    requestId,
  });
});

app.post("/approve", (req, res) => {
  const { userName, password, requestId } = req.body;

  if (users[userName] !== password) {
    res.status(401).end();
    return;
  }

  const clientReq = requests[requestId];

  if (!clientReq) {
    res.status(401).end();
    return;
  }

  delete requests[requestId];

  const authCode = randomString();
  authorizationCodes[authCode] = {
    userName,
    clientReq,
  };

  const { redirect_uri, state } = clientReq;
  const url = new URL(redirect_uri);
  url.searchParams.append("code", authCode);
  url.searchParams.append("state", state);

  res.redirect(url);
});

app.post("/token", (req, res) => {
  if (!req.headers.authorization) {
    res.status(401).end();
    return;
  }

  const { clientId, clientSecret } = decodeAuthCredentials(
    req.headers.authorization
  );
  const authCode = authorizationCodes[req.body.code];

  if (clients[clientId]?.clientSecret !== clientSecret) {
    res.status(401).end();
    return;
  }

  if (!authCode) {
    res.status(401).end();
    return;
  }

  delete authorizationCodes[req.body.code];

  const token = jwt.sign(
    {
      userName: authCode.userName,
      scope: authCode.clientReq.scope,
    },
    config.privateKey,
    { algorithm: "RS256" }
  );

  res.json({access_token: token, token_type: "Bearer"});
});

const server = app.listen(config.port, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;
});

// for testing purposes

module.exports = { app, requests, authorizationCodes, server };
