import express from "express";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";

const app = express();
app.use(cors());
app.use(express.json());

// ✅ THIS LINE FIXES "Cannot GET /"
app.use(express.static("public"));

const users = {};

const rpID = "fingerprint-auth-adz8.onrender.com";
const origin = "https://boisterous-brioche-f3d218.netlify.app";


/* REGISTER OPTIONS */
app.post("/register/options", (req, res) => {
  const { username } = req.body;

  const options = generateRegistrationOptions({
    rpName: "WebAuthn Demo",
    rpID,
    userID: username,
    userName: username,
    attestationType: "none",
    authenticatorSelection: {
      userVerification: "required"
    }
  });

  users[username] = { challenge: options.challenge };
  res.json(options);
});

/* REGISTER VERIFY */
app.post("/register/verify", async (req, res) => {
  const { username, attestation } = req.body;

  const verification = await verifyRegistrationResponse({
    response: attestation,
    expectedChallenge: users[username].challenge,
    expectedOrigin: origin,
    expectedRPID: rpID
  });

  users[username].credential = verification.registrationInfo;
  res.json({ success: true });
});

/* LOGIN OPTIONS */
app.post("/login/options", (req, res) => {
  const { username } = req.body;
  const user = users[username];

  const options = generateAuthenticationOptions({
    rpID,
    allowCredentials: [{
      id: user.credential.credentialID,
      type: "public-key"
    }],
    userVerification: "required"
  });

  user.challenge = options.challenge;
  res.json(options);
});

/* LOGIN VERIFY */
app.post("/login/verify", async (req, res) => {
  const { username, assertion } = req.body;
  const user = users[username];

  const verification = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: user.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: user.credential
  });

  res.json({ success: verification.verified });
});

app.listen(3000, () => {
  console.log("✅ Server running at http://localhost:3000");
});
