import assert from "assert";
import { CBAClient } from "../src";
import dotenv from "dotenv";
dotenv.config();

const username = process.env.AADUSERNAME || "";
const clientId = process.env.CLIENT_ID || "";
const pfxBuffer = Buffer.from(process.env.BASE64_CERT || "", "base64");
const tenantId = process.env.TENANT_ID || "";

const client = new CBAClient(
  username,
  clientId,
  pfxBuffer,
  ["https://graph.microsoft.com/.default"],
  tenantId
);

const run = async () => {
  const accessTokenResponse = await client.getAccessTokenAsync();
  const response = await fetch("https://graph.microsoft.com/v1.0/me", {
    headers: {
      Authorization: `Bearer ${accessTokenResponse.access_token}`,
    },
  });
  const data = await response.json();
  assert.equal(data.userPrincipalName, username);
};

run();
