# Certificate Based Authentication Client With Microsoft Identity Platform

This is a **personal** project developed to provide certificate-based authentication with Microsoft accounts, as an alternative until the Microsoft Entra ID team provides an official solution/SDK. This project functions similarly to how `msal-node` handles other authentication methods such as `acquireTokenByUsernamePassword`.

Before using this project, you may want to explore the [official authentication methods](https://learn.microsoft.com/en-us/javascript/api/@azure/msal-node/clientapplication?view=msal-js-latest) provided by Microsoft to determine if certificate-based authentication is necessary for your needs.

This project implements a Node.js client for authenticating with Microsoft accounts using certificates. For more information on the authentication flow, refer to the [OAuth 2.0 authorization code flow documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow). To understand how to configure certificate-based authentication in your tenant, refer to the [certificate-based authentication guide](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-certificate-based-authentication).

Does this package still work? Please check the status here! (![Livesite test status](https://github.com/test3207/ms_cert_based_authentication/actions/workflows/status-check.yml/badge.svg)
)

## Usage

### Installation

```bash
npm install @test3207/mscba
```

### Example

```javascript
import { CBAClient } from "@test3207/mscba";
import fs from "fs";
const pfxBuffer = fs.readFileSync("path/to/certificate.pfx");

const client = new CBAClient(
  "username@exampledomain.com", // UPN
  "00000000-0000-0000-0000-000000000000", // Client ID
  pfxBuffer, // Buffer containing the PFX certificate. Notice that private key is required.
  ["https://graph.microsoft.com/User.Read"], // Scopes of resources to accessm. This is an example to access graph API
  "00000000-0000-0000-0000-000000000000" // Tenant ID, required if the client app is not multi-tenant
);

client.getAccessTokenAsync().then((accessTokenResponse) => {
  console.log(accessTokenResponse.expires_in); // around an hour in seconds
  console.log(accessTokenResponse.access_token); // now you can use it for your requests
});

```

## Others

This project is a temporary solution, so I have only implemented the straightforward "happy path". Converting error information into readable content is quite challenging, given that many things could potentially go awry, and the error messages are in HTML format rather than JSON. You are welcome to add logs yourself for debugging purposes. If the Entra team does not provide a solution within a year, I will consider adding the necessary error handling myself. Alternatively, you are also welcome to contribute; PRs are appreciated!
