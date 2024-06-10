import axios, { AxiosError, AxiosInstance } from "axios";
import https from "https";
import { load } from "cheerio";
import { randomUUID } from "crypto";
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // for local backend testing please uncomment this line

type AuthConfig = {
  ctx: string;
  flowToken: string;
  canary?: string;
  flowToken2: string;
};

type AccessTokenResponse = {
  token_type: string;
  scope: string;
  expires_in: number;
  ext_expires_in: number;
  access_token: string;
};

export class CBAClient {
  private readonly redirect_uri =
    "https://login.microsoftonline.com/common/oauth2/nativeclient";
  private authority: string;
  private httpClient: AxiosInstance;
  constructor(
    private username: string,
    private clientId: string,
    private pfxBuffer: Buffer,
    private scopes: string[],
    private tenantId: string = "common"
  ) {
    this.authority = `https://login.microsoftonline.com/${this.tenantId}`;
    this.httpClient = axios.create({
      withCredentials: true,
      baseURL: this.authority,
    });
  }
  public async getAccessTokenAsync(): Promise<AccessTokenResponse> {
    const pkceChallenge = await import("pkce-challenge");
    const { code_verifier, code_challenge } = await pkceChallenge.default();
    const config = await this.getLoginContextAsync(code_challenge);
    const certAuthUrl = await this.getCertAuthUrlAsync(config);
    const certAuthParameters = await this.getCertAuthParametersAsync(
      certAuthUrl,
      config
    );
    const code = await this.loginAsync(certAuthParameters);
    const accessTokenResponse = await this.getAccessTokenWithCodeAsync(
      code,
      code_verifier
    );
    return accessTokenResponse;
  }

  private getLoginContextAsync = async (chanllengeCode: string) => {
    const loginUrl =
      `/oauth2/v2.0/authorize` +
      `?client_id=${this.clientId}` +
      `&scope=${encodeURIComponent(this.scopes.join(" "))}` +
      `&redirect_uri=${encodeURIComponent(this.redirect_uri)}` +
      `&response_mode=fragment` +
      `&response_type=code` +
      `&code_challenge=${chanllengeCode}` +
      `&code_challenge_method=S256` +
      `&nonce=${randomUUID()}`;
    // console.log(`login context url: ${this.authority + loginUrl}`);
    const response = await this.httpClient.get(loginUrl);
    const text = response.data;
    const config = this.parseAuthResponse(text);
    return {
      ctx: config.sCtx,
      flowToken: config.sFT,
      canary: config.canary,
      flowToken2: "",
    };
  };

  private getCertAuthUrlAsync = async (config: AuthConfig) => {
    const url = `/GetCredentialType?mkt=en-US`;
    const response = await this.httpClient.post(url, {
      username: this.username,
      flowToken: config.flowToken,
      originalRequest: config.ctx,
    });
    const responseJson = response.data;
    config.flowToken2 = responseJson.FlowToken;
    // console.log(`getting certauth url`);
    // console.log(responseJson);
    return responseJson.Credentials.CertAuthParams.CertAuthUrl;
  };

  private getCertAuthParametersAsync = async (
    certAuthUrl: string,
    config: AuthConfig
  ) => {
    const response = await this.httpClient.post(
      certAuthUrl,
      {
        ctx: config.ctx,
        flowToken: config.flowToken2,
      },
      {
        headers: {
          cacheControl: "no-cache no-store",
          connection: "keep-alive",
          "content-type": "application/x-www-form-urlencoded",
        },
        httpsAgent: new https.Agent({
          pfx: this.pfxBuffer,
        }),
      }
    );
    const dom = load(response.data);
    const param = {};
    dom("input").each((_, elem) => {
      param[elem.attribs.name] = elem.attribs.value;
    });
    return param;
  };

  // get string from html between //<![CDATA[ and //]]> as basicString
  // get substring of basicString from "$Config=" to the end except the fixed ending ";" as jsonString
  private parseAuthResponse = (rawResponse: string) => {
    const start = "//<![CDATA[";
    const end = "//]]>";
    const startIndex = rawResponse.indexOf(start);
    const endIndex = rawResponse.indexOf(end);
    const basicString = rawResponse.substring(
      startIndex + start.length,
      endIndex
    );
    const configStart = "$Config=";
    const configIndex = basicString.indexOf(configStart);
    const jsonString = basicString.substring(
      configIndex + configStart.length,
      basicString.length - 2
    );
    const config = JSON.parse(jsonString);
    return config;
  };

  private loginAsync = async (loginParam: {}) => {
    try {
      const res = await this.httpClient.post(
        "/login",
        {
          ...loginParam,
        },
        {
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache no-store",
            connection: "keep-alive",
          },
          maxRedirects: 0,
        }
      );
      // console.log(res);
    } catch (error) {
      if (!(error instanceof AxiosError)) {
        throw error;
      }
      if (error.response?.status === 302) {
        const location = error.response.headers.location;
        const paramsString = location.split("#")[1].split("&");
        const params = {};
        paramsString.forEach((param) => {
          const [key, value] = param.split("=");
          params[key] = value;
        });
        // console.log(params["code"]);
        return params["code"];
      }
    }
    throw new Error("login failed");
  };

  private async getAccessTokenWithCodeAsync(
    code: string,
    code_verifier: string
  ): Promise<AccessTokenResponse> {
    // console.log("getting access token");
    try {
      const response = await this.httpClient.post(
        "/oauth2/v2.0/token",
        {
          client_id: this.clientId,
          scope: this.scopes.join(" "),
          code_verifier,
          code,
          redirect_uri: this.redirect_uri,
          grant_type: "authorization_code",
        },
        {
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache no-store",
            connection: "keep-alive",
          },
        }
      );
      // console.log("access token response:");
      // console.log(response.data);
      return response.data;
    } catch (e) {
      // console.log(e);
      throw e;
    }
  }
}
