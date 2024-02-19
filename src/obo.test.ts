import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { HttpResponse, http } from "msw";
import { SetupServer, setupServer } from "msw/node";
import {
  requestTokenxOboToken,
  requestAzureOboToken,
  requestOboToken,
} from "./obo";
import { jwk, jwkPrivate, token } from "./test-provider";

describe("request obo token", () => {
  afterEach(() => {
    delete process.env.TOKEN_X_ISSUER;
    delete process.env.AZURE_OPENID_CONFIG_ISSUER;
  });

  it("fails for empty token", async () => {
    const result = await requestOboToken("", "");
    expect(result.isError() && result.getError().message).toBe("empty token");
  });

  it("fails for empty audience", async () => {
    const result = await requestOboToken(await token(), "");
    expect(result.isError() && result.getError().message).toBe(
      "empty audience",
    );
  });

  it("fails with no identity provider", async () => {
    const result = await requestOboToken(await token(), "audience");
    expect(result.isError() && result.getError().message).toBe(
      "no identity provider",
    );
  });

  it("fails with multiple identity providers", async () => {
    process.env.TOKEN_X_ISSUER = "tokenx_issuer";
    process.env.AZURE_OPENID_CONFIG_ISSUER = "azure_issuer";

    const result = await requestOboToken(await token(), "audience");
    expect(result.isError() && result.getError().message).toBe(
      "multiple identity providers",
    );
  });

  it("selects tokenx", async () => {
    process.env.TOKEN_X_ISSUER = "tokenx_issuer";
    process.env.TOKEN_X_TOKEN_ENDPOINT = "http://tokenx.test/token";
    process.env.TOKEN_X_PRIVATE_JWK = JSON.stringify(await jwkPrivate());
    process.env.TOKEN_X_CLIENT_ID = "token_x_client_id";

    const result = await requestOboToken(await token(), "audience");
    expect(result.isError() && result.getError().message).toBe(
      "getaddrinfo ENOTFOUND tokenx.test",
    );
  });

  it("selects azure", async () => {
    process.env.AZURE_OPENID_CONFIG_ISSUER = "azuer_issuer";
    process.env.AZURE_OPENID_CONFIG_TOKEN_ENDPOINT = "http://azure.test/token";
    process.env.AZURE_APP_CLIENT_ID = "azure_client_id";
    process.env.AZURE_APP_JWK = JSON.stringify(await jwkPrivate());

    const result = await requestOboToken(await token(), "audience");
    expect(result.isError() && result.getError().message).toBe(
      "getaddrinfo ENOTFOUND azure.test",
    );
  });
});

describe("request tokenX obo token", () => {
  let server: SetupServer;

  beforeAll(async () => {
    process.env.TOKEN_X_CLIENT_ID = "token_x_client_id";
    process.env.TOKEN_X_PRIVATE_JWK = JSON.stringify(await jwkPrivate());
    process.env.TOKEN_X_WELL_KNOWN_URL = "http://tokenx-provider.test/jwks";
    process.env.TOKEN_X_ISSUER = "tokenx_issuer";
    process.env.TOKEN_X_TOKEN_ENDPOINT = "http://tokenx.test/token";
    process.env.TOKEN_X_JWKS_URI = "http://tokenx-provider.test/token";

    const token_endpoint = "http://tokenx.test/token";

    server = setupServer(
      http.get(process.env.TOKEN_X_JWKS_URI, async () =>
        HttpResponse.json({ keys: [await jwk()] }),
      ),
      http.post(token_endpoint, async ({ request }) => {
        const {
          audience,
          subject_token,
          grant_type,
          client_assertion_type,
          subject_token_type,
          client_assertion,
        } = Object.fromEntries(new URLSearchParams(await request.text()));

        const client_assert_token = await jwtVerify(
          client_assertion,
          createRemoteJWKSet(new URL(process.env.TOKEN_X_JWKS_URI!)),
          {
            subject: "token_x_client_id",
            issuer: "token_x_client_id",
            audience: "http://tokenx.test/token",
            algorithms: ["RS256"],
          },
        );

        if (grant_type !== "urn:ietf:params:oauth:grant-type:token-exchange") {
          throw Error("wrong grant_type");
        } else if (
          client_assertion_type !==
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) {
          throw Error("wrong client_assertion_type");
        } else if (
          subject_token_type !== "urn:ietf:params:oauth:token-type:jwt"
        ) {
          throw Error("wrong subject_token_type");
        } else if (
          Math.abs(
            client_assert_token.payload.nbf! - Math.floor(Date.now() / 1000),
          ) > 10
        ) {
          throw Error("wrong client_assert_token.payload.nbf");
        } else if (!client_assert_token.payload.jti) {
          throw Error("missing client_assert_token.payload.jti");
        } else if (
          client_assert_token.payload.exp! - Math.floor(Date.now() / 1000) >
          120
        ) {
          throw Error("client_assert_token.payload.exp too large");
        } else if (audience === "error-audience") {
          throw Error("error-audience");
        } else if (audience === "timed-out") {
          return HttpResponse.json({
            access_token: await token({
              pid: subject_token,
              issuer: "urn:tokenx:dings",
              audience,
              exp: Math.round(Date.now() / 1000) - 10,
            }),
          });
        } else {
          return HttpResponse.json({
            access_token: await token({
              pid: subject_token,
              issuer: "urn:tokenx:dings",
              audience,
            }),
          });
        }
      }),
    );
    server.listen();
  });
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  it("returns token when exchanges succeeds", async () => {
    const jwt = await token({
      audience: "idporten_audience",
      issuer: "idporten_issuer",
    });
    const result = await requestTokenxOboToken(jwt, "audience");

    expect(result.isOk() && decodeJwt(result.get()).iss).toBe(
      "urn:tokenx:dings",
    );
    expect(result.isOk() && decodeJwt(result.get()).pid).toBe(jwt);
    expect(result.isOk() && decodeJwt(result.get()).nbf).toBe(undefined);
  });

  it("returns valid token", async () => {
    const result = await requestTokenxOboToken(
      await token({
        audience: "idporten_audience",
        issuer: "idporten_issuer",
      }),
      "audience",
    );

    expect(result.isError() && result.getError().message).toBe(false);

    if (result.isOk()) {
      expect(
        (() =>
          jwtVerify(
            result.get(),
            createRemoteJWKSet(new URL(process.env.TOKEN_X_JWKS_URI!)),
            {
              issuer: "urn:tokenx:dings",
              audience: "audience",
            },
          ))(),
      ).resolves.not.toThrow();
    }
  });

  it("returns error when exchange fails", async () => {
    const result = await requestTokenxOboToken(
      await token({
        audience: "idporten_audience",
        issuer: "idporten_issuer",
      }),
      "error-audience",
    );
    expect(result.isError() && result.getError().message).toBe(
      "error-audience",
    );
  });

  it("returns cached token", async () => {
    const clientToken = await token({
      audience: "idporten_audience",
      issuer: "idporten_issuer",
    });
    const result = await requestTokenxOboToken(clientToken, "audience");
    const result2 = await requestTokenxOboToken(clientToken, "audience");

    expect(result.isError()).toBe(false);

    if (result.isOk() && result2.isOk()) {
      const token1 = decodeJwt(result.get());
      const token2 = decodeJwt(result2.get());

      expect(token1.jti).toBe(token2.jti);
    }
  });

  it("cache times out", async () => {
    const clientToken = await token({
      audience: "idporten_audience",
      issuer: "idporten_issuer",
    });
    const result = await requestTokenxOboToken(clientToken, "timed-out");
    const result2 = await requestTokenxOboToken(clientToken, "timed-out");

    expect(result.isError()).toBe(false);
    expect(result2.isError()).toBe(false);

    if (result.isOk() && result2.isOk()) {
      const token1 = decodeJwt(result.get());
      const token2 = decodeJwt(result2.get());

      expect(token1.jti).not.toBe(token2.jti);
    }
  });
});

describe("request azure obo token", () => {
  let server: SetupServer;

  beforeAll(async () => {
    process.env.AZURE_APP_CLIENT_ID = "azure_client_id";
    process.env.AZURE_APP_CLIENT_SECRET = "azure_client_secret";
    process.env.AZURE_APP_JWK = JSON.stringify(await jwkPrivate());
    process.env.AZURE_OPENID_CONFIG_ISSUER = "azure_issuer";
    process.env.AZURE_OPENID_CONFIG_TOKEN_ENDPOINT = "http://azure.test/token";
    process.env.AZURE_OPENID_CONFIG_JWKS_URI =
      "http://tokenx-provider.test/jwks";

    const token_endpoint = "http://azure.test/token";

    server = setupServer(
      http.get(process.env.AZURE_OPENID_CONFIG_JWKS_URI, async () =>
        HttpResponse.json({ keys: [await jwk()] }),
      ),
      http.post(token_endpoint, async ({ request }) => {
        const {
          scope,
          assertion,
          client_assertion,
          requested_token_use,
          grant_type,
          client_assertion_type,
          client_id,
        } = Object.fromEntries(new URLSearchParams(await request.text()));

        const client_assert_token = await jwtVerify(
          client_assertion,
          createRemoteJWKSet(
            new URL(process.env.AZURE_OPENID_CONFIG_JWKS_URI!),
          ),
          {
            subject: "azure_client_id",
            issuer: "azure_client_id",
            audience: "http://azure.test/token",
            algorithms: ["RS256"],
          },
        );

        if (grant_type !== "urn:ietf:params:oauth:grant-type:jwt-bearer") {
          throw Error("wrong grant_type");
        } else if (requested_token_use !== "on_behalf_of") {
          throw Error("wrong requested_token_use");
        } else if (client_id !== "azure_client_id") {
          throw Error("wrong client_id");
        } else if (
          client_assertion_type !==
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) {
          throw Error("wrong client_assertion_type");
        } else if (
          Math.abs(
            client_assert_token.payload.nbf! - Math.floor(Date.now() / 1000),
          ) > 10
        ) {
          throw Error("wrong client_assert_token.payload.nbf");
        } else if (!client_assert_token.payload.jti) {
          throw Error("missing client_assert_token.payload.jti");
        } else if (
          client_assert_token.payload.exp! - Math.floor(Date.now() / 1000) >
          120
        ) {
          throw Error("client_assert_token.payload.exp too large");
        } else if (scope === "error-audience") {
          throw Error("error-audience");
        } else {
          return HttpResponse.json({
            access_token: await token({
              pid: assertion,
              issuer: "urn:azure:dings",
              audience: scope,
            }),
          });
        }
      }),
    );
    server.listen();
  });
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  it("returns token when exchanges succeeds", async () => {
    const jwt = await token({
      audience: "azure_audience",
      issuer: "azure_issuer",
    });
    const result = await requestAzureOboToken(jwt, "audience");

    expect(result.isOk() && decodeJwt(result.get()).iss).toBe(
      "urn:azure:dings",
    );
    expect(result.isOk() && decodeJwt(result.get()).pid).toBe(jwt);
    expect(result.isOk() && decodeJwt(result.get()).nbf).toBe(undefined);
  });

  it("returns valid token", async () => {
    const result = await requestAzureOboToken(
      await token({
        audience: "azure_audience",
        issuer: "azure_issuer",
      }),
      "audience",
    );

    expect(result.isError() && result.getError().message).toBe(false);

    if (result.isOk()) {
      expect(
        (() =>
          jwtVerify(
            result.get(),
            createRemoteJWKSet(
              new URL(process.env.AZURE_OPENID_CONFIG_JWKS_URI!),
            ),
            {
              issuer: "urn:azure:dings",
              audience: "audience",
            },
          ))(),
      ).resolves.not.toThrow();
    }
  });

  it("returns error when exchange fails", async () => {
    const result = await requestAzureOboToken(
      await token({
        audience: "azure_audience",
        issuer: "azure_issuer",
      }),
      "error-audience",
    );
    expect(result.isError() && result.getError().message).toBe(
      "error-audience",
    );
  });
});
