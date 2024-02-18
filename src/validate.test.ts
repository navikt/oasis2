import { HttpResponse, http } from "msw";
import { SetupServer, setupServer } from "msw/node";
import {
  validateToken,
  validateIdportenToken,
  validateAzureToken,
  validateTokenxToken,
} from "./validate";
import { jwk, token } from "./test-provider";

describe("validate token", () => {
  afterEach(() => {
    delete process.env.IDPORTEN_ISSUER;
    delete process.env.AZURE_OPENID_CONFIG_ISSUER;
    delete process.env.TOKEN_X_ISSUER;
  });

  it("fails for empty token", async () => {
    const result = await validateToken("");
    expect(result.isError() && result.getError().message).toBe("empty token");
  });

  it("fails with no identity provider", async () => {
    const result = await validateToken(await token());
    expect(result.isError() && result.getError().message).toBe(
      "no identity provider",
    );
  });

  it("fails with multiple identity providers", async () => {
    process.env.IDPORTEN_ISSUER = "idporten_issuer";
    process.env.AZURE_OPENID_CONFIG_ISSUER = "azure_issuer";

    const result = await validateToken(await token());
    expect(result.isError() && result.getError().message).toBe(
      "multiple identity providers",
    );
  });

  it("selects idporten", async () => {
    process.env.IDPORTEN_JWKS_URI = "http://idporten-provider.test/jwks";
    process.env.IDPORTEN_ISSUER = "idporten_issuer";

    const result = await validateToken(await token());
    expect(result.isError() && result.getError().message).toBe(
      "getaddrinfo ENOTFOUND idporten-provider.test",
    );
  });

  it("selects azure", async () => {
    process.env.AZURE_OPENID_CONFIG_JWKS_URI =
      "http://azure-provider.test/jwks";
    process.env.AZURE_OPENID_CONFIG_ISSUER = "azure_issuer";

    const result = await validateToken(await token());
    expect(result.isError() && result.getError().message).toBe(
      "getaddrinfo ENOTFOUND azure-provider.test",
    );
  });

  it("doesn't select tokenx", async () => {
    process.env.TOKEN_X_JWKS_URI = "http://tokenx-provider.test/jwks";
    process.env.TOKEN_X_ISSUER = "tokenx_issuer";

    const result = await validateToken(await token());
    expect(result.isError() && result.getError().message).toBe(
      "no identity provider",
    );
  });
});

describe("validate idporten token", () => {
  let server: SetupServer;

  beforeAll(() => {
    process.env.IDPORTEN_JWKS_URI = "http://idporten-provider.test/jwks";
    process.env.IDPORTEN_ISSUER = "idporten_issuer";
    process.env.IDPORTEN_AUDIENCE = "idporten_audience";

    server = setupServer(
      http.get(process.env.IDPORTEN_JWKS_URI, async () =>
        HttpResponse.json({ keys: [await jwk()] }),
      ),
    );
    server.listen();
  });

  afterAll(() => server.close());

  it("succeeds for valid token", async () => {
    expect(
      (
        await validateIdportenToken(
          await token({
            audience: "idporten_audience",
            issuer: "idporten_issuer",
          }),
        )
      ).isOk(),
    ).toBe(true);
  });

  it("fails verification when issuer is not idporten", async () => {
    const result = await validateIdportenToken(
      await token({
        audience: "idporten_audience",
        issuer: "not idporten",
      }),
    );
    expect(result.isError() && result.getError().message).toBe(
      'unexpected "iss" claim value',
    );
  });

  it("fails verification when audience is not idporten", async () => {
    const result = await validateIdportenToken(
      await token({
        audience: "not idporten",
        issuer: "idporten_issuer",
      }),
    );
    expect(result.isError() && result.getError().message).toBe(
      'unexpected "aud" claim value',
    );
  });

  it("fails verification when alg is not RS256", async () => {
    const result = await validateIdportenToken(
      await token({
        audience: "idporten_audience",
        issuer: "idporten_issuer",
        algorithm: "PS256",
      }),
    );
    expect(result.isError() && result.getError().message).toBe(
      '"alg" (Algorithm) Header Parameter value not allowed',
    );
  });
});

describe("validate azure token", () => {
  let server: SetupServer;

  beforeAll(() => {
    process.env.AZURE_OPENID_CONFIG_JWKS_URI =
      "http://azure-provider.test/jwks";
    process.env.AZURE_OPENID_CONFIG_ISSUER = "azure_issuer";
    process.env.AZURE_APP_CLIENT_ID = "azure_audience";

    server = setupServer(
      http.get(process.env.AZURE_OPENID_CONFIG_JWKS_URI, async () =>
        HttpResponse.json({ keys: [await jwk()] }),
      ),
    );
    server.listen();
  });

  afterAll(() => server.close());

  it("succeeds for valid token", async () => {
    expect(
      (
        await validateAzureToken(
          await token({
            audience: "azure_audience",
            issuer: "azure_issuer",
          }),
        )
      ).isOk(),
    ).toBe(true);
  });
});

describe("validate tokenx token", () => {
  let server: SetupServer;

  beforeAll(() => {
    process.env.TOKEN_X_JWKS_URI = "http://tokenx-provider.test/jwks";
    process.env.TOKEN_X_ISSUER = "tokenx_issuer";
    process.env.TOKEN_X_CLIENT_ID = "tokenx_audience";

    server = setupServer(
      http.get(process.env.TOKEN_X_JWKS_URI, async () =>
        HttpResponse.json({ keys: [await jwk()] }),
      ),
    );
    server.listen();
  });

  afterAll(() => server.close());

  it("succeeds for valid token", async () => {
    expect(
      (
        await validateTokenxToken(
          await token({
            audience: "tokenx_audience",
            issuer: "tokenx_issuer",
          }),
        )
      ).isOk(),
    ).toBe(true);
  });
});
