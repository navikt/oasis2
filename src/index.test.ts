import {
  GenerateKeyPairResult,
  SignJWT,
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  jwtVerify,
} from "jose";
import { HttpResponse, http } from "msw";
import { SetupServer, setupServer } from "msw/node";
import { validateToken, requestOboToken } from ".";

const alg = "RS256";

const cachedKeyPair: Promise<GenerateKeyPairResult> = generateKeyPair(alg);
const privateKey = async () => (await cachedKeyPair).privateKey;

export const jwk = async () => exportJWK((await cachedKeyPair).publicKey);
export const jwkPrivate = async () => exportJWK(await privateKey());

export const token = async ({
  pid,
  audience,
  issuer,
}: {
  pid?: string;
  audience: string | string[];
  issuer: string;
}) =>
  new SignJWT({
    pid: pid ?? "pid",
  })
    .setProtectedHeader({ alg })
    .setAudience(audience)
    .setIssuer(issuer)
    .sign(await privateKey());

describe("validate token", () => {
  it("fails for empty token", async () => {
    const result = await validateToken("");
    expect(result.isError() && result.getError().message).toBe("empty token");
  });

  it("fails with no identity provider", async () => {
    const result = await validateToken(
      await token({
        audience: "idporten_audience",
        issuer: "idporten_issuer",
      }),
    );
    expect(result.isError() && result.getError().message).toBe(
      "no identity provider",
    );
  });

  describe("idporten", () => {
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
          await validateToken(
            await token({
              audience: "idporten_audience",
              issuer: "idporten_issuer",
            }),
          )
        ).isOk(),
      ).toBe(true);
    });

    it("fails verification when issuer is not idporten", async () => {
      const result = await validateToken(
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
      const result = await validateToken(
        await token({
          audience: "not idporten",
          issuer: "idporten_issuer",
        }),
      );
      expect(result.isError() && result.getError().message).toBe(
        'unexpected "aud" claim value',
      );
    });
  });

  describe("azure", () => {
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
          await validateToken(
            await token({
              audience: "azure_audience",
              issuer: "azure_issuer",
            }),
          )
        ).isOk(),
      ).toBe(true);
    });

    it("fails verification when issuer is not azure", async () => {
      const result = await validateToken(
        await token({
          audience: "azure_audience",
          issuer: "not azure",
        }),
      );
      expect(result.isError() && result.getError().message).toBe(
        'unexpected "iss" claim value',
      );
    });

    it("fails verification when audience is not azure", async () => {
      const result = await validateToken(
        await token({
          audience: "not azure",
          issuer: "azure_issuer",
        }),
      );
      expect(result.isError() && result.getError().message).toBe(
        'unexpected "aud" claim value',
      );
    });
  });
});

describe("request obo token", () => {
  describe("tokenX", () => {
    let server: SetupServer;

    beforeAll(async () => {
      process.env.TOKEN_X_TOKEN_ENDPOINT = "http://tokenx.test/token";
      process.env.TOKEN_X_CLIENT_ID = "token_x_client_id";
      process.env.TOKEN_X_PRIVATE_JWK = JSON.stringify(await jwkPrivate());
      process.env.TOKEN_X_WELL_KNOWN_URL = "http://azure-provider.test/jwks";

      server = setupServer(
        http.get(
          `${process.env.TOKEN_X_WELL_KNOWN_URL}/.well-known/openid-configuration`,
          async () =>
            HttpResponse.json({
              issuer: process.env.TOKEN_X_ISSUER,
              token_endpoint: process.env.TOKEN_X_TOKEN_ENDPOINT,
              token_endpoint_auth_signing_alg_values_supported: ["RS256"],
            }),
        ),
        http.get(process.env.TOKEN_X_WELL_KNOWN_URL, async () =>
          HttpResponse.json({ keys: [await jwk()] }),
        ),
        http.post(process.env.TOKEN_X_TOKEN_ENDPOINT, async ({ request }) => {
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
            createRemoteJWKSet(new URL(process.env.TOKEN_X_WELL_KNOWN_URL!)),
            {
              subject: "token_x_client_id",
              issuer: "token_x_client_id",
              audience: "http://tokenx.test/token",
              algorithms: ["RS256"],
            },
          );

          return HttpResponse.json(
            audience === "error-audience" ||
              grant_type !==
                "urn:ietf:params:oauth:grant-type:token-exchange" ||
              client_assertion_type !==
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
              subject_token_type !== "urn:ietf:params:oauth:token-type:jwt" ||
              client_assert_token.payload.nbf !==
                Math.floor(Date.now() / 1000) ||
              !client_assert_token.payload.jti ||
              client_assert_token.payload.exp! - Math.floor(Date.now() / 1000) >
                120
              ? {}
              : {
                  access_token: await token({
                    pid: subject_token,
                    issuer: "urn:tokenx:dings",
                    audience,
                  }),
                },
          );
        }),
      );
      server.listen();
    });

    afterAll(() => server.close());

    it("returns token when exchanges succeeds", async () => {
      const jwt = await token({
        audience: "idporten_audience",
        issuer: "idporten_issuer",
      });
      const result = await requestOboToken(jwt, "audience");

      expect(result.isOk() && decodeJwt(result.get()).iss).toBe(
        "urn:tokenx:dings",
      );
      expect(result.isOk() && decodeJwt(result.get()).pid).toBe(jwt);
      expect(result.isOk() && decodeJwt(result.get()).nbf).toBe(undefined);
    });

    it("returns valid token", async () => {
      const result = await requestOboToken(
        await token({
          audience: "idporten_audience",
          issuer: "idporten_issuer",
        }),
        "audience",
      );

      if (result.isError()) {
        console.error("error", result.getError().message);
      }

      if (result.isOk()) {
        expect(
          (() =>
            jwtVerify(
              result.get(),
              createRemoteJWKSet(new URL(process.env.TOKEN_X_WELL_KNOWN_URL!)),
              {
                issuer: "urn:tokenx:dings",
                audience: "audience",
              },
            ))(),
        ).resolves.not.toThrow();
      }
    });

    it("returns error when exchange fails", async () => {
      const result = await requestOboToken(
        await token({
          audience: "idporten_audience",
          issuer: "idporten_issuer",
        }),
        "error-audience",
      );
      expect(result.isError() && result.getError().message).toBe(
        "TokenSet does not contain an access_token",
      );
    });
  });
});
