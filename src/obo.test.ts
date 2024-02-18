import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { HttpResponse, http } from "msw";
import { SetupServer, setupServer } from "msw/node";
import { requestOboToken } from "./obo";
import { jwk, jwkPrivate, token } from "./test-provider";

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

          if (
            grant_type !== "urn:ietf:params:oauth:grant-type:token-exchange"
          ) {
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
            client_assert_token.payload.nbf !== Math.floor(Date.now() / 1000)
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

      expect(result.isError() && result.getError().message).toBe(false);

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
        "error-audience",
      );
    });
  });
});
