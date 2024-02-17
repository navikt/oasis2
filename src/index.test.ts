import {
  GenerateKeyPairResult,
  SignJWT,
  exportJWK,
  generateKeyPair,
} from "jose";
import { HttpResponse, http } from "msw";
import { SetupServer, setupServer } from "msw/node";
import { validateToken } from ".";

const alg = "RS256";

const cachedKeyPair: Promise<GenerateKeyPairResult> = generateKeyPair(alg);
const privateKey = async () => (await cachedKeyPair).privateKey;

export const jwk = async () => exportJWK((await cachedKeyPair).publicKey);
export const jwkPrivate = async () => exportJWK(await privateKey());

export const token = async ({
  audience,
  issuer,
}: {
  audience: string | string[];
  issuer: string;
}) =>
  new SignJWT({
    pid: "pid",
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
