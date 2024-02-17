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

export const token = async (
  pid: string,
  options: {
    issuer?: string;
    expirationTime?: string;
    audience?: string | string[];
  } = {},
) =>
  new SignJWT({
    pid,
  })
    .setProtectedHeader({ alg })
    .setAudience(options.audience ?? "idporten_audience")
    .setIssuer(options.issuer ?? "idporten_issuer")
    .sign(await privateKey());

describe("validate token", () => {
  let server: SetupServer;

  beforeAll(() => {
    process.env.IDPORTEN_JWKS_URI = "http://idporten-provider.test/jwks";
    process.env.IDPORTEN_ISSUER = "idporten_issuer";
    process.env.IDPORTEN_AUDIENCE = "idporten_audience";

    server = setupServer(
      http.get(process.env.IDPORTEN_JWKS_URI!, async () =>
        HttpResponse.json({ keys: [await jwk()] }),
      ),
    );
    server.listen();
  });

  afterAll(() => server.close());

  it("succeeds for valid token", async () => {
    expect((await validateToken(await token("a valid token"))).isOk()).toBe(
      true,
    );
  });

  it("fails for empty token", async () => {
    const result = await validateToken("");
    expect(result.isError() && result.getError().message).toBe("empty token");
  });

  it("fails verification when issuer is not idporten", async () => {
    const result = await validateToken(
      await token("a valid token", {
        issuer: "not idporten",
      }),
    );
    expect(result.isError() && result.getError().message).toBe(
      'unexpected "iss" claim value',
    );
  });

  it("fails verification when audience is not idporten", async () => {
    const result = await validateToken(
      await token("a valid token", {
        audience: "not idporten",
      }),
    );
    expect(result.isError() && result.getError().message).toBe(
      'unexpected "aud" claim value',
    );
  });
});
