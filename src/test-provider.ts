import {
  GenerateKeyPairResult,
  SignJWT,
  exportJWK,
  generateKeyPair,
} from "jose";

const alg = "RS256";

const cachedKeyPair = generateKeyPair(alg);
const privateKey = async () => (await cachedKeyPair).privateKey;

export const jwk = async () => exportJWK((await cachedKeyPair).publicKey);
export const jwkPrivate = async () => exportJWK(await privateKey());

export const token = async ({
  pid = "pid",
  audience = "default_audience",
  issuer = "default_issuer",
  algorithm = alg,
}: {
  pid?: string;
  audience?: string;
  issuer?: string;
  algorithm?: string;
} = {}) =>
  new SignJWT({
    pid,
  })
    .setProtectedHeader({ alg: algorithm })
    .setAudience(audience)
    .setIssuer(issuer)
    .sign(await privateKey());
