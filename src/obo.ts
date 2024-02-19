import { GrantBody, Issuer } from "openid-client";
import { createHash } from "node:crypto";
import { Result } from "./result";
import { JWTPayload, decodeJwt } from "jose";
import SieveCache from "./cache";

function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

const grantOboToken = async ({
  issuer,
  token_endpoint,
  client_id,
  jwk,
  grant_body,
}: {
  issuer: string;
  token_endpoint: string;
  client_id: string;
  jwk: string;
  grant_body: GrantBody;
}): Promise<Result<string, Error>> => {
  try {
    const { access_token } = await new new Issuer({
      issuer,
      token_endpoint,
      token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    }).Client(
      { client_id, token_endpoint_auth_method: "private_key_jwt" },
      { keys: [JSON.parse(jwk)] },
    ).grant(grant_body, {
      clientAssertionPayload: { nbf: Math.floor(Date.now() / 1000) },
    });
    return access_token
      ? Result.Ok(access_token)
      : Result.Error(Error("TokenSet does not contain an access_token"));
  } catch (e) {
    return Result.Error(e);
  }
};

export const requestAzureOboToken = async (assertion: string, scope: string) =>
  grantOboToken({
    issuer: process.env.AZURE_OPENID_CONFIG_ISSUER!,
    token_endpoint: process.env.AZURE_OPENID_CONFIG_TOKEN_ENDPOINT!,
    client_id: process.env.AZURE_APP_CLIENT_ID!,
    jwk: process.env.AZURE_APP_JWK!,
    grant_body: {
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
      scope,
      requested_token_use: "on_behalf_of",
    },
  });

let cache: SieveCache;

const averageJwtSize = 1024; // bytes
const maxCacheSize = 128 /* MB */ * 1024 /* KB */ * 1024; /* bytes */
const maxCacheCapacity = Math.floor(maxCacheSize / averageJwtSize);

function getCache() {
  if (cache == undefined) {
    cache = new SieveCache(maxCacheCapacity);
  }
  return cache;
}

function getNow(timestamp: number) {
  const now = Date.now();
  if (Math.abs(now - timestamp) < Math.abs(now - timestamp * 1000)) {
    return now;
  } else {
    return Math.round(now / 1000);
  }
}

export function secondsUntil(timestamp: number): number {
  if (timestamp <= 0) return 0;
  const now = getNow(timestamp);
  if (timestamp <= now) return 0;
  return Math.round(timestamp - now);
}

const NO_CACHE_TTL = 0;

function getSecondsToExpire(payload: JWTPayload) {
  return Math.max(
    payload.exp ? secondsUntil(payload.exp) : NO_CACHE_TTL,
    NO_CACHE_TTL,
  );
}

export const requestTokenxOboToken = async (
  subject_token: string,
  audience: string,
) => {
  const cache = getCache();

  const key = sha256(subject_token + audience);
  const cachedToken = cache.get(key);
  if (cachedToken) {
    const now = Math.round(Date.now() / 1000);
    if (decodeJwt(cachedToken).exp! > now - 5) {
      return Result.Ok<string, Error>(cachedToken);
    }
  }

  const result = await grantOboToken({
    issuer: process.env.TOKEN_X_ISSUER!,
    token_endpoint: process.env.TOKEN_X_TOKEN_ENDPOINT!,
    client_id: process.env.TOKEN_X_CLIENT_ID!,
    jwk: process.env.TOKEN_X_PRIVATE_JWK!,
    grant_body: {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
      audience,
      subject_token,
    },
  });

  if (result.isOk()) {
    const token = result.get();
    const ttl = getSecondsToExpire(decodeJwt(token));
    if (ttl > 0) {
      cache.set(key, token, ttl);
    }
  }
  return result;
};

export const requestOboToken = async (
  token: string,
  audience: string,
): Promise<Result<string, Error>> => {
  if (!token) {
    return Result.Error(new Error("empty token"));
  }
  if (!audience) {
    return Result.Error(new Error("empty audience"));
  }

  const tokenx: boolean = !!process.env.TOKEN_X_ISSUER;
  const azure: boolean = !!process.env.AZURE_OPENID_CONFIG_ISSUER;

  if (tokenx && azure) {
    return Result.Error(new Error("multiple identity providers"));
  } else if (tokenx) {
    return requestTokenxOboToken(token, audience);
  } else if (azure) {
    return requestAzureOboToken(token, audience);
  } else {
    return Result.Error(new Error("no identity provider"));
  }
};
