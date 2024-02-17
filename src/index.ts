import { createRemoteJWKSet, jwtVerify } from "jose";
import { Client, GrantBody, GrantExtras, Issuer, errors } from "openid-client";
const { OPError } = errors;

interface Res<T> {
  isOk(this: Res<T>): this is Ok<T>;
  isError(this: Res<T>): this is Err<T>;
}

type Ok<T> = Res<T> & {
  tag: "Ok";
  get(): T;
};

type Err<T> = Res<T> & {
  tag: "Err";
  getError(): Error;
};

const Result = {
  ok: <T>(res: T): Ok<T> => ({
    tag: "Ok",
    isOk: () => true,
    isError: () => false,
    get: () => res,
  }),
  error: <T>(error: Error): Err<T> => ({
    tag: "Err",
    isOk: () => false,
    isError: () => true,
    getError: () => error,
  }),
};

export const validateToken = async (token: string): Promise<Res<undefined>> => {
  if (token) {
    if (process.env.AZURE_OPENID_CONFIG_ISSUER) {
      try {
        await jwtVerify(
          token,
          createRemoteJWKSet(
            new URL(process.env.AZURE_OPENID_CONFIG_JWKS_URI!),
          ),
          {
            issuer: process.env.AZURE_OPENID_CONFIG_ISSUER,
            audience: process.env.AZURE_APP_CLIENT_ID,
          },
        );
        return Result.ok(undefined);
      } catch (e) {
        return Result.error(e);
      }
    } else if (process.env.IDPORTEN_ISSUER) {
      try {
        await jwtVerify(
          token,
          createRemoteJWKSet(new URL(process.env.IDPORTEN_JWKS_URI!)),
          {
            issuer: process.env.IDPORTEN_ISSUER,
            audience: process.env.IDPORTEN_AUDIENCE,
          },
        );
        return Result.ok(undefined);
      } catch (e) {
        return Result.error(e);
      }
    } else {
      return Result.error(new Error("no identity provider"));
    }
  } else {
    return Result.error(new Error("empty token"));
  }
};

export const requestOboToken = async (
  token: string,
  audience: string,
): Promise<Res<string>> => {
  try {
    const { access_token } = await new new Issuer({
      issuer: process.env.TOKEN_X_ISSUER!,
      token_endpoint: process.env.TOKEN_X_TOKEN_ENDPOINT,
      token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    }).Client(
      {
        client_id: process.env.TOKEN_X_CLIENT_ID!,
        token_endpoint_auth_method: "private_key_jwt",
      },
      { keys: [JSON.parse(process.env.TOKEN_X_PRIVATE_JWK!)] },
    ).grant(
      {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        audience,
        subject_token: token,
      },
      {
        clientAssertionPayload: {
          nbf: Math.floor(Date.now() / 1000),
          aud: process.env.TOKEN_X_TOKEN_ENDPOINT,
        },
      },
    );
    return access_token
      ? Result.ok(access_token)
      : Result.error(Error("TokenSet does not contain an access_token"));
  } catch (e) {
    if (e instanceof OPError) console.warn(e.message, e.response?.body || "");
    throw e;
  }
};
