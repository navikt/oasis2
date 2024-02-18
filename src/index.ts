import { createRemoteJWKSet, jwtVerify } from "jose";
import { Issuer, errors } from "openid-client";
import { Result } from "./result";
const { OPError } = errors;

export const validateToken = async (
  token: string,
): Promise<Result<undefined, Error>> => {
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
        return Result.Ok(undefined);
      } catch (e) {
        return Result.Error(e);
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
        return Result.Ok(undefined);
      } catch (e) {
        return Result.Error(e);
      }
    } else {
      return Result.Error(new Error("no identity provider"));
    }
  } else {
    return Result.Error(new Error("empty token"));
  }
};

export const requestOboToken = async (
  token: string,
  audience: string,
): Promise<Result<string, Error>> => {
  try {
    const { access_token } = await new (
      await Issuer.discover(process.env.TOKEN_X_WELL_KNOWN_URL!)
    ).Client(
      {
        client_id: process.env.TOKEN_X_CLIENT_ID!,
        token_endpoint_auth_method: "private_key_jwt",
      },
      { keys: [JSON.parse(process.env.TOKEN_X_PRIVATE_JWK!)] },
    ).grant(
      {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        audience,
        subject_token: token,
      },
      {
        clientAssertionPayload: {
          nbf: Math.floor(Date.now() / 1000),
        },
      },
    );
    return access_token
      ? Result.Ok(access_token)
      : Result.Error(Error("TokenSet does not contain an access_token"));
  } catch (e) {
    return Result.Error(e);
  }
};
