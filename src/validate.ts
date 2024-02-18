import { createRemoteJWKSet, jwtVerify } from "jose";
import { Result } from "./result";

const validateJwt = async ({
  token,
  jwksUri,
  issuer,
  audience,
}: {
  token: string;
  jwksUri: string;
  issuer: string;
  audience: string;
}): Promise<Result<undefined, Error>> => {
  try {
    await jwtVerify(token, createRemoteJWKSet(new URL(jwksUri)), {
      issuer,
      audience,
      algorithms: ["RS256"],
    });
    return Result.Ok(undefined);
  } catch (e) {
    return Result.Error(e);
  }
};

export const validateIdportenToken = (token: string) =>
  validateJwt({
    token,
    jwksUri: process.env.IDPORTEN_JWKS_URI!,
    issuer: process.env.IDPORTEN_ISSUER!,
    audience: process.env.IDPORTEN_AUDIENCE!,
  });

export const validateAzureToken = (token: string) =>
  validateJwt({
    token,
    jwksUri: process.env.AZURE_OPENID_CONFIG_JWKS_URI!,
    issuer: process.env.AZURE_OPENID_CONFIG_ISSUER!,
    audience: process.env.AZURE_APP_CLIENT_ID!,
  });

export const validateTokenxToken = (token: string) =>
  validateJwt({
    token,
    jwksUri: process.env.TOKEN_X_JWKS_URI!,
    issuer: process.env.TOKEN_X_ISSUER!,
    audience: process.env.TOKEN_X_CLIENT_ID!,
  });

export const validateToken = async (
  token: string,
): Promise<Result<undefined, Error>> => {
  if (!token) {
    return Result.Error(new Error("empty token"));
  }

  const idporten: boolean = !!process.env.IDPORTEN_ISSUER;
  const azure: boolean = !!process.env.AZURE_OPENID_CONFIG_ISSUER;

  if (idporten && azure) {
    return Result.Error(new Error("multiple identity providers"));
  } else if (idporten) {
    return validateIdportenToken(token);
  } else if (azure) {
    return validateAzureToken(token);
  } else {
    return Result.Error(new Error("no identity provider"));
  }
};
