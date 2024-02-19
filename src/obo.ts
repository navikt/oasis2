import { GrantBody, Issuer } from "openid-client";
import { Result } from "./result";

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

export const requestTokenxOboToken = async (
  subject_token: string,
  audience: string,
) =>
  grantOboToken({
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
