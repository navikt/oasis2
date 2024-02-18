import { Issuer } from "openid-client";
import { Result } from "./result";

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
