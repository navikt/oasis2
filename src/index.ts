import { createRemoteJWKSet, jwtVerify } from "jose";

interface Res {
  isOk(this: Res): this is Ok;
  isError(this: Res): this is Err;
}

type Ok = Res & {
  tag: "Ok";
};

type Err = Res & {
  tag: "Err";
  getError(): Error;
};

const Result = {
  ok: (): Ok => ({
    tag: "Ok",
    isOk: () => true,
    isError: () => false,
  }),
  error: (error: Error): Err => ({
    tag: "Err",
    isOk: () => false,
    isError: () => true,
    getError: () => error,
  }),
};

export const validateToken = async (token: string): Promise<Res> => {
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
        return Result.ok();
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
        return Result.ok();
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
