import { JWTVerifyResult, createRemoteJWKSet, jwtVerify } from "jose";

type Result = {
  isOk: () => boolean;
};

const Result = {
  ok: () => ({
    isOk: () => true,
  }),
  error: (message: string) => ({
    isOk: () => false,
  }),
};

export const validateToken = async (token: string): Promise<Result> => {
  if (token) {
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
      console.log(e);
      return Result.error(e.message);
    }
  } else {
    return Result.error("Empty token");
  }
};
