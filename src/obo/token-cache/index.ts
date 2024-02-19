import { JWTPayload, decodeJwt } from "jose";
import { createHash } from "node:crypto";
import SieveCache from "./cache";
import { OboProvider } from "..";
import { Result } from "../../result";

function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

let cache: SieveCache;

function getCache() {
  if (!cache) {
    const averageJwtSize = 1024; // bytes
    const maxCacheSize = 128 /* MB */ * 1024 /* KB */ * 1024; /* bytes */
    const maxCacheCapacity = Math.floor(maxCacheSize / averageJwtSize);

    cache = new SieveCache(maxCacheCapacity);
  }
  return cache;
}

function getSecondsToExpire(payload: JWTPayload): number {
  function secondsUntil(timestamp: number): number {
    return Math.max(Math.round(timestamp - Math.round(Date.now() / 1000)), 0);
  }

  return payload.exp ? secondsUntil(payload.exp) : 0;
}

export const withCache = (oboProvider: OboProvider): OboProvider => {
  return async (token, audience) => {
    const cache = getCache();
    const key = sha256(token + audience);
    const cachedToken = cache.get(key);
    if (cachedToken) {
      return Promise.resolve(Result.Ok(cachedToken));
    }

    return oboProvider(token, audience).then((result) =>
      result.match<Result<string, Error>>({
        Ok: (v) => {
          const ttl = getSecondsToExpire(decodeJwt(v));
          if (ttl > 0) {
            cache.set(key, v, ttl);
          }
          return Result.Ok(v);
        },
        Error: (e) => Result.Error(e),
      }),
    );
  };
};
