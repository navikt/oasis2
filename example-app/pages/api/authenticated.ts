import { validateToken } from "@navikt/oasis";
import { decodeJwt } from "jose";
import type { NextApiRequest, NextApiResponse } from "next";

export default async function authenticatedHandler(
  req: NextApiRequest,
  res: NextApiResponse<string>,
) {
  const token = req.headers.authorization!.replace("Bearer ", "");

  (await validateToken(token)).match({
    Ok: () => res.status(200).send(`Authenticated as ${decodeJwt(token).sub}`),
    Error: () => res.status(401),
  });
}
