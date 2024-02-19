import type { NextApiRequest, NextApiResponse } from "next";
import { requestOboToken, validateToken } from "@navikt/oasis";

export default async function authenticatedHandler(
  req: NextApiRequest,
  res: NextApiResponse<string>,
) {
  const token = req.headers.authorization!.replace("Bearer ", "");

  console.log("validating token", token);
  const validationResult = await validateToken(token);
  console.log("token validated", validationResult.isOk());

  validationResult.match<any>({
    Ok: async () => {
      console.log("requesting obo");
      const oboRes = process.env.IDPORTEN_ISSUER
        ? await requestOboToken(
            token,
            "dev-gcp:oasis-maintainers:oasis-idporten",
          )
        : await requestOboToken(
            token,
            "api://dev-gcp.oasis-maintainers.oasis-azure/.default",
          );
      console.log("obo granted", "err", oboRes.isError() && oboRes.getError());

      oboRes.match<void>({
        Ok: (oboToken) =>
          res
            .status(200)
            .send(`Made obo-token request: got ${oboToken.length}`),
        Error: () => res.status(401),
      });
    },
    Error: () => {
      return res.status(401);
    },
  });
}
