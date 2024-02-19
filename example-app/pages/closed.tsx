import { validateToken } from "@navikt/oasis";
import { decodeJwt } from "jose";
import { GetServerSideProps } from "next";

export const getServerSideProps: GetServerSideProps<ClosedPageProps> = async ({
  req,
}) => {
  if (req.headers.authorization) {
    const token = req.headers.authorization!.replace("Bearer ", "");

    return (await validateToken(token)).match<any>({
      Ok: () => {
        const payload = decodeJwt(token);
        return {
          props: { sub: payload.sub as string },
        };
      },
      Error: () => ({
        redirect: {
          destination: "/oauth2/login",
          permanent: false,
        },
      }),
    });
  } else {
    return {
      redirect: {
        destination: "/oauth2/login",
        permanent: false,
      },
    };
  }
};

interface ClosedPageProps {
  sub: string;
}

export default function ClosedPage({ sub }: ClosedPageProps) {
  return (
    <>
      <h1>This page is closed</h1>
      <p>Session is authenticated with sub: {sub}</p>
    </>
  );
}
