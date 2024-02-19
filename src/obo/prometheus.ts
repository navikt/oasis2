import { Counter, Histogram } from "prom-client";
import { OboProvider } from ".";

const tokenExchangeDurationHistogram = new Histogram({
  name: "oasis_token_exchange_duration_seconds",
  help: "Duration of token exchange in seconds",
  labelNames: ["provider"],
});
const tokenExchangeFailures = new Counter({
  name: "oasis_token_exchange_failures",
  help: "Number of failed token exchanges",
  labelNames: ["provider"],
});
const tokenExchanges = new Counter({
  name: "oasis_token_exchanges",
  help: "Number of token exchanges",
  labelNames: ["provider"],
});

export function withPrometheus(oboProvider: OboProvider): OboProvider {
  const provider = oboProvider.name;
  return async (token, audience) => {
    const measureTokenExchange = tokenExchangeDurationHistogram
      .labels({ provider })
      .startTimer();

    const oboToken = await oboProvider(token, audience);

    measureTokenExchange();

    if (oboToken.isError()) {
      tokenExchangeFailures.labels({ provider }).inc();
    }

    tokenExchanges.labels({ provider }).inc();
    return oboToken;
  };
}
