import { validateToken } from ".";

const token = (pid: string) => {
  return pid;
};

describe("validate token", () => {
  it("succeeds for valid token", async () => {
    expect((await validateToken(token("d0f96fd30a"))).isOk()).toBe(true);
  });

  it("fails for empty token", async () => {
    expect((await validateToken("")).isOk()).toBe(false);
  });
});
