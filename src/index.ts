const Result = {
  ok: () => ({
    isOk: () => true,
  }),
  error: (message: string) => ({
    isOk: () => false,
  }),
};

export const validateToken = async (token: string) => {
  if (token) {
    return Result.ok();
  } else {
    return Result.error("Empty token");
  }
};
