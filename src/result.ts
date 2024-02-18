interface BaseResult<T, E> {
  isOk(): this is Ok<T, E>;
  isError(): this is Err<T, E>;
  match<B>(opts: { Ok: (value: T) => B; Error: (error: E) => B }): B;
}

type Ok<T, E> = BaseResult<T, E> & {
  get(): T;
};

type Err<T, E> = BaseResult<T, E> & {
  getError(): E;
};

export type Result<T, E> = Ok<T, E> | Err<T, E>;

export const Result = {
  Ok: <T, E>(value: T): Ok<T, E> => ({
    isOk: () => true,
    isError: () => false,
    get: () => value,
    match: ({ Ok }) => Ok(value),
  }),
  Error: <T, E>(error: E): Err<T, E> => ({
    isOk: () => false,
    isError: () => true,
    getError: () => error,
    match: ({ Error }) => Error(error),
  }),
};
