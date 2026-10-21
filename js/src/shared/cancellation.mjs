/** Returns the abort reason in a portable Error shape. */
export function abortError(signal) {
  if (signal?.reason instanceof Error) return signal.reason;
  const error = new Error(signal?.reason === undefined
    ? "The operation was aborted"
    : String(signal.reason));
  error.name = "AbortError";
  return error;
}

/** Throws when `signal` is aborted. */
export function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError(signal);
}

/** Validates an optional AbortSignal-like value without relying on realm identity. */
export function validateSignal(signal) {
  if (signal !== undefined && (!signal || typeof signal.aborted !== "boolean" ||
      typeof signal.addEventListener !== "function" ||
      typeof signal.removeEventListener !== "function"))
    throw new TypeError("signal must be an AbortSignal");
}

/**
 * Creates a cooperative cancellation point that yields to Worker messages
 * after a short CPU slice. A synchronous session.advance() cannot be preempted.
 */
export function cancellationPoint(signal, sliceMs = 8) {
  let lastYield = performance.now();
  return async () => {
    throwIfAborted(signal);
    if (!signal || performance.now() - lastYield < sliceMs) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
    lastYield = performance.now();
    throwIfAborted(signal);
  };
}
