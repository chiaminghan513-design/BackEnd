// Several mutation endpoints return a failure message with HTTP 200.
// Reject explicit failures without mistaking empty history messages for errors.
export function assertActionSucceeded(result: unknown): void {
  if (typeof result === 'string' && /\b(failed|failure|invalid|incorrect|not found|expired|insufficient|error)\b/i.test(result)) {
    throw Object.assign(new Error(result), { status: 502 });
  }
}
