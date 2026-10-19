interface Entry {
  count: number;
  resetAt: number;
}

export class FixedWindowRateLimiter {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly maxRequests: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now
  ) {}

  allow(key: string): boolean {
    const now = this.now();
    let entry = this.entries.get(key);
    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + this.windowMs };
      this.entries.set(key, entry);
    }
    entry.count += 1;

    if (this.entries.size > 1000) {
      for (const [candidate, value] of this.entries) {
        if (now >= value.resetAt) this.entries.delete(candidate);
      }
    }
    return entry.count <= this.maxRequests;
  }
}
