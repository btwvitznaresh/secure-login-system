import { describe, expect, it, vi } from "vitest";
import { deliverAccountEmail } from "./email";

describe("account email delivery configuration", () => {
  it("validates and calls the configured webhook endpoint", async () => {
    const previous = process.env.AUTH_EMAIL_WEBHOOK_URL;
    process.env.AUTH_EMAIL_WEBHOOK_URL = "https://email-provider.invalid/webhook";
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal("fetch", fetchMock);
    await deliverAccountEmail({ to: "test@example.com", kind: "verify-email", token: "test-token", expiresAt: new Date("2030-01-01T00:00:00Z") });
    expect(fetchMock).toHaveBeenCalledWith("https://email-provider.invalid/webhook", expect.objectContaining({ method: "POST" }));
    if (previous === undefined) delete process.env.AUTH_EMAIL_WEBHOOK_URL; else process.env.AUTH_EMAIL_WEBHOOK_URL = previous;
    vi.unstubAllGlobals();
  });
});
