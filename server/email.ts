type AccountEmail = { to: string; kind: "verify-email" | "reset-password"; token: string; expiresAt: Date };

export async function deliverAccountEmail(email: AccountEmail) {
  const endpoint = process.env.AUTH_EMAIL_WEBHOOK_URL;
  if (!endpoint) {
    if (process.env.NODE_ENV === "production") throw new Error("AUTH_EMAIL_WEBHOOK_URL is required in production");
    console.info(`[EmailDelivery] ${email.kind} prepared for ${email.to}; configure AUTH_EMAIL_WEBHOOK_URL to deliver it.`);
    return;
  }
  const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(email) });
  if (!response.ok) throw new Error(`Email provider returned ${response.status}`);
}
