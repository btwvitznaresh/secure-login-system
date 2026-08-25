import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, LockKeyhole, LogOut, Sparkles, Loader2 } from "lucide-react";
import { toast } from "sonner";

function AuthForm() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const utils = trpc.useUtils();
  const login = trpc.localAuth.login.useMutation({ onSuccess: () => { utils.localAuth.me.invalidate(); toast.success("Welcome back"); }, onError: e => toast.error(e.message) });
  const register = trpc.localAuth.register.useMutation({ onSuccess: () => { utils.localAuth.me.invalidate(); toast.success("Your account is ready"); }, onError: e => toast.error(e.message) });
  const busy = login.isPending || register.isPending;
  const submit = (event: React.FormEvent) => { event.preventDefault(); mode === "login" ? login.mutate({ email, password }) : register.mutate({ email, password, name: name || undefined }); };
  return <Card className="auth-card">
    <CardHeader className="space-y-3"><div className="brand-mark"><LockKeyhole size={18} /></div><div><CardTitle className="text-2xl">{mode === "login" ? "Welcome back" : "Create your account"}</CardTitle><CardDescription>{mode === "login" ? "Sign in to your protected workspace." : "Start with a secure, private account."}</CardDescription></div></CardHeader>
    <CardContent><form onSubmit={submit} className="space-y-4">
      {mode === "register" && <div className="space-y-2"><Label htmlFor="name">Name</Label><Input id="name" value={name} onChange={e => setName(e.target.value)} placeholder="Alex Morgan" autoComplete="name" maxLength={80} /></div>}
      <div className="space-y-2"><Label htmlFor="email">Email address</Label><Input id="email" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" autoComplete="email" required maxLength={320} /></div>
      <div className="space-y-2"><div className="flex items-center justify-between"><Label htmlFor="password">Password</Label>{mode === "register" && <span className="field-hint">12+ characters</span>}</div><Input id="password" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter your password" autoComplete={mode === "login" ? "current-password" : "new-password"} required minLength={mode === "register" ? 12 : 1} maxLength={128} /></div>
      <Button className="w-full" size="lg" disabled={busy}>{busy && <Loader2 className="mr-2 animate-spin" size={16} />}{mode === "login" ? "Sign in securely" : "Create account"}</Button>
      <p className="switch-copy">{mode === "login" ? "New here?" : "Already have an account?"} <button type="button" className="text-link" onClick={() => setMode(mode === "login" ? "register" : "login")}>{mode === "login" ? "Create an account" : "Sign in"}</button></p>
    </form></CardContent>
  </Card>;
}

function AccountView({ user }: { user: any }) {
  const utils = trpc.useUtils();
  const logout = trpc.localAuth.logout.useMutation({ onSuccess: () => { utils.localAuth.me.invalidate(); toast.success("You have been signed out"); } });
  const [enrollmentId, setEnrollmentId] = useState<string>();
  const [secret, setSecret] = useState<string>();
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const account = trpc.account.overview.useQuery(undefined, { retry: false });
  const begin2fa = trpc.twoFactor.beginEnrollment.useMutation({ onSuccess: data => { setEnrollmentId(data.enrollmentId); setSecret(data.secret); toast.success("Enrollment started"); }, onError: e => toast.error(e.message) });
  const verify2fa = trpc.twoFactor.verifyEnrollment.useMutation({ onSuccess: data => { setRecoveryCodes(data.recoveryCodes); toast.success("Two-factor protection is ready"); }, onError: e => toast.error(e.message) });
  return <Card className="account-card"><CardHeader><div className="flex items-center justify-between"><div><CardTitle className="text-2xl">Your secure space</CardTitle><CardDescription>Account access is protected by an HTTP-only session.</CardDescription></div><Badge variant="secondary"><ShieldCheck size={14} className="mr-1" /> Protected</Badge></div></CardHeader><CardContent className="space-y-5"><div className="profile-panel"><div className="avatar">{(user.name || user.email || "A")[0].toUpperCase()}</div><div><p className="font-semibold">{user.name || "Account holder"}</p><p className="text-sm muted">{user.email}</p></div></div><div className="security-grid"><div><p className="eyebrow">Session</p><p className="font-medium">Active and server-validated</p></div><div><p className="eyebrow">Two-factor</p><p className="font-medium">{account.data?.security.twoFactorReady ? "Ready to enroll" : "Checking…"}</p></div></div><div className="recovery-note"><Sparkles size={17} /><p><strong>Recovery guidance:</strong> enroll a TOTP authenticator, store recovery codes offline, and never share them.</p></div>{!user.twoFactorEnabled && <div className="twofa-panel"><div className="flex items-center justify-between"><div><p className="eyebrow">Optional protection</p><p className="font-medium">Add two-factor authentication</p></div><Button variant="outline" size="sm" onClick={() => begin2fa.mutate()} disabled={begin2fa.isPending}>{begin2fa.isPending ? "Preparing…" : "Begin setup"}</Button></div>{secret && <div className="twofa-setup"><p className="text-sm muted">Add this secret to your authenticator:</p><code>{secret}</code><div className="flex gap-2"><Input aria-label="Six-digit authenticator code" inputMode="numeric" placeholder="123456" value={code} onChange={e => setCode(e.target.value)} maxLength={6} /><Button onClick={() => enrollmentId && verify2fa.mutate({ enrollmentId, code })} disabled={code.length !== 6 || verify2fa.isPending}>{verify2fa.isPending ? "Verifying…" : "Verify"}</Button></div></div>}{recoveryCodes.length > 0 && <div className="recovery-note"><p><strong>Save these recovery codes now:</strong> {recoveryCodes.join(" · ")}</p></div>}</div>}<Button variant="outline" className="w-full" onClick={() => logout.mutate()} disabled={logout.isPending}>{logout.isPending ? <Loader2 className="mr-2 animate-spin" size={16} /> : <LogOut className="mr-2" size={16} />}Sign out</Button></CardContent></Card>;
}

export default function Home() {
  const { data: user, isLoading } = trpc.localAuth.me.useQuery();
  return <main className="auth-shell"><div className="auth-orb orb-one" /><div className="auth-orb orb-two" /><section className="auth-layout"><div className="intro"><div className="kicker"><ShieldCheck size={16} /> PRIVATE BY DESIGN</div><h1>Access that feels <em>effortless.</em></h1><p className="intro-copy">A considered authentication experience for people who expect their account, identity, and peace of mind to be handled with care.</p><div className="trust-list"><span><ShieldCheck size={16} /> Bcrypt-protected passwords</span><span><LockKeyhole size={16} /> HTTP-only sessions</span><span><Sparkles size={16} /> 2FA-ready security</span></div></div><div className="form-column">{isLoading ? <Card className="auth-card loading-card"><Loader2 className="animate-spin" /><span>Checking your session…</span></Card> : user ? <AccountView user={user} /> : <AuthForm />}<p className="legal-copy">By continuing, you agree to keep your credentials private. This demo uses local account authentication and never exposes raw passwords.</p></div></section></main>;
}
