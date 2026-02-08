import crypto from "crypto";

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}

function timingSafeEqualHex(a, b) {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function signSession(payloadObj, secret) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { ok: false, error: "Method not allowed" });
  }

  const { ADMIN_EMAILS, ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_HASH, SESSION_SECRET } = process.env;

  if (!ADMIN_EMAILS || !ADMIN_PASSWORD_SALT || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
    return json(res, 501, { ok: false, error: "Login not configured" });
  }

  let body = "";
  await new Promise((resolve) => {
    req.on("data", (c) => (body += c));
    req.on("end", resolve);
  });

  let parsed;
  try {
    parsed = JSON.parse(body || "{}");
  } catch {
    return json(res, 400, { ok: false, error: "Invalid JSON" });
  }

  const email = String(parsed.email || "").trim().toLowerCase();
  const password = String(parsed.password || "");

  if (!email || !password) {
    return json(res, 400, { ok: false, error: "Missing email or password" });
  }

  const allowed = ADMIN_EMAILS.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!allowed.includes(email)) {
    return json(res, 401, { ok: false, error: "Invalid credentials" });
  }

  // hash = sha256(salt + password) in hex
  const computed = crypto.createHash("sha256").update(ADMIN_PASSWORD_SALT + password).digest("hex");

  if (!timingSafeEqualHex(computed, ADMIN_PASSWORD_HASH)) {
    return json(res, 401, { ok: false, error: "Invalid credentials" });
  }

  const token = signSession({ email, iat: Date.now() }, SESSION_SECRET);

  // 7 days
  const maxAge = 60 * 60 * 24 * 7;

  res.setHeader(
    "Set-Cookie",
    [
      `admin_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}; Secure`,
    ]
  );

  return json(res, 200, { ok: true });
}
