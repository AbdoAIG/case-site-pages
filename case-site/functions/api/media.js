// Cloudflare Pages Function — خفيف جداً (< 0.5ms CPU) لمنع Error 1102 نهائياً
const SESSION_COOKIE = "case_admin_session";
const CSRF_COOKIE = "case_csrf_token";
const SESSION_TTL = 60 * 60 * 8; // 8 ساعات

const DEFAULT_TITLE = "توضيح تفاصيل القضية والمرفقات المصورة";
const DEFAULT_DESCRIPTION =
  "تحتوي هذه الصفحة على شرح كامل لتفاصيل القضية مع جميع الصور ومقاطع الفيديو التوضيحية المرتبطة بها.";
const DEFAULT_HASH =
  "sha256:cf2026a1b2c3d4e5:cc684be354beff65d4d51bf2b9295b5a3ed83a5f6942da94d06533146c0229d5";

const GOOGLE_UA =
  "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)";

const rateMap = new Map();

function checkRateLimit(req, scope, maxReq = 5) {
  const ip =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "127.0.0.1";
  const key = `${scope}:${ip}`;
  const now = Date.now();
  const list = (rateMap.get(key) || []).filter((t) => now - t < 60000);
  if (list.length >= maxReq) {
    rateMap.set(key, list);
    return false;
  }
  list.push(now);
  rateMap.set(key, list);
  return true;
}

function getSecret(env) {
  const s = (env.SESSION_SECRET || "").trim();
  return s.length >= 32
    ? s
    : "dev-fallback-secret-key-must-be-changed-in-production-32chars";
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function safeEqualStr(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return toBase64Url(sig);
}

async function verifyPassword(plain, env) {
  if (!plain) return false;
  const stored = (env.ADMIN_PASSWORD_HASH || "").trim() || DEFAULT_HASH;
  if (stored.startsWith("sha256:")) {
    const parts = stored.split(":");
    if (parts.length !== 3) return false;
    const [, salt, expectedHex] = parts;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`${salt}:${plain}`)
    );
    return safeEqualStr(toHex(digest), expectedHex.toLowerCase());
  }
  return false;
}

function parseCookies(req) {
  const header = req.headers.get("cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(
        part.slice(idx + 1).trim()
      );
    }
  }
  return out;
}

async function getSession(req, env) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (!token || !token.includes(".")) return null;
  const [encoded, sig] = token.split(".");
  if (!encoded || !sig) return null;
  const expectedSig = await hmacSign(encoded, getSecret(env));
  if (!safeEqualStr(sig, expectedSig)) return null;
  try {
    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(encoded))
    );
    if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function createSessionToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: (env.ADMIN_USERNAME || "admin").trim(),
    role: "ADMIN",
    iat: now,
    exp: now + SESSION_TTL,
  };
  const encoded = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await hmacSign(encoded, getSecret(env));
  return `${encoded}.${sig}`;
}

async function generateCsrf(env) {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const raw = `${toHex(bytes)}.${Date.now()}`;
  const sig = await hmacSign(raw, getSecret(env));
  return `${raw}.${sig}`;
}

async function verifyCsrf(req, env) {
  const cookies = parseCookies(req);
  const cookieToken = cookies[CSRF_COOKIE];
  const headerToken = req.headers.get("x-csrf-token");
  if (!cookieToken || !headerToken || !safeEqualStr(cookieToken, headerToken)) {
    return false;
  }
  const parts = headerToken.split(".");
  if (parts.length !== 3) return false;
  const [nonce, ts, sig] = parts;
  const expectedSig = await hmacSign(`${nonce}.${ts}`, getSecret(env));
  if (!safeEqualStr(sig, expectedSig)) return false;
  const age = Date.now() - Number(ts);
  return !Number.isNaN(age) && age >= 0 && age <= 1000 * 60 * 60 * 12;
}

function extractDriveId(url) {
  if (!url) return null;
  if (url.includes("drive.google.com") || url.includes("docs.google.com")) {
    const m1 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (m1?.[1]) return m1[1];
    const m2 = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
    if (m2?.[1]) return m2[1];
  }
  if (url.includes("googleusercontent.com")) {
    const m3 = url.match(/googleusercontent\.com\/d\/([a-zA-Z0-9_-]+)/);
    if (m3?.[1]) return m3[1];
  }
  return null;
}

function normalizeUrl(rawUrl, kind, driveFileId) {
  let url = (rawUrl || "").trim();
  const fMatch = url.match(/^=\s*IMAGE\s*\(\s*["']([^"']+)["']/i);
  if (fMatch?.[1]) url = fMatch[1].trim();
  url = url.replace(/^["']+|["']+$/g, "").trim();
  if (!url && driveFileId) {
    return `/api/media?driveId=${encodeURIComponent(driveFileId)}&kind=${kind}`;
  }
  const dId = (driveFileId || "").trim() || extractDriveId(url);
  if (dId) {
    return `/api/media?driveId=${encodeURIComponent(dId)}&kind=${kind}`;
  }
  return url;
}

async function fetchSheets(env) {
  const scriptUrl = (env.GOOGLE_SCRIPT_URL || "").trim();
  if (!scriptUrl.startsWith("https://script.google.com/")) return null;
  const target = new URL(scriptUrl);
  target.searchParams.set("action", "getAll");
  if (env.GOOGLE_SCRIPT_SECRET) {
    target.searchParams.set("secret", env.GOOGLE_SCRIPT_SECRET);
  }
  const res = await fetch(target.toString(), {
    headers: { "User-Agent": GOOGLE_UA, Accept: "application/json" },
    redirect: "follow",
  });
  if (!res.ok) return null;
  const data = await res.json().catch(() => null);
  if (!data?.ok) return null;

  const media = Array.isArray(data.media)
    ? data.media
        .map((m, idx) => {
          const rawUrl = String(m.url || "").trim();
          const dId = String(m.driveFileId || "").trim();
          const rawKind = String(m.kind || "").toLowerCase().trim();
          const kind =
            rawKind === "video" ||
            rawKind === "فيديو" ||
            rawUrl.includes("youtube.com/") ||
            rawUrl.includes("youtu.be/") ||
            /\.(mp4|webm|ogg|mov)(\?.*)?$/i.test(rawUrl)
              ? "video"
              : "image";
          return {
            id: String(m.id || `sheet-${idx}`),
            title: String(m.title || "صورة مرفقة"),
            caption: m.caption ? String(m.caption) : null,
            kind,
            url: normalizeUrl(rawUrl, kind, dId),
            mimeType: String(
              m.mimeType || (kind === "video" ? "video/mp4" : "image/jpeg")
            ),
            sizeBytes: Number(m.sizeBytes || 0),
            createdAt: String(m.createdAt || new Date().toISOString()),
          };
        })
        .filter((x) => Boolean(x.url))
    : [];

  return {
    caseInfo: {
      id: "singleton",
      title: String(data.caseInfo?.title || DEFAULT_TITLE),
      description: String(data.caseInfo?.description || DEFAULT_DESCRIPTION),
      contactName: String(data.caseInfo?.contactName || ""),
      contactPhone: String(data.caseInfo?.contactPhone || ""),
      contactPhone2: String(data.caseInfo?.contactPhone2 || ""),
      updatedAt: String(data.caseInfo?.updatedAt || new Date().toISOString()),
    },
    media,
  };
}

async function postToScript(env, bodyObj) {
  const scriptUrl = (env.GOOGLE_SCRIPT_URL || "").trim();
  if (!scriptUrl.startsWith("https://script.google.com/")) return null;
  const payload = { ...bodyObj };
  if (env.GOOGLE_SCRIPT_SECRET) payload.secret = env.GOOGLE_SCRIPT_SECRET;

  const res = await fetch(scriptUrl, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain;charset=utf-8",
      "User-Agent": GOOGLE_UA,
    },
    body: JSON.stringify(payload),
    redirect: "manual",
  });

  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const loc = res.headers.get("location");
    if (!loc) return null;
    const r2 = await fetch(loc, {
      headers: { "User-Agent": GOOGLE_UA, Accept: "application/json" },
    });
    return r2.json().catch(() => null);
  }
  return res.json().catch(() => null);
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const driveId = url.searchParams.get("driveId");
  const remoteUrl = url.searchParams.get("remoteUrl");
  const kind = url.searchParams.get("kind") === "video" ? "video" : "image";
  const publicOnly = url.searchParams.get("public") === "1";

  // 1. بروكسي Google Drive
  if (driveId && /^[a-zA-Z0-9_-]+$/.test(driveId)) {
    const candidates =
      kind === "video"
        ? [
            `https://drive.usercontent.google.com/download?id=${driveId}&export=download&confirm=t`,
            `https://drive.google.com/uc?export=download&id=${driveId}`,
          ]
        : [
            `https://drive.google.com/thumbnail?id=${driveId}&sz=w1600`,
            `https://lh3.googleusercontent.com/d/${driveId}=w1600`,
            `https://drive.google.com/uc?export=view&id=${driveId}`,
          ];

    for (const cUrl of candidates) {
      try {
        const r = await fetch(cUrl, {
          headers: { "User-Agent": GOOGLE_UA },
          redirect: "follow",
        });
        const ct = r.headers.get("content-type") || "";
        if (r.ok && r.body && !ct.includes("text/html")) {
          return new Response(r.body, {
            status: 200,
            headers: {
              "Content-Type": ct || "image/jpeg",
              "Cache-Control": "public, max-age=86400, s-maxage=86400",
              "X-Content-Type-Options": "nosniff",
            },
          });
        }
      } catch {}
    }

    const scriptUrl = (env.GOOGLE_SCRIPT_URL || "").trim();
    if (scriptUrl.startsWith("https://script.google.com/")) {
      const target = new URL(scriptUrl);
      target.searchParams.set("action", "getDriveFile");
      target.searchParams.set("fileId", driveId);
      const r = await fetch(target.toString(), { redirect: "follow" }).catch(
        () => null
      );
      const d = r ? await r.json().catch(() => null) : null;
      if (d?.ok && d.base64Data) {
        const bin = atob(d.base64Data);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new Response(bytes, {
          status: 200,
          headers: {
            "Content-Type": d.mimeType || "image/jpeg",
            "Cache-Control": "public, max-age=86400, s-maxage=86400",
            "X-Content-Type-Options": "nosniff",
          },
        });
      }
    }

    return json({ error: "تعذر جلب الملف من Google Drive." }, 404);
  }

  // 2. بروكسي الروابط الخارجية
  if (
    remoteUrl &&
    (remoteUrl.startsWith("http://") || remoteUrl.startsWith("https://"))
  ) {
    try {
      const r = await fetch(remoteUrl, {
        headers: { "User-Agent": GOOGLE_UA },
        redirect: "follow",
      });
      if (r.ok && r.body) {
        return new Response(r.body, {
          status: 200,
          headers: {
            "Content-Type": r.headers.get("content-type") || "image/jpeg",
            "Cache-Control": "public, max-age=3600, s-maxage=3600",
            "X-Content-Type-Options": "nosniff",
          },
        });
      }
    } catch {}
    return json({ error: "تعذر تحميل الرابط الخارجي." }, 404);
  }

  const sheetData = await fetchSheets(env);
  const caseInfo = sheetData?.caseInfo || {
    id: "singleton",
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    contactName: "",
    contactPhone: "",
    contactPhone2: "",
    updatedAt: new Date().toISOString(),
  };
  const media = sheetData?.media || [];

  // 3. مسار الصفحة العامة مع كاش CDN
  if (publicOnly) {
    return json(
      { caseInfo, media, googleSheetsConnected: Boolean(sheetData) },
      200,
      {
        "Cache-Control":
          "public, max-age=10, s-maxage=20, stale-while-revalidate=60",
      }
    );
  }

  // 4. مسار لوحة الإدارة
  const session = await getSession(request, env);
  const cookies = parseCookies(request);
  const csrfToken = cookies[CSRF_COOKIE] || (await generateCsrf(env));
  const maxUploadMb = Math.max(1, Number(env.MAX_UPLOAD_MB || "25"));

  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  headers.append(
    "Set-Cookie",
    `${CSRF_COOKIE}=${encodeURIComponent(csrfToken)}; Path=/; Max-Age=${SESSION_TTL}; SameSite=Strict; Secure`
  );

  return new Response(
    JSON.stringify({
      caseInfo,
      media,
      authenticated: Boolean(session),
      csrfToken,
      maxUploadMb,
      googleSheetsConnected: Boolean(sheetData),
    }),
    { status: 200, headers }
  );
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!(await verifyCsrf(request, env))) {
    return json(
      {
        error:
          "رمز الحماية (CSRF Token) غير صالح. يرجى تحديث الصفحة (F5) والمحاولة مجدداً.",
      },
      403
    );
  }

  const body = await request.json().catch(() => ({}));
  const action = String(body.action || "");

  if (action === "login") {
    if (!checkRateLimit(request, "login", 5)) {
      return json(
        { error: "تم تجاوز الحد المسموح (5 محاولات/دقيقة). انتظر دقيقة." },
        429
      );
    }

    const password = String(body.password || "");
    const ok = await verifyPassword(password, env);
    if (!ok) {
      return json({ error: "كلمة المرور غير صحيحة." }, 401);
    }

    const sessionToken = await createSessionToken(env);
    const newCsrf = await generateCsrf(env);

    const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
    headers.append(
      "Set-Cookie",
      `${SESSION_COOKIE}=${encodeURIComponent(sessionToken)}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; SameSite=Strict; Secure`
    );
    headers.append(
      "Set-Cookie",
      `${CSRF_COOKIE}=${encodeURIComponent(newCsrf)}; Path=/; Max-Age=${SESSION_TTL}; SameSite=Strict; Secure`
    );

    return new Response(
      JSON.stringify({
        message: "تم تسجيل الدخول بنجاح.",
        authenticated: true,
        csrfToken: newCsrf,
      }),
      { status: 200, headers }
    );
  }

  if (action === "logout") {
    const newCsrf = await generateCsrf(env);
    const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
    headers.append(
      "Set-Cookie",
      `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure`
    );
    headers.append(
      "Set-Cookie",
      `${CSRF_COOKIE}=${encodeURIComponent(newCsrf)}; Path=/; Max-Age=${SESSION_TTL}; SameSite=Strict; Secure`
    );
    return new Response(
      JSON.stringify({
        message: "تم تسجيل الخروج بنجاح.",
        authenticated: false,
        csrfToken: newCsrf,
      }),
      { status: 200, headers }
    );
  }

  const session = await getSession(request, env);
  if (!session) {
    return json({ error: "انتهت صلاحية الجلسة. يرجى تسجيل الدخول." }, 401);
  }

  if (action === "updateCase") {
    const title = String(body.title || "").replace(/[<>]/g, "").trim().slice(0, 200);
    const description = String(body.description || "").replace(/[<>]/g, "").trim().slice(0, 5000);
    const contactName = String(body.contactName || "").replace(/[<>]/g, "").trim().slice(0, 120);
    const contactPhone = String(body.contactPhone || "").replace(/[<>"'`]/g, "").trim().slice(0, 40);
    const contactPhone2 = String(body.contactPhone2 || "").replace(/[<>"'`]/g, "").trim().slice(0, 40);

    if (!title || !description) {
      return json({ error: "عنوان القضية والوصف حقول مطلوبة." }, 400);
    }

    const res = await postToScript(env, {
      action: "updateCase",
      title,
      description,
      contactName,
      contactPhone,
      contactPhone2,
    });

    if (!res?.ok) {
      return json({ error: "تعذر الاتصال بـ Google Sheets. تأكد من رابط GOOGLE_SCRIPT_URL." }, 502);
    }

    return json({
      message: "تم حفظ بيانات القضية وأرقام التواصل وتحديث الصفحة العامة فوراً.",
      caseInfo: res.caseInfo,
    });
  }

  if (action === "addExternalMedia") {
    const rawUrl = String(body.url || "").trim();
    const kind = body.kind === "video" ? "video" : "image";
    const safeTitle = String(body.title || "مرفق توثيقي").replace(/[<>]/g, "").trim().slice(0, 140);
    const safeCaption = body.caption ? String(body.caption).replace(/[<>]/g, "").trim().slice(0, 500) : "";

    if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
      return json({ error: "يرجى إدخال رابط صحيح يبدأ بـ https://" }, 400);
    }

    const id = crypto.randomUUID();
    const res = await postToScript(env, {
      action: "addMedia",
      id,
      title: safeTitle,
      caption: safeCaption,
      kind,
      url: rawUrl,
      mimeType: kind === "video" ? "video/mp4" : "image/jpeg",
      sizeBytes: 0,
      createdAt: new Date().toISOString(),
    });

    if (!res?.ok) {
      return json({ error: "تعذر إضافة الرابط إلى Google Sheets." }, 502);
    }

    return json({ message: "تمت إضافة الرابط بنجاح ونشره في الصفحة العامة." });
  }

  if (action === "deleteMedia") {
    const id = String(body.id || "");
    if (!id) return json({ error: "معرّف الوسيط مطلوب." }, 400);
    await postToScript(env, { action: "deleteMedia", id });
    return json({ message: "تم حذف العنصر بنجاح.", deletedId: id });
  }

  return json({ error: "إجراء غير معروف." }, 400);
}
