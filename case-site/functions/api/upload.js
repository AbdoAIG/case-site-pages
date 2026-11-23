// Cloudflare Pages Function لرفع الملفات بأمان (Magic Bytes + CSRF + Rate Limit) إلى Google Drive & Sheets
const SESSION_COOKIE = "case_admin_session";
const CSRF_COOKIE = "case_csrf_token";
const GOOGLE_UA =
  "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)";

const uploadRateMap = new Map();

function checkUploadRate(req) {
  const ip =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "127.0.0.1";
  const now = Date.now();
  const list = (uploadRateMap.get(ip) || []).filter((t) => now - t < 60000);
  if (list.length >= 5) {
    uploadRateMap.set(ip, list);
    return false;
  }
  list.push(now);
  uploadRateMap.set(ip, list);
  return true;
}

function getSecret(env) {
  const s = (env.SESSION_SECRET || "").trim();
  return s.length >= 32
    ? s
    : "dev-fallback-secret-key-must-be-changed-in-production-32chars";
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
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
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

function parseCookies(req) {
  const header = req.headers.get("cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return out;
}

function detectMagicBytes(bytes) {
  if (!bytes || bytes.length < 16) return null;
  const head = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 512))).toLowerCase();
  if (head.includes("<svg") || head.includes("<html") || head.includes("<!doctype") || head.includes("<script")) {
    return null;
  }
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return { ext: "jpg", mime: "image/jpeg", kind: "image" };
  }
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return { ext: "png", mime: "image/png", kind: "image" };
  }
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 && bytes[8] === 0x57 && bytes[9] === 0x45) {
    return { ext: "webp", mime: "image/webp", kind: "image" };
  }
  if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    return { ext: "mp4", mime: "video/mp4", kind: "video" };
  }
  if (bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) {
    return { ext: "webm", mime: "video/webm", kind: "video" };
  }
  return null;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. التحقق من الجلسة
  const cookies = parseCookies(request);
  const sessToken = cookies[SESSION_COOKIE];
  if (!sessToken || !sessToken.includes(".")) {
    return json({ error: "غير مصرح لك بالوصول. يرجى تسجيل الدخول أولاً." }, 401);
  }
  const [encoded, sig] = sessToken.split(".");
  const expectedSig = await hmacSign(encoded, getSecret(env));
  if (!safeEqualStr(sig, expectedSig)) {
    return json({ error: "الجلسة غير صالحة." }, 401);
  }
  const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(encoded)));
  if (payload.exp <= Math.floor(Date.now() / 1000)) {
    return json({ error: "انتهت الجلسة." }, 401);
  }

  // 2. التحقق من CSRF
  const csrfCookie = cookies[CSRF_COOKIE];
  const csrfHeader = request.headers.get("x-csrf-token");
  if (!csrfCookie || !csrfHeader || !safeEqualStr(csrfCookie, csrfHeader)) {
    return json({ error: "رمز الحماية (CSRF Token) غير صالح." }, 403);
  }

  // 3. Rate Limit (5 طلبات/دقيقة)
  if (!checkUploadRate(request)) {
    return json({ error: "تم تجاوز الحد المسموح للرفع (5 طلبات/دقيقة)." }, 429);
  }

  const formData = await request.formData();
  const file = formData.get("file");
  const rawTitle = String(formData.get("title") || "").trim();
  const rawCaption = String(formData.get("caption") || "").trim();

  if (!file || typeof file === "string") {
    return json({ error: "لم يتم إرفاق ملف صالح." }, 400);
  }

  const maxMb = Math.max(1, Number(env.MAX_UPLOAD_MB || "25"));
  if (file.size > maxMb * 1024 * 1024) {
    return json({ error: `حجم الملف يتجاوز الحد المسموح (${maxMb} ميجابايت).` }, 413);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const detected = detectMagicBytes(bytes);
  if (!detected) {
    return json(
      { error: "نوع الملف غير مدعوم. يُقبل فقط: JPG, PNG, WEBP, MP4, WEBM." },
      415
    );
  }

  const scriptUrl = (env.GOOGLE_SCRIPT_URL || "").trim();
  if (!scriptUrl.startsWith("https://script.google.com/")) {
    return json({ error: "متغير GOOGLE_SCRIPT_URL غير مضبوط." }, 500);
  }

  const id = crypto.randomUUID();
  const storedName = `${Date.now()}-${id}.${detected.ext}`;
  const bodyObj = {
    action: "addMedia",
    secret: env.GOOGLE_SCRIPT_SECRET || "",
    id,
    title: (rawTitle || file.name || "مرفق توثيقي").replace(/[<>]/g, "").slice(0, 140),
    caption: rawCaption.replace(/[<>]/g, "").slice(0, 500),
    kind: detected.kind,
    mimeType: detected.mime,
    sizeBytes: bytes.length,
    storedName,
    base64Data: bytesToBase64(bytes),
    createdAt: new Date().toISOString(),
  };

  const res = await fetch(scriptUrl, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain;charset=utf-8",
      "User-Agent": GOOGLE_UA,
    },
    body: JSON.stringify(bodyObj),
    redirect: "manual",
  });

  let data = null;
  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const loc = res.headers.get("location");
    if (loc) {
      const r2 = await fetch(loc, { headers: { "User-Agent": GOOGLE_UA } });
      data = await r2.json().catch(() => null);
    }
  } else {
    data = await res.json().catch(() => null);
  }

  if (!data?.ok) {
    return json({ error: "تعذر حفظ الملف في Google Drive / Sheets." }, 502);
  }

  return json({ message: "تم رفع الملف وتسجيله في Google Sheets بنجاح.", media: data.media }, 201);
}
