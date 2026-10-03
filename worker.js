// ================================================================
// DAIMONIUM BACKEND — Cloudflare Worker
// نسخه V10.0 — Security Hardening + Dual-Network
// ================================================================
// تغییرات نسبت به V9.3:
//   🔴 WEBHOOK_SECRET اجباری — بدون آن webhook = 503
//   🔴 رفع race condition در پرداخت Stars (atomic UPDATE RETURNING)
//   🔴 JWT_SECRET حداقل ۳۲ کاراکتر — startup reject
//   🔴 Timing-safe comparison برای initData hash
//   🔴 ولیدیشن دقیق تاریخ در /sync (فقط امروز/دیروز)
//   🟡 نرمال‌سازی path برای rate limit
//   🟡 CRC16 verification برای TON addresses
//   🟡 محدودیت حجم body (64KB)
//   🟡 Sanitize خطاها در production
//   🟢 Audit logging برای ولت
// ================================================================

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Telegram-Init-Data',
    'Access-Control-Max-Age': '86400',
};

const PACKAGE_DEFINITIONS = {
    package_1: { coins: 10000,    usdt: 1,   stars: 100 },
    package_2: { coins: 80000,    usdt: 5,   stars: 500 },
    package_3: { coins: 200000,   usdt: 10,  stars: 1000 },
    package_4: { coins: 1000000,  usdt: 50,  stars: 5000 },
    package_5: { coins: 3000000,  usdt: 100, stars: 10000 },
};

const TASK_REWARDS = {
    task1: 100,
    task2: 100,
    ad_watch: 150,
};

const REFERRAL_REWARDS = {
    invite3:  { required: 3,  reward: 5000 },
    invite5:  { required: 5,  reward: 10000 },
    invite10: { required: 10, reward: 30000 },
    invite20: { required: 20, reward: 100000 },
};

// ✅ V10.0 — آدرس‌های پیش‌فرض هر شبکه
const DEFAULT_USDT_MASTER = {
    mainnet: 'UQBVTscttZ6fcfyHZu2kpDUVbC1QHEDvl-hJhv8YRrLIih7P',
    testnet: '0QCe7M2fePiGus4T4AqPJ8ica3Bzj60RPTPJexM8kP6gD30c',
};

const DEFAULT_TON_RECIPIENT = {
    mainnet: 'UQBVTscttZ6fcfyHZu2kpDUVbC1QHEDvl-hJhv8YRrLIih7P',
    // 👇 TODO: آدرس testnet واقعی خودت را اینجا بگذار
    testnet: '0QCe7M2fePiGus4T4AqPJ8ica3Bzj60RPTPJexM8kP6gD30c',
};

const USDT_DECIMALS = 6;
const CONFIG_CACHE_TTL = 7 * 24 * 60 * 60;  // seconds
const JWT_EXPIRES = 30 * 24 * 60 * 60;      // 30 روز
const MAX_BODY_SIZE = 64 * 1024;             // ✅ V10.0: 64KB
const MIN_JWT_SECRET_LEN = 32;               // ✅ V10.0
const IS_PRODUCTION = true;                   // ✅ V10.0: sanitize errors

// ================================================================
// HELPERS
// ================================================================
function jsonResponse(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...headers }
    });
}

function errorResponse(code, message, status = 400) {
    return jsonResponse({ code, message }, status);
}

// ✅ V10.0 — sanitize خطا برای production
function sanitizeError(err, fallbackCode = 'SERVER_ERROR') {
    if (IS_PRODUCTION) {
        // فقط کد و پیام عمومی
        console.error('[sanitized]', err.message || err);
        return { code: fallbackCode, message: 'Something went wrong. Please try again.' };
    }
    return { code: fallbackCode, message: (err && err.message) || 'Unknown error' };
}

// ✅ V10.0 — timing-safe comparison
function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}

// ✅ V10.0 — نرمال‌سازی path
function normalizePath(path) {
    let p = path.split('?')[0];                 // حذف query
    p = p.replace(/\/{2,}/g, '/');              // // → /
    p = p.replace(/\/+$/, '');                  // حذف / انتهایی
    if (p === '') p = '/';
    return p.toLowerCase();
}

// ================================================================
// TON ADDRESS — CRC16 + Validation
// ================================================================
function crc16Ton(data) {
    let crc = 0;
    for (let i = 0; i < data.length; i++) {
        crc ^= data[i] << 8;
        for (let j = 0; j < 8; j++) {
            crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
        }
    }
    return crc;
}

// ✅ V10.0 — ولیدیشن دقیق با CRC
function verifyTonAddress(address) {
    if (typeof address !== 'string') return false;
    if (address.length !== 48) return false;

    const validPrefixes = ['EQ', 'UQ', 'kQ', '0Q'];
    if (!validPrefixes.some(p => address.startsWith(p))) return false;

    if (!/^[A-Za-z0-9\-_]+$/.test(address)) return false;

    // decode base64url
    try {
        let clean = address.replace(/-/g, '+').replace(/_/g, '/');
        while (clean.length % 4) clean += '=';
        const raw = atob(clean);
        if (raw.length !== 36) return false;

        const bytes = new Uint8Array(36);
        for (let i = 0; i < 36; i++) bytes[i] = raw.charCodeAt(i);

        // tag byte → باید 0x11, 0x51, 0x91, 0xD1 باشه
        const tag = bytes[0];
        const validTags = [0x11, 0x51, 0x91, 0xD1];
        if (!validTags.includes(tag)) return false;

        // CRC
        const expectedCrc = (bytes[34] << 8) | bytes[35];
        const actualCrc = crc16Ton(bytes.slice(0, 34));
        if (expectedCrc !== actualCrc) return false;

        return true;
    } catch (e) {
        return false;
    }
}

// نگه‌داشتن برای backward-compat
function isValidTonAddress(address) {
    return verifyTonAddress(address);
}

// ✅ V10.0 — تشخیص شبکه از tag byte
function detectAddressNetwork(addr) {
    if (!addr || typeof addr !== 'string') return null;
    if (addr.startsWith('EQ') || addr.startsWith('UQ')) return 'mainnet';
    if (addr.startsWith('kQ') || addr.startsWith('0Q')) return 'testnet';
    return null;
}

function normalizeNetwork(n) {
    if (!n) return null;
    const s = String(n).toLowerCase();
    if (s === 'testnet' || s === 'test') return 'testnet';
    if (s === 'mainnet' || s === 'main') return 'mainnet';
    return null;
}

function tonAddressHash(addr) {
    if (!addr || typeof addr !== 'string') return '';
    if (addr.includes(':')) return addr.split(':')[1].toLowerCase();
    try {
        let clean = addr.replace(/-/g, '+').replace(/_/g, '/');
        while (clean.length % 4) clean += '=';
        const buf = atob(clean);
        if (buf.length !== 36) return addr.toLowerCase();
        let hex = '';
        for (let i = 2; i < 34; i++) {
            hex += buf.charCodeAt(i).toString(16).padStart(2, '0');
        }
        return hex;
    } catch (e) {
        return addr.toLowerCase();
    }
}

// ================================================================
// JWT
// ================================================================
function base64UrlEncode(data) {
    return btoa(JSON.stringify(data))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return JSON.parse(atob(str));
}

async function generateJWT(payload, secret, expiresIn = JWT_EXPIRES) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const data = { ...payload, iat: now, exp: now + expiresIn };
    const encodedHeader = base64UrlEncode(header);
    const encodedPayload = base64UrlEncode(data);
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign(
        'HMAC', key, new TextEncoder().encode(encodedHeader + '.' + encodedPayload)
    );
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return encodedHeader + '.' + encodedPayload + '.' + encodedSignature;
}

async function verifyJWT(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Invalid format');
        const [header, payload, signature] = parts;
        const key = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
        );
        const valid = await crypto.subtle.verify(
            'HMAC', key,
            Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            new TextEncoder().encode(header + '.' + payload)
        );
        if (!valid) throw new Error('Invalid signature');
        const data = base64UrlDecode(payload);
        if (data.exp < Math.floor(Date.now() / 1000)) throw new Error('Expired');
        return data;
    } catch (e) {
        throw new Error('Invalid token: ' + e.message);
    }
}

// ================================================================
// TELEGRAM INITDATA — timing-safe verify
// ================================================================
async function verifyTelegramInitData(initData, botToken) {
    try {
        const params = new URLSearchParams(initData);
        const hash = params.get('hash');
        if (!hash) return null;
        params.delete('hash');
        const sortedKeys = Array.from(params.keys()).sort();
        const dataCheckString = sortedKeys.map(k => k + '=' + params.get(k)).join('\n');
        const secretKey = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode('WebAppData'),
            { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const secret = await crypto.subtle.sign('HMAC', secretKey, new TextEncoder().encode(botToken));
        const signatureKey = await crypto.subtle.importKey(
            'raw', secret,
            { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const calculatedHash = await crypto.subtle.sign(
            'HMAC', signatureKey, new TextEncoder().encode(dataCheckString)
        );
        const calculatedHex = Array.from(new Uint8Array(calculatedHash))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        // ✅ V10.0 — timing-safe
        if (!timingSafeEqual(calculatedHex, hash)) return null;

        // ✅ V10.0 — چک سن initData (حداکثر ۲۴ ساعت)
        const authDate = parseInt(params.get('auth_date') || '0');
        if (authDate > 0 && (Math.floor(Date.now() / 1000) - authDate) > 86400) {
            console.warn('[auth] initData expired');
            return null;
        }

        const userStr = params.get('user');
        if (!userStr) return null;
        return JSON.parse(userStr);
    } catch (e) {
        console.error('Telegram verification error:', e);
        return null;
    }
}

// ================================================================
// TON JETTON TRANSFER VERIFICATION
// ================================================================
async function findMatchingJettonTransfer(senderWallet, expectedAmountUsdt, ourAddress, usdtMaster, network, apiKey) {
    try {
        const apiBase = (network === 'testnet') ? 'https://testnet.tonapi.io' : 'https://tonapi.io';
        const url = apiBase + '/v2/accounts/' + encodeURIComponent(senderWallet) + '/events?limit=20';
        const res = await fetch(url, {
            headers: apiKey ? { 'Authorization': 'Bearer ' + apiKey } : {}
        });
        if (!res.ok) return { error: 'TON API returned ' + res.status };
        const data = await res.json();

        const expectedRawAmount = Math.round(expectedAmountUsdt * Math.pow(10, USDT_DECIMALS));
        const ourHash = tonAddressHash(ourAddress);
        const usdtHash = tonAddressHash(usdtMaster);
        const now = Math.floor(Date.now() / 1000);

        for (const ev of data.events || []) {
            if (ev.timestamp && (now - ev.timestamp) > 600) continue;
            for (const act of ev.actions || []) {
                if (act.type !== 'JettonTransfer') continue;
                const jt = act.JettonTransfer;
                if (!jt) continue;
                if (tonAddressHash(jt.jetton && jt.jetton.address) !== usdtHash) continue;
                if (tonAddressHash(jt.recipient && jt.recipient.address) !== ourHash) continue;
                if (parseInt(jt.amount, 10) !== expectedRawAmount) continue;
                return {
                    txHash: ev.event_id || ev.lt,
                    sender: (jt.sender && jt.sender.address) || senderWallet,
                    amount: expectedAmountUsdt,
                    rawAmount: expectedRawAmount,
                    network,
                };
            }
        }
        return null;
    } catch (e) {
        return { error: e.message };
    }
}

// ================================================================
// RATE LIMITER
// ================================================================
async function checkRateLimit(kv, key, limit, windowSeconds) {
    const now = Math.floor(Date.now() / 1000);
    const windowKey = Math.floor(now / windowSeconds);
    const kvKey = 'ratelimit:' + key + ':' + windowKey;
    const current = await kv.get(kvKey, 'json');
    if (current === null) {
        await kv.put(kvKey, JSON.stringify({ count: 1 }), { expirationTtl: windowSeconds + 10 });
        return true;
    }
    if (current.count >= limit) return false;
    await kv.put(kvKey, JSON.stringify({ count: current.count + 1 }), { expirationTtl: windowSeconds + 10 });
    return true;
}

// ================================================================
// AUTH HELPER
// ================================================================
async function getUserFromJWT(request, secret) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    try {
        const token = authHeader.substring(7);
        const payload = await verifyJWT(token, secret);
        return payload.telegramId;
    } catch (e) {
        return null;
    }
}

// ================================================================
// BODY READER — با limit
// ================================================================
async function readJsonBody(request) {
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > MAX_BODY_SIZE) {
        throw new Error('BODY_TOO_LARGE');
    }
    const text = await request.text();
    if (text.length > MAX_BODY_SIZE) {
        throw new Error('BODY_TOO_LARGE');
    }
    try {
        return text ? JSON.parse(text) : {};
    } catch (e) {
        throw new Error('INVALID_JSON');
    }
}

// ================================================================
// CONFIG LOADER
// ================================================================
async function loadConfig(kv, db, cache, ctx) {
    const CACHE_KEY = 'https://daimonium.internal/config-v10';
    const cached = await cache.match(CACHE_KEY);
    if (cached) {
        try { return await cached.json(); } catch (e) {}
    }

    const [featuresRow, packagesRow] = await Promise.all([
        db.prepare('SELECT value FROM config WHERE key = ?').bind('features').first(),
        db.prepare('SELECT value FROM config WHERE key = ?').bind('package_prices').first(),
    ]);

    const features = featuresRow ? JSON.parse(featuresRow.value) : {
        stars: true, ton: true, referral: true, tasks: true, walletConnect: true, ads: false
    };
    features.ads = false;

    const packages = packagesRow ? JSON.parse(packagesRow.value) : PACKAGE_DEFINITIONS;
    const data = { features, packages };

    const resp = new Response(JSON.stringify(data), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=86400' }
    });
    ctx.waitUntil(cache.put(CACHE_KEY, resp.clone()));
    return data;
}

// ================================================================
// WELCOME MESSAGE
// ================================================================
async function sendWelcomeMessage(chatId, firstName, botToken) {
    const message = 'Hey ' + firstName + '! 👋\n' +
        'Welcome to Daimonium — your gateway to the future of crypto!\n\n' +
        '💠 For the first time ever on Telegram, you can buy Daimonium tokens at the base price before listing, or collect them completely free along the way!\n\n' +
        '🚀 Why is Daimonium unique?\n' +
        '✅ Early access: Buy & invest before listing\n' +
        '✅ Integrated with the Future Finance App Project\n' +
        '✅ Target market cap: $1B+';

    const keyboard = {
        inline_keyboard: [[
            { text: '🚀 Stars earn more', url: 'https://t.me/Daimonium_bot/Daimonium' }
        ]]
    };

    const res = await fetch('https://api.telegram.org/bot' + botToken + '/sendMessage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: message, reply_markup: keyboard, parse_mode: 'HTML' })
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.description || 'Telegram error');
    return data;
}

// ================================================================
// MAIN HANDLER
// ================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const rawPath = url.pathname;
        const path = normalizePath(rawPath);
        const method = request.method;

        if (method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

        // ============================================================
        // CONFIG — با ولیدیشن امنیتی
        // ============================================================
        const config = {
            TELEGRAM_BOT_TOKEN: env.TELEGRAM_BOT_TOKEN,
            TON_API_KEY: env.TON_API_KEY || '',
            JWT_SECRET: env.JWT_SECRET || '',
            ADMIN_TOKEN: env.ADMIN_TOKEN || '',
            WEBHOOK_SECRET: env.WEBHOOK_SECRET || '',

            USDT_MASTER: {
                mainnet: env.USDT_JETTON_ADDRESS_MAINNET || env.USDT_JETTON_ADDRESS || DEFAULT_USDT_MASTER.mainnet,
                testnet: env.USDT_JETTON_ADDRESS_TESTNET || DEFAULT_USDT_MASTER.testnet,
            },

            TON_RECIPIENT: {
                mainnet: env.TON_RECIPIENT_MAINNET || env.TON_RECIPIENT || DEFAULT_TON_RECIPIENT.mainnet,
                testnet: env.TON_RECIPIENT_TESTNET || DEFAULT_TON_RECIPIENT.testnet,
            },
        };

        // ✅ V10.0 — ولیدیشن سخت‌گیرانه‌ی startup
        if (!config.JWT_SECRET || config.JWT_SECRET.length < MIN_JWT_SECRET_LEN) {
            console.error('🚨 JWT_SECRET missing or too weak (need >= ' + MIN_JWT_SECRET_LEN + ' chars)');
            return errorResponse('SERVER_ERROR', 'Server not properly configured', 500);
        }
        if (!config.TELEGRAM_BOT_TOKEN) {
            console.error('🚨 TELEGRAM_BOT_TOKEN missing');
            return errorResponse('SERVER_ERROR', 'Server not properly configured', 500);
        }

        const db = env.DB;
        const kv = env.KV;
        const cache = caches.default;

        // ============================================================
        // WEBHOOK — ✅ V10.0: SECRET اجباری
        // ============================================================
        if (path === '/webhook' && method === 'POST') {
            // 🔴 اگر secret تنظیم نشده، webhook کاملاً غیرفعال
            if (!config.WEBHOOK_SECRET) {
                console.error('🚨 WEBHOOK_SECRET not set — webhook is DISABLED for security');
                return new Response('Webhook not configured', { status: 503 });
            }

            const got = request.headers.get('X-Telegram-Bot-Api-Secret-Token') || '';
            if (!timingSafeEqual(got, config.WEBHOOK_SECRET)) {
                console.warn('⚠️ Webhook: invalid secret token');
                return new Response('Forbidden', { status: 403 });
            }

            let body;
            try {
                body = await readJsonBody(request);
            } catch (e) {
                return new Response('Bad Request', { status: 400 });
            }

            try {
                // /start
                if (body.message && body.message.text === '/start') {
                    const chatId = body.message.chat.id;
                    const firstName = body.message.from.first_name || 'User';
                    ctx.waitUntil(
                        sendWelcomeMessage(chatId, firstName, config.TELEGRAM_BOT_TOKEN).catch(e => console.error(e))
                    );
                }

                // successful_payment — ✅ V10.0: ATOMIC
                if (body.message && body.message.successful_payment) {
                    const payment = body.message.successful_payment;
                    const payload = payment.invoice_payload;
                    const telegramId = body.message.from.id.toString();

                    if (!payload || typeof payload !== 'string') {
                        return new Response('OK', { headers: CORS_HEADERS });
                    }

                    // ✅ V10.0: فقط اگر status='pending' باشه به paid تغییر می‌کنه
                    //    اگه یک webhook دیگه هم‌زمان رسید، RETURNING خالی برمی‌گردونه
                    const claimed = await db.prepare(
                        `UPDATE payments 
                         SET status = 'paid', updated_at = CURRENT_TIMESTAMP 
                         WHERE invoice_id = ? AND telegram_id = ? AND status = 'pending' 
                         RETURNING id, coins`
                    ).bind(payload, telegramId).first();

                    if (claimed) {
                        await db.prepare(
                            'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ?'
                        ).bind(claimed.coins, telegramId).run();

                        ctx.waitUntil(fetch(
                            'https://api.telegram.org/bot' + config.TELEGRAM_BOT_TOKEN + '/sendMessage',
                            {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    chat_id: telegramId,
                                    text: '✅ Payment confirmed! Your tokens have been added to your balance.'
                                })
                            }
                        ));

                        console.log('✅ [webhook] Payment credited: ' + claimed.coins + ' to ' + telegramId);
                    } else {
                        console.log('ℹ️ [webhook] Duplicate/already-processed payment ignored');
                    }
                }

                return new Response('OK', { headers: CORS_HEADERS });
            } catch (e) {
                console.error('Webhook error:', e);
                return new Response('Error', { status: 500, headers: CORS_HEADERS });
            }
        }

        // ============================================================
        // SETWEBHOOK
        // ============================================================
        if (path === '/setwebhook' && method === 'POST') {
            const auth = request.headers.get('Authorization') || '';
            const adminToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';
            if (!config.ADMIN_TOKEN || !timingSafeEqual(adminToken, config.ADMIN_TOKEN)) {
                return errorResponse('FORBIDDEN', 'Invalid admin token', 403);
            }
            if (!config.WEBHOOK_SECRET) {
                return errorResponse('SERVER_ERROR', 'WEBHOOK_SECRET not set', 500);
            }
            const workerUrl = 'https://' + url.hostname + '/webhook';
            const setUrl = new URL('https://api.telegram.org/bot' + config.TELEGRAM_BOT_TOKEN + '/setWebhook');
            setUrl.searchParams.set('url', workerUrl);
            setUrl.searchParams.set('secret_token', config.WEBHOOK_SECRET);
            const res = await fetch(setUrl.toString());
            const data = await res.json();
            return jsonResponse(data, res.status);
        }

        // ============================================================
        // HEALTH
        // ============================================================
        if (path === '/health' || path === '/') {
            return new Response('✅ Daimonium V10.0 running', { headers: CORS_HEADERS });
        }

        // ============================================================
        // RATE LIMIT — ✅ V10.0: با path نرمال‌شده
        // ============================================================
        if (path !== '/webhook') {
            const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
            const limitKey = 'ip:' + clientIp + ':' + path;
            let limit = 120;
            if (path === '/bootstrap') limit = 60;
            else if (path === '/auth') limit = 60;
            else if (path.startsWith('/payments/')) limit = 30;
            else if (path === '/sync') limit = 60;
            else if (path === '/ton/jetton-wallet') limit = 30;
            else if (path === '/wallet/connect') limit = 10;   // ✅ V10.0: سخت‌گیرانه

            const allowed = await checkRateLimit(kv, limitKey, limit, 60);
            if (!allowed) return errorResponse('RATE_LIMITED', 'Too many requests', 429);
        }

        // ============================================================
        // /ton/jetton-wallet
        // ============================================================
        if (path === '/ton/jetton-wallet' && method === 'GET') {
            try {
                const owner = url.searchParams.get('owner');
                const chainParam = normalizeNetwork(url.searchParams.get('chain')) || 'mainnet';
                const isTestnet = chainParam === 'testnet';

                const master = url.searchParams.get('master') || config.USDT_MASTER[chainParam];

                if (!owner || !master) {
                    return errorResponse('INVALID_REQUEST', 'Missing owner or master', 400);
                }
                if (!verifyTonAddress(owner)) {
                    return errorResponse('INVALID_WALLET', 'Invalid TON address', 400);
                }

                const detected = detectAddressNetwork(owner);
                if (detected && detected !== chainParam) {
                    console.warn('[jetton] chain mismatch: param=' + chainParam + ' detected=' + detected);
                }

                const apiBase = isTestnet ? 'https://testnet.tonapi.io' : 'https://tonapi.io';
                const apiUrl = apiBase + '/v2/accounts/'
                             + encodeURIComponent(owner) + '/jettons/'
                             + encodeURIComponent(master);

                const res = await fetch(apiUrl, {
                    headers: config.TON_API_KEY ? { 'Authorization': 'Bearer ' + config.TON_API_KEY } : {},
                    signal: AbortSignal.timeout(8000),
                });

                if (!res.ok) {
                    return jsonResponse({
                        wallet_address: null,
                        chain: chainParam,
                        error: 'tonapi returned ' + res.status
                    });
                }
                const data = await res.json();
                return jsonResponse({
                    wallet_address: (data.wallet_address && data.wallet_address.address) || null,
                    balance: data.balance || '0',
                    jetton: data.jetton || null,
                    chain: chainParam,
                });
            } catch (e) {
                console.error('Jetton wallet lookup error:', e);
                return jsonResponse({ wallet_address: null, error: 'lookup_failed' });
            }
        }

        // ============================================================
        // /bootstrap
        // ============================================================
        if (path === '/bootstrap' && method === 'GET') {
            try {
                let telegramId = await getUserFromJWT(request, config.JWT_SECRET);

                const initDataHeader = request.headers.get('X-Telegram-Init-Data');
                if (!telegramId && initDataHeader) {
                    const user = await verifyTelegramInitData(initDataHeader, config.TELEGRAM_BOT_TOKEN);
                    if (user) {
                        telegramId = user.id.toString();
                        const username = user.username || '';
                        const firstName = user.first_name || '';

                        const existing = await db.prepare('SELECT id FROM users WHERE telegram_id = ?')
                            .bind(telegramId).first();
                        if (!existing) {
                            await db.prepare(
                                'INSERT INTO users (telegram_id, username, first_name) VALUES (?, ?, ?)'
                            ).bind(telegramId, username, firstName).run();
                        } else {
                            await db.prepare(
                                'UPDATE users SET username = ?, first_name = ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ?'
                            ).bind(username, firstName, telegramId).run();
                        }
                    }
                }

                const configData = await loadConfig(kv, db, cache, ctx);

                if (!telegramId) {
                    return jsonResponse({ config: configData, user: null, token: null });
                }

                const refParam = url.searchParams.get('ref');
                if (refParam && refParam !== telegramId && /^\d+$/.test(refParam)) {
                    const existing = await db.prepare('SELECT id FROM referrals WHERE referred_id = ?')
                        .bind(telegramId).first();
                    if (!existing) {
                        const referrer = await db.prepare('SELECT telegram_id FROM users WHERE telegram_id = ?')
                            .bind(refParam).first();
                        if (referrer) {
                            await db.batch([
                                db.prepare('INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)')
                                    .bind(refParam, telegramId),
                                db.prepare('UPDATE users SET referrals_count = referrals_count + 1, balance = balance + 100 WHERE telegram_id = ?')
                                    .bind(refParam),
                            ]);
                        }
                    }
                }

                const [user, wallet] = await Promise.all([
                    db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first(),
                    db.prepare('SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1')
                        .bind(telegramId).first(),
                ]);

                if (!user) {
                    return jsonResponse({ config: configData, user: null, token: null });
                }

                const token = await generateJWT(
                    { sub: telegramId, userId: user.id, telegramId },
                    config.JWT_SECRET,
                    JWT_EXPIRES
                );

                return jsonResponse({
                    config: configData,
                    user: {
                        telegramId: user.telegram_id,
                        firstName: user.first_name,
                        username: user.username,
                        balance: user.balance || 0,
                        referrals: user.referrals_count || 0,
                        walletAddress: wallet ? wallet.wallet_address : null,
                    },
                    token,
                });
            } catch (e) {
                const err = sanitizeError(e, 'BOOTSTRAP_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /auth
        // ============================================================
        if (path === '/auth' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const initData = body.initData;
                if (!initData) return errorResponse('AUTH_FAILED', 'Missing initData', 400);

                const user = await verifyTelegramInitData(initData, config.TELEGRAM_BOT_TOKEN);
                if (!user) return errorResponse('AUTH_FAILED', 'Invalid initData', 401);

                const telegramId = user.id.toString();
                const username = user.username || '';
                const firstName = user.first_name || '';

                let dbUser = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first();
                if (!dbUser) {
                    await db.prepare('INSERT INTO users (telegram_id, username, first_name) VALUES (?, ?, ?)')
                        .bind(telegramId, username, firstName).run();
                    dbUser = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first();
                } else {
                    await db.prepare('UPDATE users SET username = ?, first_name = ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ?')
                        .bind(username, firstName, telegramId).run();
                }

                const wallet = await db.prepare(
                    'SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId).first();

                const token = await generateJWT(
                    { sub: telegramId, userId: dbUser.id, telegramId },
                    config.JWT_SECRET, JWT_EXPIRES
                );

                return jsonResponse({
                    success: true,
                    token,
                    user: {
                        telegramId,
                        firstName,
                        username,
                        balance: dbUser.balance || 0,
                        referrals: dbUser.referrals_count || 0,
                        walletAddress: wallet ? wallet.wallet_address : null,
                    }
                });
            } catch (e) {
                const err = sanitizeError(e, 'AUTH_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /config
        // ============================================================
        if (path === '/config' && method === 'GET') {
            try {
                const data = await loadConfig(kv, db, cache, ctx);
                return jsonResponse(data, 200, { 'Cache-Control': 'public, max-age=86400' });
            } catch (e) {
                return jsonResponse({
                    features: { stars: true, ton: true, referral: true, tasks: true, walletConnect: true, ads: false },
                    packages: PACKAGE_DEFINITIONS
                }, 200);
            }
        }

        // ============================================================
        // AUTH MIDDLEWARE
        // ============================================================
        const publicPaths = [
            '/auth', '/config', '/webhook', '/setwebhook', '/health', '/',
            '/bootstrap', '/ton/jetton-wallet'
        ];
        let telegramId = null;
        if (!publicPaths.includes(path)) {
            telegramId = await getUserFromJWT(request, config.JWT_SECRET);
            if (!telegramId) {
                return errorResponse('AUTH_FAILED', 'Invalid or missing token', 401);
            }
        }

        // ============================================================
        // /user/verify
        // ============================================================
        if (path === '/user/verify' && method === 'GET') {
            const user = await db.prepare('SELECT telegram_id FROM users WHERE telegram_id = ?').bind(telegramId).first();
            if (!user) return errorResponse('AUTH_FAILED', 'User not found', 401);
            return jsonResponse({ valid: true });
        }

        // ============================================================
        // /user/profile
        // ============================================================
        if (path === '/user/profile' && method === 'GET') {
            const user = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first();
            if (!user) return errorResponse('USER_NOT_FOUND', 'User not found', 404);
            const wallet = await db.prepare(
                'SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1'
            ).bind(telegramId).first();
            return jsonResponse({
                telegramId: user.telegram_id,
                firstName: user.first_name,
                username: user.username,
                balance: user.balance || 0,
                referrals: user.referrals_count || 0,
                walletAddress: wallet ? wallet.wallet_address : null,
            });
        }

        // ============================================================
        // /sync — ✅ V10.0: date validation
        // ============================================================
        if (path === '/sync' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) {
                    if (e.message === 'BODY_TOO_LARGE') return errorResponse('BODY_TOO_LARGE', 'Request too large', 413);
                    return errorResponse('INVALID_REQUEST', 'Invalid body', 400);
                }

                const events = Array.isArray(body.events) ? body.events : [];
                if (events.length === 0) {
                    const u = await db.prepare('SELECT balance, referrals_count FROM users WHERE telegram_id = ?')
                        .bind(telegramId).first();
                    return jsonResponse({
                        success: true,
                        reward: 0,
                        balance: (u && u.balance) || 0,
                        referrals: (u && u.referrals_count) || 0
                    });
                }
                if (events.length > 50) return errorResponse('TOO_MANY_EVENTS', 'Max 50 events per sync', 400);

                // ✅ V10.0 — محاسبه‌ی تاریخ‌های مجاز
                const now = new Date();
                const todayUtc = now.toISOString().split('T')[0];
                const yesterdayUtc = new Date(now.getTime() - 86400000).toISOString().split('T')[0];
                const allowedDates = new Set([todayUtc, yesterdayUtc]);

                let totalReward = 0;
                const batchOps = [];
                const seenTaskKeys = new Set();
                const seenInviteKeys = new Set();

                for (const ev of events) {
                    if (!ev || typeof ev !== 'object' || !ev.type) continue;

                    if (ev.type === 'task_completed') {
                        const taskId = ev.data && ev.data.taskId;
                        const date = ev.data && ev.data.date;
                        const reward = TASK_REWARDS[taskId];
                        if (!reward || !date) continue;
                        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) continue;

                        // ✅ V10.0 — فقط امروز/دیروز
                        if (!allowedDates.has(date)) {
                            console.warn('[sync] rejected old date: ' + date);
                            continue;
                        }

                        const key = taskId + '|' + date;
                        if (seenTaskKeys.has(key)) continue;
                        seenTaskKeys.add(key);

                        const already = await db.prepare(
                            'SELECT id FROM user_tasks WHERE telegram_id = ? AND task_id = ? AND done_date = ?'
                        ).bind(telegramId, taskId, date).first();
                        if (already) continue;

                        batchOps.push(
                            db.prepare('INSERT OR IGNORE INTO user_tasks (telegram_id, task_id, done_date) VALUES (?, ?, ?)')
                                .bind(telegramId, taskId, date)
                        );
                        totalReward += reward;
                    }
                    else if (ev.type === 'invite_claim') {
                        const task = ev.data && ev.data.task;
                        const cfg = REFERRAL_REWARDS[task];
                        if (!cfg) continue;

                        if (seenInviteKeys.has(task)) continue;
                        seenInviteKeys.add(task);

                        const u = await db.prepare('SELECT referrals_count FROM users WHERE telegram_id = ?')
                            .bind(telegramId).first();
                        if (!u || u.referrals_count < cfg.required) continue;

                        const already = await db.prepare('SELECT id FROM referral_rewards WHERE telegram_id = ? AND task = ?')
                            .bind(telegramId, task).first();
                        if (already) continue;

                        batchOps.push(
                            db.prepare('INSERT OR IGNORE INTO referral_rewards (telegram_id, task, reward) VALUES (?, ?, ?)')
                                .bind(telegramId, task, cfg.reward)
                        );
                        totalReward += cfg.reward;
                    }
                    else {
                        batchOps.push(
                            db.prepare('INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)')
                                .bind(telegramId, ev.type, JSON.stringify(ev.data || {}))
                        );
                    }
                }

                if (batchOps.length > 0) {
                    await db.batch(batchOps);
                }

                let newBalance;
                if (totalReward > 0) {
                    newBalance = await db.prepare(
                        'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance, referrals_count'
                    ).bind(totalReward, telegramId).first();
                } else {
                    newBalance = await db.prepare(
                        'SELECT balance, referrals_count FROM users WHERE telegram_id = ?'
                    ).bind(telegramId).first();
                }

                return jsonResponse({
                    success: true,
                    reward: totalReward,
                    balance: (newBalance && newBalance.balance) || 0,
                    referrals: (newBalance && newBalance.referrals_count) || 0,
                });
            } catch (e) {
                const err = sanitizeError(e, 'SYNC_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /user/sync (backward compat)
        // ============================================================
        if (path === '/user/sync' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }
                const events = body.events || [];
                if (events.length > 0) {
                    const ops = events.slice(0, 50).map(ev =>
                        db.prepare('INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)')
                            .bind(telegramId, ev.type, JSON.stringify(ev.data || {}))
                    );
                    await db.batch(ops);
                }
                return jsonResponse({ success: true, count: events.length });
            } catch (e) {
                const err = sanitizeError(e, 'SYNC_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /wallet/connect — ✅ V10.0: strict + audit
        // ============================================================
        if (path === '/wallet/connect' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const walletAddress = body.walletAddress;
                if (!walletAddress) return errorResponse('INVALID_REQUEST', 'Missing walletAddress', 400);
                if (!verifyTonAddress(walletAddress)) return errorResponse('INVALID_WALLET', 'Invalid TON address', 400);

                const network = detectAddressNetwork(walletAddress);
                console.log('🔗 [wallet/connect] user=' + telegramId + ' network=' + network + ' addr=' + walletAddress.substring(0, 10) + '...');

                const existing = await db.prepare(
                    'SELECT id FROM wallets WHERE telegram_id = ? AND wallet_address = ?'
                ).bind(telegramId, walletAddress).first();

                if (existing) {
                    await db.prepare('UPDATE wallets SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
                        .bind(existing.id).run();
                } else {
                    await db.prepare('INSERT INTO wallets (telegram_id, wallet_address) VALUES (?, ?)')
                        .bind(telegramId, walletAddress).run();
                }

                // ✅ V10.0 — audit log
                ctx.waitUntil((async () => {
                    try {
                        await db.prepare(
                            'INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)'
                        ).bind(telegramId, 'wallet_connected', JSON.stringify({
                            wallet: walletAddress,
                            network,
                            ts: Date.now(),
                            ip: request.headers.get('CF-Connecting-IP') || 'unknown'
                        })).run();
                    } catch (e) { /* silent */ }
                })());

                return jsonResponse({ success: true, walletAddress, network });
            } catch (e) {
                const err = sanitizeError(e, 'WALLET_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /wallet/disconnect
        // ============================================================
        if (path === '/wallet/disconnect' && method === 'POST') {
            try {
                await db.prepare('UPDATE wallets SET is_active = 0 WHERE telegram_id = ?').bind(telegramId).run();

                ctx.waitUntil((async () => {
                    try {
                        await db.prepare(
                            'INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)'
                        ).bind(telegramId, 'wallet_disconnected', JSON.stringify({ ts: Date.now() })).run();
                    } catch (e) { /* silent */ }
                })());

                return jsonResponse({ success: true });
            } catch (e) {
                const err = sanitizeError(e, 'WALLET_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /payments/ton/verify
        // ============================================================
        if (path === '/payments/ton/verify' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const packageId = body.packageId;
                if (!packageId) return errorResponse('INVALID_REQUEST', 'Missing packageId', 400);

                const packagesRow = await db.prepare('SELECT value FROM config WHERE key = ?').bind('package_prices').first();
                const packageData = packagesRow ? JSON.parse(packagesRow.value) : PACKAGE_DEFINITIONS;
                const pkg = packageData[packageId];
                if (!pkg) return errorResponse('INVALID_PACKAGE', 'Invalid package', 400);

                const wallet = await db.prepare(
                    'SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId).first();
                if (!wallet) return errorResponse('WALLET_NOT_CONNECTED', 'Connect wallet first', 400);

                const detectedNetwork = detectAddressNetwork(wallet.wallet_address);
                const clientNetwork = normalizeNetwork(body.network);
                const network = detectedNetwork || clientNetwork || 'mainnet';

                console.log('🔎 [ton/verify] user=' + telegramId
                          + ' detected=' + detectedNetwork
                          + ' client=' + clientNetwork
                          + ' final=' + network);

                if (clientNetwork && detectedNetwork && clientNetwork !== detectedNetwork) {
                    return errorResponse(
                        'NETWORK_MISMATCH',
                        'Wallet is on ' + detectedNetwork + ' but request says ' + clientNetwork,
                        400
                    );
                }

                const expectedRecipient = config.TON_RECIPIENT[network];
                const usdtMaster = config.USDT_MASTER[network];

                if (!expectedRecipient || !usdtMaster) {
                    return errorResponse('SERVER_ERROR', 'Missing config for network', 500);
                }

                const match = await findMatchingJettonTransfer(
                    wallet.wallet_address,
                    pkg.usdt,
                    expectedRecipient,
                    usdtMaster,
                    network,
                    config.TON_API_KEY
                );

                if (!match || match.error) {
                    return jsonResponse({
                        verified: false,
                        pending: true,
                        message: 'Waiting for blockchain confirmation...',
                        network,
                    });
                }

                // ✅ V10.0 — atomic claim
                const existing = await db.prepare('SELECT * FROM processed_transactions WHERE tx_hash = ?')
                    .bind(match.txHash).first();
                if (existing) return errorResponse('PAYMENT_REPLAY', 'Already processed', 400);

                // چک second-time برای race condition
                const insertTx = await db.prepare(
                    'INSERT OR IGNORE INTO processed_transactions (tx_hash, telegram_id) VALUES (?, ?) RETURNING id'
                ).bind(match.txHash, telegramId).first();

                if (!insertTx) {
                    return errorResponse('PAYMENT_REPLAY', 'Already processed', 400);
                }

                await db.prepare(
                    'INSERT INTO payments (telegram_id, type, package_id, amount, coins, tx_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
                ).bind(telegramId, 'ton', packageId, pkg.usdt, pkg.coins, match.txHash, 'paid').run();

                const newBal = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(pkg.coins, telegramId).first();

                return jsonResponse({
                    verified: true,
                    coins: pkg.coins,
                    balance: (newBal && newBal.balance) || 0,
                    txHash: match.txHash,
                    network,
                });
            } catch (e) {
                const err = sanitizeError(e, 'PAYMENT_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /payments/stars/create
        // ============================================================
        if (path === '/payments/stars/create' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const packageId = body.packageId;
                if (!packageId) return errorResponse('INVALID_REQUEST', 'Missing packageId', 400);

                const packagesRow = await db.prepare('SELECT value FROM config WHERE key = ?').bind('package_prices').first();
                const packageData = packagesRow ? JSON.parse(packagesRow.value) : PACKAGE_DEFINITIONS;
                const pkg = packageData[packageId];
                if (!pkg) return errorResponse('INVALID_PACKAGE', 'Invalid package', 400);

                const amount = pkg.stars;
                // ✅ V10.0 — payload با nonce تصادفی
                const rand = crypto.randomUUID().replace(/-/g, '').substring(0, 16);
                const invoicePayload = 'stars_' + Date.now() + '_' + telegramId + '_' + rand;

                const res = await fetch('https://api.telegram.org/bot' + config.TELEGRAM_BOT_TOKEN + '/createInvoiceLink', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: 'Daimonium Token Package',
                        description: 'Purchase ' + pkg.coins + ' Daimonium tokens',
                        payload: invoicePayload,
                        currency: 'XTR',
                        prices: [{ label: pkg.coins + ' Daimonium Tokens', amount: amount }],
                    })
                });
                const result = await res.json();
                if (!result.ok) return errorResponse('INVOICE_FAILED', 'Could not create invoice', 500);

                await db.prepare(
                    'INSERT INTO payments (telegram_id, type, package_id, amount, coins, invoice_id, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
                ).bind(telegramId, 'stars', packageId, amount, pkg.coins, invoicePayload, 'pending').run();

                return jsonResponse({ success: true, invoiceLink: result.result, paymentId: invoicePayload });
            } catch (e) {
                const err = sanitizeError(e, 'PAYMENT_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /payments/:id
        // ============================================================
        if (path.startsWith('/payments/') && method === 'GET') {
            try {
                const paymentId = path.split('/')[2];
                if (!paymentId) return errorResponse('INVALID_REQUEST', 'Missing payment id', 400);

                const payment = await db.prepare(
                    'SELECT * FROM payments WHERE telegram_id = ? AND (id = ? OR invoice_id = ? OR tx_hash = ?) ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId, paymentId, paymentId, paymentId).first();
                if (!payment) return errorResponse('PAYMENT_NOT_FOUND', 'Payment not found', 404);

                if (payment.status === 'pending') {
                    const created = new Date(payment.created_at);
                    if ((Date.now() - created.getTime()) / 1000 > 600) {
                        await db.prepare('UPDATE payments SET status = ? WHERE id = ?').bind('expired', payment.id).run();
                        payment.status = 'expired';
                    }
                }

                const balance = await db.prepare('SELECT balance FROM users WHERE telegram_id = ?').bind(telegramId).first();
                return jsonResponse({
                    id: payment.id,
                    status: payment.status,
                    coins: payment.coins,
                    amount: payment.amount,
                    type: payment.type,
                    packageId: payment.package_id,
                    createdAt: payment.created_at,
                    balance: (balance && balance.balance) || 0,
                });
            } catch (e) {
                const err = sanitizeError(e, 'PAYMENT_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /tasks/complete
        // ============================================================
        if (path === '/tasks/complete' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const taskId = body.taskId;
                if (!taskId) return errorResponse('INVALID_REQUEST', 'Missing taskId', 400);

                const reward = TASK_REWARDS[taskId];
                if (!reward) return errorResponse('INVALID_TASK', 'Invalid task', 400);

                const done = await db.prepare(
                    'SELECT * FROM user_tasks WHERE telegram_id = ? AND task_id = ? AND done_date = date("now")'
                ).bind(telegramId, taskId).first();
                if (done) return errorResponse('TASK_ALREADY_DONE', 'Already done today', 400);

                await db.prepare('INSERT OR IGNORE INTO user_tasks (telegram_id, task_id, done_date) VALUES (?, ?, date("now"))')
                    .bind(telegramId, taskId).run();

                const newBalance = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(reward, telegramId).first();

                return jsonResponse({ success: true, reward, balance: (newBalance && newBalance.balance) || 0 });
            } catch (e) {
                const err = sanitizeError(e, 'TASK_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /ads/reward
        // ============================================================
        if (path === '/ads/reward' && method === 'POST') {
            return errorResponse('ADS_DISABLED', 'Ad task is coming soon', 400);
        }

        // ============================================================
        // /referral/register
        // ============================================================
        if (path === '/referral/register' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const referrerId = body.referrerId;
                if (!referrerId || referrerId === telegramId) {
                    return errorResponse('INVALID_REFERRAL', 'Invalid referrer', 400);
                }
                if (!/^\d+$/.test(String(referrerId))) {
                    return errorResponse('INVALID_REFERRAL', 'Invalid referrer format', 400);
                }

                const existing = await db.prepare('SELECT * FROM referrals WHERE referred_id = ?').bind(telegramId).first();
                if (existing) return errorResponse('ALREADY_REFERRED', 'Already referred', 400);

                const referrer = await db.prepare('SELECT telegram_id FROM users WHERE telegram_id = ?').bind(referrerId).first();
                if (!referrer) return errorResponse('REFERRER_NOT_FOUND', 'Referrer not found', 404);

                await db.batch([
                    db.prepare('INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)').bind(referrerId, telegramId),
                    db.prepare('UPDATE users SET referrals_count = referrals_count + 1, balance = balance + 100 WHERE telegram_id = ?').bind(referrerId),
                ]);

                return jsonResponse({ success: true });
            } catch (e) {
                const err = sanitizeError(e, 'REFERRAL_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // /referral/claim
        // ============================================================
        if (path === '/referral/claim' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const task = body.task;
                const cfg = REFERRAL_REWARDS[task];
                if (!cfg) return errorResponse('INVALID_TASK', 'Invalid task', 400);

                const claimed = await db.prepare('SELECT * FROM referral_rewards WHERE telegram_id = ? AND task = ?')
                    .bind(telegramId, task).first();
                if (claimed) return errorResponse('ALREADY_CLAIMED', 'Already claimed', 400);

                const user = await db.prepare('SELECT referrals_count FROM users WHERE telegram_id = ?').bind(telegramId).first();
                const count = (user && user.referrals_count) || 0;
                if (count < cfg.required) {
                    return errorResponse('NOT_ENOUGH', 'Need ' + (cfg.required - count) + ' more', 400);
                }

                await db.prepare('INSERT OR IGNORE INTO referral_rewards (telegram_id, task, reward) VALUES (?, ?, ?)')
                    .bind(telegramId, task, cfg.reward).run();

                const newBal = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(cfg.reward, telegramId).first();

                return jsonResponse({
                    success: true,
                    reward: cfg.reward,
                    balance: (newBal && newBal.balance) || 0,
                    referrals: count
                });
            } catch (e) {
                const err = sanitizeError(e, 'REFERRAL_ERROR');
                return errorResponse(err.code, err.message, 500);
            }
        }

        // ============================================================
        // 404
        // ============================================================
        return errorResponse('NOT_FOUND', 'Endpoint not found', 404);
    }
};
