// ================================================================
// DAIMONIUM BACKEND — Cloudflare Worker
// نسخه V10.2 — Mainnet-only + Jetton presets (hardcoded)
// ================================================================
// تغییرات نسبت به V10.1:
//   🔴 testnet کاملاً حذف شد
//   🔴 Jetton config از env به hardcoded (بدون نیاز به Cloudflare vars)
//   🔴 سوییچ NOT ↔ USDT با یک خط (تغییر ACTIVE_JETTON)
//   🟡 تمام fix های امنیتی حفظ شده
// ================================================================

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Telegram-Init-Data',
    'Access-Control-Max-Age': '86400',
};

// ================================================================
// 🎯 ACTIVE JETTON — این خط رو برای سوییچ عوض کن
// ================================================================
//   'NOT'  → تست با Notcoin
//   'USDT' → production با Tether USD
// ================================================================
const ACTIVE_JETTON = 'USDT';

const JETTON_PRESETS = {
    NOT: {
        master: 'EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT',
        decimals: 9,
        symbol: 'NOT',
    },
    USDT: {
        master: 'EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs',
        decimals: 6,
        symbol: 'USDT',
    },
};

const JETTON = JETTON_PRESETS[ACTIVE_JETTON];

// آدرس گیرنده — این رو با آدرس ولت اصلی خودت عوض کن
const TON_RECIPIENT = 'UQBVTscttZ6fcfyHZu2kpDUVbC1QHEDvl-hJhv8YRrLIih7P';

// ================================================================
// PACKAGE DEFINITIONS
// ================================================================
const PACKAGE_DEFINITIONS = {
    package_1: { coins: 10000,    amount: 1,   stars: 100 },
    package_2: { coins: 80000,    amount: 5,   stars: 500 },
    package_3: { coins: 200000,   amount: 10,  stars: 1000 },
    package_4: { coins: 1000000,  amount: 50,  stars: 5000 },
    package_5: { coins: 3000000,  amount: 100, stars: 10000 },
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

const CONFIG_CACHE_TTL = 7 * 24 * 60 * 60;
const JWT_EXPIRES = 30 * 24 * 60 * 60;
const MAX_BODY_SIZE = 64 * 1024;
const MIN_JWT_SECRET_LEN = 32;
const IS_PRODUCTION = true;

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

function sanitizeError(err, fallbackCode = 'SERVER_ERROR') {
    if (IS_PRODUCTION) {
        console.error('[sanitized]', err.message || err);
        return { code: fallbackCode, message: 'Something went wrong. Please try again.' };
    }
    return { code: fallbackCode, message: (err && err.message) || 'Unknown error' };
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

function normalizePath(path) {
    let p = path.split('?')[0];
    p = p.replace(/\/{2,}/g, '/');
    p = p.replace(/\/+$/, '');
    if (p === '') p = '/';
    return p.toLowerCase();
}

// ================================================================
// TON ADDRESS — CRC16 + Validation (mainnet-only)
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

// ✅ Mainnet-only: فقط EQ و UQ قبول می‌شن
function verifyTonAddress(address) {
    if (typeof address !== 'string') return false;
    if (address.length !== 48) return false;
    if (!address.startsWith('EQ') && !address.startsWith('UQ')) return false;
    if (!/^[A-Za-z0-9\-_]+$/.test(address)) return false;

    try {
        let clean = address.replace(/-/g, '+').replace(/_/g, '/');
        while (clean.length % 4) clean += '=';
        const raw = atob(clean);
        if (raw.length !== 36) return false;

        const bytes = new Uint8Array(36);
        for (let i = 0; i < 36; i++) bytes[i] = raw.charCodeAt(i);

        // Mainnet tags: 0x11 (EQ) یا 0x51 (UQ)
        const tag = bytes[0];
        if (tag !== 0x11 && tag !== 0x51) return false;

        const expectedCrc = (bytes[34] << 8) | bytes[35];
        const actualCrc = crc16Ton(bytes.slice(0, 34));
        if (expectedCrc !== actualCrc) return false;

        return true;
    } catch (e) {
        return false;
    }
}

function isValidTonAddress(address) {
    return verifyTonAddress(address);
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
// TELEGRAM INITDATA
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

        if (!timingSafeEqual(calculatedHex, hash)) return null;

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
async function findMatchingJettonTransfer(
    senderWallet,
    expectedAmount,
    ourAddress,
    jettonMaster,
    decimals,
    apiKey
) {
    try {
        const url = 'https://tonapi.io/v2/accounts/'
                  + encodeURIComponent(senderWallet) + '/events?limit=20';
        const res = await fetch(url, {
            headers: apiKey ? { 'Authorization': 'Bearer ' + apiKey } : {}
        });
        if (!res.ok) return { error: 'TON API returned ' + res.status };
        const data = await res.json();

        const expectedRawAmount = Math.round(expectedAmount * Math.pow(10, decimals));
        const ourHash = tonAddressHash(ourAddress);
        const jettonHash = tonAddressHash(jettonMaster);
        const now = Math.floor(Date.now() / 1000);

        console.log('🔍 [ton-verify] amount=' + expectedAmount
                  + ' (raw=' + expectedRawAmount + ', decimals=' + decimals + ')');

        for (const ev of data.events || []) {
            if (ev.timestamp && (now - ev.timestamp) > 600) continue;
            for (const act of ev.actions || []) {
                if (act.type !== 'JettonTransfer') continue;
                const jt = act.JettonTransfer;
                if (!jt) continue;
                if (tonAddressHash(jt.jetton && jt.jetton.address) !== jettonHash) continue;
                if (tonAddressHash(jt.recipient && jt.recipient.address) !== ourHash) continue;
                if (parseInt(jt.amount, 10) !== expectedRawAmount) continue;
                return {
                    txHash: ev.event_id || ev.lt,
                    sender: (jt.sender && jt.sender.address) || senderWallet,
                    amount: expectedAmount,
                    rawAmount: expectedRawAmount,
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
// BODY READER
// ================================================================
async function readJsonBody(request) {
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > MAX_BODY_SIZE) throw new Error('BODY_TOO_LARGE');
    const text = await request.text();
    if (text.length > MAX_BODY_SIZE) throw new Error('BODY_TOO_LARGE');
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
    const CACHE_KEY = 'https://daimonium.internal/config-v12';
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
        // CONFIG
        // ============================================================
        const config = {
            TELEGRAM_BOT_TOKEN: env.TELEGRAM_BOT_TOKEN,
            TON_API_KEY: env.TON_API_KEY || '',
            JWT_SECRET: env.JWT_SECRET || '',
            ADMIN_TOKEN: env.ADMIN_TOKEN || '',
            WEBHOOK_SECRET: env.WEBHOOK_SECRET || '',
        };

        // ولیدیشن startup
        if (!config.JWT_SECRET || config.JWT_SECRET.length < MIN_JWT_SECRET_LEN) {
            console.error('🚨 JWT_SECRET missing or too weak');
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
        // WEBHOOK
        // ============================================================
        if (path === '/webhook' && method === 'POST') {
            if (!config.WEBHOOK_SECRET) {
                console.error('🚨 WEBHOOK_SECRET not set');
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
                if (body.message && body.message.text === '/start') {
                    const chatId = body.message.chat.id;
                    const firstName = body.message.from.first_name || 'User';
                    ctx.waitUntil(
                        sendWelcomeMessage(chatId, firstName, config.TELEGRAM_BOT_TOKEN).catch(e => console.error(e))
                    );
                }

                if (body.message && body.message.successful_payment) {
                    const payment = body.message.successful_payment;
                    const payload = payment.invoice_payload;
                    const telegramId = body.message.from.id.toString();

                    if (!payload || typeof payload !== 'string') {
                        return new Response('OK', { headers: CORS_HEADERS });
                    }

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

                        console.log('✅ [webhook] Payment credited: ' + claimed.coins);
                    } else {
                        console.log('ℹ️ [webhook] Duplicate payment ignored');
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
            return new Response(
                '✅ Daimonium V10.2 running\n' +
                'Network: mainnet only\n' +
                'Active Jetton: ' + JETTON.symbol + ' (' + JETTON.decimals + ' decimals)\n' +
                'Jetton Master: ' + JETTON.master + '\n' +
                'Recipient: ' + TON_RECIPIENT,
                { headers: CORS_HEADERS }
            );
        }

        // ============================================================
        // RATE LIMIT
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
            else if (path === '/wallet/connect') limit = 10;

            const allowed = await checkRateLimit(kv, limitKey, limit, 60);
            if (!allowed) return errorResponse('RATE_LIMITED', 'Too many requests', 429);
        }

        // ============================================================
        // /ton/jetton-wallet
        // ============================================================
        if (path === '/ton/jetton-wallet' && method === 'GET') {
            try {
                const owner = url.searchParams.get('owner');
                // ✅ master از کلاینت پذیرفته می‌شه ولی فقط اگه معتبر باشه
                //    در غیر این صورت از ACTIVE_JETTON استفاده می‌کنیم
                const clientMaster = url.searchParams.get('master');
                const master = (clientMaster && /^[EUk0]Q[A-Za-z0-9\-_]{46}$/.test(clientMaster))
                             ? clientMaster
                             : JETTON.master;

                if (!owner) {
                    return errorResponse('INVALID_REQUEST', 'Missing owner', 400);
                }
                if (!verifyTonAddress(owner)) {
                    return errorResponse('INVALID_WALLET', 'Invalid TON address', 400);
                }

                const apiUrl = 'https://tonapi.io/v2/accounts/'
                             + encodeURIComponent(owner) + '/jettons/'
                             + encodeURIComponent(master);

                const res = await fetch(apiUrl, {
                    headers: config.TON_API_KEY ? { 'Authorization': 'Bearer ' + config.TON_API_KEY } : {},
                    signal: AbortSignal.timeout(8000),
                });

                if (!res.ok) {
                    return jsonResponse({
                        wallet_address: null,
                        symbol: JETTON.symbol,
                        error: 'tonapi returned ' + res.status
                    });
                }
                const data = await res.json();
                return jsonResponse({
                    wallet_address: (data.wallet_address && data.wallet_address.address) || null,
                    balance: data.balance || '0',
                    jetton: data.jetton || null,
                    symbol: JETTON.symbol,
                    decimals: JETTON.decimals,
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
        // /sync
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
        // /wallet/connect
        // ============================================================
        if (path === '/wallet/connect' && method === 'POST') {
            try {
                let body;
                try { body = await readJsonBody(request); }
                catch (e) { return errorResponse('INVALID_REQUEST', 'Invalid body', 400); }

                const walletAddress = body.walletAddress;
                if (!walletAddress) return errorResponse('INVALID_REQUEST', 'Missing walletAddress', 400);
                if (!verifyTonAddress(walletAddress)) return errorResponse('INVALID_WALLET', 'Invalid TON address', 400);

                console.log('🔗 [wallet/connect] user=' + telegramId + ' addr=' + walletAddress.substring(0, 10) + '...');

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

                ctx.waitUntil((async () => {
                    try {
                        await db.prepare(
                            'INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)'
                        ).bind(telegramId, 'wallet_connected', JSON.stringify({
                            wallet: walletAddress,
                            ts: Date.now(),
                            ip: request.headers.get('CF-Connecting-IP') || 'unknown'
                        })).run();
                    } catch (e) { /* silent */ }
                })());

                return jsonResponse({ success: true, walletAddress });
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

                // ✅ مقدار پرداخت — هم از usdt قبلی، هم از amount جدید
                const expectedAmount = pkg.amount !== undefined ? pkg.amount : pkg.usdt;
                if (expectedAmount === undefined) {
                    return errorResponse('SERVER_ERROR', 'Package amount missing', 500);
                }

                const wallet = await db.prepare(
                    'SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId).first();
                if (!wallet) return errorResponse('WALLET_NOT_CONNECTED', 'Connect wallet first', 400);

                console.log('🔎 [ton/verify] user=' + telegramId
                          + ' pkg=' + packageId
                          + ' amount=' + expectedAmount + ' ' + JETTON.symbol);

                const match = await findMatchingJettonTransfer(
                    wallet.wallet_address,
                    expectedAmount,
                    TON_RECIPIENT,
                    JETTON.master,
                    JETTON.decimals,
                    config.TON_API_KEY
                );

                if (!match || match.error) {
                    return jsonResponse({
                        verified: false,
                        pending: true,
                        message: 'Waiting for blockchain confirmation...',
                        jetton: JETTON.symbol,
                    });
                }

                const existing = await db.prepare('SELECT * FROM processed_transactions WHERE tx_hash = ?')
                    .bind(match.txHash).first();
                if (existing) return errorResponse('PAYMENT_REPLAY', 'Already processed', 400);

                const insertTx = await db.prepare(
                    'INSERT OR IGNORE INTO processed_transactions (tx_hash, telegram_id) VALUES (?, ?) RETURNING id'
                ).bind(match.txHash, telegramId).first();

                if (!insertTx) {
                    return errorResponse('PAYMENT_REPLAY', 'Already processed', 400);
                }

                await db.prepare(
                    'INSERT INTO payments (telegram_id, type, package_id, amount, coins, tx_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
                ).bind(telegramId, 'ton', packageId, expectedAmount, pkg.coins, match.txHash, 'paid').run();

                const newBal = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(pkg.coins, telegramId).first();

                console.log('✅ [ton/verify] Payment verified: ' + pkg.coins + ' coins');

                return jsonResponse({
                    verified: true,
                    coins: pkg.coins,
                    balance: (newBal && newBal.balance) || 0,
                    txHash: match.txHash,
                    jetton: JETTON.symbol,
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
