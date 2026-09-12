// ================================================================
// DAIMONIUM BACKEND - Cloudflare Worker (Full Integrated)
// نسخه V2.2 - افزودن لاگ‌های تشخیصی
// ================================================================

// ================================================================
// CONSTANTS
// ================================================================
const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

const PACKAGE_DEFINITIONS = {
    package_1: { coins: 10000, usdt: 1, stars: 100 },
    package_2: { coins: 80000, usdt: 5, stars: 500 },
    package_3: { coins: 200000, usdt: 10, stars: 1000 },
    package_4: { coins: 1000000, usdt: 50, stars: 5000 },
    package_5: { coins: 3000000, usdt: 100, stars: 10000 },
};

const TASK_REWARDS = {
    task1: 100,
    task2: 100,
    ad_watch: 150,
};

const CONFIG_CACHE_TTL = 7 * 24 * 60 * 60;

// ================================================================
// HELPERS
// ================================================================
function jsonResponse(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            ...CORS_HEADERS,
            ...headers,
        }
    });
}

function errorResponse(code, message, status = 400) {
    return jsonResponse({ code, message }, status);
}

// ================================================================
// VALIDATION
// ================================================================
function isValidTonAddress(address) {
    if (typeof address !== 'string') return false;
    if (address.length < 48 || address.length > 52) return false;
    if (!address.startsWith('EQ') && !address.startsWith('UQ')) return false;
    if (!/^[A-Za-z0-9\-_]+$/.test(address)) return false;
    return true;
}

// ================================================================
// JWT (با Web Crypto API)
// ================================================================
function base64UrlEncode(data) {
    return btoa(JSON.stringify(data))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return JSON.parse(atob(str));
}

async function generateJWT(payload, secret, expiresIn = 604800) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const exp = now + expiresIn;
    const data = { ...payload, iat: now, exp };
    const encodedHeader = base64UrlEncode(header);
    const encodedPayload = base64UrlEncode(data);
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(encodedHeader + '.' + encodedPayload)
    );
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    return encodedHeader + '.' + encodedPayload + '.' + encodedSignature;
}

async function verifyJWT(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Invalid token format');
        const [header, payload, signature] = parts;
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );
        const expected = await crypto.subtle.verify(
            'HMAC',
            key,
            Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            new TextEncoder().encode(header + '.' + payload)
        );
        if (!expected) throw new Error('Invalid signature');
        const data = base64UrlDecode(payload);
        if (data.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
        return data;
    } catch (e) {
        throw new Error('Invalid token: ' + e.message);
    }
}

// ================================================================
// TELEGRAM initData VERIFICATION
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
            'raw',
            new TextEncoder().encode('WebAppData'),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const secret = await crypto.subtle.sign('HMAC', secretKey, new TextEncoder().encode(botToken));
        const signatureKey = await crypto.subtle.importKey(
            'raw',
            secret,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const calculatedHash = await crypto.subtle.sign('HMAC', signatureKey, new TextEncoder().encode(dataCheckString));
        const calculatedHex = Array.from(new Uint8Array(calculatedHash)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (calculatedHex !== hash) return null;
        const userStr = params.get('user');
        if (!userStr) return null;
        return JSON.parse(decodeURIComponent(userStr));
    } catch (e) {
        console.error('Telegram verification error:', e);
        return null;
    }
}

// ================================================================
// TON VERIFICATION
// ================================================================
async function verifyTonTransaction(boc, expectedAmount, expectedRecipient, tonApiKey) {
    try {
        const response = await fetch(
            'https://toncenter.com/api/v2/decrypt?boc=' + encodeURIComponent(boc),
            {
                headers: tonApiKey ? { 'X-API-Key': tonApiKey } : {}
            }
        );
        if (!response.ok) throw new Error('TON API error: ' + response.status);
        const data = await response.json();
        if (!data.ok) throw new Error('Invalid BOC: ' + (data.error || 'unknown'));

        const tx = data.result;
        const sender = tx.source || tx.in_msg?.source || null;
        const recipient = tx.destination || tx.in_msg?.destination || null;
        const amount = tx.value || tx.in_msg?.value || 0;
        const txHash = tx.transaction_id?.hash || tx.hash || null;

        if (!sender || !recipient || !txHash) {
            return { valid: false, error: 'Missing transaction data' };
        }
        if (recipient.toLowerCase() !== expectedRecipient.toLowerCase()) {
            return { valid: false, error: 'Recipient mismatch' };
        }
        const amountTon = parseFloat(amount) / 1e9;
        if (Math.abs(amountTon - expectedAmount) > 0.0001) {
            return { valid: false, error: 'Amount mismatch' };
        }

        return { valid: true, sender, recipient, amount: amountTon, txHash };
    } catch (e) {
        console.error('TON verification error:', e);
        return { valid: false, error: e.message };
    }
}

// ================================================================
// RATE LIMITER
// ================================================================
async function checkRateLimit(kv, key, limit, windowSeconds) {
    const now = Math.floor(Date.now() / 1000);
    const windowKey = Math.floor(now / windowSeconds);
    const kvKey = `ratelimit:${key}:${windowKey}`;
    const current = await kv.get(kvKey, 'json');
    if (current === null) {
        await kv.put(kvKey, JSON.stringify({ count: 1 }), { expirationTtl: windowSeconds + 10 });
        return true;
    }
    if (current.count >= limit) {
        return false;
    }
    await kv.put(kvKey, JSON.stringify({ count: current.count + 1 }), { expirationTtl: windowSeconds + 10 });
    return true;
}

// ================================================================
// MIDDLEWARE: دریافت کاربر از JWT
// ================================================================
async function getUserFromJWT(request, secret) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    try {
        const token = authHeader.substring(7);
        const payload = await verifyJWT(token, secret);
        return payload.telegramId;
    } catch (e) {
        return null;
    }
}

// ================================================================
// BOT FUNCTIONS
// ================================================================
async function sendWelcomeMessage(chatId, firstName, botToken) {
    console.log('========== SEND MESSAGE ==========');
    console.log('chatId type:', typeof chatId);
    console.log('chatId value:', chatId);
    console.log('firstName:', firstName);
    console.log('token exists:', !!botToken);
    console.log('token length:', botToken ? botToken.length : 0);

    const message = `Hey ${firstName}! 👋
Welcome to Daimonium — your gateway to the future of crypto!

💠 For the first time ever on Telegram, you can buy Daimonium tokens at the base price before listing, or collect them completely free along the way!

🚀 Why is Daimonium unique?
✅ Early access: Buy & invest before listing (no other mini app allows this!)
✅ Integrated with the Future Finance App Project. Your tokens will have real utility
✅ Target market cap: $1B+`;

    console.log('Message length:', message.length);
    console.log('Message preview:', message.substring(0, 200));

    const keyboard = {
        inline_keyboard: [
            [
                { text: '🚀 Stars earn more', url: 'https://t.me/Daimonium_bot/Daimonium' }
            ]
        ]
    };

    const payload = {
        chat_id: chatId,
        text: message,
        reply_markup: keyboard,
        parse_mode: 'HTML'
    };

    let body;
    try {
        body = JSON.stringify(payload);
        console.log('Payload size:', body.length);
        console.log('Payload:', body);
    } catch (err) {
        console.error('JSON stringify failed:', err);
        throw err;
    }

    const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
    console.log('Sending request to Telegram');

    let response;
    try {
        response = await fetch(telegramUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body
        });
        console.log('Fetch completed');
    } catch (fetchError) {
        console.error('Fetch failed:', fetchError);
        throw fetchError;
    }

    console.log('Status:', response.status);
    console.log('StatusText:', response.statusText);

    const rawBody = await response.text();
    console.log('Telegram response:', rawBody);

    let telegramResult;
    try {
        telegramResult = JSON.parse(rawBody);
    } catch {
        throw new Error('Telegram returned invalid JSON');
    }

    console.log('Telegram OK:', telegramResult.ok);

    if (!telegramResult.ok) {
        console.error('Telegram Error:', telegramResult);
        throw new Error(telegramResult.description || 'Unknown Telegram Error');
    }

    console.log('Message sent successfully');
    return response;
}

// ================================================================
// HANDLER PRINCIPAL
// ================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // CORS
        if (method === 'OPTIONS') {
            return new Response(null, { headers: CORS_HEADERS });
        }

        // Load config from env
        const config = {
            TELEGRAM_BOT_TOKEN: env.TELEGRAM_BOT_TOKEN,
            TON_API_KEY: env.TON_API_KEY || '',
            JWT_SECRET: env.JWT_SECRET,
            TON_RECIPIENT_FALLBACK: env.TON_RECIPIENT || null,
            USDT_JETTON_ADDRESS: env.USDT_JETTON_ADDRESS || 'EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2E_sFs',
        };

        if (!config.JWT_SECRET) {
            console.error('JWT_SECRET not set');
            return errorResponse('SERVER_ERROR', 'JWT secret not configured', 500);
        }
        if (!config.TELEGRAM_BOT_TOKEN) {
            console.error('TELEGRAM_BOT_TOKEN not set');
            return errorResponse('SERVER_ERROR', 'Telegram bot token not configured', 500);
        }

        const db = env.DB;
        const kv = env.KV;

        // ============================================================
        // BOT WEBHOOK: /webhook
        // ============================================================
        if (path === '/webhook' && method === 'POST') {
            console.log('========== WEBHOOK START ==========');
            console.log('Method:', request.method);
            console.log('Path:', path);

            try {
                const update = await request.json();
                console.log('Update:', JSON.stringify(update));

                // پردازش پیام‌های معمولی (مثل دستور /start)
                if (update.message) {
                    console.log('Message detected');
                    console.log('Text:', update.message.text);
                    console.log('Chat ID:', update.message.chat?.id);
                    console.log('User:', update.message.from?.first_name);

                    const chatId = update.message.chat.id;
                    const firstName = update.message.from.first_name || 'User';
                    const text = update.message.text || '';

                    if (text === '/start') {
                        console.log('Calling sendWelcomeMessage...');
                        await sendWelcomeMessage(chatId, firstName, config.TELEGRAM_BOT_TOKEN);
                        console.log('sendWelcomeMessage completed');
                    }
                }

                // پردازش رویدادهای پرداخت موفق Stars
                if (update.message && update.message.successful_payment) {
                    const payment = update.message.successful_payment;
                    const payload = payment.invoice_payload;
                    const telegramId = update.message.from.id.toString();

                    const result = await db.prepare(
                        'UPDATE payments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE invoice_id = ? AND telegram_id = ?'
                    ).bind('paid', payload, telegramId).run();

                    if (result.changes > 0) {
                        const payRecord = await db.prepare(
                            'SELECT * FROM payments WHERE invoice_id = ? AND telegram_id = ?'
                        ).bind(payload, telegramId).first();

                        if (payRecord) {
                            await db.prepare(
                                'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ?'
                            ).bind(payRecord.coins, telegramId).run();

                            await fetch('https://api.telegram.org/bot' + config.TELEGRAM_BOT_TOKEN + '/sendMessage', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    chat_id: telegramId,
                                    text: '✅ Payment confirmed! Your tokens have been added to your balance.',
                                })
                            });
                        }
                    } else {
                        console.warn('Payment record not found for payload:', payload);
                    }
                }

                return new Response('OK', { headers: CORS_HEADERS });
            } catch (error) {
                console.error('Webhook error:', error);
                return new Response('Error: ' + error.message, { status: 500, headers: CORS_HEADERS });
            }
        }

        // ============================================================
        // SETWEBHOOK
        // ============================================================
        if (path === '/setwebhook' && method === 'GET') {
            try {
                const workerUrl = `https://${url.hostname}/webhook`;

                const response = await fetch(
                    `https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/setWebhook?url=${encodeURIComponent(workerUrl)}`
                );
                const result = await response.json();

                return new Response(JSON.stringify(result, null, 2), {
                    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
                });
            } catch (error) {
                return new Response('Error: ' + error.message, { status: 500, headers: CORS_HEADERS });
            }
        }

        // ============================================================
        // HEALTH CHECK
        // ============================================================
        if (path === '/health' || path === '/') {
            return new Response('✅ Daimonium Backend is running!', { headers: CORS_HEADERS });
        }

        // ============================================================
        // RATE LIMITING (به جز webhook)
        // ============================================================
        if (path !== '/webhook') {
            const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
            const limitKey = `ip:${clientIp}`;
            let limit = 100;
            if (path === '/auth') limit = 20;
            else if (path.startsWith('/payments/')) limit = 30;
            else if (path.startsWith('/tasks/')) limit = 50;
            else if (path.startsWith('/referral/')) limit = 30;
            else if (path === '/user/verify') limit = 100;
            const allowed = await checkRateLimit(kv, limitKey, limit, 60);
            if (!allowed) {
                return errorResponse('RATE_LIMITED', 'Too many requests', 429);
            }
        }

        // ============================================================
        // 1. POST /auth
        // ============================================================
        if (path === '/auth' && method === 'POST') {
            try {
                const body = await request.json();
                const initData = body.initData;
                if (!initData) {
                    return errorResponse('AUTH_FAILED', 'Missing initData', 400);
                }

                const user = await verifyTelegramInitData(initData, config.TELEGRAM_BOT_TOKEN);
                if (!user) {
                    return errorResponse('AUTH_FAILED', 'Invalid initData', 401);
                }

                const telegramId = user.id.toString();
                const username = user.username || '';
                const firstName = user.first_name || '';

                let dbUser = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first();
                if (!dbUser) {
                    await db.prepare(
                        'INSERT INTO users (telegram_id, username, first_name) VALUES (?, ?, ?)'
                    ).bind(telegramId, username, firstName).run();
                    dbUser = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first();
                } else {
                    await db.prepare(
                        'UPDATE users SET username = ?, first_name = ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ?'
                    ).bind(username, firstName, telegramId).run();
                }

                const wallet = await db.prepare(
                    'SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId).first();
                const walletAddress = wallet?.wallet_address || null;

                const token = await generateJWT({
                    sub: telegramId,
                    userId: dbUser.id,
                    telegramId: telegramId,
                }, config.JWT_SECRET, 604800);

                return jsonResponse({
                    success: true,
                    token: token,
                    user: {
                        telegramId: telegramId,
                        firstName: firstName,
                        username: username,
                        balance: dbUser.balance || 0,
                        referrals: dbUser.referrals_count || 0,
                        walletAddress: walletAddress,
                    }
                });
            } catch (e) {
                console.error('Auth error:', e);
                return errorResponse('AUTH_FAILED', e.message, 500);
            }
        }

        // ============================================================
        // 2. GET /user/verify
        // ============================================================
        if (path === '/user/verify' && method === 'GET') {
            try {
                const telegramId = await getUserFromJWT(request, config.JWT_SECRET);
                if (!telegramId) {
                    return errorResponse('AUTH_FAILED', 'Invalid or missing token', 401);
                }
                const user = await db.prepare('SELECT telegram_id FROM users WHERE telegram_id = ?').bind(telegramId).first();
                if (!user) {
                    return errorResponse('AUTH_FAILED', 'User not found', 401);
                }
                return jsonResponse({ valid: true });
            } catch (e) {
                return jsonResponse({ valid: false }, 401);
            }
        }

        // ============================================================
        // 3. GET /config
        // ============================================================
        if (path === '/config' && method === 'GET') {
            try {
                let cached = await kv.get('config_cache');
                if (cached) {
                    const parsed = JSON.parse(cached);
                    return jsonResponse(parsed, 200, {
                        'Cache-Control': 'public, max-age=604800',
                    });
                }

                const features = await db.prepare('SELECT value FROM config WHERE key = ?').bind('features').first();
                const packages = await db.prepare('SELECT value FROM config WHERE key = ?').bind('package_prices').first();

                const configData = {
                    features: features ? JSON.parse(features.value) : {
                        stars: true,
                        ton: true,
                        referral: true,
                        tasks: true,
                        walletConnect: true,
                        ads: true,
                    },
                    packages: packages ? JSON.parse(packages.value) : PACKAGE_DEFINITIONS
                };

                await kv.put('config_cache', JSON.stringify(configData), { expirationTtl: CONFIG_CACHE_TTL });

                return jsonResponse(configData, 200, {
                    'Cache-Control': 'public, max-age=604800',
                });
            } catch (e) {
                console.error('Config error:', e);
                return jsonResponse({
                    features: {
                        stars: true,
                        ton: true,
                        referral: true,
                        tasks: true,
                        walletConnect: true,
                        ads: true,
                    },
                    packages: PACKAGE_DEFINITIONS
                }, 200, {
                    'Cache-Control': 'public, max-age=604800',
                });
            }
        }

        // ============================================================
        // MIDDLEWARE: JWT برای تمام مسیرهای محافظت‌شده
        // ============================================================
        let telegramId = null;

        if (path !== '/auth' && path !== '/config' && path !== '/webhook' && path !== '/setwebhook' && path !== '/health' && path !== '/') {
            telegramId = await getUserFromJWT(request, config.JWT_SECRET);
            if (!telegramId) {
                return errorResponse('AUTH_FAILED', 'Invalid or missing token', 401);
            }
        }

        // ============================================================
        // 4. GET /user/profile
        // ============================================================
        if (path === '/user/profile' && method === 'GET') {
            try {
                const user = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(telegramId).first();
                if (!user) {
                    return errorResponse('USER_NOT_FOUND', 'User not found', 404);
                }
                const wallet = await db.prepare(
                    'SELECT wallet_address FROM wallets WHERE telegram_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId).first();
                return jsonResponse({
                    telegramId: user.telegram_id,
                    firstName: user.first_name,
                    username: user.username,
                    balance: user.balance || 0,
                    referrals: user.referrals_count || 0,
                    walletAddress: wallet?.wallet_address || null,
                });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 5. POST /user/sync
        // ============================================================
        if (path === '/user/sync' && method === 'POST') {
            try {
                const body = await request.json();
                const events = body.events || [];
                if (events.length > 0) {
                    const stmt = db.prepare('INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)');
                    for (const ev of events) {
                        await stmt.bind(telegramId, ev.type, JSON.stringify(ev.data || {})).run();
                    }
                }
                return jsonResponse({ success: true, count: events.length });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 6. POST /wallet/connect
        // ============================================================
        if (path === '/wallet/connect' && method === 'POST') {
            try {
                const body = await request.json();
                const walletAddress = body.walletAddress;
                if (!walletAddress) {
                    return errorResponse('INVALID_REQUEST', 'Missing walletAddress', 400);
                }
                if (!isValidTonAddress(walletAddress)) {
                    return errorResponse('INVALID_WALLET', 'Invalid TON address format', 400);
                }
                const existing = await db.prepare(
                    'SELECT id FROM wallets WHERE telegram_id = ? AND wallet_address = ?'
                ).bind(telegramId, walletAddress).first();
                if (!existing) {
                    await db.prepare(
                        'INSERT INTO wallets (telegram_id, wallet_address) VALUES (?, ?)'
                    ).bind(telegramId, walletAddress).run();
                } else {
                    await db.prepare(
                        'UPDATE wallets SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
                    ).bind(existing.id).run();
                }
                return jsonResponse({ success: true, walletAddress });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 7. POST /wallet/disconnect
        // ============================================================
        if (path === '/wallet/disconnect' && method === 'POST') {
            try {
                await db.prepare(
                    'UPDATE wallets SET is_active = 0 WHERE telegram_id = ?'
                ).bind(telegramId).run();
                return jsonResponse({ success: true });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 8. POST /payments/ton/verify
        // ============================================================
        if (path === '/payments/ton/verify' && method === 'POST') {
            try {
                const body = await request.json();
                const { boc, packageId, usdPrice, recipientAddress } = body;
                if (!boc || !packageId) {
                    return errorResponse('INVALID_REQUEST', 'Missing boc or packageId', 400);
                }
                if (!recipientAddress) {
                    return errorResponse('INVALID_REQUEST', 'Missing recipientAddress', 400);
                }
                if (!isValidTonAddress(recipientAddress)) {
                    return errorResponse('INVALID_WALLET', 'Invalid recipient address format', 400);
                }

                const packages = await db.prepare('SELECT value FROM config WHERE key = ?').bind('package_prices').first();
                const packageData = packages ? JSON.parse(packages.value) : PACKAGE_DEFINITIONS;
                const pkg = packageData[packageId];
                if (!pkg) {
                    return errorResponse('INVALID_PACKAGE', 'Invalid package', 400);
                }

                const verification = await verifyTonTransaction(
                    boc,
                    pkg.usdt,
                    recipientAddress,
                    config.TON_API_KEY
                );
                if (!verification.valid) {
                    return errorResponse('PAYMENT_VERIFICATION_FAILED', verification.error, 400);
                }

                const existing = await db.prepare(
                    'SELECT * FROM processed_transactions WHERE tx_hash = ?'
                ).bind(verification.txHash).first();
                if (existing) {
                    return errorResponse('PAYMENT_REPLAY', 'Transaction already processed', 400);
                }

                await db.prepare(
                    'INSERT INTO processed_transactions (tx_hash, telegram_id) VALUES (?, ?)'
                ).bind(verification.txHash, telegramId).run();

                await db.prepare(
                    'INSERT INTO payments (telegram_id, type, package_id, amount, coins, tx_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
                ).bind(telegramId, 'ton', packageId, pkg.usdt, pkg.coins, verification.txHash, 'paid').run();

                const newBalance = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(pkg.coins, telegramId).first();

                return jsonResponse({
                    verified: true,
                    coins: pkg.coins,
                    balance: newBalance?.balance || 0,
                    txHash: verification.txHash,
                });
            } catch (e) {
                console.error('TON verify error:', e);
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 9. POST /payments/stars/create
        // ============================================================
        if (path === '/payments/stars/create' && method === 'POST') {
            try {
                const body = await request.json();
                const { packageId, amount, coins } = body;
                if (!packageId || !amount) {
                    return errorResponse('INVALID_REQUEST', 'Missing packageId or amount', 400);
                }

                const packages = await db.prepare('SELECT value FROM config WHERE key = ?').bind('package_prices').first();
                const packageData = packages ? JSON.parse(packages.value) : PACKAGE_DEFINITIONS;
                const pkg = packageData[packageId];
                if (!pkg) {
                    return errorResponse('INVALID_PACKAGE', 'Invalid package', 400);
                }

                const invoicePayload = 'stars_' + Date.now() + '_' + telegramId;

                const invoiceData = {
                    chat_id: telegramId,
                    title: 'Daimonium Token Package',
                    description: `Purchase ${pkg.coins} Daimonium tokens`,
                    payload: invoicePayload,
                    provider_token: '',
                    currency: 'XTR',
                    prices: [{ label: `${pkg.coins} Daimonium Tokens`, amount: amount }],
                    start_parameter: invoicePayload,
                };

                const response = await fetch('https://api.telegram.org/bot' + config.TELEGRAM_BOT_TOKEN + '/createInvoiceLink', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(invoiceData)
                });
                const result = await response.json();
                if (!result.ok) {
                    return errorResponse('INVOICE_FAILED', result.description || 'Telegram API error', 500);
                }

                const invoiceLink = result.result;

                await db.prepare(
                    'INSERT INTO payments (telegram_id, type, package_id, amount, coins, invoice_id, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
                ).bind(telegramId, 'stars', packageId, amount, pkg.coins, invoicePayload, 'pending').run();

                return jsonResponse({
                    success: true,
                    invoiceLink: invoiceLink,
                    paymentId: invoicePayload,
                });
            } catch (e) {
                console.error('Stars create error:', e);
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 10. GET /payments/:id
        // ============================================================
        if (path.startsWith('/payments/') && method === 'GET') {
            try {
                const paymentId = path.split('/')[2];
                if (!paymentId) {
                    return errorResponse('INVALID_REQUEST', 'Missing payment id', 400);
                }

                const payment = await db.prepare(
                    'SELECT * FROM payments WHERE telegram_id = ? AND (id = ? OR invoice_id = ? OR tx_hash = ?) ORDER BY created_at DESC LIMIT 1'
                ).bind(telegramId, paymentId, paymentId, paymentId).first();

                if (!payment) {
                    return errorResponse('PAYMENT_NOT_FOUND', 'Payment not found', 404);
                }

                if (payment.status === 'pending') {
                    const created = new Date(payment.created_at);
                    const now = new Date();
                    const diff = (now - created) / 1000;
                    if (diff > 600) {
                        await db.prepare(
                            'UPDATE payments SET status = ? WHERE id = ?'
                        ).bind('expired', payment.id).run();
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
                    balance: balance?.balance || 0,
                });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 11. POST /tasks/complete
        // ============================================================
        if (path === '/tasks/complete' && method === 'POST') {
            try {
                const body = await request.json();
                const taskId = body.taskId;
                if (!taskId) {
                    return errorResponse('INVALID_REQUEST', 'Missing taskId', 400);
                }

                const reward = TASK_REWARDS[taskId];
                if (!reward) {
                    return errorResponse('INVALID_TASK', 'Invalid task', 400);
                }

                const done = await db.prepare(
                    'SELECT * FROM user_tasks WHERE telegram_id = ? AND task_id = ? AND done_date = date("now")'
                ).bind(telegramId, taskId).first();
                if (done) {
                    return errorResponse('TASK_ALREADY_DONE', 'Task already completed today', 400);
                }

                await db.prepare(
                    'INSERT INTO user_tasks (telegram_id, task_id, done_date) VALUES (?, ?, date("now"))'
                ).bind(telegramId, taskId).run();

                const newBalance = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(reward, telegramId).first();

                return jsonResponse({
                    success: true,
                    reward: reward,
                    balance: newBalance?.balance || 0,
                });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 12. POST /ads/reward
        // ============================================================
        if (path === '/ads/reward' && method === 'POST') {
            try {
                const body = await request.json();
                const progress = body.progress || 0;
                const reward = body.reward || 150;

                const today = new Date().toISOString().split('T')[0];
                const done = await db.prepare(
                    'SELECT * FROM user_tasks WHERE telegram_id = ? AND task_id = ? AND done_date = ?'
                ).bind(telegramId, 'ad_watch', today).first();

                if (done) {
                    return errorResponse('TASK_ALREADY_DONE', 'Ad reward already claimed today', 400);
                }

                if (progress >= 3) {
                    await db.prepare(
                        'INSERT INTO user_tasks (telegram_id, task_id, done_date) VALUES (?, ?, ?)'
                    ).bind(telegramId, 'ad_watch', today).run();

                    const newBalance = await db.prepare(
                        'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                    ).bind(reward, telegramId).first();

                    await db.prepare(
                        'INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)'
                    ).bind(telegramId, 'ad_reward_claimed', JSON.stringify({ progress, reward })).run();

                    return jsonResponse({
                        success: true,
                        claimed: true,
                        balance: newBalance?.balance || 0,
                        reward: reward,
                    });
                } else {
                    return errorResponse('NOT_ENOUGH', `Watch ${3 - progress} more ads to claim`, 400);
                }
            } catch (e) {
                console.error('Ad reward error:', e);
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 13. POST /tasks/sync
        // ============================================================
        if (path === '/tasks/sync' && method === 'POST') {
            try {
                const body = await request.json();
                const days = body.days || [];
                if (!Array.isArray(days) || days.length === 0) {
                    return errorResponse('INVALID_REQUEST', 'Missing days array', 400);
                }

                let totalReward = 0;
                const operations = [];

                for (const day of days) {
                    const date = day.date;
                    const tasks = day.tasks || [];
                    if (!date || !Array.isArray(tasks)) continue;

                    for (const taskId of tasks) {
                        const reward = TASK_REWARDS[taskId];
                        if (!reward) continue;

                        const existing = await db.prepare(
                            'SELECT id FROM user_tasks WHERE telegram_id = ? AND task_id = ? AND done_date = ?'
                        ).bind(telegramId, taskId, date).first();

                        if (!existing) {
                            operations.push({
                                sql: 'INSERT INTO user_tasks (telegram_id, task_id, done_date) VALUES (?, ?, ?)',
                                args: [telegramId, taskId, date]
                            });
                            totalReward += reward;
                        }
                    }
                }

                if (operations.length === 0) {
                    const current = await db.prepare('SELECT balance FROM users WHERE telegram_id = ?').bind(telegramId).first();
                    return jsonResponse({ success: true, reward: 0, balance: current?.balance || 0 });
                }

                await db.batch(operations.map(op => db.prepare(op.sql).bind(...op.args)));

                let newBalance = null;
                if (totalReward > 0) {
                    const result = await db.prepare(
                        'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                    ).bind(totalReward, telegramId).first();
                    newBalance = result?.balance || 0;
                } else {
                    const current = await db.prepare('SELECT balance FROM users WHERE telegram_id = ?').bind(telegramId).first();
                    newBalance = current?.balance || 0;
                }

                return jsonResponse({
                    success: true,
                    reward: totalReward,
                    balance: newBalance,
                    inserted: operations.length,
                });
            } catch (e) {
                console.error('Task sync error:', e);
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 14. POST /referral/register
        // ============================================================
        if (path === '/referral/register' && method === 'POST') {
            try {
                const body = await request.json();
                const referrerId = body.referrerId;
                if (!referrerId || referrerId === telegramId) {
                    return errorResponse('INVALID_REFERRAL', 'Invalid referrer', 400);
                }

                const existing = await db.prepare(
                    'SELECT * FROM referrals WHERE referred_id = ?'
                ).bind(telegramId).first();
                if (existing) {
                    return errorResponse('ALREADY_REFERRED', 'Already referred', 400);
                }

                const referrer = await db.prepare('SELECT * FROM users WHERE telegram_id = ?').bind(referrerId).first();
                if (!referrer) {
                    return errorResponse('REFERRER_NOT_FOUND', 'Referrer not found', 404);
                }

                await db.prepare(
                    'INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)'
                ).bind(referrerId, telegramId).run();

                await db.prepare(
                    'UPDATE users SET referrals_count = referrals_count + 1 WHERE telegram_id = ?'
                ).bind(referrerId).run();

                await db.prepare(
                    'UPDATE users SET balance = balance + 100 WHERE telegram_id = ?'
                ).bind(referrerId).run();

                return jsonResponse({
                    success: true,
                    message: 'Referral registered',
                });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 15. POST /referral/claim
        // ============================================================
        if (path === '/referral/claim' && method === 'POST') {
            try {
                const body = await request.json();
                const task = body.task;
                if (!task) {
                    return errorResponse('INVALID_REQUEST', 'Missing task', 400);
                }

                const rewardMap = {
                    invite3: { required: 3, reward: 5000 },
                    invite5: { required: 5, reward: 10000 },
                    invite10: { required: 10, reward: 30000 },
                    invite20: { required: 20, reward: 100000 },
                };
                const cfg = rewardMap[task];
                if (!cfg) {
                    return errorResponse('INVALID_TASK', 'Invalid task', 400);
                }

                const claimed = await db.prepare(
                    'SELECT * FROM referral_rewards WHERE telegram_id = ? AND task = ?'
                ).bind(telegramId, task).first();
                if (claimed) {
                    return errorResponse('ALREADY_CLAIMED', 'Reward already claimed', 400);
                }

                const user = await db.prepare('SELECT referrals_count FROM users WHERE telegram_id = ?').bind(telegramId).first();
                const count = user?.referrals_count || 0;
                if (count < cfg.required) {
                    return errorResponse('NOT_ENOUGH', `Need ${cfg.required - count} more referrals`, 400);
                }

                await db.prepare(
                    'INSERT INTO referral_rewards (telegram_id, task, reward) VALUES (?, ?, ?)'
                ).bind(telegramId, task, cfg.reward).run();

                const newBalance = await db.prepare(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = ? RETURNING balance'
                ).bind(cfg.reward, telegramId).first();

                await db.prepare(
                    'INSERT INTO events (telegram_id, event_type, data) VALUES (?, ?, ?)'
                ).bind(telegramId, 'referral_claimed', JSON.stringify({ task, reward: cfg.reward })).run();

                return jsonResponse({
                    success: true,
                    reward: cfg.reward,
                    balance: newBalance?.balance || 0,
                    referrals: count,
                });
            } catch (e) {
                return errorResponse('SERVER_ERROR', e.message, 500);
            }
        }

        // ============================================================
        // 404
        // ============================================================
        return errorResponse('NOT_FOUND', 'Endpoint not found', 404);
    }
};