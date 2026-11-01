import { Pool } from 'pg';
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const DAY = 86_400_000, HOUR = 3_600_000, MIN = 60_000;
const REMEMBER_MS = 30 * DAY, ABSOLUTE_MS = 90 * DAY, IDLE_MS = 12 * HOUR;
const MAX_FAILS = 5, LOCK_MS = HOUR; // 5 échecs de connexion = compte verrouillé 1 h (jamais plus)
const SCRYPT = { N: 2 ** 15, r: 8, p: 3, keylen: 64, maxmem: 128 * 1024 * 1024 };
const COOKIE_NAME = '__Host-os_sid';
const ADMIN_COOKIE = '__Host-os_admin';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'outfitshirt@gmail.com').trim().toLowerCase();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
  max: 3,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 10_000,
});
pool.on('error', e => errLog(e, 'pool_idle_client'));
// --- Schéma PostgreSQL ------------------------------------------------------
// Toutes les instances Netlify partagent la même base : la création/modification
// du schéma doit donc être sérialisée entre instances (verrou consultatif PostgreSQL)
// et ne jamais mémoriser un échec (sinon l'instance reste cassée tant qu'elle est « chaude »).
const SCHEMA_LOCK_KEY = 726841337; // identifiant arbitraire, propre à ce projet
const SCHEMA_TABLES = ['users', 'sessions', 'password_reset_tokens', 'admin_sessions', 'products', 'orders', 'site_settings', 'payments', 'payment_events', 'provider_tokens'];
const REQUIRED_COLUMNS = [
  'users.last_name', 'users.post_name', 'users.phone', 'users.birth_date', 'users.address', 'users.account_blocked',
  'sessions.id_hash', 'password_reset_tokens.token_hash', 'admin_sessions.id_hash',
  'products.quantity', 'products.sizes', 'products.size_stock',
  'orders.id', 'orders.tracking_code', 'site_settings.key',
  'payments.reference', 'payments.status', 'payment_events.payment_id', 'provider_tokens.provider',
];
const REQUIRED_INDEXES = ['sessions_user_idx', 'sessions_exp_idx', 'password_reset_user_idx', 'password_reset_exp_idx', 'orders_created_idx', 'payments_order_idx', 'payments_active_uniq', 'payments_success_uniq', 'payments_created_idx', 'payment_events_pay_idx'];
// Ordre important : chaque table est créée AVANT toute commande ALTER TABLE qui la concerne.
const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      first_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      last_login_at BIGINT,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until BIGINT NOT NULL DEFAULT 0
    )`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS post_name TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS birth_date TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS account_blocked BOOLEAN NOT NULL DEFAULT FALSE`,
  `CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL,
      remember BOOLEAN NOT NULL DEFAULT FALSE,
      created_at BIGINT NOT NULL,
      last_seen BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      ip TEXT,
      ua TEXT
    )`,
  'CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)',
  'CREATE INDEX IF NOT EXISTS sessions_exp_idx ON sessions(expires_at)',
  `CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL
    )`,
  'CREATE INDEX IF NOT EXISTS password_reset_user_idx ON password_reset_tokens(user_id)',
  'CREATE INDEX IF NOT EXISTS password_reset_exp_idx ON password_reset_tokens(expires_at)',
  `CREATE TABLE IF NOT EXISTS admin_sessions (id_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, ip TEXT, ua TEXT)`,
  `CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, brand TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, price INTEGER NOT NULL, old_price INTEGER, badge TEXT, free BOOLEAN NOT NULL DEFAULT FALSE, color TEXT NOT NULL DEFAULT '#FFFFFF', ink TEXT NOT NULL DEFAULT '#000000', print TEXT NOT NULL DEFAULT 'blank', tags JSONB NOT NULL DEFAULT '[]'::jsonb, img_front TEXT NOT NULL DEFAULT '', img_back TEXT NOT NULL DEFAULT '', quantity INTEGER NOT NULL DEFAULT 1, sizes JSONB NOT NULL DEFAULT '["S","M","L","XL"]'::jsonb, active BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)`,
  'ALTER TABLE products ADD COLUMN IF NOT EXISTS quantity INTEGER NOT NULL DEFAULT 1',
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS sizes JSONB NOT NULL DEFAULT '["S","M","L","XL"]'::jsonb`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS size_stock JSONB NOT NULL DEFAULT '{}'::jsonb`,
  `CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE SET NULL, customer_name TEXT NOT NULL, customer_email TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL, items JSONB NOT NULL, total INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'En attente', created_at BIGINT NOT NULL)`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_code TEXT NOT NULL DEFAULT ''`,
  'CREATE INDEX IF NOT EXISTS orders_created_idx ON orders(created_at DESC)',
  `CREATE TABLE IF NOT EXISTS site_settings (key TEXT PRIMARY KEY, value JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at BIGINT NOT NULL)`,
  // Paiements Mobile Money : nouvelles tables uniquement (aucune table existante n'est modifiée ni supprimée).
  `CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE RESTRICT, provider TEXT NOT NULL, reference TEXT NOT NULL UNIQUE, provider_ref TEXT, amount BIGINT NOT NULL, currency TEXT NOT NULL, msisdn_masked TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending_payment', notif_token TEXT, pay_url TEXT, error_code TEXT, error_message TEXT, environment TEXT NOT NULL DEFAULT 'sandbox', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, confirmed_at BIGINT, last_checked_at BIGINT, check_count INTEGER NOT NULL DEFAULT 0)`,
  'CREATE INDEX IF NOT EXISTS payments_order_idx ON payments(order_id)',
  `CREATE UNIQUE INDEX IF NOT EXISTS payments_active_uniq ON payments(order_id) WHERE status IN ('pending_payment','processing','needs_review')`,
  `CREATE UNIQUE INDEX IF NOT EXISTS payments_success_uniq ON payments(order_id) WHERE status = 'success'`,
  'CREATE INDEX IF NOT EXISTS payments_created_idx ON payments(created_at DESC)',
  `CREATE TABLE IF NOT EXISTS payment_events (id BIGSERIAL PRIMARY KEY, payment_id TEXT NOT NULL REFERENCES payments(id) ON DELETE CASCADE, at BIGINT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')`,
  'CREATE INDEX IF NOT EXISTS payment_events_pay_idx ON payment_events(payment_id)',
  `CREATE TABLE IF NOT EXISTS provider_tokens (provider TEXT PRIMARY KEY, token TEXT NOT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, next_token TEXT, next_created_at BIGINT)`,
];
// Lecture seule, sans verrou : le schéma est-il déjà complet ?
async function schemaReady(db) {
  const cols = await db.query(
    `SELECT table_name || '.' || column_name AS c FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ANY($1::text[])`,
    [SCHEMA_TABLES]);
  const have = new Set(cols.rows.map(r => r.c));
  if (!REQUIRED_COLUMNS.every(c => have.has(c))) return false;
  const idx = await db.query(
    `SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ANY($1::text[])`,
    [REQUIRED_INDEXES]);
  return idx.rows.length === REQUIRED_INDEXES.length;
}
async function applySchema() {
  if (await schemaReady(pool)) return; // cas normal : aucun DDL, aucun verrou
  const client = await pool.connect();
  let destroy = false;
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL lock_timeout = '5s'`);
    // Verrou lié à la transaction : libéré automatiquement par COMMIT/ROLLBACK ou
    // à la perte de la connexion (compatible serverless et pooler en mode transaction).
    await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [SCHEMA_LOCK_KEY]);
    // Double vérification : une autre instance a peut-être tout créé pendant l'attente.
    if (!(await schemaReady(client))) {
      for (const sql of SCHEMA_STATEMENTS) await client.query(sql);
    }
    await client.query('COMMIT');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { destroy = true; }
    throw e;
  } finally {
    client.release(destroy);
  }
}
// Erreurs transitoires : conflit de création concurrente, deadlock, verrou non obtenu, connexion coupée.
const SCHEMA_RETRY_CODES = new Set(['23505', '42P07', '42710', '40P01', '40001', '55P03', '57P01', '08006', '08003', '08001', 'ECONNRESET']);
let schemaPromise = null;
function ensureSchema() {
  if (!process.env.DATABASE_URL) return Promise.reject(new Error('DATABASE_URL manquant'));
  if (!schemaPromise) {
    schemaPromise = (async () => {
      for (let attempt = 1; ; attempt++) {
        try { return await applySchema(); }
        catch (e) {
          if (attempt >= 3 || !SCHEMA_RETRY_CODES.has(e?.code)) throw e;
          errLog(e, `ensure_schema_retry_${attempt}`);
          await new Promise(r => setTimeout(r, 150 * attempt + Math.floor(Math.random() * 150)));
        }
      }
    })().catch(e => { schemaPromise = null; throw e; }); // ne jamais mémoriser un échec
  }
  return schemaPromise;
}
class HttpError extends Error { constructor(status, code, message, details) { super(message); this.status=status; this.code=code; this.details=details; } }
const sha256 = v => crypto.createHash('sha256').update(v).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');
const safeEqual = (a,b) => { const x=Buffer.from(String(a)), y=Buffer.from(String(b)); return x.length===y.length && crypto.timingSafeEqual(x,y); };
const normEmail = v => typeof v === 'string' ? v.normalize('NFKC').trim().toLowerCase() : '';
const emailOk = e => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const nameOk = n => /^\p{L}[\p{L}\p{M} '’-]{0,59}$/u.test(n);
const publicUser = row => ({ firstName: row.first_name, email: row.email, lastName: row.last_name || '', postName: row.post_name || '', phone: row.phone || '', birthDate: row.birth_date || '', address: row.address || '' });
const COMMON = ['password','motdepasse','azerty','qwerty','123456','111111','000000','abcdef','iloveyou','admin','welcome','bienvenue','football','outfit','changeme','letmein','soleil','dragon','monkey','master'];
const strip = s => String(s || '').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
function passwordProblems(pw, ctx={}) {
  if (typeof pw !== 'string') return ['Mot de passe invalide.'];
  const errs=[];
  if (pw.length<12) errs.push('12 caractères minimum.');
  if (pw.length>128) errs.push('128 caractères maximum.');
  if (!/\p{Ll}/u.test(pw)) errs.push('Ajoute au moins une minuscule.');
  if (!/\p{Lu}/u.test(pw)) errs.push('Ajoute au moins une majuscule.');
  if (!/\p{Nd}/u.test(pw)) errs.push('Ajoute au moins un chiffre.');
  if (!/[^\p{L}\p{N}]/u.test(pw)) errs.push('Ajoute au moins un symbole (! ? # @ …).');
  const norm=strip(pw);
  if (COMMON.some(w=>norm.includes(w))) errs.push('Ce mot de passe est trop courant ou prévisible.');
  if (/(.)\1{3,}/u.test(pw)) errs.push('Évite de répéter le même caractère 4 fois de suite.');
  const local=strip(String(ctx.email||'').split('@')[0]);
  if(local.length>=4 && norm.includes(local)) errs.push('Le mot de passe ne doit pas contenir ton e-mail.');
  const fn=strip(ctx.firstName); if(fn.length>=3 && norm.includes(fn)) errs.push('Le mot de passe ne doit pas contenir ton prénom.');
  return errs;
}
function profileFields(b) {
  const clean=(v,m)=>typeof v==='string'?v.normalize('NFKC').trim().slice(0,m):'';
  const firstName=clean(b.firstName,60), lastName=clean(b.lastName,60), postName=clean(b.postName,60), phone=clean(b.phone,30), address=clean(b.address,300), birthDate=clean(b.birthDate,10);
  if(!nameOk(firstName)) throw new HttpError(400,'invalid_name','Entre un prénom valide (lettres uniquement).');
  if(!nameOk(lastName)) throw new HttpError(400,'invalid_last_name','Entre un nom valide (lettres uniquement).');
  if(postName&&!nameOk(postName)) throw new HttpError(400,'invalid_post_name','Entre un postnom valide (lettres uniquement).');
  if(!/^\+?[0-9 ().-]{8,20}$/.test(phone)) throw new HttpError(400,'invalid_phone','Entre un numéro de téléphone valide.');
  if(address.length<8) throw new HttpError(400,'invalid_address','Entre une adresse de livraison complète.');
  if(birthDate){ const d=new Date(birthDate+'T00:00:00Z'); if(!/^\d{4}-\d{2}-\d{2}$/.test(birthDate)||isNaN(d)||d.toISOString().slice(0,10)!==birthDate||d>new Date()||d.getUTCFullYear()<1900) throw new HttpError(400,'invalid_birth','Date de naissance invalide.'); }
  return {firstName,lastName,postName,phone,address,birthDate};
}
async function hashPassword(pw) {
  const salt=crypto.randomBytes(16); const {N,r,p,keylen,maxmem}=SCRYPT;
  const key=await scrypt(pw.normalize('NFKC'),salt,keylen,{N,r,p,maxmem});
  return ['scrypt',N,r,p,salt.toString('base64'),key.toString('base64')].join('$');
}
async function verifyPassword(pw, stored) {
  const [alg,N,r,p,saltB64,hashB64]=String(stored).split('$'); if(alg!=='scrypt') return false;
  const expected=Buffer.from(hashB64,'base64');
  const key=await scrypt(pw.normalize('NFKC'),Buffer.from(saltB64,'base64'),expected.length,{N:+N,r:+r,p:+p,maxmem:SCRYPT.maxmem});
  return crypto.timingSafeEqual(key,expected);
}
const DUMMY_HASH_PROMISE = hashPassword(crypto.randomBytes(16).toString('hex'));
function parseCookies(req) { const out={}; for(const part of (req.headers.get('cookie')||'').split(';')) { const i=part.indexOf('='); if(i>0) out[part.slice(0,i).trim()]=part.slice(i+1).trim(); } return out; }
function cookieHeader(value, maxAgeMs=null) {
  const parts=[`${COOKIE_NAME}=${value}`,'Path=/','HttpOnly','Secure','SameSite=Lax'];
  if(maxAgeMs!==null) parts.push(`Max-Age=${Math.max(0,Math.floor(maxAgeMs/1000))}`);
  return parts.join('; ');
}
const hits = new Map();
function allow(key,max,windowMs) { const now=Date.now(), arr=(hits.get(key)||[]).filter(t=>now-t<windowMs); if(arr.length>=max){hits.set(key,arr);return false;} arr.push(now);hits.set(key,arr);return true; }
function getIp(req) { return req.headers.get('x-nf-client-connection-ip') || req.headers.get('x-forwarded-for')?.split(',').at(-1)?.trim() || 'unknown'; }
async function createSession(userId, remember, req) {
  const tok=token(), csrf=token(), now=Date.now(), ttl=remember?REMEMBER_MS:IDLE_MS;
  await pool.query('INSERT INTO sessions (id_hash,user_id,csrf,remember,created_at,last_seen,expires_at,ip,ua) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
    [sha256(tok),userId,csrf,remember,now,now,now+ttl,getIp(req),(req.headers.get('user-agent')||'').slice(0,200)]);
  return {csrf,cookie:cookieHeader(tok,remember?ttl:null)};
}
async function currentSession(req) {
  const tok=parseCookies(req)[COOKIE_NAME]; if(!tok||tok.length>100) return null;
  const idHash=sha256(tok);
  const {rows}=await pool.query(`SELECT s.*,u.email,u.first_name,u.last_name,u.post_name,u.phone,u.birth_date,u.address,u.password_hash,u.account_blocked FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=$1`,[idHash]);
  const row=rows[0]; if(!row) return null;
  const now=Date.now();
  if(Number(row.expires_at)<=now || now-Number(row.created_at)>ABSOLUTE_MS || row.account_blocked===true){await pool.query('DELETE FROM sessions WHERE id_hash=$1',[idHash]);return null;}
  let refreshCookie=null;
  if(now-Number(row.last_seen)>(row.remember?DAY:MIN)){
    const ttl=row.remember?REMEMBER_MS:IDLE_MS, exp=Math.min(now+ttl,Number(row.created_at)+ABSOLUTE_MS);
    await pool.query('UPDATE sessions SET last_seen=$1,expires_at=$2 WHERE id_hash=$3',[now,exp,idHash]);
    if(row.remember) refreshCookie=cookieHeader(tok,exp-now);
  }
  return {row,idHash,refreshCookie};
}
async function currentAdminSession(req) {
  const tok=parseCookies(req)[ADMIN_COOKIE]; if(!tok||tok.length>100) return null;
  const idHash=sha256(tok), {rows}=await pool.query('SELECT * FROM admin_sessions WHERE id_hash=$1',[idHash]);
  const row=rows[0]; if(!row) return null;
  if(Number(row.expires_at)<=Date.now()){await pool.query('DELETE FROM admin_sessions WHERE id_hash=$1',[idHash]);return null;}
  return {row,idHash};
}
function adminCookie(value,maxAgeMs) { return [`${ADMIN_COOKIE}=${value}`,'Path=/','HttpOnly','Secure','SameSite=Strict',`Max-Age=${Math.max(0,Math.floor(maxAgeMs/1000))}`].join('; '); }
async function createAdminSession(req) {
  const tok=token(), csrf=token(), now=Date.now(), ttl=8*HOUR;
  await pool.query('INSERT INTO admin_sessions (id_hash,csrf,created_at,expires_at,ip,ua) VALUES ($1,$2,$3,$4,$5,$6)',[sha256(tok),csrf,now,now+ttl,getIp(req),(req.headers.get('user-agent')||'').slice(0,200)]);
  return {csrf,cookie:adminCookie(tok,ttl)};
}
function requireAdmin(req,admin,mutating) {
  if(!admin) throw new HttpError(401,'admin_unauthenticated','Connecte-toi à l’administration.');
  if(mutating&&!safeEqual(req.headers.get('x-csrf-token')||'',admin.row.csrf)) throw new HttpError(403,'bad_csrf','Session administrateur invalide. Recharge la page.');
}
const productPublic = r => ({id:r.id,brand:r.brand,name:r.name,price:Number(r.price),old:r.old_price==null?null:Number(r.old_price),badge:r.badge,free:!!r.free,color:r.color,ink:r.ink,print:r.print,tags:Array.isArray(r.tags)?r.tags:[],img:{front:r.img_front||'',back:r.img_back||''},quantity:Number(r.quantity??1),sizes:Array.isArray(r.sizes)?r.sizes:['S','M','L','XL'],sizeStock:r.size_stock&&typeof r.size_stock==='object'&&!Array.isArray(r.size_stock)?r.size_stock:{},active:!!r.active});
async function readJson(req) { const ct=(req.headers.get('content-type')||'').split(';')[0].trim().toLowerCase(); if(ct!=='application/json') throw new HttpError(415,'unsupported_media_type','Format de requête invalide.'); const raw=await req.text(); if(raw.length>10000) throw new HttpError(413,'too_large','Requête trop volumineuse.'); try { const b=JSON.parse(raw); if(!b||typeof b!=='object'||Array.isArray(b)) throw 0; return b; } catch { throw new HttpError(400,'bad_json','Requête invalide.'); } }
function guardMutation(req) { const origin=req.headers.get('origin'); const requestOrigin=new URL(req.url).origin; if(origin!==requestOrigin) throw new HttpError(403,'bad_origin','Requête refusée.'); const site=req.headers.get('sec-fetch-site'); if(site && site!=='same-origin') throw new HttpError(403,'bad_origin','Requête refusée.'); }
function requireAuth(req,auth,mutating) { if(!auth) throw new HttpError(401,'unauthenticated','Connecte-toi pour continuer.'); if(mutating&&!safeEqual(req.headers.get('x-csrf-token')||'',auth.row.csrf)) throw new HttpError(403,'bad_csrf','Session invalide, recharge la page.'); }
function json(body,status=200,cookies=[],extra={}) { const headers=new Headers({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin',...extra}); for(const c of cookies) headers.append('Set-Cookie',c); return new Response(JSON.stringify(body),{status,headers}); }
function errLog(e,context){ console.error(JSON.stringify({event:'server_error',context:context||undefined,code:e?.code||undefined,message:String(e?.message||e).slice(0,500)})); }
const ORDER_STATUSES = ['En attente', 'Payée', 'Expédiée', 'Livrée', 'Annulée'];
async function brevoSend(email, subject, textContent, htmlContent) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL || process.env.MAIL_FROM;
  if (!apiKey || !senderEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(senderEmail)) {
    throw new Error('Configuration Brevo manquante : BREVO_API_KEY et BREVO_SENDER_EMAIL');
  }
  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': apiKey, 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ sender: { email: senderEmail, name: 'Outfit-Shirt' }, to: [{ email }], subject, textContent, htmlContent })
  });
  if (!response.ok) {
    const details = (await response.text()).slice(0, 500);
    throw new Error(`Échec de l’envoi Brevo (${response.status}) : ${details}`);
  }
}
async function sendPasswordResetEmail(email, resetUrl) {
  return brevoSend(email,
    'Réinitialisation de ton mot de passe Outfit-Shirt',
    `Tu as demandé à réinitialiser ton mot de passe Outfit-Shirt. Ouvre ce lien dans les 30 minutes : ${resetUrl}\n\nSi tu n’as pas fait cette demande, ignore cet e-mail.`,
    `<p>Tu as demandé à réinitialiser ton mot de passe Outfit-Shirt.</p><p><a href=\"${resetUrl}\">Choisir un nouveau mot de passe</a></p><p>Ce lien expire dans 30 minutes. Si tu n’as pas fait cette demande, ignore cet e-mail.</p>`);
}
// Alerte de sécurité envoyée au propriétaire du compte une fois le mot de passe changé (ne contient aucun lien ni secret).
async function sendPasswordChangedEmail(email) {
  return brevoSend(email,
    'Ton mot de passe Outfit-Shirt a été modifié',
    `Le mot de passe de ton compte Outfit-Shirt vient d’être modifié et tes autres connexions ont été fermées.\n\nSi c’est bien toi, tu n’as rien à faire. Sinon, demande vite une nouvelle réinitialisation sur le site et écris-nous à ${ADMIN_EMAIL}.`,
    `<p>Le mot de passe de ton compte Outfit-Shirt vient d’être modifié et tes autres connexions ont été fermées.</p><p>Si c’est bien toi, tu n’as rien à faire. Sinon, demande vite une nouvelle réinitialisation sur le site et écris-nous à ${ADMIN_EMAIL}.</p>`);
}
async function notifyAdminOrder(order) {
  if (!process.env.RESEND_API_KEY) return;
  const lines = order.items.map(i => `- ${i.name} (${i.size}) x${i.qty} : ${i.total} FC`).join('\n');
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.MAIL_FROM || 'onboarding@resend.dev',
        to: ADMIN_EMAIL,
        subject: `Nouvelle commande ${order.ref} — ${order.total} FC`,
        text: `Client : ${order.customerName}\nE-mail : ${order.email}\nTéléphone : ${order.phone}\nLivraison : ${order.address}\n\n${lines}\n\nTotal : ${order.total} FC`
      })
    });
  } catch (e) { errLog(e); }
}
// Réglages modifiables depuis l'administration (sans redéploiement) : article d'accueil, WhatsApp, e-mail de contact.
const SETTINGS_KEY = 'site';
const SETTINGS_DEFAULTS = { heroPrice: 19500, heroFront: '', heroBack: '', heroColor: '#2B3BFF', heroInk: '#FFFFFF', heroPrint: 'block', whatsapp: '243906049174', contactEmail: 'outfitshirt@gmail.com' };
const PRINTS = ['blank', 'block', 'wave', 'campus', 'stripes', 'plain'];
function settingsFromValue(v) {
  const o = v && typeof v === 'object' && !Array.isArray(v) ? v : {}, out = { ...SETTINGS_DEFAULTS };
  for (const k of Object.keys(SETTINGS_DEFAULTS)) if (typeof o[k] === typeof SETTINGS_DEFAULTS[k]) out[k] = o[k];
  if (out.whatsapp === '243979237585') out.whatsapp = SETTINGS_DEFAULTS.whatsapp; // ancien numéro saisi par erreur : remplacé par le bon
  return out;
}
function parseSettings(b) {
  const heroPrice = Number(b.heroPrice);
  if (!Number.isSafeInteger(heroPrice) || heroPrice < 1 || heroPrice > 100000000) throw new HttpError(400, 'invalid_settings', 'Prix de départ invalide (en FC, nombre entier).');
  const url = v => { const u = typeof v === 'string' ? v.trim().slice(0, 2000) : ''; if (u && !/^https?:\/\/\S+$/i.test(u)) throw new HttpError(400, 'invalid_settings', 'Les liens photo doivent commencer par https://'); return u; };
  const heroFront = url(b.heroFront), heroBack = url(b.heroBack);
  const heroColor = /^#[0-9a-f]{6}$/i.test(b.heroColor || '') ? b.heroColor : SETTINGS_DEFAULTS.heroColor;
  const heroInk = /^#[0-9a-f]{6}$/i.test(b.heroInk || '') ? b.heroInk : SETTINGS_DEFAULTS.heroInk;
  const heroPrint = PRINTS.includes(b.heroPrint) ? b.heroPrint : SETTINGS_DEFAULTS.heroPrint;
  const whatsapp = String(b.whatsapp ?? '').replace(/[\s().+-]/g, '').replace(/^00/, '');
  if (!/^\d{8,15}$/.test(whatsapp)) throw new HttpError(400, 'invalid_settings', 'Numéro WhatsApp invalide. Format international sans +, ex. 243979237585.');
  const contactEmail = normEmail(b.contactEmail);
  if (!emailOk(contactEmail)) throw new HttpError(400, 'invalid_settings', 'Adresse e-mail de contact invalide.');
  return { heroPrice, heroFront, heroBack, heroColor, heroInk, heroPrint, whatsapp, contactEmail };
}
const RESET_COOLDOWN_MS = 60_000;
// ============================================================================
// PAIEMENTS MOBILE MONEY : Airtel Money, Vodacom M-Pesa, Orange Money (RDC)
// ----------------------------------------------------------------------------
// - Aucun opérateur n'est actif tant que <OPERATEUR>_ENABLED=true ET que tous ses identifiants sont configurés
//   dans les variables d'environnement Netlify (jamais dans le code, jamais dans le frontend).
// - Le montant est TOUJOURS relu en base (commande) : le navigateur ne l'envoie jamais.
// - Une commande ne passe à « Payée » qu'après une vérification serveur à serveur auprès de l'opérateur.
//   Une redirection, un callback ou une capture d'écran ne prouvent rien : ils déclenchent seulement une vérification.
// - Les contrats d'API ci-dessous suivent la documentation publique / les SDK publics de chaque opérateur ;
//   ils doivent être validés en environnement de test de l'opérateur avant tout passage en production.
// ============================================================================
const PROVIDER_LABELS = { airtel: 'Airtel Money', mpesa: 'Vodacom M-Pesa', orange: 'Orange Money' };
const PROVIDER_ENV_PREFIX = { airtel: 'AIRTEL_', mpesa: 'MPESA_', orange: 'OM_' };
const PAYMENT_STATUS_LABELS = {
  pending_payment: 'En attente de paiement', processing: 'Paiement en cours', success: 'Paiement réussi',
  failed: 'Paiement échoué', cancelled: 'Paiement annulé', expired: 'Paiement expiré', needs_review: 'Vérification nécessaire'
};
const PAYMENT_OPEN = ['pending_payment', 'processing', 'needs_review'];
const PAYMENT_TTL_MS = 15 * MIN;
const PAYMENT_SECRET_ENV = ['AIRTEL_CLIENT_ID', 'AIRTEL_CLIENT_SECRET', 'MPESA_API_KEY', 'MPESA_PUBLIC_KEY', 'OM_CLIENT_ID', 'OM_CLIENT_SECRET', 'OM_AUTH_HEADER', 'OM_MERCHANT_KEY', 'PAYMENT_CALLBACK_SECRET', 'DATABASE_URL'];
class ProviderUnavailable extends Error {}
const penv = n => (process.env[n] || '').trim();
// Journaux : jamais de secret (les valeurs des variables sensibles sont masquées) ni de caractères de contrôle.
function payRedact(s) { let t = String(s ?? ''); for (const n of PAYMENT_SECRET_ENV) { const v = process.env[n]; if (v && v.length >= 6) t = t.split(v).join('***'); } return t; }
const payClean = (s, n = 300) => payRedact(String(s ?? '').replace(/[\u0000-\u001f]/g, ' ')).slice(0, n);
async function payFetch(url, opts = {}, timeoutMs = 8000) {
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctl.signal });
    const text = await res.text(); let body = null; try { body = JSON.parse(text); } catch {}
    return { ok: res.ok, status: res.status, body, text: payClean(text, 300) };
  } finally { clearTimeout(timer); }
}
// Numéro RDC au format international sans « + » : 243 + 9 chiffres.
function normalizeMsisdn(input) {
  let d = String(input ?? '').replace(/[\s().-]/g, '');
  if (d.startsWith('+')) d = d.slice(1);
  if (d.startsWith('00')) d = d.slice(2);
  if (/^0\d{9}$/.test(d)) d = '243' + d.slice(1);
  else if (/^[1-9]\d{8}$/.test(d)) d = '243' + d;
  return /^243[1-9]\d{8}$/.test(d) ? d : null;
}
const maskMsisdn = m => m.slice(0, 5) + '*'.repeat(m.length - 7) + m.slice(-2);

// --- Configuration par opérateur (rien n'est supposé : tout ce qui manque est listé, jamais inventé) -------------
function providerConfig(id) {
  const prefix = PROVIDER_ENV_PREFIX[id], missing = [], need = (...names) => names.forEach(n => { if (!penv(n)) missing.push(n); });
  if (penv('PAYMENT_CALLBACK_SECRET').length < 16) missing.push('PAYMENT_CALLBACK_SECRET (16 caractères minimum)');
  let cfg = {}, environment = 'sandbox';
  if (id === 'airtel') {
    need('AIRTEL_CLIENT_ID', 'AIRTEL_CLIENT_SECRET');
    environment = penv('AIRTEL_ENV') === 'production' ? 'production' : 'sandbox';
    cfg = { base: penv('AIRTEL_BASE_URL') || (environment === 'production' ? 'https://openapi.airtel.africa' : 'https://openapiuat.airtel.africa'), country: penv('AIRTEL_COUNTRY') || 'CD', currency: penv('AIRTEL_CURRENCY') || 'CDF', clientId: penv('AIRTEL_CLIENT_ID'), clientSecret: penv('AIRTEL_CLIENT_SECRET') };
  } else if (id === 'mpesa') {
    need('MPESA_API_KEY', 'MPESA_PUBLIC_KEY', 'MPESA_SERVICE_PROVIDER_CODE', 'MPESA_CURRENCY');
    environment = penv('MPESA_ENV') === 'production' ? 'production' : 'sandbox';
    cfg = { host: penv('MPESA_HOST') || 'openapi.m-pesa.com', path: (environment === 'production' ? 'openapi' : 'sandbox') + '/ipg/v2/vodacomDRC', country: penv('MPESA_COUNTRY') || 'DRC', currency: penv('MPESA_CURRENCY'), origin: penv('MPESA_ORIGIN') || '*', apiKey: penv('MPESA_API_KEY'), publicKey: penv('MPESA_PUBLIC_KEY'), shortcode: penv('MPESA_SERVICE_PROVIDER_CODE'), sessionTtlMs: (Number(penv('MPESA_SESSION_TTL_MINUTES')) || 20) * MIN };
  } else if (id === 'orange') {
    need('OM_MERCHANT_KEY', 'OM_PAYMENT_PATH', 'OM_STATUS_PATH', 'OM_CURRENCY', 'SITE_URL');
    if (!penv('OM_AUTH_HEADER') && !(penv('OM_CLIENT_ID') && penv('OM_CLIENT_SECRET'))) missing.push('OM_AUTH_HEADER (ou OM_CLIENT_ID + OM_CLIENT_SECRET)');
    environment = penv('OM_ENV') === 'production' ? 'production' : 'sandbox';
    cfg = { base: (penv('OM_BASE_URL') || 'https://api.orange.com').replace(/\/$/, ''), tokenPath: penv('OM_TOKEN_PATH') || '/oauth/v3/token', paymentPath: penv('OM_PAYMENT_PATH'), statusPath: penv('OM_STATUS_PATH'), currency: penv('OM_CURRENCY'), merchantKey: penv('OM_MERCHANT_KEY'), site: penv('SITE_URL').replace(/\/$/, ''), authHeader: penv('OM_AUTH_HEADER') || ('Basic ' + Buffer.from(penv('OM_CLIENT_ID') + ':' + penv('OM_CLIENT_SECRET')).toString('base64')) };
  } else throw new Error('Opérateur inconnu');
  const enabled = penv(prefix + 'ENABLED') === 'true';
  // Les prix du site sont en CDF et aucune conversion n'est faite : en production, la devise de l'opérateur doit être CDF.
  if (environment === 'production' && cfg.currency && cfg.currency !== 'CDF') missing.push(`${prefix}CURRENCY doit valoir CDF en production`);
  return { id, label: PROVIDER_LABELS[id], prefix, enabled, environment, missing, ready: enabled && missing.length === 0, cfg };
}

// --- Airtel Money (API Airtel Africa : OAuth2 + Collection « USSD Push ») -----------------------------------------
const airtelTokens = new Map(); // cache par instance (jeton OAuth court)
async function airtelToken(cfg) {
  const key = cfg.base + cfg.clientId, c = airtelTokens.get(key);
  if (c && c.exp > Date.now() + 30000) return c.token;
  const r = await payFetch(`${cfg.base}/auth/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: '*/*' }, body: JSON.stringify({ client_id: cfg.clientId, client_secret: cfg.clientSecret, grant_type: 'client_credentials' }) });
  const t = r.body?.access_token;
  if (!r.ok || !t) throw new Error(`Airtel authentification refusée (${r.status}) ${r.text}`);
  airtelTokens.set(key, { token: t, exp: Date.now() + (Number(r.body.expires_in) || 3600) * 1000 });
  return t;
}
const airtelHeaders = (cfg, t) => ({ 'Content-Type': 'application/json', Accept: '*/*', 'X-Country': cfg.country, 'X-Currency': cfg.currency, Authorization: `Bearer ${t}` });
const AIRTEL_STATES = { TS: 'success', TF: 'failed', TIP: 'processing', TE: 'expired', TA: 'needs_review' };
const ADAPTERS = {
  airtel: {
    async initiate(cfg, { payment, msisdn, orderRef }) {
      const t = await airtelToken(cfg);
      const r = await payFetch(`${cfg.base}/merchant/v2/payments/`, { method: 'POST', headers: airtelHeaders(cfg, t), body: JSON.stringify({
        reference: `Commande ${orderRef}`,
        subscriber: { country: cfg.country, currency: cfg.currency, msisdn: msisdn.startsWith('243') ? msisdn.slice(3) : msisdn },
        transaction: { amount: payment.amount, country: cfg.country, currency: cfg.currency, id: payment.reference } }) });
      const st = r.body?.status;
      if (r.status === 401) airtelTokens.clear();
      if (r.ok && (st?.success === true || String(st?.code) === '200')) return { state: 'processing', providerRef: payClean(r.body?.data?.transaction?.id || payment.reference, 100), code: payClean(st?.response_code || '', 40), message: 'Demande envoyée' };
      if ((r.status >= 400 && r.status < 500) || st?.success === false) return { state: 'failed', code: payClean(st?.response_code || st?.result_code || r.status, 40), message: payClean(st?.message || r.text, 200) };
      throw new Error(`Airtel réponse inattendue (${r.status})`);
    },
    async verify(cfg, payment) {
      const t = await airtelToken(cfg);
      const r = await payFetch(`${cfg.base}/standard/v1/payments/${encodeURIComponent(payment.reference)}`, { headers: airtelHeaders(cfg, t) });
      const tx = r.body?.data?.transaction;
      if (!r.ok || !tx) return { state: 'unknown', code: String(r.status), message: payClean(r.body?.status?.message || r.text, 200) };
      if (tx.id && String(tx.id) !== payment.reference) return { state: 'needs_review', code: 'reference_mismatch', message: 'La référence renvoyée ne correspond pas.' };
      const code = String(tx.status || '').toUpperCase();
      return { state: AIRTEL_STATES[code] || 'needs_review', providerRef: payClean(tx.airtel_money_id || '', 100) || undefined, code, message: payClean(tx.message || '', 200) };
    }
  },

  // --- Vodacom M-Pesa RDC (Open API : session chiffrée RSA + C2B « single stage ») --------------------------------
  mpesa: {
    async prepare(cfg) { await mpesaSession(cfg); },
    async initiate(cfg, { payment, msisdn, orderRef }) {
      const sid = await mpesaSession(cfg);
      const r = await payFetch(mpesaUrl(cfg, 'c2bPayment/singleStage/'), { method: 'POST', headers: mpesaHeaders(cfg, sid), body: JSON.stringify({
        input_Amount: String(payment.amount), input_Country: cfg.country, input_Currency: cfg.currency, input_CustomerMSISDN: msisdn,
        input_ServiceProviderCode: cfg.shortcode, input_TransactionReference: payment.reference, input_ThirdPartyConversationID: payment.reference,
        input_PurchasedItemsDesc: `Commande ${orderRef}` }) });
      const code = String(r.body?.output_ResponseCode || ''), msg = payClean(r.body?.output_ResponseDesc || r.text, 200);
      const ref = payClean(r.body?.output_TransactionID || r.body?.output_ConversationID || '', 100) || undefined;
      if (code === 'INS-0') return { state: 'processing', verifyNow: true, providerRef: ref, code, message: msg };
      if (code === 'INS-5') return { state: 'cancelled', code, message: msg };
      if (code === 'INS-9' || code === 'INS-10') return { state: 'processing', providerRef: ref, code, message: msg };
      if (MPESA_FAILED.has(code)) return { state: 'failed', code, message: msg };
      if (!code) throw new Error(`M-Pesa réponse inattendue (${r.status})`);
      return { state: 'needs_review', providerRef: ref, code, message: msg };
    },
    async verify(cfg, payment) {
      let sid; try { sid = await mpesaSession(cfg); } catch (e) { if (e instanceof ProviderUnavailable) return { state: 'unknown', code: 'session', message: 'Session M-Pesa indisponible' }; throw e; }
      const q = new URLSearchParams({ input_QueryReference: payment.provider_ref || payment.reference, input_ServiceProviderCode: cfg.shortcode, input_ThirdPartyConversationID: payment.reference + 'Q' + Date.now().toString(36).toUpperCase(), input_Country: cfg.country });
      const r = await payFetch(mpesaUrl(cfg, 'queryTransactionStatus/') + '?' + q, { headers: mpesaHeaders(cfg, sid) });
      const code = String(r.body?.output_ResponseCode || '');
      if (!r.ok || !code) return { state: 'unknown', code: String(r.status), message: payClean(r.text, 200) };
      if (code !== 'INS-0') return { state: 'unknown', code, message: payClean(r.body?.output_ResponseDesc || '', 200) };
      const st = String(r.body?.output_ResponseTransactionStatus || '').toLowerCase();
      const map = { completed: 'success', cancelled: 'cancelled', canceled: 'cancelled', expired: 'expired', failed: 'failed', pending: 'processing', processing: 'processing' };
      return { state: map[st] || 'needs_review', providerRef: payClean(r.body?.output_ConversationID || '', 100) || undefined, code: st || code, message: payClean(r.body?.output_ResponseDesc || '', 200) };
    }
  },

  // --- Orange Money RDC (Orange Money Web Payment : redirection vers la page sécurisée Orange) -------------------
  orange: {
    async initiate(cfg, { payment, orderRef }) {
      const t = await omToken(cfg);
      const back = `${cfg.site}/?pay=${encodeURIComponent(payment.reference)}`;
      const r = await payFetch(cfg.base + cfg.paymentPath, { method: 'POST', headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({
        merchant_key: cfg.merchantKey, currency: cfg.currency, order_id: payment.reference, amount: payment.amount, lang: 'fr', reference: `Commande ${orderRef}`,
        return_url: back, cancel_url: back, notif_url: `${cfg.site}/api/payments/callback/orange?k=${encodeURIComponent(penv('PAYMENT_CALLBACK_SECRET'))}` }) });
      const b = r.body || {};
      let payUrl = ''; try { const u = new URL(String(b.payment_url || '')); if (u.protocol === 'https:') payUrl = u.toString(); } catch {}
      if (r.ok && (!payUrl || !b.pay_token)) return { state: 'failed', code: 'invalid_payment_url', message: 'Orange n’a pas fourni de page de paiement sécurisée valide.' };
      if (r.ok && payUrl && b.pay_token) return { state: 'processing', providerRef: payClean(b.pay_token, 200), notifToken: payClean(b.notif_token || '', 200) || undefined, payUrl, code: String(b.status || ''), message: 'Redirection vers Orange Money' };
      if (r.status >= 400 && r.status < 500) return { state: 'failed', code: payClean(b.code || b.status || r.status, 40), message: payClean(b.message || b.description || r.text, 200) };
      throw new Error(`Orange réponse inattendue (${r.status})`);
    },
    async verify(cfg, payment) {
      const t = await omToken(cfg);
      const r = await payFetch(cfg.base + cfg.statusPath, { method: 'POST', headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ order_id: payment.reference, amount: Number(payment.amount), pay_token: payment.provider_ref }) });
      const b = r.body || {};
      if (!r.ok || !b.status) return { state: 'unknown', code: String(r.status), message: payClean(b.message || r.text, 200) };
      if (b.order_id && String(b.order_id) !== payment.reference) return { state: 'needs_review', code: 'reference_mismatch', message: 'La référence renvoyée ne correspond pas.' };
      const map = { SUCCESS: 'success', FAILED: 'failed', EXPIRED: 'expired', PENDING: 'processing', INITIATED: 'processing' };
      return { state: map[String(b.status).toUpperCase()] || 'needs_review', providerRef: undefined, code: String(b.status), message: '', txnid: payClean(b.txnid || '', 100) };
    }
  }
};
const omTokens = new Map();
async function omToken(cfg) {
  const key = cfg.base + cfg.tokenPath + cfg.authHeader.slice(-8), c = omTokens.get(key);
  if (c && c.exp > Date.now() + 30000) return c.token;
  const r = await payFetch(cfg.base + cfg.tokenPath, { method: 'POST', headers: { Authorization: cfg.authHeader, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: 'grant_type=client_credentials' });
  const t = r.body?.access_token;
  if (!r.ok || !t) throw new Error(`Orange authentification refusée (${r.status}) ${r.text}`);
  omTokens.set(key, { token: t, exp: Date.now() + (Number(r.body.expires_in) || 3600) * 1000 });
  return t;
}
// M-Pesa : le gateway n'utilise pas OAuth. La clé API et le SessionID sont chiffrés en RSA avec la clé publique fournie par M-Pesa.
const MPESA_FAILED = new Set(['INS-6', 'INS-13', 'INS-15', 'INS-17', 'INS-20', 'INS-21', 'INS-26', 'INS-28', 'INS-30', 'INS-2006', 'INS-2051', 'INS-996', 'INS-997', 'INS-998']);
const MPESA_ACTIVATION_MS = 35_000; // un nouveau SessionID peut mettre jusqu'à ~30 s à devenir actif
const mpesaUrl = (cfg, p) => `https://${cfg.host}/${cfg.path}/${p}`;
function mpesaBearer(value, cfg) {
  const b64 = cfg.publicKey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  return crypto.publicEncrypt({ key: pem, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(value, 'utf8')).toString('base64');
}
const mpesaHeaders = (cfg, sid) => ({ 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${mpesaBearer(sid, cfg)}`, Origin: cfg.origin });
async function mpesaFetchSession(cfg) {
  const r = await payFetch(mpesaUrl(cfg, 'getSession/'), { headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${mpesaBearer(cfg.apiKey, cfg)}`, Origin: cfg.origin } });
  const sid = r.body?.output_SessionID;
  if (!r.ok || r.body?.output_ResponseCode !== 'INS-0' || !sid) throw new Error(`M-Pesa session refusée (${r.status}) ${payClean(r.body?.output_ResponseCode || '', 20)} ${payClean(r.body?.output_ResponseDesc || r.text, 150)}`);
  return String(sid);
}
// Session partagée entre toutes les instances Netlify (table provider_tokens) : session courante + session suivante en cours d'activation.
async function mpesaSession(cfg) {
  const now = Date.now(), { rows } = await pool.query("SELECT * FROM provider_tokens WHERE provider='mpesa'"), row = rows[0];
  const age = row ? now - Number(row.created_at) : Infinity, curValid = !!row && !!row.token && age < cfg.sessionTtlMs;
  const nextAge = row?.next_token ? now - Number(row.next_created_at) : Infinity;
  const nextPending = !!row?.next_token && nextAge < cfg.sessionTtlMs, nextUsable = nextPending && nextAge >= MPESA_ACTIVATION_MS;
  if (nextUsable && (!curValid || age >= cfg.sessionTtlMs * 0.8)) {
    await pool.query("UPDATE provider_tokens SET token=next_token, created_at=next_created_at, expires_at=$1, next_token=NULL, next_created_at=NULL WHERE provider='mpesa'", [Number(row.next_created_at) + cfg.sessionTtlMs]);
    return row.next_token;
  }
  if (curValid) {
    if (age >= cfg.sessionTtlMs * 0.7 && !nextPending) {
      try { const sid = await mpesaFetchSession(cfg); await pool.query("UPDATE provider_tokens SET next_token=$1, next_created_at=$2 WHERE provider='mpesa'", [sid, now]); } catch (e) { errLog(e, 'mpesa_session_refresh'); }
    }
    return row.token;
  }
  if (!nextPending) {
    const sid = await mpesaFetchSession(cfg);
    await pool.query("INSERT INTO provider_tokens (provider,token,created_at,expires_at,next_token,next_created_at) VALUES ('mpesa','',0,0,$1,$2) ON CONFLICT (provider) DO UPDATE SET next_token=EXCLUDED.next_token, next_created_at=EXCLUDED.next_created_at", [sid, now]);
  }
  throw new ProviderUnavailable('Le service M-Pesa est en cours d’initialisation. Réessaie dans une minute.');
}

// --- Journal technique + changements de statut (une seule porte d'entrée, transactionnelle et idempotente) ---------
async function addPaymentEvent(paymentId, kind, detail) {
  try { await pool.query('INSERT INTO payment_events (payment_id,at,kind,detail) VALUES ($1,$2,$3,$4)', [paymentId, Date.now(), kind, payClean(detail, 400)]); } catch (e) { errLog(e, 'payment_event'); }
}
const TERMINAL_PAYMENT = ['success', 'failed', 'cancelled', 'expired'];
async function applyPaymentState(paymentId, next, info = {}) {
  const client = await pool.connect(); let destroy = false, out = null;
  try {
    await client.query('BEGIN');
    const { rows } = await client.query('SELECT * FROM payments WHERE id=$1 FOR UPDATE', [paymentId]);
    const p = rows[0];
    if (!p) { await client.query('ROLLBACK'); return null; }
    out = { payment: p, changed: false, becameSuccess: false };
    // Jamais de retour en arrière : un paiement réussi reste réussi ; un état final ne change que si l'opérateur confirme un succès tardif.
    if (p.status === 'success' || (TERMINAL_PAYMENT.includes(p.status) && next !== 'success')) { await client.query('COMMIT'); return out; }
    let target = next, code = info.code ?? null, message = info.message ?? null;
    if (next === 'success') {
      const dup = await client.query("SELECT 1 FROM payments WHERE order_id=$1 AND status='success' AND id<>$2", [p.order_id, p.id]);
      if (dup.rowCount) { target = 'needs_review'; code = 'duplicate_payment'; message = 'Un autre paiement réussi existe déjà pour cette commande : remboursement à vérifier.'; }
    }
    if (target === p.status && !info.providerRef) { await client.query('COMMIT'); return out; }
    const now = Date.now();
    const upd = await client.query('UPDATE payments SET status=$1, provider_ref=COALESCE($2,provider_ref), error_code=$3, error_message=$4, updated_at=$5, confirmed_at=COALESCE($6,confirmed_at) WHERE id=$7 RETURNING *',
      [target, info.providerRef ?? null, code ? payClean(code, 60) : null, message ? payClean(message, 300) : null, now, target === 'success' ? now : null, p.id]);
    out = { payment: upd.rows[0] || { ...p, status: target }, changed: target !== p.status, becameSuccess: target === 'success' };
    if (target === 'success') await client.query("UPDATE orders SET status='Payée' WHERE id=$1 AND status='En attente'", [p.order_id]);
    await client.query('COMMIT');
    return out;
  } catch (e) { try { await client.query('ROLLBACK'); } catch { destroy = true; } throw e; }
  finally { client.release(destroy); }
}
async function notifyPaymentSuccess(p) {
  try {
    const { rows } = await pool.query('SELECT customer_email, customer_name, UPPER(LEFT(id,8)) AS ref FROM orders WHERE id=$1', [p.order_id]);
    const o = rows[0]; if (!o) return;
    const amount = `${Number(p.amount).toLocaleString('fr-FR')} FC`;
    const subject = `Paiement reçu — commande ${o.ref}`;
    const text = `Bonjour ${o.customer_name},\n\nNous avons bien reçu ton paiement de ${amount} par ${PROVIDER_LABELS[p.provider]} pour la commande ${o.ref}. Nous préparons ta livraison.\n\nMerci d’avoir choisi Outfit-Shirt.`;
    await Promise.race([brevoSend(o.customer_email, subject, text, `<p>Bonjour ${o.customer_name.replace(/[<>&]/g, '')},</p><p>Nous avons bien reçu ton paiement de <strong>${amount}</strong> par ${PROVIDER_LABELS[p.provider]} pour la commande <strong>${o.ref}</strong>. Nous préparons ta livraison.</p><p>Merci d’avoir choisi Outfit-Shirt.</p>`), new Promise((_, rej) => setTimeout(() => rej(new Error('délai e-mail dépassé')), 5000))]);
  } catch (e) { errLog(e, 'payment_success_email'); }
}
// Vérification serveur à serveur auprès de l'opérateur : SEULE source de vérité pour passer un paiement en « réussi ».
async function verifyPayment(p, reason) {
  const prov = providerConfig(p.provider);
  if (!prov.ready) { await addPaymentEvent(p.id, 'verify_skipped', 'opérateur non activé'); return p; }
  const now = Date.now();
  await pool.query('UPDATE payments SET last_checked_at=$1, check_count=check_count+1 WHERE id=$2', [now, p.id]);
  let r;
  try { r = await ADAPTERS[p.provider].verify(prov.cfg, p); }
  catch (e) { await addPaymentEvent(p.id, 'verify_error', `${reason}: ${e.message}`); r = { state: 'unknown', code: 'unreachable', message: 'API opérateur injoignable' }; }
  await addPaymentEvent(p.id, 'verify', `${reason}: ${r.state} (${r.code || '-'}) ${r.message || ''}`);
  let state = r.state, info = { providerRef: r.providerRef, code: r.code, message: r.message };
  if (state === 'success' && r.amount != null && Number(r.amount) !== Number(p.amount)) { state = 'needs_review'; info = { ...info, code: 'amount_mismatch', message: 'Montant différent de celui attendu.' }; }
  if (state === 'success' && r.currency && String(r.currency) !== p.currency) { state = 'needs_review'; info = { ...info, code: 'currency_mismatch', message: 'Devise différente de celle attendue.' }; }
  if (state === 'unknown') {
    if (now <= Number(p.expires_at) || !PAYMENT_OPEN.includes(p.status)) return (await reloadPayment(p.id)) || p;
    state = 'needs_review'; info = { ...info, code: info.code || 'no_confirmation', message: 'Aucune confirmation de l’opérateur après le délai.' };
  } else if (state === 'processing' && now > Number(p.expires_at) && PAYMENT_OPEN.includes(p.status)) {
    state = 'expired'; info = { ...info, code: 'expired', message: 'Délai de paiement dépassé.' };
  }
  const res = await applyPaymentState(p.id, state, info);
  if (res?.becameSuccess) { await addPaymentEvent(p.id, 'success', 'paiement confirmé par l’opérateur'); await notifyPaymentSuccess(res.payment); }
  return res?.payment || p;
}
async function reloadPayment(id) { const { rows } = await pool.query('SELECT * FROM payments WHERE id=$1', [id]); return rows[0] || null; }
// Aucune tâche planifiée n'existe : les paiements ouverts sont revérifiés au passage (liste admin, nouveau paiement).
async function sweepOpenPayments(limit = 5) {
  const now = Date.now();
  const { rows } = await pool.query('SELECT * FROM payments WHERE status = ANY($1::text[]) AND created_at < $2 AND COALESCE(last_checked_at,0) < $3 ORDER BY created_at LIMIT $4', [PAYMENT_OPEN.filter(s => s !== 'pending_payment'), now - 20_000, now - 60_000, limit]);
  await Promise.allSettled(rows.map(r => verifyPayment(r, 'sweep')));
}
const PAYMENT_CUSTOMER_TEXT = {
  pending_payment: 'Préparation du paiement…',
  success: 'Paiement confirmé. Merci ! Nous préparons ta livraison.',
  failed: 'Le paiement n’a pas abouti. Tu peux réessayer. Si ton compte a été débité, contacte-nous avec ton numéro de commande.',
  cancelled: 'Le paiement a été annulé. Tu peux réessayer.',
  expired: 'Le délai de paiement est dépassé. Tu peux relancer un paiement.',
  needs_review: 'Nous vérifions ton paiement auprès de l’opérateur. Ne paie pas une deuxième fois ; si cela dure, contacte-nous avec ton numéro de commande.'
};
function paymentPublic(p, orderRef) {
  const open = PAYMENT_OPEN.includes(p.status);
  const processing = p.provider === 'orange'
    ? 'Tu vas être redirigé vers la page sécurisée d’Orange Money pour confirmer le paiement. Nous ne te demandons jamais ton code PIN.'
    : `Une demande de paiement a été envoyée au ${p.msisdn_masked}. Valide-la sur ton téléphone avec ton code secret Mobile Money. Ne communique jamais ton code PIN à qui que ce soit.`;
  return { ref: p.reference, orderRef, provider: p.provider, providerLabel: PROVIDER_LABELS[p.provider], amount: Number(p.amount), currency: p.currency, phone: p.msisdn_masked,
    status: p.status, statusLabel: PAYMENT_STATUS_LABELS[p.status] || p.status, message: p.status === 'processing' ? processing : (PAYMENT_CUSTOMER_TEXT[p.status] || ''),
    payUrl: p.provider === 'orange' && open ? (p.pay_url || '') : '', testMode: p.environment !== 'production', createdAt: Number(p.created_at), expiresAt: Number(p.expires_at) };
}
const paymentAdmin = p => ({ id: p.id, orderRef: p.order_ref, orderId: p.order_id, amount: Number(p.amount), currency: p.currency, provider: p.provider, providerLabel: PROVIDER_LABELS[p.provider], reference: p.reference, providerRef: p.provider_ref || '', createdAt: Number(p.created_at), confirmedAt: p.confirmed_at ? Number(p.confirmed_at) : null, status: p.status, statusLabel: PAYMENT_STATUS_LABELS[p.status] || p.status, phone: p.msisdn_masked, environment: p.environment, errorCode: p.error_code || '', errorMessage: p.error_message || '' });
// Callback des opérateurs : ne prouve RIEN, il déclenche seulement la vérification serveur à serveur.
async function handlePaymentCallback(req, url, ip) {
  const provider = url.pathname.split('/').pop();
  if (!PROVIDER_LABELS[provider]) throw new HttpError(404, 'not_found', 'Introuvable.');
  if (!allow('payment-callback:' + ip, 120, MIN)) throw new HttpError(429, 'rate_limited', 'Trop de requêtes.');
  const secret = penv('PAYMENT_CALLBACK_SECRET');
  if (secret.length < 16 || !safeEqual(url.searchParams.get('k') || '', secret)) throw new HttpError(403, 'forbidden', 'Accès refusé.');
  let body = {}; try { const raw = await req.text(); if (raw.length > 20000) throw 0; body = JSON.parse(raw) || {}; } catch { body = {}; }
  let p = null;
  if (provider === 'airtel') { const ref = body?.transaction?.id; if (typeof ref === 'string') p = (await pool.query("SELECT * FROM payments WHERE provider='airtel' AND reference=$1", [ref.slice(0, 60)])).rows[0]; }
  if (provider === 'mpesa') { const ref = body?.input_ThirdPartyConversationID; if (typeof ref === 'string') p = (await pool.query("SELECT * FROM payments WHERE provider='mpesa' AND reference=$1", [ref.slice(0, 60)])).rows[0]; }
  if (provider === 'orange') { const nt = body?.notif_token; if (typeof nt === 'string' && nt.length >= 8) p = (await pool.query("SELECT * FROM payments WHERE provider='orange' AND notif_token=$1", [nt.slice(0, 200)])).rows[0]; }
  if (p) { await addPaymentEvent(p.id, 'callback', `reçu (${provider}), vérification en cours`); await verifyPayment(p, 'callback'); }
  if (provider === 'mpesa') return json({ output_OriginalConversationID: payClean(body?.input_OriginalConversationID, 60), output_ResponseCode: '0', output_ResponseDesc: 'Successfully Accepted Result', output_ThirdPartyConversationID: payClean(body?.input_ThirdPartyConversationID, 60) });
  return json({ ok: true });
}
const orderPublic = r => ({ id: r.id, ref: r.id.slice(0, 8).toUpperCase(), createdAt: Number(r.created_at), customerName: r.customer_name, email: r.customer_email, phone: r.phone, address: r.address, items: r.items, total: Number(r.total), status: r.status, trackingCode: r.tracking_code || '' });
export const config = { path: '/api/*' };
export default async function handler(req) {
  let cookies=[], routeName='init';
  try {
    await ensureSchema();
    const url=new URL(req.url), route=`${req.method} ${url.pathname}`, ip=getIp(req); routeName=route;
    const auth=await currentSession(req); if(auth?.refreshCookie) cookies.push(auth.refreshCookie);
    const admin=await currentAdminSession(req);
    if(route==='GET /api/me') return json(auth?{user:publicUser(auth.row),csrfToken:auth.row.csrf}:{user:null,csrfToken:null},200,cookies);
    if(route==='GET /api/products') { const {rows}=await pool.query('SELECT * FROM products WHERE active=TRUE ORDER BY created_at DESC'); return json({products:rows.map(productPublic)}); }
    if(route==='GET /api/settings') { const {rows}=await pool.query('SELECT value FROM site_settings WHERE key=$1',[SETTINGS_KEY]); return json({settings:settingsFromValue(rows[0]?.value)}); }
    if(route==='GET /api/my-orders') { requireAuth(req,auth,false); const {rows}=await pool.query('SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[auth.row.user_id]); return json({orders:rows.map(orderPublic)}); }
    if(route==='GET /api/admin/me') return json({admin:!!admin,email:admin?ADMIN_EMAIL:null,csrfToken:admin?admin.row.csrf:null},200,cookies);
    if(route==='GET /api/admin/clients') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT id,email,first_name,last_name,post_name,phone,birth_date,address,created_at,last_login_at,locked_until,account_blocked FROM users ORDER BY created_at DESC LIMIT 1000'); return json({clients:rows.map(r=>({id:r.id,email:r.email,firstName:r.first_name,lastName:r.last_name||'',postName:r.post_name||'',phone:r.phone||'',birthDate:r.birth_date||'',address:r.address||'',createdAt:Number(r.created_at),lastLoginAt:r.last_login_at==null?null:Number(r.last_login_at),lockedUntil:Number(r.locked_until||0),blocked:!!r.account_blocked}))}); }
    if(route==='GET /api/admin/products') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT * FROM products ORDER BY created_at DESC'); return json({products:rows.map(productPublic)}); }
    if(route==='GET /api/admin/orders') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500'); return json({orders:rows.map(orderPublic)}); }
    if(route==='GET /api/admin/stats') { requireAdmin(req,admin,false); const {rows}=await pool.query(`SELECT COUNT(*)::int AS orders, COALESCE(SUM(total) FILTER (WHERE status='Livrée'),0)::bigint AS revenue, COUNT(*) FILTER (WHERE status='En attente')::int AS pending, COUNT(DISTINCT user_id)::int AS customers FROM orders`); const {rows:daily}=await pool.query(`SELECT TO_CHAR(TO_TIMESTAMP(created_at/1000.0),'YYYY-MM-DD') AS day, COALESCE(SUM(total) FILTER (WHERE status='Livrée'),0)::bigint AS revenue, COUNT(*) FILTER (WHERE status='Livrée')::int AS orders FROM orders WHERE created_at >= $1 AND status='Livrée' GROUP BY day ORDER BY day`,[Date.now()-30*24*60*60*1000]); return json({summary:rows[0],daily}); }
    if(route.startsWith('POST /api/payments/callback/')) return await handlePaymentCallback(req,url,ip);
    if(route==='GET /api/payments/providers') return json({currency:'CDF',providers:Object.keys(PROVIDER_LABELS).map(id=>{const c=providerConfig(id);return {id,label:c.label,available:c.ready,testMode:c.ready&&c.environment!=='production'};})});
    if(route==='GET /api/payments/status') {
      requireAuth(req,auth,false);
      const ref=(url.searchParams.get('ref')||'').slice(0,40);
      const {rows}=await pool.query('SELECT p.*, UPPER(LEFT(o.id,8)) AS order_ref FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.reference=$1 AND o.user_id=$2',[ref,auth.row.user_id]);
      let p=rows[0]; if(!p) throw new HttpError(404,'payment_not_found','Paiement introuvable.');
      if(PAYMENT_OPEN.includes(p.status)&&p.status!=='pending_payment'&&Date.now()-Number(p.last_checked_at||0)>4000){ const v=await verifyPayment(p,'poll'); p={...p,...v}; }
      return json({payment:paymentPublic(p,p.order_ref)});
    }
    if(route==='GET /api/admin/payments') {
      requireAdmin(req,admin,false);
      await sweepOpenPayments();
      const q=url.searchParams, provider=PROVIDER_LABELS[q.get('provider')]?q.get('provider'):null, status=PAYMENT_STATUS_LABELS[q.get('status')]?q.get('status'):null;
      const day=(d,add)=>/^\d{4}-\d{2}-\d{2}$/.test(d||'')?Date.parse(d+'T00:00:00+02:00')+add:null, from=day(q.get('from'),0), to=day(q.get('to'),DAY);
      const {rows}=await pool.query('SELECT p.*, UPPER(LEFT(o.id,8)) AS order_ref FROM payments p JOIN orders o ON o.id=p.order_id WHERE ($1::text IS NULL OR p.provider=$1) AND ($2::text IS NULL OR p.status=$2) AND ($3::bigint IS NULL OR p.created_at>=$3) AND ($4::bigint IS NULL OR p.created_at<$4) ORDER BY p.created_at DESC LIMIT 500',[provider,status,from,to]);
      const counts={}; rows.forEach(r=>{counts[r.status]=(counts[r.status]||0)+1;});
      const providers=Object.keys(PROVIDER_LABELS).map(id=>{const c=providerConfig(id);return {id,label:c.label,enabled:c.enabled,ready:c.ready,environment:c.environment,missing:c.missing,callbackPath:`/api/payments/callback/${id}`};});
      return json({payments:rows.map(paymentAdmin),counts,providers});
    }
    if(route==='GET /api/admin/payment-events') {
      requireAdmin(req,admin,false);
      const {rows}=await pool.query('SELECT at,kind,detail FROM payment_events WHERE payment_id=$1 ORDER BY id DESC LIMIT 50',[(url.searchParams.get('id')||'').slice(0,60)]);
      return json({events:rows.map(r=>({at:Number(r.at),kind:r.kind,detail:r.detail}))});
    }
    if(req.method!=='POST') throw new HttpError(404,'not_found','Introuvable.');
    guardMutation(req);
    switch(url.pathname){
      case '/api/forgot-password': {
        if(!allow('forgot-ip:'+ip,8,HOUR)) throw new HttpError(429,'rate_limited','Trop de demandes. Réessaie plus tard.');
        const b=await readJson(req), email=normEmail(b.email);
        if(!emailOk(email)) return json({ok:true,message:'Si un compte correspond à cette adresse, un e-mail de réinitialisation sera envoyé.'});
        if(!allow('forgot-email:'+sha256(email),3,HOUR)) return json({ok:true,message:'Si un compte correspond à cette adresse, un e-mail de réinitialisation sera envoyé.'});
        const {rows}=await pool.query('SELECT id,email,account_blocked FROM users WHERE email=$1',[email]);
        const user=rows[0];
        if(user&&user.account_blocked!==true){
          const rawToken=token(), now=Date.now(), expiresAt=now+30*MIN;
          // Délai de 60 s entre deux demandes pour le même compte (vérifié en base, donc valable entre toutes les instances) : évite le spam d'e-mails.
          const recent=await pool.query('SELECT 1 FROM password_reset_tokens WHERE user_id=$1 AND created_at>$2 LIMIT 1',[user.id,now-RESET_COOLDOWN_MS]);
          if(recent.rowCount) return json({ok:true,message:'Si un compte correspond à cette adresse, un e-mail de réinitialisation sera envoyé.'});
          await pool.query('DELETE FROM password_reset_tokens WHERE user_id=$1 OR expires_at<=$2',[user.id,now]);
          await pool.query('INSERT INTO password_reset_tokens (token_hash,user_id,expires_at,created_at) VALUES ($1,$2,$3,$4)',[sha256(rawToken),user.id,expiresAt,now]);
          const base=(process.env.SITE_URL||'https://outfitshirt.netlify.app').replace(/\/$/,'');
          const resetUrl=`${base}/?resetToken=${encodeURIComponent(rawToken)}`;
          try { await sendPasswordResetEmail(user.email,resetUrl); }
          catch(e) { errLog(e); await pool.query('DELETE FROM password_reset_tokens WHERE token_hash=$1',[sha256(rawToken)]); }
        }
        return json({ok:true,message:'Si un compte correspond à cette adresse, un e-mail de réinitialisation sera envoyé.'});
      }
      case '/api/reset-password': {
        if(!allow('reset-ip:'+ip,10,HOUR)) throw new HttpError(429,'rate_limited','Trop de tentatives. Réessaie plus tard.');
        const b=await readJson(req), rawToken=typeof b.token==='string'?b.token:'', next=typeof b.password==='string'?b.password:'';
        if(rawToken.length<32||rawToken.length>200) throw new HttpError(400,'invalid_reset_token','Ce lien de réinitialisation est invalide ou expiré.');
        const found=await pool.query('SELECT pr.token_hash,pr.user_id,pr.expires_at,u.email,u.first_name FROM password_reset_tokens pr JOIN users u ON u.id=pr.user_id WHERE pr.token_hash=$1',[sha256(rawToken)]);
        const reset=found.rows[0];
        if(!reset||Number(reset.expires_at)<=Date.now()) {
          if(reset) await pool.query('DELETE FROM password_reset_tokens WHERE token_hash=$1',[reset.token_hash]);
          throw new HttpError(400,'invalid_reset_token','Ce lien de réinitialisation est invalide ou expiré.');
        }
        const problems=passwordProblems(next,{email:reset.email,firstName:reset.first_name});
        if(problems.length) throw new HttpError(400,'password_policy',problems[0],problems);
        const newHash=await hashPassword(next), client=await pool.connect();
        try {
          await client.query('BEGIN');
          const locked=await client.query('SELECT user_id,expires_at FROM password_reset_tokens WHERE token_hash=$1 FOR UPDATE',[reset.token_hash]);
          if(!locked.rowCount||Number(locked.rows[0].expires_at)<=Date.now()) throw new HttpError(400,'invalid_reset_token','Ce lien de réinitialisation est invalide ou expiré.');
          await client.query('UPDATE users SET password_hash=$1,failed_attempts=0,locked_until=0 WHERE id=$2',[newHash,reset.user_id]);
          await client.query('DELETE FROM password_reset_tokens WHERE user_id=$1',[reset.user_id]);
          await client.query('DELETE FROM sessions WHERE user_id=$1',[reset.user_id]);
          await client.query('COMMIT');
        } catch(e) { await client.query('ROLLBACK'); throw e; }
        finally { client.release(); }
        try { await sendPasswordChangedEmail(reset.email); } catch(e) { errLog(e,'password_changed_notice'); }
        return json({ok:true,message:'Mot de passe modifié. Tu peux maintenant te connecter.'});
      }
      case '/api/admin/login': {
        if(!allow('admin-login:'+ip,8,15*MIN)) throw new HttpError(429,'rate_limited','Trop de tentatives. Réessaie dans quelques minutes.');
        const b=await readJson(req), email=normEmail(b.email), password=typeof b.password==='string'?b.password:'';
        const expected=process.env.ADMIN_PASSWORD||'';
        if(!expected) throw new HttpError(503,'admin_not_configured','L’administration doit être configurée dans les variables Netlify.');
        if(email!==ADMIN_EMAIL||!safeEqual(password,expected)) throw new HttpError(401,'invalid_credentials','E-mail ou mot de passe administrateur incorrect.');
        if(admin) await pool.query('DELETE FROM admin_sessions WHERE id_hash=$1',[admin.idHash]);
        const session=await createAdminSession(req);
        return json({admin:true,email:ADMIN_EMAIL,csrfToken:session.csrf},200,[adminCookie('',0),session.cookie]);
      }
      case '/api/admin/logout': { const b=await readJson(req); requireAdmin(req,admin,true); await pool.query('DELETE FROM admin_sessions WHERE id_hash=$1',[admin.idHash]); return json({ok:true},200,[adminCookie('',0)]); }
      case '/api/admin/settings-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const settings=parseSettings(b);
        await pool.query('INSERT INTO site_settings (key,value,updated_at) VALUES ($1,$2::jsonb,$3) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at',[SETTINGS_KEY,JSON.stringify(settings),Date.now()]);
        return json({ok:true,settings});
      }
      case '/api/payments/initiate': {
        const b=await readJson(req); requireAuth(req,auth,true);
        if(!allow('pay:'+auth.row.user_id,8,15*MIN)) throw new HttpError(429,'rate_limited','Trop de tentatives de paiement. Réessaie dans quelques minutes.');
        const providerId=String(b.provider||''); if(!PROVIDER_LABELS[providerId]) throw new HttpError(400,'invalid_provider','Choisis un moyen de paiement.');
        const prov=providerConfig(providerId);
        if(!prov.ready) throw new HttpError(503,'provider_not_active',`${prov.label} n’est pas encore disponible. Choisis un autre moyen de paiement ou contacte-nous.`);
        const msisdn=normalizeMsisdn(b.phone); if(!msisdn) throw new HttpError(400,'invalid_phone','Entre un numéro Mobile Money valide : +243 suivi de 9 chiffres.');
        const orderRef=String(b.orderRef||'').toUpperCase(); if(!/^[A-F0-9]{8}$/.test(orderRef)) throw new HttpError(400,'invalid_order','Commande invalide.');
        const {rows:orows}=await pool.query('SELECT * FROM orders WHERE user_id=$1 AND UPPER(LEFT(id,8))=$2 ORDER BY created_at DESC LIMIT 1',[auth.row.user_id,orderRef]);
        const order=orows[0]; if(!order) throw new HttpError(404,'order_not_found','Commande introuvable.');
        if(order.status!=='En attente') throw new HttpError(409,'order_not_payable','Cette commande ne peut plus être payée en ligne.');
        const amount=Number(order.total); if(!Number.isSafeInteger(amount)||amount<=0) throw new HttpError(400,'invalid_amount','Montant de commande invalide.');
        const paid=await pool.query("SELECT 1 FROM payments WHERE order_id=$1 AND status='success'",[order.id]); if(paid.rowCount) throw new HttpError(409,'already_paid','Cette commande est déjà payée.');
        await pool.query("UPDATE payments SET status='failed', error_code='abandoned', error_message='Tentative abandonnée avant l’appel à l’opérateur.', updated_at=$2 WHERE order_id=$1 AND status='pending_payment' AND created_at<$3",[order.id,Date.now(),Date.now()-2*MIN]);
        try { await ADAPTERS[providerId].prepare?.(prov.cfg); } catch(e) { if(e instanceof ProviderUnavailable) throw new HttpError(503,'provider_unavailable',e.message); throw e; }
        const id=crypto.randomUUID(), reference='OS'+crypto.randomBytes(8).toString('hex').toUpperCase(), now=Date.now();
        try { await pool.query('INSERT INTO payments (id,order_id,provider,reference,amount,currency,msisdn_masked,status,environment,created_at,updated_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)',[id,order.id,providerId,reference,amount,'CDF',maskMsisdn(msisdn),'pending_payment',prov.environment,now,now+PAYMENT_TTL_MS]); }
        catch(e) {
          if(e?.code==='23505') { const cur=(await pool.query('SELECT * FROM payments WHERE order_id=$1 AND status = ANY($2::text[]) ORDER BY created_at DESC LIMIT 1',[order.id,PAYMENT_OPEN])).rows[0]; if(cur) return json({ok:true,existing:true,payment:paymentPublic(cur,orderRef)},200,cookies); }
          throw e;
        }
        await addPaymentEvent(id,'initiate',`${providerId} (${prov.environment}) ${amount} CDF`);
        let result;
        try { result=await ADAPTERS[providerId].initiate(prov.cfg,{payment:{id,reference,amount},msisdn,orderRef}); }
        catch(e) { await addPaymentEvent(id,'initiate_error',e.message); errLog(e,'payment_initiate'); result={state:'processing',code:'no_response',message:'Pas de réponse de l’opérateur : vérification en cours.'}; }
        await pool.query('UPDATE payments SET provider_ref=$1, notif_token=$2, pay_url=$3, updated_at=$4 WHERE id=$5',[result.providerRef||null,result.notifToken||null,result.payUrl||null,Date.now(),id]);
        await addPaymentEvent(id,'initiate_result',`${result.state} (${result.code||'-'}) ${result.message||''}`);
        let row=(await applyPaymentState(id,result.state,{providerRef:result.providerRef,code:result.code,message:result.message}))?.payment||await reloadPayment(id);
        if(result.verifyNow&&row&&row.status==='processing') row=await verifyPayment(row,'initiate');
        return json({ok:true,payment:paymentPublic(row,orderRef)},201,cookies);
      }
      case '/api/admin/payment-recheck': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const {rows}=await pool.query('SELECT p.*, UPPER(LEFT(o.id,8)) AS order_ref FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.id=$1',[String(b.id||'').slice(0,60)]);
        const p=rows[0]; if(!p) throw new HttpError(404,'payment_not_found','Paiement introuvable.');
        if(p.status==='success') return json({ok:true,payment:paymentAdmin(p)});
        const v=await verifyPayment(p,'admin');
        return json({ok:true,payment:paymentAdmin({...p,...v})});
      }
      case '/api/admin/product-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const name=typeof b.name==='string'?b.name.trim().slice(0,100):'', brand=typeof b.brand==='string'?b.brand.trim().slice(0,60):'';
        const price=Number(b.price), old=b.old===''||b.old==null?null:Number(b.old);
        if(!name||!Number.isSafeInteger(price)||price<1||price>100000000||(old!==null&&(!Number.isSafeInteger(old)||old<price||old>100000000))) throw new HttpError(400,'invalid_product','Vérifie le nom et les prix en FC.');
        const color=/^#[0-9a-f]{6}$/i.test(b.color||'')?b.color:'#FFFFFF', ink=/^#[0-9a-f]{6}$/i.test(b.ink||'')?b.ink:'#000000';
        const tags=Array.isArray(b.tags)?b.tags.filter(t=>typeof t==='string').slice(0,12):[];
        const id=typeof b.id==='string'&&/^[a-f0-9-]{36}$/i.test(b.id)?b.id:crypto.randomUUID(), now=Date.now();
        const sizesAllowed=['XS','S','M','L','XL','XXL','XXXL','36','37','38','39','40','41','42','43','44','45','46'];
        const sizeStock=(b.sizeStock&&typeof b.sizeStock==='object'&&!Array.isArray(b.sizeStock))?b.sizeStock:{};
        const sizes=Array.isArray(b.sizes)?[...new Set(b.sizes.filter(x=>sizesAllowed.includes(x)))].slice(0,20):Object.keys(sizeStock).filter(x=>sizesAllowed.includes(x));
        if(!sizes.length) throw new HttpError(400,'invalid_stock','Ajoute au moins une taille.');
        const normalizedStock={}; for(const z of sizes){const q=Number(sizeStock[z]??0);if(!Number.isInteger(q)||q<0||q>100000)throw new HttpError(400,'invalid_stock',`Stock invalide pour la taille ${z}.`);normalizedStock[z]=q;}
        const quantity=Object.values(normalizedStock).reduce((a,n)=>a+n,0);
        const values=[id,brand,name,price,old,typeof b.badge==='string'?b.badge.trim().slice(0,40)||null:null,b.free===true,color,ink,['blank','block','wave','campus','stripes','plain'].includes(b.print)?b.print:'blank',JSON.stringify(tags),typeof b.front==='string'?b.front.trim().slice(0,2000):'',typeof b.back==='string'?b.back.trim().slice(0,2000):'',quantity,JSON.stringify(sizes),JSON.stringify(normalizedStock),now,now];
        await pool.query(`INSERT INTO products (id,brand,name,price,old_price,badge,free,color,ink,print,tags,img_front,img_back,quantity,sizes,size_stock,active,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15::jsonb,$16::jsonb,TRUE,$17,$18) ON CONFLICT(id) DO UPDATE SET brand=EXCLUDED.brand,name=EXCLUDED.name,price=EXCLUDED.price,old_price=EXCLUDED.old_price,badge=EXCLUDED.badge,free=EXCLUDED.free,color=EXCLUDED.color,ink=EXCLUDED.ink,print=EXCLUDED.print,tags=EXCLUDED.tags,img_front=EXCLUDED.img_front,img_back=EXCLUDED.img_back,quantity=EXCLUDED.quantity,sizes=EXCLUDED.sizes,size_stock=EXCLUDED.size_stock,active=TRUE,updated_at=EXCLUDED.updated_at`,values);
        return json({ok:true,id});
      }
      case '/api/admin/product-delete': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string') throw new HttpError(400,'bad_request','Article invalide.'); await pool.query('UPDATE products SET active=FALSE,updated_at=$1 WHERE id=$2',[Date.now(),b.id]); return json({ok:true}); }
      case '/api/admin/product-hard-delete': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string') throw new HttpError(400,'bad_request','Article invalide.'); await pool.query('DELETE FROM products WHERE id=$1',[b.id]); return json({ok:true}); }
      case '/api/admin/client-toggle': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||typeof b.blocked!=='boolean') throw new HttpError(400,'bad_request','Client invalide.'); await pool.query('UPDATE users SET account_blocked=$1,failed_attempts=0 WHERE id=$2',[b.blocked,b.id]); if(b.blocked) await pool.query('DELETE FROM sessions WHERE user_id=$1',[b.id]); return json({ok:true}); }
      case '/api/admin/order-delete': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||!b.id.trim()) throw new HttpError(400,'bad_request','Commande invalide.'); const hasPay=await pool.query('SELECT 1 FROM payments WHERE order_id=$1 LIMIT 1',[b.id]); if(hasPay.rowCount) throw new HttpError(409,'order_has_payments','Impossible de supprimer une commande qui a un historique de paiement.'); const result=await pool.query('DELETE FROM orders WHERE id=$1',[b.id]); if(!result.rowCount) throw new HttpError(404,'order_not_found','Commande introuvable.'); return json({ok:true}); }
      case '/api/admin/order-status': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||!ORDER_STATUSES.includes(b.status)) throw new HttpError(400,'bad_request','Statut invalide.'); if(b.status==='Payée'||b.status==='En attente'){ const {rows:pc}=await pool.query("SELECT COUNT(*)::int AS n, COUNT(*) FILTER (WHERE status='success')::int AS ok FROM payments WHERE order_id=$1",[b.id]); const n=pc[0]?.n||0, ok=pc[0]?.ok||0; if(b.status==='Payée'&&n>0&&!ok) throw new HttpError(409,'payment_not_confirmed','Le statut « Payée » est réservé aux paiements confirmés par l’opérateur. Utilise « Revérifier » dans l’onglet Paiements.'); if(b.status==='En attente'&&ok) throw new HttpError(409,'already_paid','Cette commande est déjà payée.'); } await pool.query('UPDATE orders SET status=$1 WHERE id=$2',[b.status,b.id]); return json({ok:true}); }
      case '/api/admin/order-tracking': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||typeof b.trackingCode!=='string'||b.trackingCode.length>100) throw new HttpError(400,'bad_request','Code de suivi invalide.'); await pool.query('UPDATE orders SET tracking_code=$1 WHERE id=$2',[b.trackingCode.trim(),b.id]); return json({ok:true}); }
      default: break;
    }
    switch(url.pathname){
      case '/api/profile': {
        const b=await readJson(req); requireAuth(req,auth,true);
        const f=profileFields(b);
        const {rows}=await pool.query('UPDATE users SET first_name=$1,last_name=$2,post_name=$3,phone=$4,birth_date=$5,address=$6 WHERE id=$7 RETURNING *',[f.firstName,f.lastName,f.postName,f.phone,f.birthDate,f.address,auth.row.user_id]);
        return json({user:publicUser(rows[0])},200,cookies);
      }
      case '/api/orders': {
        const b=await readJson(req); requireAuth(req,auth,true);
        if(!allow('order:'+auth.row.user_id,10,HOUR)) throw new HttpError(429,'rate_limited','Trop de commandes. Réessaie plus tard.');
        const fullName=typeof b.fullName==='string'?b.fullName.normalize('NFKC').trim().slice(0,100):'';
        const phone=typeof b.phone==='string'?b.phone.trim().slice(0,30):'';
        const address=typeof b.address==='string'?b.address.trim().slice(0,300):'';
        if(fullName.length<3) throw new HttpError(400,'invalid_name','Entre ton nom et ton prénom.');
        if(!/^\+?[0-9 ().-]{8,20}$/.test(phone)) throw new HttpError(400,'invalid_phone','Entre un numéro de téléphone valide.');
        if(address.length<8) throw new HttpError(400,'invalid_address','Entre une adresse de livraison complète.');
        if(!Array.isArray(b.items)||!b.items.length||b.items.length>30) throw new HttpError(400,'invalid_cart','Ton panier est vide ou invalide.');
        const dbIds=[...new Set(b.items.map(i=>String(i?.id)))];
        const dbRows=dbIds.length?(await pool.query('SELECT id,brand,name,price,quantity,sizes,size_stock FROM products WHERE active=TRUE AND id=ANY($1::text[])',[dbIds])).rows:[];
        const dbMap=Object.fromEntries(dbRows.map(r=>[r.id,r]));
        const items=[];
        for(const i of b.items){
          const key=String(i?.id), p=dbMap[key], qty=Number(i?.qty), allowedSizes=p?.sizes&&Array.isArray(p.sizes)?p.sizes:['S','M','L','XL'], size=allowedSizes.includes(i?.size)?i.size:null;
          const stockMap=p?.size_stock&&typeof p.size_stock==='object'?p.size_stock:{}; const sizeQty=Object.keys(stockMap).length?Number(stockMap[i?.size]||0):Number(p?.quantity??1);
          if(!p||!size||!Number.isInteger(qty)||qty<1||qty>20||qty>sizeQty) throw new HttpError(400,'out_of_stock','Cette taille est en rupture de stock ou la quantité demandée est trop élevée. Recharge la page.');
          const unitPrice=Number(p.price);
          items.push({id:key,name:(p.brand?p.brand+' ':'')+p.name,size,qty,unitPrice,total:unitPrice*qty});
        }
        const itemCount=items.reduce((s,x)=>s+x.qty,0); if(itemCount===3 && items.some(x=>x.unitPrice<19500)) throw new HttpError(400,'minimum_item_price','Pour une commande de 3 articles, chaque article doit coûter au moins 19 500 FC.'); const subtotal=items.reduce((s,x)=>s+x.total,0), delivery=itemCount>=4?0:6000, total=subtotal+delivery, id=crypto.randomUUID();
        for (const line of items) { const row=dbMap[line.id]; const stock=row?.size_stock&&typeof row.size_stock==='object'?row.size_stock:{}; if(Object.keys(stock).length){const current=Number(stock[line.size]||0);if(current<line.qty)throw new HttpError(409,'out_of_stock',`La taille ${line.size} de ${line.name} vient d’être épuisée.`);stock[line.size]=current-line.qty;await pool.query('UPDATE products SET size_stock=$1::jsonb, quantity=GREATEST(quantity-$2,0), updated_at=$3 WHERE id=$4',[JSON.stringify(stock),line.qty,Date.now(),line.id]);} }
        await pool.query('INSERT INTO orders (id,user_id,customer_name,customer_email,phone,address,items,total,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)',[id,auth.row.user_id,fullName,auth.row.email,phone,address,JSON.stringify(items),total,'En attente',Date.now()]);
        await notifyAdminOrder({ref:id.slice(0,8).toUpperCase(),customerName:fullName,email:auth.row.email,phone,address,items,total});
        return json({ok:true,ref:id.slice(0,8).toUpperCase(),total},201,cookies);
      }
      case '/api/register': {
        if(!allow('reg:'+ip,5,HOUR)) throw new HttpError(429,'rate_limited','Trop de créations de compte. Réessaie plus tard.');
        const b=await readJson(req), prof=profileFields(b), firstName=prof.firstName, email=normEmail(b.email);
        
        if(!emailOk(email)) throw new HttpError(400,'invalid_email','Entre une adresse e-mail valide.');
        const problems=passwordProblems(b.password,{email,firstName}); if(problems.length) throw new HttpError(400,'password_policy',problems[0],problems);
        const exists=await pool.query('SELECT id FROM users WHERE email=$1',[email]); if(exists.rowCount) throw new HttpError(409,'email_taken','Un compte existe déjà avec cet e-mail. Connecte-toi.');
        const hash=await hashPassword(b.password), id=crypto.randomUUID();
        try { await pool.query('INSERT INTO users (id,email,first_name,last_name,post_name,phone,birth_date,address,password_hash,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id,email,firstName,prof.lastName,prof.postName,prof.phone,prof.birthDate,prof.address,hash,Date.now()]); }
        catch(e){if(e.code==='23505') throw new HttpError(409,'email_taken','Un compte existe déjà avec cet e-mail. Connecte-toi.');throw e;}
        const s=await createSession(id,b.remember===true,req); cookies.push(s.cookie); console.log(JSON.stringify({event:'register',ip}));
        return json({user:publicUser({first_name:firstName,email,last_name:prof.lastName,post_name:prof.postName,phone:prof.phone,birth_date:prof.birthDate,address:prof.address}),csrfToken:s.csrf},201,cookies);
      }
      case '/api/login': {
        if(!allow('login:'+ip,10,15*MIN)) throw new HttpError(429,'rate_limited','Trop de tentatives. Réessaie dans quelques minutes.');
        const b=await readJson(req),email=normEmail(b.email),password=typeof b.password==='string'?b.password:'';
        if(password.length>1024) throw new HttpError(400,'bad_request','Requête invalide.');
        const found=email?await pool.query('SELECT * FROM users WHERE email=$1',[email]):{rows:[]}; const user=found.rows[0],now=Date.now();
        if(user&&user.account_blocked===true) throw new HttpError(403,'account_blocked','Ton compte a été bloqué par l’administration. Contacte la boutique.');
        let lockedFor=user?Number(user.locked_until)-now:0;
        // Un verrou ne peut pas dépasser 1 h. Une valeur plus grande est anormale (ancienne version, valeur erronée) : on la supprime au lieu de bloquer le client.
        if(user&&lockedFor>LOCK_MS){ await pool.query('UPDATE users SET failed_attempts=0,locked_until=0 WHERE id=$1',[user.id]); user.failed_attempts=0; lockedFor=0; }
        if(lockedFor>0) throw new HttpError(429,'locked',`Trop d'échecs. Compte verrouillé, réessaie dans ${Math.min(Math.ceil(lockedFor/MIN),60)} min.`);
        const ok=password.length>0&&await verifyPassword(password,user?user.password_hash:await DUMMY_HASH_PROMISE);
        if(!user||!ok){if(user){const fails=user.failed_attempts+1;if(fails>=MAX_FAILS){await pool.query('UPDATE users SET failed_attempts=0,locked_until=$1 WHERE id=$2',[now+LOCK_MS,user.id]);}else await pool.query('UPDATE users SET failed_attempts=$1 WHERE id=$2',[fails,user.id]);} throw new HttpError(401,'invalid_credentials','E-mail ou mot de passe incorrect.');}
        await pool.query('UPDATE users SET failed_attempts=0,locked_until=0,last_login_at=$1 WHERE id=$2',[now,user.id]);
        if(auth) await pool.query('DELETE FROM sessions WHERE id_hash=$1',[auth.idHash]);
        const s=await createSession(user.id,b.remember===true,req); cookies=[s.cookie];
        return json({user:publicUser(user),csrfToken:s.csrf},200,cookies);
      }
      case '/api/logout': {
        await readJson(req); if(auth) await pool.query('DELETE FROM sessions WHERE id_hash=$1',[auth.idHash]);
        return json({ok:true},200,[cookieHeader('',0)]);
      }
      case '/api/logout-all': {
        await readJson(req); requireAuth(req,auth,true); await pool.query('DELETE FROM sessions WHERE user_id=$1',[auth.row.user_id]);
        return json({ok:true},200,[cookieHeader('',0)]);
      }
      case '/api/password': {
        const b=await readJson(req); requireAuth(req,auth,true);
        if(!allow('pwd:'+auth.row.user_id,10,HOUR)) throw new HttpError(429,'rate_limited','Trop de tentatives. Réessaie plus tard.');
        if(typeof b.current!=='string'||typeof b.next!=='string'||b.current.length>1024) throw new HttpError(400,'bad_request','Requête invalide.');
        if(!(await verifyPassword(b.current,auth.row.password_hash))) throw new HttpError(403,'wrong_password','Mot de passe actuel incorrect.');
        const problems=passwordProblems(b.next,{email:auth.row.email,firstName:auth.row.first_name}); if(b.next===b.current) problems.unshift("Le nouveau mot de passe doit être différent de l'actuel.");
        if(problems.length) throw new HttpError(400,'password_policy',problems[0],problems);
        await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2',[await hashPassword(b.next),auth.row.user_id]);
        await pool.query('DELETE FROM sessions WHERE user_id=$1 AND id_hash<>$2',[auth.row.user_id,auth.idHash]);
        return json({ok:true},200,cookies);
      }
      default: throw new HttpError(404,'not_found','Introuvable.');
    }
  } catch(e) {
    if(e instanceof HttpError) return json({error:e.code,message:e.message,...(e.details?{details:e.details}:{})},e.status,cookies);
    errLog(e,routeName); return json({error:'server_error',message:'Erreur du serveur. Réessaie plus tard.'},500,cookies);
  }
}
