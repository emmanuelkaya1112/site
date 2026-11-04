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
const SCHEMA_TABLES = ['invoices', 'order_emails', 'order_events', 'returns', 'reviews', 'favorites', 'carts', 'suppliers', 'supplier_payments', 'delivery_companies', 'order_supplier_parts', 'users', 'sessions', 'password_reset_tokens', 'admin_sessions', 'products', 'orders', 'site_settings', 'payments', 'payment_events', 'provider_tokens'];
const REQUIRED_COLUMNS = [
  'users.last_name', 'users.post_name', 'users.phone', 'users.birth_date', 'users.address', 'users.account_blocked',
  'sessions.id_hash', 'password_reset_tokens.token_hash', 'admin_sessions.id_hash',
  'products.quantity', 'products.sizes', 'products.size_stock',
  'orders.id', 'orders.tracking_code', 'orders.stock_state', 'orders.reserved_until', 'orders.payment_method', 'orders.cash_collected_at', 'orders.cash_amount', 'orders.delivery_company_id', 'orders.delivery_status', 'orders.delivery_cost', 'products.supplier_id', 'products.cost_price', 'users.deleted_at', 'users.whatsapp', 'orders.whatsapp', 'orders.payment_fees', 'orders.other_costs', 'orders.refunded_amount', 'orders.delivered_at', 'products.description', 'products.img_mode', 'products.gallery', 'products.size_type', 'invoices.order_id', 'order_emails.order_id', 'order_events.order_id', 'returns.order_id', 'reviews.product_id', 'reviews.reports', 'favorites.user_id', 'carts.user_id', 'suppliers.id', 'supplier_payments.supplier_id', 'delivery_companies.id', 'order_supplier_parts.order_id', 'site_settings.key',
  'payments.reference', 'payments.status', 'payment_events.payment_id', 'provider_tokens.provider',
];
const REQUIRED_INDEXES = ['sessions_user_idx', 'sessions_exp_idx', 'password_reset_user_idx', 'password_reset_exp_idx', 'orders_created_idx', 'orders_reserved_idx', 'payments_order_idx', 'payments_active_uniq', 'payments_success_uniq', 'payments_created_idx', 'payment_events_pay_idx', 'products_supplier_idx', 'supplier_payments_idx', 'order_events_idx', 'returns_order_idx', 'reviews_product_idx'];
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
  // Stock : les commandes existantes passent à 'sold' (déjà décomptées à l'époque) ; les nouvelles commandes seront 'reserved'.
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS stock_state TEXT NOT NULL DEFAULT 'sold'`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS reserved_until BIGINT`,
  `CREATE INDEX IF NOT EXISTS orders_reserved_idx ON orders(reserved_until) WHERE stock_state = 'reserved'`,
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
  // Fournisseurs, livraison, anonymisation : uniquement des ajouts (tables et colonnes nouvelles, rien n'est modifié ni supprimé).
  `CREATE TABLE IF NOT EXISTS suppliers (id TEXT PRIMARY KEY, name TEXT NOT NULL, company TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', whatsapp TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', contact TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', active BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS supplier_payments (id TEXT PRIMARY KEY, supplier_id TEXT NOT NULL REFERENCES suppliers(id) ON DELETE RESTRICT, amount BIGINT NOT NULL CHECK (amount > 0), method TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', paid_at BIGINT NOT NULL, created_at BIGINT NOT NULL)`,
  'CREATE INDEX IF NOT EXISTS supplier_payments_idx ON supplier_payments(supplier_id)',
  `CREATE TABLE IF NOT EXISTS delivery_companies (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', whatsapp TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', contact_name TEXT NOT NULL DEFAULT '', contact_phone TEXT NOT NULL DEFAULT '', rates TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', active BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS order_supplier_parts (order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE, supplier_id TEXT NOT NULL REFERENCES suppliers(id) ON DELETE RESTRICT, status TEXT NOT NULL DEFAULT 'À commander', updated_at BIGINT NOT NULL, PRIMARY KEY (order_id, supplier_id))`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS supplier_id TEXT REFERENCES suppliers(id) ON DELETE SET NULL`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS cost_price INTEGER`,
  'CREATE INDEX IF NOT EXISTS products_supplier_idx ON products(supplier_id)',
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_company_id TEXT REFERENCES delivery_companies(id) ON DELETE SET NULL`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_name TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_phone TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_cost INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'En attente de préparation'`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS picked_up_at BIGINT`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_notes TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at BIGINT`,
  // Lot 2 : WhatsApp, factures, e-mails, historique, retours, avis, favoris, paniers, fiches produits (ajouts uniquement).
  // Paiement en espèces à la réception : les commandes existantes restent en 'mobile_money'.
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT NOT NULL DEFAULT 'mobile_money'`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS cash_collected_at BIGINT`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS cash_amount INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS whatsapp TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_fees INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS other_costs INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS refunded_amount INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_at BIGINT`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS img_mode TEXT NOT NULL DEFAULT 'face_dos'`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS gallery JSONB NOT NULL DEFAULT '[]'::jsonb`,
  `ALTER TABLE products ADD COLUMN IF NOT EXISTS size_type TEXT NOT NULL DEFAULT 'alpha'`,
  'CREATE SEQUENCE IF NOT EXISTS invoice_seq',
  `CREATE TABLE IF NOT EXISTS invoices (order_id TEXT PRIMARY KEY REFERENCES orders(id) ON DELETE RESTRICT, number TEXT NOT NULL UNIQUE, issued_at BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS order_emails (order_id TEXT PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', updated_at BIGINT NOT NULL, sent_at BIGINT)`,
  `CREATE TABLE IF NOT EXISTS order_events (id BIGSERIAL PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE, at BIGINT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')`,
  'CREATE INDEX IF NOT EXISTS order_events_idx ON order_events(order_id, at)',
  `CREATE TABLE IF NOT EXISTS returns (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE RESTRICT, user_id TEXT REFERENCES users(id) ON DELETE SET NULL, kind TEXT NOT NULL, product_id TEXT NOT NULL DEFAULT '', product_name TEXT NOT NULL DEFAULT '', size TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Demande reçue', admin_comment TEXT NOT NULL DEFAULT '', decision TEXT NOT NULL DEFAULT '', refund_amount INTEGER NOT NULL DEFAULT 0, refund_applied BOOLEAN NOT NULL DEFAULT FALSE, exchange_note TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)`,
  'CREATE INDEX IF NOT EXISTS returns_order_idx ON returns(order_id)',
  `CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, product_id TEXT NOT NULL, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE SET NULL, author TEXT NOT NULL DEFAULT '', rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5), comment TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'published', reports INTEGER NOT NULL DEFAULT 0, reported_by JSONB NOT NULL DEFAULT '[]'::jsonb, report_reason TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL, UNIQUE (order_id, product_id))`,
  'CREATE INDEX IF NOT EXISTS reviews_product_idx ON reviews(product_id, status)',
  `CREATE TABLE IF NOT EXISTS favorites (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, product_id TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (user_id, product_id))`,
  `CREATE TABLE IF NOT EXISTS carts (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, items JSONB NOT NULL DEFAULT '[]'::jsonb, updated_at BIGINT NOT NULL)`,
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
const publicUser = row => ({ firstName: row.first_name, email: row.email, lastName: row.last_name || '', postName: row.post_name || '', phone: row.phone || '', whatsapp: row.whatsapp || '', birthDate: row.birth_date || '', address: row.address || '' });
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
  const {rows}=await pool.query(`SELECT s.*,u.email,u.first_name,u.last_name,u.post_name,u.phone,u.whatsapp,u.birth_date,u.address,u.password_hash,u.account_blocked FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=$1`,[idHash]);
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
const productPublic = r => ({id:r.id,brand:r.brand,name:r.name,price:Number(r.price),old:r.old_price==null?null:Number(r.old_price),badge:r.badge,free:!!r.free,color:r.color,ink:r.ink,print:r.print,tags:Array.isArray(r.tags)?r.tags:[],img:{front:r.img_front||'',back:r.img_back||''},quantity:Number(r.quantity??1),sizes:Array.isArray(r.sizes)?r.sizes:['S','M','L','XL'],sizeStock:r.size_stock&&typeof r.size_stock==='object'&&!Array.isArray(r.size_stock)?r.size_stock:{},description:r.description||'',imgMode:r.img_mode==='galerie'?'galerie':'face_dos',gallery:Array.isArray(r.gallery)?r.gallery:[],sizeType:['alpha','numeric','shoe'].includes(r.size_type)?r.size_type:'alpha',createdAt:Number(r.created_at||0),active:!!r.active});
async function readJson(req, max = 10000) { const ct=(req.headers.get('content-type')||'').split(';')[0].trim().toLowerCase(); if(ct!=='application/json') throw new HttpError(415,'unsupported_media_type','Format de requête invalide.'); const raw=await req.text(); if(raw.length>max) throw new HttpError(413,'too_large','Requête trop volumineuse.'); try { const b=JSON.parse(raw); if(!b||typeof b!=='object'||Array.isArray(b)) throw 0; return b; } catch { throw new HttpError(400,'bad_json','Requête invalide.'); } }
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
        subject: `Nouvelle commande ${order.ref} — ${order.total} FC${order.paymentMethod === 'cash' ? ' (espèces à la réception)' : ''}`,
        text: `Client : ${order.customerName}\nE-mail : ${order.email}\nTéléphone : ${order.phone}\nLivraison : ${order.address}\n\n${lines}\n\nTotal : ${order.total} FC`
      })
    });
  } catch (e) { errLog(e); }
}
// Réglages modifiables depuis l'administration (sans redéploiement) : article d'accueil, WhatsApp, e-mail de contact.
const SETTINGS_KEY = 'site';
const SETTINGS_DEFAULTS = { heroPrice: 19500, heroFront: '', heroBack: '', heroColor: '#2B3BFF', heroInk: '#FFFFFF', heroPrint: 'block', whatsapp: '243906049174', contactEmail: 'outfitshirt@gmail.com', texts: {}, codEnabled: true };
const PRINTS = ['blank', 'block', 'wave', 'campus', 'stripes', 'plain'];
function settingsFromValue(v) {
  const o = v && typeof v === 'object' && !Array.isArray(v) ? v : {}, out = { ...SETTINGS_DEFAULTS };
  for (const k of Object.keys(SETTINGS_DEFAULTS)) if (typeof o[k] === typeof SETTINGS_DEFAULTS[k]) out[k] = o[k];
  out.texts = cleanTexts(o.texts);
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
  return { heroPrice, heroFront, heroBack, heroColor, heroInk, heroPrint, whatsapp, contactEmail, texts: cleanTexts(b.texts), codEnabled: b.codEnabled !== false };
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
// ==== STOCK:BEGIN
// Stock : réservation temporaire à la commande, vente définitive seulement après paiement confirmé.
// size_stock = stock DISPONIBLE (stock réel moins réservations en cours). Toute modification passe par une transaction
// qui verrouille les lignes produits (SELECT … FOR UPDATE) : deux clients ne peuvent pas prendre le même dernier exemplaire.
// orders.stock_state : 'reserved' (retenu, expire) · 'sold' (vendu, définitif) · 'released' (rendu au stock).
// Les commandes antérieures à cette mise à jour reçoivent 'sold' par défaut : leur comportement et leurs données ne changent pas.
const RESERVATION_MS = 30 * MIN; // doit rester supérieur à PAYMENT_TTL_MS (15 min)
const liveItems = items => (Array.isArray(items) ? items : []).filter(i => !i.cancelled);
const stockLines = items => {
  const m = new Map();
  for (const i of Array.isArray(items) ? items : []) {
    const id = String(i?.id ?? ''), size = String(i?.size ?? ''), qty = Number(i?.qty);
    if (!id || !Number.isInteger(qty) || qty < 1) continue;
    const k = id + '\u0000' + size, cur = m.get(k);
    m.set(k, { id, size, qty: (cur?.qty || 0) + qty });
  }
  return [...m.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : a.size < b.size ? -1 : a.size > b.size ? 1 : 0));
};
const stockMapOf = r => (r.size_stock && typeof r.size_stock === 'object' && !Array.isArray(r.size_stock)) ? { ...r.size_stock } : {};
// direction = -1 : retenir du stock (échoue si insuffisant) ; +1 : rendre du stock. Vérifie tout AVANT d'écrire.
async function changeStock(client, items, direction) {
  const lines = stockLines(items), rows = new Map();
  for (const id of [...new Set(lines.map(l => l.id))]) { // ordre stable : pas d'interblocage entre deux commandes
    const sql = direction < 0
      ? 'SELECT id,brand,name,quantity,size_stock FROM products WHERE id=$1 AND active=TRUE FOR UPDATE'
      : 'SELECT id,brand,name,quantity,size_stock FROM products WHERE id=$1 FOR UPDATE';
    const r = (await client.query(sql, [id])).rows[0];
    if (!r) { if (direction < 0) throw new HttpError(409, 'out_of_stock', 'Un article de ta commande n’est plus disponible. Recharge la page.'); continue; }
    rows.set(id, { row: r, map: stockMapOf(r), qty: Number(r.quantity ?? 0), touched: false });
  }
  for (const l of lines) {
    const e = rows.get(l.id); if (!e) continue;
    const label = (e.row.brand ? e.row.brand + ' ' : '') + e.row.name;
    const hasMap = Object.keys(e.map).length > 0;
    const cur = hasMap ? Number(e.map[l.size] || 0) : e.qty;
    if (direction < 0 && cur < l.qty) throw new HttpError(409, 'out_of_stock', hasMap ? `La taille ${l.size} de ${label} vient d’être épuisée.` : `${label} vient d’être épuisé.`);
  }
  for (const l of lines) {
    const e = rows.get(l.id); if (!e) continue;
    if (Object.keys(e.map).length) {
      if (direction > 0 && !(l.size in e.map)) continue; // taille retirée depuis par l'admin : on ne la recrée pas
      e.map[l.size] = Math.max(0, Number(e.map[l.size] || 0) + direction * l.qty);
    } else e.qty = Math.max(0, e.qty + direction * l.qty);
    e.touched = true;
  }
  for (const [id, e] of rows) {
    if (!e.touched) continue;
    const total = Object.keys(e.map).length ? Object.values(e.map).reduce((a, n) => a + Math.max(0, Number(n) || 0), 0) : e.qty;
    await client.query('UPDATE products SET size_stock=$1::jsonb, quantity=$2, updated_at=$3 WHERE id=$4', [JSON.stringify(e.map), total, Date.now(), id]);
  }
}
const takeStock = (client, items) => changeStock(client, items, -1);
const returnStock = (client, items) => changeStock(client, items, +1);
async function releaseOrderStock(orderId) {
  const client = await pool.connect(); let destroy = false;
  try {
    await client.query('BEGIN');
    const o = (await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE', [orderId])).rows[0];
    if (!o || o.stock_state !== 'reserved') { await client.query('COMMIT'); return false; }
    // Jamais de libération si de l'argent peut être en route ou déjà reçu.
    const pay = await client.query("SELECT 1 FROM payments WHERE order_id=$1 AND (status='success' OR status = ANY($2::text[])) LIMIT 1", [orderId, PAYMENT_OPEN]);
    if (pay.rowCount) { await client.query('COMMIT'); return false; }
    await returnStock(client, liveItems(o.items));
    await client.query("UPDATE orders SET stock_state='released', status=CASE WHEN status='En attente' THEN 'Annulée' ELSE status END WHERE id=$1", [orderId]);
    await client.query('COMMIT');
    return true;
  } catch (e) { try { await client.query('ROLLBACK'); } catch { destroy = true; } throw e; }
  finally { client.release(destroy); }
}
let lastReservationSweep = 0;
// Aucune tâche planifiée : les réservations expirées sont libérées au passage (boutique, commande, admin).
async function sweepExpiredReservations(force = false) {
  const now = Date.now(); if (!force && now - lastReservationSweep < 30_000) return; lastReservationSweep = now;
  try {
    const { rows } = await pool.query("SELECT id FROM orders WHERE stock_state='reserved' AND status='En attente' AND reserved_until < $1 ORDER BY reserved_until LIMIT 10", [now]);
    for (const r of rows) await releaseOrderStock(r.id);
  } catch (e) { errLog(e, 'reservation_sweep'); }
}
// Insertion du paiement sous verrou de la commande : une commande annulée/expirée ne peut pas recevoir de paiement.
async function insertPaymentForReservedOrder(orderId, values) {
  const client = await pool.connect(); let destroy = false;
  try {
    await client.query('BEGIN');
    const o = (await client.query('SELECT status, stock_state, reserved_until FROM orders WHERE id=$1 FOR UPDATE', [orderId])).rows[0];
    if (!o || o.status !== 'En attente') throw new HttpError(409, 'order_not_payable', 'Cette commande ne peut plus être payée en ligne.');
    if (o.stock_state === 'released' || (o.stock_state === 'reserved' && Number(o.reserved_until) < Date.now())) throw new HttpError(409, 'reservation_expired', 'Le délai de réservation de ta commande est dépassé. Repasse ta commande.');
    await client.query('INSERT INTO payments (id,order_id,provider,reference,amount,currency,msisdn_masked,status,environment,created_at,updated_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)', values);
    await client.query('COMMIT');
  } catch (e) { try { await client.query('ROLLBACK'); } catch { destroy = true; } throw e; }
  finally { client.release(destroy); }
}
// Changement de statut par l'admin, cohérent avec le stock.
async function setOrderStatus(id, status) {
  const client = await pool.connect(); let destroy = false;
  try {
    await client.query('BEGIN');
    const o = (await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE', [id])).rows[0];
    if (!o) throw new HttpError(404, 'order_not_found', 'Commande introuvable.');
    let state = o.stock_state, until = o.reserved_until;
    const cashUnpaid = o.payment_method === 'cash' && o.cash_collected_at == null; // espèces non encaissées : le stock reste réservé, sans expiration
    if (status === 'Annulée') {
      const open = await client.query('SELECT 1 FROM payments WHERE order_id=$1 AND status = ANY($2::text[]) LIMIT 1', [id, PAYMENT_OPEN]);
      if (open.rowCount) throw new HttpError(409, 'payment_open', 'Un paiement est en cours de vérification pour cette commande. Revérifie-le dans l’onglet Paiements avant d’annuler.');
      if (state === 'reserved') { await returnStock(client, liveItems(o.items)); state = 'released'; }
    } else if (status === 'En attente') {
      if (state === 'released') { await takeStock(client, liveItems(o.items)); state = 'reserved'; until = o.payment_method === 'cash' ? null : Date.now() + RESERVATION_MS; }
    } else if (state === 'released') { await takeStock(client, liveItems(o.items)); state = cashUnpaid ? 'reserved' : 'sold'; }
    else if (state === 'reserved') state = cashUnpaid ? 'reserved' : 'sold';
    await client.query('UPDATE orders SET status=$1, stock_state=$2, reserved_until=$3, delivered_at=CASE WHEN $1 = \'Livrée\' AND delivered_at IS NULL THEN $5::bigint ELSE delivered_at END WHERE id=$4', [status, state, until == null ? null : Number(until), id, Date.now()]);
    await client.query('COMMIT');
    return { previous: o.status, method: o.payment_method };
  } catch (e) { try { await client.query('ROLLBACK'); } catch { destroy = true; } throw e; }
  finally { client.release(destroy); }
}
// ==== STOCK:END
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
    if (target === 'success') {
      // Le paiement est confirmé : le stock réservé devient une vente définitive (une seule fois, sous verrou de la commande).
      const o = (await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE', [p.order_id])).rows[0];
      if (o && o.stock_state === 'released') {
        // Succès tardif après libération du stock : on ne revend pas un article déjà attribué à quelqu'un d'autre.
        try { await takeStock(client, o.items); }
        catch (e) { if (e instanceof HttpError && e.code === 'out_of_stock') { target = 'needs_review'; code = 'stock_unavailable'; message = 'Paiement reçu mais le stock n’est plus disponible : remplacement ou remboursement à traiter.'; } else throw e; }
      }
    }
    if (target === p.status && !info.providerRef) { await client.query('COMMIT'); return out; }
    const now = Date.now();
    const upd = await client.query('UPDATE payments SET status=$1, provider_ref=COALESCE($2,provider_ref), error_code=$3, error_message=$4, updated_at=$5, confirmed_at=COALESCE($6,confirmed_at) WHERE id=$7 RETURNING *',
      [target, info.providerRef ?? null, code ? payClean(code, 60) : null, message ? payClean(message, 300) : null, now, target === 'success' ? now : null, p.id]);
    out = { payment: upd.rows[0] || { ...p, status: target }, changed: target !== p.status, becameSuccess: target === 'success' };
    if (target === 'success') await client.query("UPDATE orders SET status='Payée', stock_state='sold' WHERE id=$1 AND status IN ('En attente','Annulée')", [p.order_id]);
    if (target === 'success') await client.query("UPDATE orders SET stock_state='sold' WHERE id=$1 AND stock_state IN ('reserved','released')", [p.order_id]);
    await client.query('COMMIT');
    return out;
  } catch (e) { try { await client.query('ROLLBACK'); } catch { destroy = true; } throw e; }
  finally { client.release(destroy); }
}
async function notifyPaymentSuccess(p) {
  try { await sendOrderConfirmation(p.order_id); } catch (e) { errLog(e, 'payment_success_email'); }
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
const DELIVERY_STATUSES = ['En attente de préparation', 'Prête pour la livraison', 'Confiée au livreur', 'En cours de livraison', 'Livrée', 'Livraison échouée', 'Retour en cours'];
const PART_STATUSES = ['À commander', 'Commandé', 'Prêt', 'Récupéré', 'Indisponible'];
const PAID_ORDER_STATUSES = ['Payée', 'Expédiée', 'Livrée'];
// Une commande payée en espèces n'est « payée » qu'une fois l'argent encaissé et enregistré (jamais d'office à la livraison).
const orderIsPaid = r => r.payment_method === 'cash' ? r.cash_collected_at != null : PAID_ORDER_STATUSES.includes(r.status);
const collectedOf = (o, successPaid) => Number(successPaid) > 0 ? Number(successPaid) : (orderIsPaid(o) ? (o.payment_method === 'cash' ? Number(o.cash_amount || o.total) : Number(o.total)) : 0);
// Vue CLIENT : jamais de fournisseur, de coût d'achat ni de livreur.
const customerItems = items => (Array.isArray(items) ? items : []).map(i => ({ id: i.id, name: i.name, size: i.size, qty: i.qty, unitPrice: i.unitPrice, total: i.total, cancelled: !!i.cancelled }));
const orderPublic = r => { const its = customerItems(r.items), gone = its.filter(i => i.cancelled).reduce((a, i) => a + Number(i.total || 0), 0); return { id: r.id, ref: r.id.slice(0, 8).toUpperCase(), createdAt: Number(r.created_at), customerName: r.customer_name, email: r.customer_email, phone: r.phone, address: r.address, items: its, total: Number(r.total), adjustedTotal: Number(r.total) - gone, refundedAmount: Number(r.refunded_amount || 0), status: r.status, trackingCode: r.tracking_code || '', paymentMethod: r.payment_method === 'cash' ? 'cash' : 'mobile_money', cashCollected: r.cash_collected_at != null, deliveryStatus: r.delivery_status || '', deliveredAt: r.delivered_at == null ? null : Number(r.delivered_at) }; };
// Vue ADMIN : détail complet (fournisseurs, coûts, livraison, paiements confirmés, finances, e-mail, facture).
async function ordersAdmin(rows) {
  if (!rows.length) return [];
  const ids = rows.map(r => r.id);
  const [sup, parts, paid, comp, mails, invs] = await Promise.all([
    pool.query('SELECT id,name FROM suppliers'),
    pool.query('SELECT order_id,supplier_id,status FROM order_supplier_parts WHERE order_id=ANY($1::text[])', [ids]),
    pool.query("SELECT order_id, COALESCE(SUM(amount),0)::bigint AS paid FROM payments WHERE status='success' AND order_id=ANY($1::text[]) GROUP BY order_id", [ids]),
    pool.query('SELECT id,name FROM delivery_companies'),
    pool.query('SELECT order_id,status,last_error FROM order_emails WHERE order_id=ANY($1::text[])', [ids]),
    pool.query('SELECT order_id,number FROM invoices WHERE order_id=ANY($1::text[])', [ids]),
  ]);
  const names = Object.fromEntries(sup.rows.map(x => [x.id, x.name])), compNames = Object.fromEntries(comp.rows.map(x => [x.id, x.name]));
  const paidMap = Object.fromEntries(paid.rows.map(x => [x.order_id, Number(x.paid)])), mailMap = Object.fromEntries(mails.rows.map(x => [x.order_id, x])), invMap = Object.fromEntries(invs.rows.map(x => [x.order_id, x.number]));
  return rows.map(r => {
    const items = (Array.isArray(r.items) ? r.items : []).map(i => ({ ...i, supplierName: i.supplierId ? (names[i.supplierId] || 'Fournisseur supprimé') : '' }));
    const bySup = new Map();
    for (const i of items) { if (!i.supplierId || i.cancelled) continue; const g = bySup.get(i.supplierId) || { supplierId: i.supplierId, supplierName: i.supplierName, status: 'À commander', cost: 0, missingCost: 0 }; if (i.unitCost == null) g.missingCost++; else g.cost += Number(i.unitCost) * Number(i.qty); bySup.set(i.supplierId, g); }
    for (const pt of parts.rows.filter(x => x.order_id === r.id)) { const g = bySup.get(pt.supplier_id); if (g) g.status = pt.status; }
    const pa = paidMap[r.id] || 0, fin = orderFinancials(r, pa), cancelledCount = items.filter(i => i.cancelled).length, mail = mailMap[r.id];
    return { ...orderPublic(r), items, paidAmount: pa, collected: fin.collected, fin, paid: orderIsPaid(r), cashCollectedAt: r.cash_collected_at == null ? null : Number(r.cash_collected_at), whatsapp: r.whatsapp || '', stockState: r.stock_state || 'sold', reservedUntil: r.reserved_until == null ? null : Number(r.reserved_until), userId: r.user_id || null,
      cancellation: r.status === 'Annulée' || (cancelledCount && cancelledCount === items.length) ? 'full' : cancelledCount ? 'partial' : 'none',
      emailStatus: mail ? mail.status : '', emailError: mail ? mail.last_error : '', invoiceNumber: invMap[r.id] || '',
      supplierParts: [...bySup.values()],
      delivery: { companyId: r.delivery_company_id || '', companyName: r.delivery_company_id ? (compNames[r.delivery_company_id] || '') : '', courierName: r.courier_name || '', courierPhone: r.courier_phone || '', cost: Number(r.delivery_cost || 0), status: r.delivery_status || DELIVERY_STATUSES[0], pickedUpAt: r.picked_up_at == null ? null : Number(r.picked_up_at), notes: r.delivery_notes || '' } };
  });
}
const productAdmin = r => ({ ...productPublic(r), supplierId: r.supplier_id || '', costPrice: r.cost_price == null ? null : Number(r.cost_price) });
const supplierRow = r => ({ id: r.id, name: r.name, company: r.company, phone: r.phone, whatsapp: r.whatsapp, address: r.address, contact: r.contact, notes: r.notes, active: !!r.active, createdAt: Number(r.created_at) });
const deliveryRow = r => ({ id: r.id, name: r.name, phone: r.phone, whatsapp: r.whatsapp, address: r.address, contactName: r.contact_name, contactPhone: r.contact_phone, rates: r.rates, notes: r.notes, active: !!r.active });
const txt = (v, n) => typeof v === 'string' ? v.normalize('NFKC').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n) : '';
const phoneOk = v => v === '' || /^\+?[0-9 ().-]{8,20}$/.test(v);
async function supplierTotals() {
  const due = await pool.query(`SELECT i->>'supplierId' AS sid, COALESCE(SUM((i->>'unitCost')::bigint * (i->>'qty')::int) FILTER (WHERE i->>'unitCost' IS NOT NULL),0)::bigint AS due, COUNT(*) FILTER (WHERE i->>'unitCost' IS NULL)::int AS missing FROM orders o, jsonb_array_elements(o.items) i WHERE (CASE WHEN o.payment_method = 'cash' THEN o.cash_collected_at IS NOT NULL ELSE o.status = ANY($1::text[]) END) AND i->>'supplierId' IS NOT NULL AND COALESCE(i->>'cancelled','false') <> 'true' GROUP BY 1`, [PAID_ORDER_STATUSES]);
  const paid = await pool.query('SELECT supplier_id, COALESCE(SUM(amount),0)::bigint AS paid FROM supplier_payments GROUP BY 1');
  const m = {}; for (const r of due.rows) m[r.sid] = { due: Number(r.due), missing: r.missing, paid: 0 };
  for (const r of paid.rows) { m[r.supplier_id] = m[r.supplier_id] || { due: 0, missing: 0, paid: 0 }; m[r.supplier_id].paid = Number(r.paid); }
  return m;
}
// Collections (ex. « Crocs ») : liste enregistrée dans site_settings (clé « collections ») ; un article y appartient grâce à l'étiquette « col:<id> » dans ses tags.
const COLLECTIONS_KEY = 'collections';
const slugify = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
async function loadCollections() {
  const { rows } = await pool.query('SELECT value FROM site_settings WHERE key=$1', [COLLECTIONS_KEY]);
  const items = Array.isArray(rows[0]?.value?.items) ? rows[0].value.items : [];
  return items.filter(c => c && typeof c.id === 'string' && typeof c.name === 'string').map(c => ({ id: c.id, name: c.name, image: typeof c.image === 'string' ? c.image : '' }));
}
export const config = { path: '/api/*' };
const RETURN_STATUSES = ['Demande reçue', 'En cours d’examen', 'Acceptée', 'Refusée', 'Retour en cours', 'Échange effectué', 'Remboursement effectué'];
const TEXT_KEYS = [{"key": "heroTitle", "label": "Accueil : grand titre (Entrée = retour à la ligne)", "def": "Ton style.\nTon budget.", "multi": true}, {"key": "heroText", "label": "Accueil : phrase sous le titre", "def": "Nos modèles à petit prix, et des articles Nike, Adidas, Puma et Vans.", "multi": false}, {"key": "productsTitle", "label": "Articles : titre de la section", "def": "Bestsellers", "multi": false}, {"key": "productsText", "label": "Articles : description de la section", "def": "Nos articles à petits prix : hauts, pantalons, sous-vêtements, chaussures et accessoires.", "multi": true}, {"key": "aboutTitle", "label": "À propos : titre", "def": "Le style ne devrait pas coûter cher.", "multi": false}, {"key": "aboutText", "label": "À propos : texte de présentation", "def": "Sur outfit-shirt, on réunit des hauts (pulls, chemises, t-shirts), pantalons, sous-vêtements, chaussures et accessoires tendance à des prix doux : s'habiller streetwear sans vider son portefeuille. Pensé pour les jeunes, les étudiants et tous ceux qui vivent le style au quotidien.", "multi": true}, {"key": "about1Title", "label": "À propos : carte 1, titre", "def": "Livraison rapide", "multi": false}, {"key": "about1Text", "label": "À propos : carte 1, texte", "def": "Livraison en moins de 24 h. Offerte dès 4 articles ; sinon 6 000 FC.", "multi": false}, {"key": "about2Title", "label": "À propos : carte 2, titre", "def": "Coton de qualité", "multi": false}, {"key": "about2Text", "label": "À propos : carte 2, texte", "def": "Un tissu doux, épais et résistant au lavage. Il garde sa forme et ses couleurs.", "multi": false}, {"key": "about3Title", "label": "À propos : carte 3, titre", "def": "Accessible à tous les budgets", "multi": false}, {"key": "deliveryTitle", "label": "Livraison : titre de la section", "def": "Livraison & commandes", "multi": false}, {"key": "delivery1Title", "label": "Livraison : bloc 1, titre", "def": "Livraison rapide", "multi": false}, {"key": "delivery1Text", "label": "Livraison : bloc 1, texte", "def": "La livraison est annoncée en moins de 24 heures. Le délai peut dépendre de la zone et de la disponibilité du livreur.", "multi": true}, {"key": "delivery2Title", "label": "Livraison : bloc 2, titre", "def": "Frais de livraison", "multi": false}, {"key": "delivery2Text", "label": "Livraison : bloc 2, texte", "def": "À partir de 4 articles, la livraison est offerte. Pour 1 à 3 articles, les frais sont de 6 000 FC. Pour une commande de 3 articles, chaque article doit coûter au moins 19 500 FC.", "multi": true}, {"key": "delivery3Title", "label": "Livraison : bloc 3, titre", "def": "Suivi de commande", "multi": false}, {"key": "delivery3Text", "label": "Livraison : bloc 3, texte", "def": "Connecte-toi à ton compte puis ouvre l’onglet « Commandes » pour voir le statut et le code de suivi lorsqu’il est disponible.", "multi": true}, {"key": "faqTitle", "label": "FAQ : titre", "def": "Questions fréquentes", "multi": false}, {"key": "faq1Q", "label": "FAQ : question 1", "def": "Comment choisir la taille ?", "multi": false}, {"key": "faq1A", "label": "FAQ : réponse 1", "def": "Consulte les tailles disponibles sur la fiche de l’article. Si une taille n’apparaît pas ou est indiquée en rupture, elle n’est pas disponible à la commande.", "multi": true}, {"key": "faq2Q", "label": "FAQ : question 2", "def": "Comment suivre ma commande ?", "multi": false}, {"key": "faq2A", "label": "FAQ : réponse 2", "def": "Ouvre « Mon compte », connecte-toi puis sélectionne « Commandes ». Le statut et le code de suivi s’affichent dès que la boutique les renseigne.", "multi": true}, {"key": "faq3Q", "label": "FAQ : question 3", "def": "Quand la livraison est-elle gratuite ?", "multi": false}, {"key": "faq3A", "label": "FAQ : réponse 3", "def": "La livraison est offerte à partir de 4 articles. Pour moins de 4 articles, elle coûte 6 000 FC.", "multi": true}, {"key": "faq4Q", "label": "FAQ : question 4", "def": "Comment demander de l’aide ?", "multi": false}, {"key": "faq5Q", "label": "FAQ : question 5", "def": "Que faire si ma taille est épuisée ?", "multi": false}, {"key": "faq5A", "label": "FAQ : réponse 5", "def": "Choisis une autre taille disponible ou contacte le service client pour demander si un réapprovisionnement est prévu.", "multi": true}, {"key": "footerText", "label": "Pied de page : phrase de présentation", "def": "Vêtements et accessoires tendance, bonne qualité, petits prix.", "multi": false}, {"key": "siteNotice", "label": "Bandeau d’annonce en haut du site (laisse vide pour ne rien afficher)", "def": "", "multi": false}];
const cleanTexts = v => { const o = v && typeof v === 'object' && !Array.isArray(v) ? v : {}, out = {}; for (const k of TEXT_KEYS) { const t = typeof o[k.key] === 'string' ? o[k.key].normalize('NFKC').replace(/[\u0000-\u0009\u000b-\u001f]/g, ' ').trim().slice(0, 700) : ''; if (t && t !== k.def) out[k.key] = t; } return out; };
// ==== EXTRA:BEGIN
// ---------- WhatsApp : numéro international obligatoire à l'inscription ----------
function normalizeWhatsapp(v, required = true) {
  let s = typeof v === 'string' ? v.normalize('NFKC').replace(/[\s().-]/g, '') : '';
  if (s.startsWith('00')) s = '+' + s.slice(2);
  if (!s) { if (required) throw new HttpError(400, 'whatsapp_required', 'Le numéro WhatsApp est obligatoire.'); return ''; }
  if (!/^\+[1-9]\d{7,14}$/.test(s)) throw new HttpError(400, 'invalid_whatsapp', 'Numéro WhatsApp invalide : choisis l’indicatif du pays et entre ton numéro, par exemple +243 900 000 000.');
  return s;
}
// ---------- Historique interne des commandes (visible uniquement par l'admin) ----------
async function logOrderEvent(orderId, kind, detail) {
  try { await pool.query('INSERT INTO order_events (order_id,at,kind,detail) VALUES ($1,$2,$3,$4)', [orderId, Date.now(), kind, String(detail || '').slice(0, 500)]); } catch (e) { errLog(e, 'order_event'); }
}
// ---------- Finances d'une commande (estimation, jamais un bénéfice net réel) ----------
function orderFinancials(r, successPaid) {
  const all = Array.isArray(r.items) ? r.items : [], act = all.filter(i => !i.cancelled);
  const isPaid = orderIsPaid(r), cancelledOrder = r.status === 'Annulée', isCash = r.payment_method === 'cash';
  const sp = Number(successPaid || 0);
  const collected = collectedOf(r, sp);
  const itemsTotal = all.reduce((a, i) => a + Number(i.total || 0), 0);
  const cancelledTotal = all.filter(i => i.cancelled).reduce((a, i) => a + Number(i.total || 0), 0);
  const refunded = Number(r.refunded_amount || 0);
  // Ce qui doit revenir au client : tout si la commande est annulée, sinon les articles annulés (au moins ce qui est déjà remboursé).
  // Espèces : un article annulé avant l'encaissement n'a jamais été payé, donc rien à rembourser.
  const refundDue = collected > 0 ? (cancelledOrder ? collected : isCash ? Math.min(collected, refunded) : Math.min(collected, Math.max(refunded, cancelledTotal))) : 0;
  let productCost = 0, missing = 0;
  if (!cancelledOrder) for (const i of act) { if (i.unitCost == null) missing++; else productCost += Number(i.unitCost) * Number(i.qty); }
  const deliveryCost = Number(r.delivery_cost || 0), paymentFees = Number(r.payment_fees || 0), otherCosts = Number(r.other_costs || 0);
  const net = collected - refundDue;
  const hasMoney = collected > 0;
  return { collected, refunded, refundDue, refundLeft: Math.max(0, refundDue - refunded), cancelledTotal, deliveryCharged: Math.max(0, Number(r.total) - itemsTotal), productCost, missingCost: missing, deliveryCost, paymentFees, otherCosts, net,
    margin: hasMoney ? net - productCost - deliveryCost - paymentFees - otherCosts : 0, complete: missing === 0 };
}
// ---------- PDF minimal sans dépendance (Helvetica, texte uniquement) ----------
const HELV = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584];
const pdfClean = s => String(s ?? '').normalize('NFC').replace(/[\r\n\t]+/g, ' ').replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"').replace(/[\u2013\u2014]/g, '-').replace(/[\u00a0\u202f\u2009]/g, ' ').replace(/\u2026/g, '...').replace(/[^\x20-\x7e\u00a1-\u00ff]/g, '?');
const pdfWidth = (s, size, bold) => { let w = 0; for (const ch of pdfClean(s)) { let c = ch.charCodeAt(0); if (c > 126) c = ch.normalize('NFD').charCodeAt(0); w += (c >= 32 && c <= 126 ? HELV[c - 32] : 556); } return w * size / 1000 * (bold ? 1.06 : 1); };
const pdfEsc = s => pdfClean(s).replace(/[\\()]/g, '\\$&');
function pdfWrap(s, maxW, size, bold) { const words = pdfClean(s).split(' ').filter(Boolean), lines = []; let cur = ''; for (const w of words) { const t = cur ? cur + ' ' + w : w; if (pdfWidth(t, size, bold) <= maxW || !cur) cur = t; else { lines.push(cur); cur = w; } } if (cur) lines.push(cur); return lines.length ? lines : ['']; }
class PdfPage {
  constructor() { this.ops = []; }
  text(x, top, s, size = 10, bold = false, align = 'l', gray = 0) { const w = pdfWidth(s, size, bold), px = align === 'r' ? x - w : align === 'c' ? x - w / 2 : x; this.ops.push(`BT ${gray} g /${bold ? 'F2' : 'F1'} ${size} Tf ${px.toFixed(2)} ${(842 - top).toFixed(2)} Td (${pdfEsc(s)}) Tj ET`); }
  rect(x, top, w, h, gray) { this.ops.push(`${gray} g ${x} ${(842 - top - h).toFixed(2)} ${w} ${h} re f`); }
  line(x1, x2, top, gray = 0.8) { this.ops.push(`${gray} G 0.6 w ${x1} ${(842 - top).toFixed(2)} m ${x2} ${(842 - top).toFixed(2)} l S`); }
  stream() { return this.ops.join('\n'); }
}
function buildPdf(pageStreams) {
  const parts = [Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'latin1')], offsets = []; let len = parts[0].length;
  const put = (n, body) => { offsets[n] = len; const b = Buffer.concat([Buffer.from(`${n} 0 obj\n`, 'latin1'), Buffer.isBuffer(body) ? body : Buffer.from(body, 'latin1'), Buffer.from('\nendobj\n', 'latin1')]); parts.push(b); len += b.length; };
  const n = pageStreams.length;
  put(1, '<< /Type /Catalog /Pages 2 0 R >>');
  put(2, `<< /Type /Pages /Kids [${pageStreams.map((_, i) => `${5 + 2 * i} 0 R`).join(' ')}] /Count ${n} >>`);
  put(3, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  put(4, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  pageStreams.forEach((st, i) => {
    put(5 + 2 * i, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${6 + 2 * i} 0 R >>`);
    const sb = Buffer.from(st, 'latin1'); put(6 + 2 * i, Buffer.concat([Buffer.from(`<< /Length ${sb.length} >>\nstream\n`, 'latin1'), sb, Buffer.from('\nendstream', 'latin1')]));
  });
  const total = 4 + 2 * n, xref = len; let x = `xref\n0 ${total + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= total; i++) x += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  parts.push(Buffer.from(x + `trailer\n<< /Size ${total + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(parts);
}
const fcPdf = n => String(Math.round(Number(n) || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, ' ') + ' FC';
function renderInvoicePdf(d) {
  const pages = []; let pg = new PdfPage(), top = 0;
  const L = 45, R = 550, GREY = 0.45;
  const header = () => { pg.rect(0, 0, 595, 70, 0.08); pg.text(L, 44, d.company.name, 22, true, 'l', 1); pg.text(R, 34, 'FACTURE', 18, true, 'r', 1); pg.text(R, 52, d.number, 11, false, 'r', 1); top = 96; };
  const tableHead = () => { pg.rect(L, top - 12, R - L, 20, 0.92); pg.text(L + 6, top + 2, 'Désignation', 9, true); pg.text(330, top + 2, 'Taille', 9, true, 'c'); pg.text(380, top + 2, 'Qté', 9, true, 'c'); pg.text(465, top + 2, 'Prix unitaire', 9, true, 'r'); pg.text(R - 6, top + 2, 'Total', 9, true, 'r'); top += 24; };
  header();
  // Vendeur / client
  pg.text(L, top, 'Vendeur', 9, true, 'l', GREY); pg.text(320, top, 'Facturé à', 9, true, 'l', GREY); top += 14;
  const seller = [d.company.name, d.company.address, d.company.phone && ('Tél. / WhatsApp : ' + d.company.phone), d.company.email, d.company.legal].filter(Boolean);
  const client = [d.order.customer_name, d.order.address, (d.order.whatsapp || d.order.phone) && ('Tél. : ' + (d.order.whatsapp || d.order.phone)), d.order.customer_email].filter(Boolean);
  let ys = top, yc = top;
  for (const t of seller) for (const ln of pdfWrap(t, 250, 10, false)) { pg.text(L, ys, ln, 10); ys += 13; }
  for (const t of client) for (const ln of pdfWrap(t, 230, 10, false)) { pg.text(320, yc, ln, 10); yc += 13; }
  top = Math.max(ys, yc) + 14;
  pg.line(L, R, top - 6); top += 8;
  pg.text(L, top, `Date de facture : ${new Date(d.issuedAt).toLocaleDateString('fr-FR')}`, 10); pg.text(R, top, `Commande n° ${String(d.order.id).slice(0, 8).toUpperCase()} du ${new Date(Number(d.order.created_at)).toLocaleDateString('fr-FR')}`, 10, false, 'r'); top += 28;
  tableHead();
  for (const it of d.items) {
    const lines = pdfWrap(it.name, 215, 10, false), need = lines.length * 13 + 8;
    if (top + need > 760) { pages.push(pg.stream()); pg = new PdfPage(); header(); tableHead(); }
    lines.forEach((ln, k) => pg.text(L + 6, top + k * 13, ln, 10));
    pg.text(330, top, it.size, 10, false, 'c'); pg.text(380, top, String(it.qty), 10, false, 'c'); pg.text(465, top, fcPdf(it.unitPrice), 10, false, 'r'); pg.text(R - 6, top, fcPdf(it.total), 10, false, 'r');
    top += need - 2; pg.line(L, R, top - 8, 0.9);
  }
  if (top > 640) { pages.push(pg.stream()); pg = new PdfPage(); header(); }
  top += 8;
  const row = (label, val, bold = false) => { pg.text(400, top, label, bold ? 11 : 10, bold, 'r'); pg.text(R - 6, top, val, bold ? 11 : 10, bold, 'r'); top += bold ? 18 : 15; };
  row('Sous-total articles', fcPdf(d.subtotal));
  row('Frais de livraison', d.delivery > 0 ? fcPdf(d.delivery) : 'Offerts');
  if (d.cancelledTotal > 0) row('Articles annulés', '- ' + fcPdf(d.cancelledTotal));
  row('TOTAL', fcPdf(d.total), true);
  if (d.refunded > 0) row('Déjà remboursé', '- ' + fcPdf(d.refunded));
  top += 6; pg.rect(L, top - 12, R - L, 36, 0.92);
  pg.text(L + 8, top + 2, 'Statut du paiement : ' + d.paymentStatus, 10, true); pg.text(L + 8, top + 16, d.paymentDetail, 9, false, 'l', GREY);
  top += 52;
  pg.text(L, top, 'Merci pour ta confiance. Cette facture atteste du paiement confirmé de la commande indiquée ci-dessus.', 9, false, 'l', GREY);
  pages.push(pg.stream());
  return buildPdf(pages);
}
const pdfResponse = (buf, filename) => new Response(new Uint8Array(buf), { status: 200, headers: { 'Content-Type': 'application/pdf', 'Content-Disposition': `inline; filename="${filename}"`, 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' } });
async function ensureInvoice(orderId) {
  const got = await pool.query('SELECT * FROM invoices WHERE order_id=$1', [orderId]); if (got.rows[0]) return got.rows[0];
  const seq = (await pool.query("SELECT nextval('invoice_seq')::int AS n")).rows[0].n;
  const number = `FA-${new Date().getFullYear()}-${String(seq).padStart(6, '0')}`;
  await pool.query('INSERT INTO invoices (order_id,number,issued_at) VALUES ($1,$2,$3) ON CONFLICT (order_id) DO NOTHING', [orderId, number, Date.now()]);
  return (await pool.query('SELECT * FROM invoices WHERE order_id=$1', [orderId])).rows[0];
}
// Une facture n'existe que pour une commande dont le paiement est confirmé (Payée / Expédiée / Livrée).
async function invoicePdfFor(orderId) {
  const o = (await pool.query('SELECT * FROM orders WHERE id=$1', [orderId])).rows[0];
  if (!o) throw new HttpError(404, 'order_not_found', 'Commande introuvable.');
  if (!orderIsPaid(o)) throw new HttpError(409, 'invoice_unavailable', 'La facture n’est disponible qu’une fois le paiement confirmé.');
  const inv = await ensureInvoice(orderId);
  const pay = (await pool.query("SELECT provider, amount, updated_at FROM payments WHERE order_id=$1 AND status='success' ORDER BY updated_at DESC LIMIT 1", [orderId])).rows[0];
  const set = settingsFromValue((await pool.query('SELECT value FROM site_settings WHERE key=$1', [SETTINGS_KEY])).rows[0]?.value);
  const all = Array.isArray(o.items) ? o.items : [], act = all.filter(i => !i.cancelled);
  const itemsTotal = all.reduce((a, i) => a + Number(i.total || 0), 0), cancelledTotal = all.filter(i => i.cancelled).reduce((a, i) => a + Number(i.total || 0), 0);
  const subtotal = act.reduce((a, i) => a + Number(i.total || 0), 0), delivery = Math.max(0, Number(o.total) - itemsTotal);
  const company = { name: process.env.INVOICE_COMPANY_NAME || 'OutfiT-shirt', address: process.env.INVOICE_ADDRESS || '', phone: process.env.INVOICE_PHONE || ('+' + set.whatsapp), email: process.env.INVOICE_EMAIL || set.contactEmail, legal: process.env.INVOICE_LEGAL || '' };
  const d = { number: inv.number, issuedAt: Number(inv.issued_at), order: o, items: act, subtotal, delivery, cancelledTotal, total: subtotal + delivery, refunded: Number(o.refunded_amount || 0), company,
    paymentStatus: 'PAYÉ', paymentDetail: o.payment_method === 'cash' ? `Paiement en espèces reçu à la livraison le ${new Date(Number(o.cash_collected_at)).toLocaleDateString('fr-FR')} (${fcPdf(o.cash_amount || o.total)}).` : pay ? `Paiement ${PROVIDER_LABELS[pay.provider] || pay.provider} confirmé le ${new Date(Number(pay.updated_at)).toLocaleDateString('fr-FR')} (${fcPdf(pay.amount)}).` : 'Paiement confirmé par la boutique.' };
  return { pdf: renderInvoicePdf(d), number: inv.number };
}
// ---------- E-mail de confirmation : un seul par commande, avec nouvelle tentative possible ----------
const escH = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function sendOrderConfirmation(orderId) {
  const now = Date.now();
  const claim = await pool.query(`INSERT INTO order_emails (order_id,status,attempts,updated_at) VALUES ($1,'sending',1,$2) ON CONFLICT (order_id) DO UPDATE SET status='sending', attempts=order_emails.attempts+1, updated_at=$2 WHERE order_emails.status='failed' OR (order_emails.status='sending' AND order_emails.updated_at < $3) RETURNING order_id`, [orderId, now, now - 5 * MIN]);
  if (!claim.rowCount) return { sent: false, skipped: true };
  try {
    const o = (await pool.query('SELECT * FROM orders WHERE id=$1', [orderId])).rows[0]; if (!o) throw new Error('commande introuvable');
    const pay = (await pool.query("SELECT provider, amount FROM payments WHERE order_id=$1 AND status='success' ORDER BY updated_at DESC LIMIT 1", [orderId])).rows[0];
    const ref = o.id.slice(0, 8).toUpperCase(), act = (Array.isArray(o.items) ? o.items : []).filter(i => !i.cancelled);
    const itemsTotal = act.reduce((a, i) => a + Number(i.total || 0), 0), delivery = Math.max(0, Number(o.total) - (Array.isArray(o.items) ? o.items : []).reduce((a, i) => a + Number(i.total || 0), 0));
    const cash = o.payment_method === 'cash', paid = pay ? Number(pay.amount) : Number(o.total), fc = n => `${Number(n).toLocaleString('fr-FR')} FC`;
    const dueCash = itemsTotal + delivery;
    const lines = act.map(i => `• ${i.name} (taille ${i.size}) × ${i.qty} — ${fc(i.total)}`);
    const deliveryTxt = `Livraison à : ${o.address}. Délai annoncé : moins de 24 heures selon la zone. Frais de livraison : ${delivery > 0 ? fc(delivery) : 'offerts'}. Tu peux suivre l’état de ta commande dans « Mon compte » > « Commandes ».`;
    const text = cash
      ? `Bonjour ${o.customer_name},\n\nMerci pour ta commande sur OutfiT-shirt ! Elle est bien enregistrée sous le numéro ${ref}.\n\n${lines.join('\n')}\n\nSous-total articles : ${fc(itemsTotal)}\nMONTANT À PAYER EN ESPÈCES À LA RÉCEPTION : ${fc(dueCash)}\n\n${deliveryTxt}\nNous te contactons pour confirmer la livraison. Prépare si possible l’appoint pour le livreur. La facture sera disponible dans « Mon compte » après l’encaissement.\n\nL’équipe OutfiT-shirt`
      : `Bonjour ${o.customer_name},\n\nMerci pour ton achat sur OutfiT-shirt ! Ta commande ${ref} est confirmée.\n\n${lines.join('\n')}\n\nSous-total articles : ${fc(itemsTotal)}\nMontant payé : ${fc(paid)}${pay ? ' par ' + (PROVIDER_LABELS[pay.provider] || pay.provider) : ''}\n\n${deliveryTxt}\nTa facture est disponible dans « Mon compte » > « Commandes » > « Facture ».\n\nL’équipe OutfiT-shirt`;
    const html = cash
      ? `<p>Bonjour ${escH(o.customer_name)},</p><p>Merci pour ta commande sur <strong>OutfiT-shirt</strong> ! Elle est bien enregistrée sous le numéro <strong>${ref}</strong>.</p><ul>${act.map(i => `<li>${escH(i.name)} (taille ${escH(i.size)}) × ${i.qty} — ${fc(i.total)}</li>`).join('')}</ul><p>Sous-total articles : ${fc(itemsTotal)}<br><strong>Montant à payer en espèces à la réception : ${fc(dueCash)}</strong></p><p>${escH(deliveryTxt)}</p><p>Nous te contactons pour confirmer la livraison. Prépare si possible l’appoint pour le livreur. La facture sera disponible dans « Mon compte » après l’encaissement.</p><p>L’équipe OutfiT-shirt</p>`
      : `<p>Bonjour ${escH(o.customer_name)},</p><p>Merci pour ton achat sur <strong>OutfiT-shirt</strong> ! Ta commande <strong>${ref}</strong> est confirmée.</p><ul>${act.map(i => `<li>${escH(i.name)} (taille ${escH(i.size)}) × ${i.qty} — ${fc(i.total)}</li>`).join('')}</ul><p>Sous-total articles : ${fc(itemsTotal)}<br><strong>Montant payé : ${fc(paid)}</strong>${pay ? ' par ' + escH(PROVIDER_LABELS[pay.provider] || pay.provider) : ''}</p><p>${escH(deliveryTxt)}</p><p>Ta facture est disponible dans « Mon compte » &gt; « Commandes » &gt; « Facture ».</p><p>L’équipe OutfiT-shirt</p>`;
    await Promise.race([brevoSend(o.customer_email, cash ? `Commande ${ref} enregistrée — paiement à la réception — OutfiT-shirt` : `Confirmation de ta commande ${ref} — OutfiT-shirt`, text, html), new Promise((_, rej) => setTimeout(() => rej(new Error('délai e-mail dépassé')), 8000))]);
    await pool.query("UPDATE order_emails SET status='sent', sent_at=$2, updated_at=$2, last_error='' WHERE order_id=$1", [orderId, Date.now()]);
    await logOrderEvent(orderId, 'email', cash ? 'E-mail de commande (paiement à la réception) envoyé au client' : 'E-mail de confirmation envoyé au client');
    return { sent: true };
  } catch (e) {
    await pool.query("UPDATE order_emails SET status='failed', last_error=$2, updated_at=$3 WHERE order_id=$1", [orderId, String(e.message || e).slice(0, 300), Date.now()]).catch(() => {});
    await logOrderEvent(orderId, 'email', 'Échec de l’e-mail de confirmation : ' + String(e.message || e).slice(0, 120));
    errLog(e, 'order_confirmation_email'); return { sent: false, error: String(e.message || e).slice(0, 200) };
  }
}
// ---------- Avis ----------
const reviewAuthor = u => [u.first_name, (u.last_name || '').slice(0, 1) && (u.last_name || '').slice(0, 1).toUpperCase() + '.'].filter(Boolean).join(' ');
// ---------- Produits similaires ou complémentaires ----------
const COMPLEMENT = { hauts: ['pantalons', 'accessoires', 'chaussures'], pantalons: ['hauts', 'chaussures'], chaussures: ['accessoires', 'pantalons', 'hauts'], sousvetements: ['hauts', 'accessoires'], accessoires: ['chaussures', 'hauts'] };
const inStock = r => { const m = r.size_stock && typeof r.size_stock === 'object' ? r.size_stock : {}; return Object.keys(m).length ? Object.values(m).some(n => Number(n) > 0) : Number(r.quantity ?? 1) > 0; };
function relatedProducts(target, rows) {
  const cat = t => { const x = (Array.isArray(t.tags) ? t.tags : []).map(v => v === 'tshirts' ? 'hauts' : v); return ['hauts', 'pantalons', 'sousvetements', 'chaussures', 'accessoires'].find(c => x.includes(c)) || 'hauts'; };
  const tc = cat(target), comp = COMPLEMENT[tc] || [];
  return rows.filter(r => r.id !== target.id && r.active && inStock(r)).map(r => { const c = cat(r); let s = 0; if (c === tc) s += 3; if (comp.includes(c)) s += 4 - comp.indexOf(c) * 0.5; if (target.brand && r.brand === target.brand) s += 1; s -= Math.abs(Number(r.price) - Number(target.price)) / 1e7; return { r, s }; }).filter(x => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 6).map(x => x.r);
}
// ---------- Tableau de bord : tout vient de la base, rien n'est compté deux fois ----------
async function buildDashboard(from, to) {
  const { rows: ords } = await pool.query('SELECT * FROM orders WHERE created_at >= $1 AND created_at < $2 ORDER BY created_at', [from, to]);
  const ids = ords.map(o => o.id);
  const paid = ids.length ? (await pool.query("SELECT order_id, COALESCE(SUM(amount),0)::bigint AS paid FROM payments WHERE status='success' AND order_id=ANY($1::text[]) GROUP BY order_id", [ids])).rows : [];
  const pm = Object.fromEntries(paid.map(x => [x.order_id, Number(x.paid)]));
  const c = { total: ords.length, awaitingPayment: 0, paid: 0, inPreparation: 0, inDelivery: 0, delivered: 0, cancelled: 0, partial: 0, cashPending: 0 }; let cashToCollect = 0;
  const money = { collected: 0, refunded: 0, productCost: 0, deliveryCharged: 0, deliveryCost: 0, fees: 0, other: 0, margin: 0, ordersMissingCost: 0 };
  const byDay = new Map(), top = new Map(); const DELIV = ['Confiée au livreur', 'En cours de livraison'];
  let supplierDue = 0;
  for (const o of ords) {
    const f = orderFinancials(o, pm[o.id] || 0), isPaid = orderIsPaid(o), cod = o.payment_method === 'cash';
    if (o.status === 'Annulée') c.cancelled++;
    else if (!cod && o.status === 'En attente') c.awaitingPayment++;
    else { if (isPaid) c.paid++; if (o.status === 'Livrée') c.delivered++; else if (o.status === 'Expédiée' || DELIV.includes(o.delivery_status)) c.inDelivery++; else c.inPreparation++; }
    if (cod && !isPaid && o.status !== 'Annulée') { c.cashPending++; cashToCollect += Number(o.total) - (o.items || []).filter(i => i.cancelled).reduce((a, i) => a + Number(i.total || 0), 0); }
    if ((o.items || []).some(i => i.cancelled) && o.status !== 'Annulée') c.partial++;
    if (f.collected > 0 || isPaid) {
      money.collected += f.collected; money.refunded += f.refundDue; money.productCost += f.productCost; money.deliveryCharged += f.deliveryCharged; money.deliveryCost += f.deliveryCost; money.fees += f.paymentFees; money.other += f.otherCosts; money.margin += f.margin; if (!f.complete) money.ordersMissingCost++;
      const day = new Date(Number(o.created_at) + 2 * HOUR).toISOString().slice(0, 10), d = byDay.get(day) || { day, orders: 0, collected: 0, margin: 0 }; d.orders++; d.collected += f.collected - f.refundDue; d.margin += f.margin; byDay.set(day, d);
      if (isPaid) for (const i of (o.items || [])) { if (i.cancelled) continue; const t = top.get(i.id + '|' + i.name) || { id: i.id, name: i.name, qty: 0, revenue: 0, margin: 0, missing: 0 }; t.qty += Number(i.qty); t.revenue += Number(i.total); if (i.unitCost == null) t.missing++; else t.margin += Number(i.total) - Number(i.unitCost) * Number(i.qty); top.set(i.id + '|' + i.name, t); if (i.supplierId && i.unitCost != null) supplierDue += Number(i.unitCost) * Number(i.qty); }
    }
  }
  const users = (await pool.query('SELECT COUNT(*)::int AS n, COUNT(*) FILTER (WHERE created_at >= $1 AND created_at < $2)::int AS fresh FROM users WHERE deleted_at IS NULL', [from, to])).rows[0];
  const prods = (await pool.query('SELECT quantity,size_stock FROM products WHERE active=TRUE')).rows;
  const available = prods.filter(inStock).length;
  const supPaid = Number((await pool.query('SELECT COALESCE(SUM(amount),0)::bigint AS n FROM supplier_payments WHERE paid_at >= $1 AND paid_at < $2', [from, to])).rows[0].n);
  return { from, to, orders: c, money: { ...money, net: money.collected - money.refunded, cashToCollect }, clients: { total: users.n, newInPeriod: users.fresh }, products: { available, outOfStock: prods.length - available },
    suppliers: { dueInPeriod: supplierDue, paidInPeriod: supPaid }, byDay: [...byDay.values()].sort((a, b) => a.day < b.day ? -1 : 1), top: [...top.values()].sort((a, b) => b.qty - a.qty).slice(0, 8) };
}
// ==== EXTRA:END
export default async function handler(req) {
  let cookies=[], routeName='init';
  try {
    await ensureSchema();
    const url=new URL(req.url), route=`${req.method} ${url.pathname}`, ip=getIp(req); routeName=route;
    const auth=await currentSession(req); if(auth?.refreshCookie) cookies.push(auth.refreshCookie);
    const admin=await currentAdminSession(req);
    if(route==='GET /api/me') return json(auth?{user:publicUser(auth.row),csrfToken:auth.row.csrf}:{user:null,csrfToken:null},200,cookies);
    if(route==='GET /api/products') { await sweepExpiredReservations(); const {rows}=await pool.query('SELECT * FROM products WHERE active=TRUE ORDER BY created_at DESC'); const rv=await pool.query("SELECT product_id, AVG(rating)::float AS avg, COUNT(*)::int AS n FROM reviews WHERE status='published' GROUP BY product_id"); const rm=Object.fromEntries(rv.rows.map(x=>[x.product_id,x])); const sd=await pool.query("SELECT i->>'id' AS pid, COALESCE(SUM((i->>'qty')::int),0)::int AS sold FROM orders o, jsonb_array_elements(o.items) i WHERE o.status<>'Annulée' AND COALESCE(i->>'cancelled','false')<>'true' GROUP BY 1"); const sm=Object.fromEntries(sd.rows.map(x=>[x.pid,x.sold])); const rk=Object.fromEntries([...rows].sort((a,b)=>(sm[b.id]||0)-(sm[a.id]||0)).map((r,i)=>[r.id,i])); return json({products:rows.map(r=>({...productPublic(r),rating:rm[r.id]?Math.round(rm[r.id].avg*10)/10:0,reviewCount:rm[r.id]?rm[r.id].n:0,popRank:rk[r.id]}))}); }
    if(route==='GET /api/settings') { const {rows}=await pool.query('SELECT value FROM site_settings WHERE key=$1',[SETTINGS_KEY]); return json({settings:settingsFromValue(rows[0]?.value)}); }
    if(route==='GET /api/collections') { const cols=await loadCollections(); const {rows}=await pool.query('SELECT tags FROM products WHERE active=TRUE'); const counts={}; for(const r of rows) for(const t of (Array.isArray(r.tags)?r.tags:[])) if(typeof t==='string'&&t.startsWith('col:')) counts[t]=(counts[t]||0)+1; return json({collections:cols.map(c=>({...c,count:counts['col:'+c.id]||0}))}); }
    if(route==='GET /api/my-orders') { requireAuth(req,auth,false); const {rows}=await pool.query('SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[auth.row.user_id]); const ids=rows.map(r=>r.id); const rv=ids.length?(await pool.query('SELECT order_id,product_id FROM reviews WHERE user_id=$1 AND order_id=ANY($2::text[])',[auth.row.user_id,ids])).rows:[]; const seen=new Set(rv.map(x=>x.order_id+'|'+x.product_id)); const days=Number(process.env.RETURN_WINDOW_DAYS||7);
      return json({returnWindowDays:days,orders:rows.map(r=>{const o=orderPublic(r),paid=orderIsPaid(r); return {...o,items:o.items.map(i=>({...i,reviewed:seen.has(r.id+'|'+i.id)})),invoiceAvailable:paid,canReview:paid,canReturn:r.status==='Livrée'&&Date.now()-Number(r.delivered_at||r.created_at)<=days*DAY};})}); }
    if(route==='GET /api/admin/me') return json({admin:!!admin,email:admin?ADMIN_EMAIL:null,csrfToken:admin?admin.row.csrf:null},200,cookies);
    if(route==='GET /api/admin/clients') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT id,email,first_name,last_name,post_name,phone,whatsapp,birth_date,address,created_at,last_login_at,locked_until,account_blocked FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 1000'); return json({clients:rows.map(r=>({id:r.id,email:r.email,firstName:r.first_name,lastName:r.last_name||'',postName:r.post_name||'',phone:r.phone||'',whatsapp:r.whatsapp||'',birthDate:r.birth_date||'',address:r.address||'',createdAt:Number(r.created_at),lastLoginAt:r.last_login_at==null?null:Number(r.last_login_at),lockedUntil:Number(r.locked_until||0),blocked:!!r.account_blocked}))}); }
    if(route==='GET /api/admin/products') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT * FROM products ORDER BY created_at DESC'); return json({products:rows.map(productAdmin)}); }
    // ----- Routes GET : avis, favoris, similaires, retours, facture client (clients connectés) -----
    if(route==='GET /api/reviews') { const pid=String(url.searchParams.get('productId')||'').slice(0,60); const [agg,list]=await Promise.all([pool.query("SELECT COALESCE(AVG(rating),0)::float AS avg, COUNT(*)::int AS n FROM reviews WHERE product_id=$1 AND status='published'",[pid]),pool.query("SELECT id,rating,comment,author,created_at FROM reviews WHERE product_id=$1 AND status='published' ORDER BY created_at DESC LIMIT 50",[pid])]); return json({average:Math.round((agg.rows[0]?.avg||0)*10)/10,count:agg.rows[0]?.n||0,reviews:list.rows.map(r=>({id:r.id,rating:r.rating,comment:r.comment,author:r.author,createdAt:Number(r.created_at),verified:true}))}); }
    if(route==='GET /api/related') { const id=String(url.searchParams.get('id')||'').slice(0,60); const {rows}=await pool.query('SELECT * FROM products WHERE active=TRUE'); const t=rows.find(r=>r.id===id); return json({products:t?relatedProducts(t,rows).map(productPublic):[]}); }
    if(route==='GET /api/favorites') { requireAuth(req,auth,false); const {rows}=await pool.query('SELECT product_id FROM favorites WHERE user_id=$1 ORDER BY created_at DESC',[auth.row.user_id]); return json({ids:rows.map(r=>r.product_id)}); }
    if(route==='GET /api/my-returns') { requireAuth(req,auth,false); const {rows}=await pool.query('SELECT r.*, o.id AS oid FROM returns r JOIN orders o ON o.id=r.order_id WHERE o.user_id=$1 ORDER BY r.created_at DESC LIMIT 100',[auth.row.user_id]); return json({returns:rows.map(r=>({id:r.id,ref:String(r.order_id).slice(0,8).toUpperCase(),kind:r.kind,productName:r.product_name,size:r.size,reason:r.reason,status:r.status,decision:r.decision,createdAt:Number(r.created_at),updatedAt:Number(r.updated_at)}))}); }
    if(route==='GET /api/my-invoice') { requireAuth(req,auth,false); const id=String(url.searchParams.get('id')||'').slice(0,60); const o=(await pool.query('SELECT id FROM orders WHERE id=$1 AND user_id=$2',[id,auth.row.user_id])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.'); const {pdf,number}=await invoicePdfFor(id); return pdfResponse(pdf,`facture-${number}.pdf`); }
    // ----- Routes GET administrateur : facture, historique, retours, avis, paniers, tableau de bord, textes -----
    if(route==='GET /api/admin/invoice') { requireAdmin(req,admin,false); const id=String(url.searchParams.get('id')||'').slice(0,60); const {pdf,number}=await invoicePdfFor(id); return pdfResponse(pdf,`facture-${number}.pdf`); }
    if(route==='GET /api/admin/order-events') { requireAdmin(req,admin,false); const id=String(url.searchParams.get('id')||'').slice(0,60); const {rows}=await pool.query('SELECT at,kind,detail FROM order_events WHERE order_id=$1 ORDER BY at DESC, id DESC LIMIT 100',[id]); return json({events:rows.map(r=>({at:Number(r.at),kind:r.kind,detail:r.detail}))}); }
    if(route==='GET /api/admin/returns') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT r.*, o.customer_name, o.phone, o.whatsapp FROM returns r JOIN orders o ON o.id=r.order_id ORDER BY r.created_at DESC LIMIT 300'); return json({statuses:RETURN_STATUSES,returns:rows.map(r=>({id:r.id,orderId:r.order_id,ref:String(r.order_id).slice(0,8).toUpperCase(),customerName:r.customer_name,contact:r.whatsapp||r.phone||'',kind:r.kind,productId:r.product_id,productName:r.product_name,size:r.size,reason:r.reason,status:r.status,adminComment:r.admin_comment,decision:r.decision,refundAmount:Number(r.refund_amount),refundApplied:!!r.refund_applied,exchangeNote:r.exchange_note,createdAt:Number(r.created_at),updatedAt:Number(r.updated_at)}))}); }
    if(route==='GET /api/admin/reviews') { requireAdmin(req,admin,false); const f=url.searchParams.get('filter')||'reported'; const where=f==='all'?'TRUE':f==='hidden'?"r.status='hidden'":'r.reports > 0'; const {rows}=await pool.query(`SELECT r.*, COALESCE(NULLIF(TRIM(CONCAT(p.brand,' ',p.name)),''),r.product_id) AS pname FROM reviews r LEFT JOIN products p ON p.id=r.product_id WHERE ${where} ORDER BY r.reports DESC, r.created_at DESC LIMIT 200`); return json({reviews:rows.map(r=>({id:r.id,productName:r.pname,author:r.author,rating:r.rating,comment:r.comment,status:r.status,reports:r.reports,reportReason:r.report_reason,createdAt:Number(r.created_at)}))}); }
    if(route==='GET /api/admin/carts') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT c.user_id,c.items,c.updated_at,u.first_name,u.last_name,u.email,u.phone,u.whatsapp FROM carts c JOIN users u ON u.id=c.user_id WHERE u.deleted_at IS NULL AND jsonb_array_length(c.items)>0 ORDER BY c.updated_at DESC LIMIT 200'); const ids=[...new Set(rows.flatMap(r=>(r.items||[]).map(i=>String(i.id))))]; const pr=ids.length?(await pool.query('SELECT id,brand,name,price,quantity,size_stock,active FROM products WHERE id=ANY($1::text[])',[ids])).rows:[]; const pm=Object.fromEntries(pr.map(p=>[p.id,p])); return json({carts:rows.map(r=>{const items=(r.items||[]).map(i=>{const p=pm[String(i.id)];return {name:p?((p.brand?p.brand+' ':'')+p.name):'Article supprimé',size:i.size,qty:i.qty,unitPrice:p?Number(p.price):0,available:!!(p&&p.active&&inStock(p))};});return {userId:r.user_id,client:[r.first_name,r.last_name].filter(Boolean).join(' '),email:r.email,contact:r.whatsapp||r.phone||'',items,estimated:items.reduce((a,i)=>a+i.unitPrice*i.qty,0),updatedAt:Number(r.updated_at)};})}); }
    if(route==='GET /api/admin/dashboard') { requireAdmin(req,admin,false); const isoDay=v=>/^\d{4}-\d{2}-\d{2}$/.test(v||'')?v:null; const today=new Date(Date.now()+2*HOUR).toISOString().slice(0,10); const toD=isoDay(url.searchParams.get('to'))||today; const fromD=isoDay(url.searchParams.get('from'))||new Date(Date.parse(toD+'T00:00:00Z')-29*DAY).toISOString().slice(0,10); const from=Date.parse(fromD+'T00:00:00+02:00'), to=Date.parse(toD+'T00:00:00+02:00')+DAY; if(!Number.isFinite(from)||!Number.isFinite(to)||to<=from||to-from>370*DAY) throw new HttpError(400,'invalid_range','Période invalide (366 jours maximum).'); return json({fromDay:fromD,toDay:toD,...(await buildDashboard(from,to))}); }
    if(route==='GET /api/admin/text-keys') { requireAdmin(req,admin,false); return json({keys:TEXT_KEYS}); }
    if(route==='GET /api/admin/suppliers') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT s.*, (SELECT COUNT(*)::int FROM products p WHERE p.supplier_id=s.id) AS products FROM suppliers s ORDER BY s.active DESC, LOWER(s.name)'); const t=await supplierTotals(); return json({suppliers:rows.map(r=>{const x=t[r.id]||{due:0,missing:0,paid:0};return {...supplierRow(r),products:r.products,due:x.due,paid:x.paid,balance:x.due-x.paid,missingCost:x.missing}})}); }
    if(route==='GET /api/admin/supplier') { requireAdmin(req,admin,false); const id=String(url.searchParams.get('id')||'').slice(0,60); const {rows}=await pool.query('SELECT * FROM suppliers WHERE id=$1',[id]); if(!rows[0]) throw new HttpError(404,'supplier_not_found','Fournisseur introuvable.'); const [pr,pay,ord,t]=await Promise.all([pool.query('SELECT id,brand,name,price,cost_price,quantity,active FROM products WHERE supplier_id=$1 ORDER BY LOWER(name)',[id]),pool.query('SELECT id,amount,method,note,paid_at FROM supplier_payments WHERE supplier_id=$1 ORDER BY paid_at DESC',[id]),pool.query(`SELECT * FROM orders WHERE (CASE WHEN payment_method = 'cash' THEN cash_collected_at IS NOT NULL ELSE status = ANY($1::text[]) END) AND items @> jsonb_build_array(jsonb_build_object('supplierId',$2::text)) ORDER BY created_at DESC LIMIT 200`,[PAID_ORDER_STATUSES,id]),supplierTotals()]); const x=t[id]||{due:0,missing:0,paid:0}; const orders=(await ordersAdmin(ord.rows)).map(o=>({ref:o.ref,id:o.id,createdAt:o.createdAt,status:o.status,partStatus:(o.supplierParts.find(g=>g.supplierId===id)||{}).status||'À commander',items:o.items.filter(i=>i.supplierId===id)})); return json({supplier:supplierRow(rows[0]),products:pr.rows.map(r=>({id:r.id,name:(r.brand?r.brand+' ':'')+r.name,price:Number(r.price),costPrice:r.cost_price==null?null:Number(r.cost_price),quantity:Number(r.quantity),active:!!r.active})),payments:pay.rows.map(r=>({id:r.id,amount:Number(r.amount),method:r.method,note:r.note,paidAt:Number(r.paid_at)})),orders,due:x.due,paid:x.paid,balance:x.due-x.paid,missingCost:x.missing}); }
    if(route==='GET /api/admin/delivery-companies') { requireAdmin(req,admin,false); const {rows}=await pool.query('SELECT * FROM delivery_companies ORDER BY active DESC, LOWER(name)'); return json({companies:rows.map(deliveryRow),statuses:DELIVERY_STATUSES,partStatuses:PART_STATUSES}); }
    if(route==='GET /api/admin/client') { requireAdmin(req,admin,false); const id=String(url.searchParams.get('id')||'').slice(0,60); const {rows}=await pool.query('SELECT id,email,first_name,last_name,post_name,phone,whatsapp,birth_date,address,created_at,last_login_at,account_blocked FROM users WHERE id=$1 AND deleted_at IS NULL',[id]); const u=rows[0]; if(!u) throw new HttpError(404,'client_not_found','Client introuvable.'); const {rows:or}=await pool.query('SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200',[id]); const orders=await ordersAdmin(or); return json({client:{id:u.id,email:u.email,firstName:u.first_name,lastName:u.last_name||'',postName:u.post_name||'',phone:u.phone||'',whatsapp:u.whatsapp||'',birthDate:u.birth_date||'',address:u.address||'',createdAt:Number(u.created_at),lastLoginAt:u.last_login_at==null?null:Number(u.last_login_at),blocked:!!u.account_blocked},orders,totalPaid:orders.reduce((a,o)=>a+o.collected-o.fin.refundDue,0)}); }
    if(route==='GET /api/admin/orders') { requireAdmin(req,admin,false); await sweepExpiredReservations(true); const {rows}=await pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500'); return json({orders:await ordersAdmin(rows)}); }
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
        const b=await readJson(req,40000); requireAdmin(req,admin,true);
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
        if(order.payment_method==='cash') throw new HttpError(409,'order_cash','Cette commande se paie en espèces à la réception.');
        if(order.status!=='En attente') throw new HttpError(409,'order_not_payable','Cette commande ne peut plus être payée en ligne.');
        const amount=Number(order.total); if(!Number.isSafeInteger(amount)||amount<=0) throw new HttpError(400,'invalid_amount','Montant de commande invalide.');
        const paid=await pool.query("SELECT 1 FROM payments WHERE order_id=$1 AND status='success'",[order.id]); if(paid.rowCount) throw new HttpError(409,'already_paid','Cette commande est déjà payée.');
        await pool.query("UPDATE payments SET status='failed', error_code='abandoned', error_message='Tentative abandonnée avant l’appel à l’opérateur.', updated_at=$2 WHERE order_id=$1 AND status='pending_payment' AND created_at<$3",[order.id,Date.now(),Date.now()-2*MIN]);
        try { await ADAPTERS[providerId].prepare?.(prov.cfg); } catch(e) { if(e instanceof ProviderUnavailable) throw new HttpError(503,'provider_unavailable',e.message); throw e; }
        const id=crypto.randomUUID(), reference='OS'+crypto.randomBytes(8).toString('hex').toUpperCase(), now=Date.now();
        try { await insertPaymentForReservedOrder(order.id,[id,order.id,providerId,reference,amount,'CDF',maskMsisdn(msisdn),'pending_payment',prov.environment,now,now+PAYMENT_TTL_MS]); }
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
      case '/api/admin/order-cash-collect': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const client=await pool.connect(); let destroy=false, info;
        try { await client.query('BEGIN');
          const o=(await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[String(b.id||'')])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
          if(o.payment_method!=='cash') throw new HttpError(409,'not_cash','Cette commande ne se paie pas en espèces.');
          if(o.cash_collected_at!=null) throw new HttpError(409,'already_collected','L’encaissement de cette commande est déjà enregistré.');
          if(!['Expédiée','Livrée'].includes(o.status)) throw new HttpError(409,'order_state','Passe d’abord la commande en « Expédiée » ou « Livrée » avant d’enregistrer l’encaissement.');
          const due=Number(o.total)-(Array.isArray(o.items)?o.items:[]).filter(i=>i.cancelled).reduce((a,i)=>a+Number(i.total||0),0);
          const amount=b.amount===''||b.amount==null?due:Number(b.amount);
          if(!Number.isSafeInteger(amount)||amount<1||amount>due) throw new HttpError(400,'invalid_amount',`Montant invalide : il doit être entre 1 et ${due} FC (montant à encaisser).`);
          await client.query("UPDATE orders SET cash_collected_at=$1, cash_amount=$2, stock_state=CASE WHEN stock_state IN ('reserved','released') THEN 'sold' ELSE stock_state END WHERE id=$3",[Date.now(),amount,o.id]);
          await client.query('COMMIT'); info={amount,due};
        } catch(e) { try { await client.query('ROLLBACK'); } catch { destroy=true; } throw e; } finally { client.release(destroy); }
        await logOrderEvent(b.id,'cash',`Espèces encaissées à la réception : ${info.amount} FC${info.amount<info.due?` (sur ${info.due} FC à encaisser)`:''}`);
        return json({ok:true});
      }
      case '/api/admin/order-costs-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const fees=b.paymentFees===''||b.paymentFees==null?0:Number(b.paymentFees), other=b.otherCosts===''||b.otherCosts==null?0:Number(b.otherCosts);
        if(![fees,other].every(n=>Number.isSafeInteger(n)&&n>=0&&n<=100_000_000)) throw new HttpError(400,'invalid_amount','Montants invalides.');
        const r=await pool.query('UPDATE orders SET payment_fees=$1, other_costs=$2 WHERE id=$3',[fees,other,String(b.id||'')]); if(!r.rowCount) throw new HttpError(404,'order_not_found','Commande introuvable.');
        await logOrderEvent(b.id,'costs',`Frais de paiement : ${fees} FC · autres frais : ${other} FC`); return json({ok:true});
      }
      case '/api/admin/order-item-cancel': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const idx=Number(b.index), reason=txt(b.reason,300)||'Article indisponible';
        const client=await pool.connect(); let destroy=false, info;
        try { await client.query('BEGIN');
          const o=(await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[String(b.id||'')])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
          const cashOrder=o.payment_method==='cash';
          if(!(cashOrder?['En attente','Expédiée']:['Payée','Expédiée']).includes(o.status)) throw new HttpError(409,'order_state',cashOrder?'L’annulation d’un article n’est possible que sur une commande non encore livrée.':'L’annulation d’un article n’est possible que sur une commande payée non encore livrée.');
          const items=Array.isArray(o.items)?o.items:[]; const it=items[idx]; if(!Number.isInteger(idx)||!it||it.cancelled) throw new HttpError(400,'invalid_item','Article introuvable ou déjà annulé.');
          items[idx]={...it,cancelled:true,cancelledAt:Date.now(),cancelReason:reason};
          if(b.restock===true||(cashOrder&&o.stock_state==='reserved')) await returnStock(client,[it]);
          const allGone=items.every(i=>i.cancelled);
          await client.query('UPDATE orders SET items=$1::jsonb, status=$2 WHERE id=$3',[JSON.stringify(items),allGone?'Annulée':o.status,o.id]);
          await client.query('COMMIT'); info={o,it,allGone};
        } catch(e) { try { await client.query('ROLLBACK'); } catch { destroy=true; } throw e; } finally { client.release(destroy); }
        await logOrderEvent(info.o.id,'item_cancel',`Article annulé : ${info.it.name} (${info.it.size}) × ${info.it.qty} — ${reason}${b.restock===true||(info.o.payment_method==='cash'&&info.o.stock_state==='reserved')?' — remis en stock':''}${info.allGone?' — commande entièrement annulée':''}`);
        return json({ok:true,fullyCancelled:info.allGone,refundDue:Number(info.it.total)});
      }
      case '/api/admin/order-refund': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const amount=Number(b.amount); if(!Number.isSafeInteger(amount)||amount<1||amount>1_000_000_000) throw new HttpError(400,'invalid_amount','Montant invalide.');
        const client=await pool.connect(); let destroy=false;
        try { await client.query('BEGIN');
          const o=(await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[String(b.id||'')])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
          const sp=Number((await client.query("SELECT COALESCE(SUM(amount),0)::bigint AS n FROM payments WHERE order_id=$1 AND status='success'",[o.id])).rows[0].n);
          const collected=collectedOf(o,sp);
          if(collected<=0) throw new HttpError(409,'no_payment','Aucun paiement confirmé à rembourser pour cette commande.');
          if(Number(o.refunded_amount)+amount>collected) throw new HttpError(400,'refund_too_high','Ce remboursement dépasse le montant payé restant.');
          await client.query('UPDATE orders SET refunded_amount=refunded_amount+$1 WHERE id=$2',[amount,o.id]); await client.query('COMMIT');
        } catch(e) { try { await client.query('ROLLBACK'); } catch { destroy=true; } throw e; } finally { client.release(destroy); }
        await logOrderEvent(b.id,'refund',`Remboursement enregistré : ${amount} FC${txt(b.note,200)?' — '+txt(b.note,200):''} (le versement réel se fait auprès de l’opérateur Mobile Money)`);
        return json({ok:true});
      }
      case '/api/admin/order-note': {
        const b=await readJson(req); requireAdmin(req,admin,true); const text=txt(b.text,400); if(text.length<3) throw new HttpError(400,'bad_request','Écris une note.');
        const kind={replacement:'Remplacement proposé',contact:'Client contacté',note:'Note'}[b.kind]||'Note';
        if(!(await pool.query('SELECT 1 FROM orders WHERE id=$1',[String(b.id||'')])).rowCount) throw new HttpError(404,'order_not_found','Commande introuvable.');
        await logOrderEvent(b.id,'note',`${kind} : ${text}`); return json({ok:true});
      }
      case '/api/admin/order-email-resend': {
        const b=await readJson(req); requireAdmin(req,admin,true); const id=String(b.id||'');
        const o=(await pool.query('SELECT status,payment_method,cash_collected_at FROM orders WHERE id=$1',[id])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
        if(!orderIsPaid(o)&&o.payment_method!=='cash') throw new HttpError(409,'order_state','L’e-mail de confirmation n’est envoyé que pour une commande payée.');
        const st=(await pool.query('SELECT status FROM order_emails WHERE order_id=$1',[id])).rows[0]?.status;
        if(st==='sent'&&b.force!==true) throw new HttpError(409,'already_sent','L’e-mail a déjà été envoyé. Confirme pour le renvoyer.');
        if(st==='sent') await pool.query("UPDATE order_emails SET status='failed' WHERE order_id=$1",[id]);
        const r=await sendOrderConfirmation(id); if(r.skipped) throw new HttpError(409,'in_progress','Un envoi est déjà en cours. Réessaie dans quelques minutes.');
        return json({ok:r.sent,error:r.error||null});
      }
      case '/api/admin/return-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        if(!['Retour','Échange'].includes(b.kind)) throw new HttpError(400,'bad_request','Type de demande invalide.');
        if(!RETURN_STATUSES.includes(b.status||RETURN_STATUSES[0])) throw new HttpError(400,'bad_request','Statut invalide.');
        const status=b.status||RETURN_STATUSES[0], refund=b.refundAmount===''||b.refundAmount==null?0:Number(b.refundAmount);
        if(!Number.isSafeInteger(refund)||refund<0||refund>1_000_000_000) throw new HttpError(400,'invalid_amount','Montant de remboursement invalide.');
        const f={reason:txt(b.reason,500),adminComment:txt(b.adminComment,1000),decision:txt(b.decision,500),exchangeNote:txt(b.exchangeNote,500)};
        const client=await pool.connect(); let destroy=false, rid, orderRef;
        try { await client.query('BEGIN');
          const o=(await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[String(b.orderId||'')])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.'); orderRef=o.id;
          if(!orderIsPaid(o)) throw new HttpError(409,'order_state','Une demande ne peut concerner qu’une commande payée.');
          let cur=null; if(b.id){ cur=(await client.query('SELECT * FROM returns WHERE id=$1 FOR UPDATE',[String(b.id)])).rows[0]; if(!cur) throw new HttpError(404,'return_not_found','Demande introuvable.'); }
          const it=(o.items||[]).find(i=>String(i.id)===String(b.productId||cur?.product_id)&&String(i.size)===String(b.size||cur?.size)&&!i.cancelled);
          if(!cur&&!it) throw new HttpError(400,'invalid_item','Choisis un article de cette commande.');
          let applied=cur?.refund_applied===true;
          if(status==='Remboursement effectué'&&refund>0&&!applied){
            const sp=Number((await client.query("SELECT COALESCE(SUM(amount),0)::bigint AS n FROM payments WHERE order_id=$1 AND status='success'",[o.id])).rows[0].n), collected=collectedOf(o,sp);
            if(Number(o.refunded_amount)+refund>collected) throw new HttpError(400,'refund_too_high','Ce remboursement dépasse le montant payé restant.');
            await client.query('UPDATE orders SET refunded_amount=refunded_amount+$1 WHERE id=$2',[refund,o.id]); applied=true;
          }
          const now=Date.now();
          if(cur){ rid=cur.id; await client.query('UPDATE returns SET kind=$1,reason=$2,status=$3,admin_comment=$4,decision=$5,refund_amount=$6,refund_applied=$7,exchange_note=$8,updated_at=$9 WHERE id=$10',[b.kind,f.reason||cur.reason,status,f.adminComment,f.decision,refund,applied,f.exchangeNote,now,rid]); }
          else { rid=crypto.randomUUID(); await client.query('INSERT INTO returns (id,order_id,user_id,kind,product_id,product_name,size,reason,status,admin_comment,decision,refund_amount,refund_applied,exchange_note,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)',[rid,o.id,o.user_id,b.kind,String(it.id),it.name,String(it.size),f.reason,status,f.adminComment,f.decision,refund,applied,f.exchangeNote,now]); }
          await client.query('COMMIT');
        } catch(e) { try { await client.query('ROLLBACK'); } catch { destroy=true; } throw e; } finally { client.release(destroy); }
        await logOrderEvent(orderRef,'return',`${b.kind} — statut : ${status}${refund?` — remboursement ${refund} FC`:''}`);
        return json({ok:true,id:rid});
      }
      case '/api/admin/review-moderate': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const sql={hide:"UPDATE reviews SET status='hidden' WHERE id=$1",publish:"UPDATE reviews SET status='published' WHERE id=$1",dismiss:"UPDATE reviews SET reports=0, reported_by='[]'::jsonb, report_reason='' WHERE id=$1"}[b.action];
        if(!sql) throw new HttpError(400,'bad_request','Action invalide.'); const r=await pool.query(sql,[String(b.id||'')]); if(!r.rowCount) throw new HttpError(404,'review_not_found','Avis introuvable.'); return json({ok:true});
      }
      case '/api/admin/supplier-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const f={name:txt(b.name,100),company:txt(b.company,100),phone:txt(b.phone,30),whatsapp:txt(b.whatsapp,30),address:txt(b.address,300),contact:txt(b.contact,200),notes:txt(b.notes,1000)};
        if(f.name.length<2) throw new HttpError(400,'invalid_supplier','Entre le nom du fournisseur.');
        if(!phoneOk(f.phone)||!phoneOk(f.whatsapp)) throw new HttpError(400,'invalid_phone','Numéro de téléphone invalide.');
        const id=typeof b.id==='string'&&/^[a-f0-9-]{36}$/i.test(b.id)?b.id:crypto.randomUUID(), now=Date.now();
        await pool.query('INSERT INTO suppliers (id,name,company,phone,whatsapp,address,contact,notes,active,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9,$9) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,company=EXCLUDED.company,phone=EXCLUDED.phone,whatsapp=EXCLUDED.whatsapp,address=EXCLUDED.address,contact=EXCLUDED.contact,notes=EXCLUDED.notes,updated_at=EXCLUDED.updated_at',[id,f.name,f.company,f.phone,f.whatsapp,f.address,f.contact,f.notes,now]);
        return json({ok:true,id});
      }
      case '/api/admin/supplier-active': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||typeof b.active!=='boolean') throw new HttpError(400,'bad_request','Requête invalide.'); const r=await pool.query('UPDATE suppliers SET active=$1,updated_at=$2 WHERE id=$3',[b.active,Date.now(),b.id]); if(!r.rowCount) throw new HttpError(404,'supplier_not_found','Fournisseur introuvable.'); return json({ok:true}); }
      case '/api/admin/supplier-payment-add': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const amount=Number(b.amount), paidAt=b.paidAt?Date.parse(String(b.paidAt)):Date.now();
        if(!Number.isSafeInteger(amount)||amount<1||amount>1_000_000_000) throw new HttpError(400,'invalid_amount','Montant invalide.');
        if(!Number.isFinite(paidAt)||paidAt>Date.now()+DAY) throw new HttpError(400,'invalid_date','Date de paiement invalide.');
        const sup=await pool.query('SELECT 1 FROM suppliers WHERE id=$1',[String(b.supplierId||'')]); if(!sup.rowCount) throw new HttpError(404,'supplier_not_found','Fournisseur introuvable.');
        await pool.query('INSERT INTO supplier_payments (id,supplier_id,amount,method,note,paid_at,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',[crypto.randomUUID(),b.supplierId,amount,txt(b.method,60),txt(b.note,300),paidAt,Date.now()]);
        return json({ok:true});
      }
      case '/api/admin/order-supplier-status': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        if(!PART_STATUSES.includes(b.status)) throw new HttpError(400,'bad_request','Statut invalide.');
        const o=(await pool.query('SELECT items FROM orders WHERE id=$1',[String(b.orderId||'')])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
        if(!(o.items||[]).some(i=>i.supplierId===b.supplierId)) throw new HttpError(400,'bad_request','Ce fournisseur n’est pas concerné par cette commande.');
        await pool.query('INSERT INTO order_supplier_parts (order_id,supplier_id,status,updated_at) VALUES ($1,$2,$3,$4) ON CONFLICT(order_id,supplier_id) DO UPDATE SET status=EXCLUDED.status,updated_at=EXCLUDED.updated_at',[b.orderId,b.supplierId,b.status,Date.now()]);
        return json({ok:true});
      }
      case '/api/admin/delivery-company-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        const f={name:txt(b.name,100),phone:txt(b.phone,30),whatsapp:txt(b.whatsapp,30),address:txt(b.address,300),contactName:txt(b.contactName,100),contactPhone:txt(b.contactPhone,30),rates:txt(b.rates,1500),notes:txt(b.notes,1000)};
        if(f.name.length<2) throw new HttpError(400,'invalid_company','Entre le nom de l’entreprise de livraison.');
        if(!phoneOk(f.phone)||!phoneOk(f.whatsapp)||!phoneOk(f.contactPhone)) throw new HttpError(400,'invalid_phone','Numéro de téléphone invalide.');
        const id=typeof b.id==='string'&&/^[a-f0-9-]{36}$/i.test(b.id)?b.id:crypto.randomUUID(), now=Date.now();
        await pool.query('INSERT INTO delivery_companies (id,name,phone,whatsapp,address,contact_name,contact_phone,rates,notes,active,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,$10,$10) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,phone=EXCLUDED.phone,whatsapp=EXCLUDED.whatsapp,address=EXCLUDED.address,contact_name=EXCLUDED.contact_name,contact_phone=EXCLUDED.contact_phone,rates=EXCLUDED.rates,notes=EXCLUDED.notes,updated_at=EXCLUDED.updated_at',[id,f.name,f.phone,f.whatsapp,f.address,f.contactName,f.contactPhone,f.rates,f.notes,now]);
        return json({ok:true,id});
      }
      case '/api/admin/delivery-company-active': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||typeof b.active!=='boolean') throw new HttpError(400,'bad_request','Requête invalide.'); const r=await pool.query('UPDATE delivery_companies SET active=$1,updated_at=$2 WHERE id=$3',[b.active,Date.now(),b.id]); if(!r.rowCount) throw new HttpError(404,'company_not_found','Entreprise introuvable.'); return json({ok:true}); }
      case '/api/admin/order-delivery-save': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        if(typeof b.id!=='string') throw new HttpError(400,'bad_request','Commande invalide.');
        if(!DELIVERY_STATUSES.includes(b.status)) throw new HttpError(400,'bad_request','Statut de livraison invalide.');
        const companyId=b.companyId?String(b.companyId):null;
        if(companyId&&!(await pool.query('SELECT 1 FROM delivery_companies WHERE id=$1',[companyId])).rowCount) throw new HttpError(400,'company_not_found','Entreprise de livraison introuvable.');
        const cost=b.cost===''||b.cost==null?0:Number(b.cost); if(!Number.isSafeInteger(cost)||cost<0||cost>100_000_000) throw new HttpError(400,'invalid_amount','Frais de livraison invalides.');
        const courierPhone=txt(b.courierPhone,30); if(!phoneOk(courierPhone)) throw new HttpError(400,'invalid_phone','Numéro du livreur invalide.');
        const picked=b.pickedUpAt?Date.parse(String(b.pickedUpAt)):null; if(b.pickedUpAt&&!Number.isFinite(picked)) throw new HttpError(400,'invalid_date','Date de prise en charge invalide.');
        const r=await pool.query("UPDATE orders SET delivery_company_id=$1,courier_name=$2,courier_phone=$3,delivery_cost=$4,delivery_status=$5,picked_up_at=$6,delivery_notes=$7, delivered_at=CASE WHEN $5='Livrée' AND delivered_at IS NULL THEN $9::bigint ELSE delivered_at END WHERE id=$8",[companyId,txt(b.courierName,100),courierPhone,cost,b.status,picked,txt(b.notes,500),b.id,Date.now()]);
        if(!r.rowCount) throw new HttpError(404,'order_not_found','Commande introuvable.');
        await logOrderEvent(b.id,'delivery',`Livraison : ${b.status}${companyId?' — entreprise enregistrée':''}${cost?` — frais ${cost} FC`:''}`);
        return json({ok:true});
      }
      case '/api/admin/client-delete': {
        const b=await readJson(req); requireAdmin(req,admin,true);
        if(typeof b.id!=='string') throw new HttpError(400,'bad_request','Client invalide.');
        const u=(await pool.query('SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL',[b.id])).rows[0]; if(!u) throw new HttpError(404,'client_not_found','Client introuvable.');
        const oc=(await pool.query('SELECT COUNT(*)::int AS n FROM orders WHERE user_id=$1',[b.id])).rows[0].n;
        if(!oc) { await pool.query('DELETE FROM users WHERE id=$1',[b.id]); return json({ok:true,mode:'deleted'}); }
        const open=await pool.query('SELECT 1 FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.user_id=$1 AND p.status = ANY($2::text[]) LIMIT 1',[b.id,PAYMENT_OPEN]);
        if(open.rowCount) throw new HttpError(409,'payment_open','Un paiement de ce client est en cours de vérification. Attends son résultat avant de supprimer le compte.');
        // Le client a des commandes : on anonymise le compte (identité effacée, accès fermé) ; les commandes, paiements et factures sont conservés.
        const dead=await hashPassword(crypto.randomBytes(32).toString('hex'));
        await pool.query("UPDATE users SET email=$2, first_name='Client', last_name='supprimé', post_name='', phone='', whatsapp='', birth_date='', address='', password_hash=$3, account_blocked=TRUE, deleted_at=$4 WHERE id=$1",[b.id,`supprime-${b.id}@anonymise.invalid`,dead,Date.now()]);
        await pool.query('DELETE FROM sessions WHERE user_id=$1',[b.id]); await pool.query('DELETE FROM password_reset_tokens WHERE user_id=$1',[b.id]); await pool.query('DELETE FROM favorites WHERE user_id=$1',[b.id]); await pool.query('DELETE FROM carts WHERE user_id=$1',[b.id]);
        return json({ok:true,mode:'anonymized'});
      }
      case '/api/admin/product-save': {
        const b=await readJson(req,60000); requireAdmin(req,admin,true);
        const name=typeof b.name==='string'?b.name.trim().slice(0,100):'', brand=typeof b.brand==='string'?b.brand.trim().slice(0,60):'';
        const price=Number(b.price), old=b.old===''||b.old==null?null:Number(b.old);
        if(!name||!Number.isSafeInteger(price)||price<1||price>100000000||(old!==null&&(!Number.isSafeInteger(old)||old<price||old>100000000))) throw new HttpError(400,'invalid_product','Vérifie le nom et les prix en FC.');
        const color=/^#[0-9a-f]{6}$/i.test(b.color||'')?b.color:'#FFFFFF', ink=/^#[0-9a-f]{6}$/i.test(b.ink||'')?b.ink:'#000000';
        const tags=Array.isArray(b.tags)?b.tags.filter(t=>typeof t==='string').slice(0,12):[];
        const id=typeof b.id==='string'&&/^[a-f0-9-]{36}$/i.test(b.id)?b.id:crypto.randomUUID(), now=Date.now();
        // Type de tailles : lettres (S, M, L…), numériques (1, 2, 3…) ou pointures de chaussures (36, 37…) : jamais mélangés.
        const SIZE_RULES={alpha:z=>['XS','S','M','L','XL','XXL','XXXL'].includes(z),numeric:z=>/^\d{1,2}$/.test(z)&&+z>=1&&+z<=60,shoe:z=>/^\d{2}$/.test(z)&&+z>=20&&+z<=50};
        const givenSizes=Array.isArray(b.sizes)?b.sizes.map(String):Object.keys((b.sizeStock&&typeof b.sizeStock==='object')?b.sizeStock:{});
        const sizeType=['alpha','numeric','shoe'].includes(b.sizeType)?b.sizeType:(givenSizes.length&&givenSizes.every(z=>/^\d{2}$/.test(z)&&+z>=30)?'shoe':givenSizes.length&&givenSizes.every(z=>/^\d{1,2}$/.test(z))?'numeric':'alpha');
        const sizesAllowed={includes:z=>SIZE_RULES[sizeType](String(z))};
        const description=txt(b.description,3000), imgMode=b.imgMode==='galerie'?'galerie':'face_dos';
        const gallery=Array.isArray(b.gallery)?b.gallery.map(u=>typeof u==='string'?u.trim():'').filter(Boolean).slice(0,12):[];
        for(const u of gallery) if(u.length>2000||!/^https?:\/\/\S+$/i.test(u)) throw new HttpError(400,'invalid_gallery','Chaque photo doit être un lien commençant par https://');
        if(imgMode==='galerie'&&!gallery.length) throw new HttpError(400,'invalid_gallery','Mode galerie : ajoute au moins une photo (4 ou 5 recommandées).');
        const sizeStock=(b.sizeStock&&typeof b.sizeStock==='object'&&!Array.isArray(b.sizeStock))?b.sizeStock:{};
        const sizes=Array.isArray(b.sizes)?[...new Set(b.sizes.filter(x=>sizesAllowed.includes(x)))].slice(0,20):Object.keys(sizeStock).filter(x=>sizesAllowed.includes(x));
        if(!sizes.length) throw new HttpError(400,'invalid_stock','Ajoute au moins une taille.');
        const normalizedStock={}; for(const z of sizes){const q=Number(sizeStock[z]??0);if(!Number.isInteger(q)||q<0||q>100000)throw new HttpError(400,'invalid_stock',`Stock invalide pour la taille ${z}.`);normalizedStock[z]=q;}
        const quantity=Object.values(normalizedStock).reduce((a,n)=>a+n,0);
        let supplierSet=false, supplierVal=null, costSet=false, costVal=null;
        if(b.supplierId!==undefined){ supplierSet=true; supplierVal=b.supplierId===''||b.supplierId==null?null:String(b.supplierId); if(supplierVal&&!(await pool.query('SELECT 1 FROM suppliers WHERE id=$1',[supplierVal])).rowCount) throw new HttpError(400,'supplier_not_found','Fournisseur introuvable.'); }
        if(b.costPrice!==undefined){ costSet=true; costVal=b.costPrice===''||b.costPrice==null?null:Number(b.costPrice); if(costVal!==null&&(!Number.isSafeInteger(costVal)||costVal<0||costVal>100000000)) throw new HttpError(400,'invalid_cost','Prix d’achat invalide.'); }
        const values=[id,brand,name,price,old,typeof b.badge==='string'?b.badge.trim().slice(0,40)||null:null,b.free===true,color,ink,['blank','block','wave','campus','stripes','plain'].includes(b.print)?b.print:'blank',JSON.stringify(tags),typeof b.front==='string'?b.front.trim().slice(0,2000):'',typeof b.back==='string'?b.back.trim().slice(0,2000):'',quantity,JSON.stringify(sizes),JSON.stringify(normalizedStock),now,now];
        await pool.query(`INSERT INTO products (id,brand,name,price,old_price,badge,free,color,ink,print,tags,img_front,img_back,quantity,sizes,size_stock,active,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15::jsonb,$16::jsonb,TRUE,$17,$18) ON CONFLICT(id) DO UPDATE SET brand=EXCLUDED.brand,name=EXCLUDED.name,price=EXCLUDED.price,old_price=EXCLUDED.old_price,badge=EXCLUDED.badge,free=EXCLUDED.free,color=EXCLUDED.color,ink=EXCLUDED.ink,print=EXCLUDED.print,tags=EXCLUDED.tags,img_front=EXCLUDED.img_front,img_back=EXCLUDED.img_back,quantity=EXCLUDED.quantity,sizes=EXCLUDED.sizes,size_stock=EXCLUDED.size_stock,active=TRUE,updated_at=EXCLUDED.updated_at`,values);
        await pool.query('UPDATE products SET description=$1,img_mode=$2,gallery=$3::jsonb,size_type=$4 WHERE id=$5',[description,imgMode,JSON.stringify(gallery),sizeType,id]);
        if(supplierSet) await pool.query('UPDATE products SET supplier_id=$1 WHERE id=$2',[supplierVal,id]);
        if(costSet) await pool.query('UPDATE products SET cost_price=$1 WHERE id=$2',[costVal,id]);
        return json({ok:true,id});
      }
      case '/api/admin/collections-save': {
        const b=await readJson(req,20000); requireAdmin(req,admin,true);
        const list=Array.isArray(b.collections)?b.collections:[]; if(list.length>40) throw new HttpError(400,'invalid_collections','40 collections maximum.');
        const seen=new Set(), items=[];
        for(const c of list){
          const name=txt(c?.name,60); if(name.length<2) throw new HttpError(400,'invalid_collections','Chaque collection doit avoir un nom (2 caractères minimum).');
          const id=slugify(c?.id||name); if(!id) throw new HttpError(400,'invalid_collections','Nom de collection invalide.');
          if(seen.has(id)) throw new HttpError(400,'invalid_collections',`Collection en double : ${name}.`); seen.add(id);
          const image=typeof c?.image==='string'?c.image.trim().slice(0,2000):''; if(image&&!/^https?:\/\/\S+$/i.test(image)) throw new HttpError(400,'invalid_collections','Le lien de l’image doit commencer par https://');
          items.push({id,name,image});
        }
        await pool.query('INSERT INTO site_settings (key,value,updated_at) VALUES ($1,$2::jsonb,$3) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at',[COLLECTIONS_KEY,JSON.stringify({items}),Date.now()]);
        return json({ok:true,collections:items});
      }
      case '/api/admin/product-delete': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string') throw new HttpError(400,'bad_request','Article invalide.'); await pool.query('UPDATE products SET active=FALSE,updated_at=$1 WHERE id=$2',[Date.now(),b.id]); return json({ok:true}); }
      case '/api/admin/product-hard-delete': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string') throw new HttpError(400,'bad_request','Article invalide.'); const used=await pool.query("SELECT 1 FROM orders WHERE items @> jsonb_build_array(jsonb_build_object('id',$1::text)) LIMIT 1",[b.id]); if(used.rowCount) throw new HttpError(409,'product_in_orders','Cet article figure dans des commandes : suppression définitive impossible pour garder l’historique et les factures. Utilise « Retirer » pour le masquer.'); await pool.query('DELETE FROM products WHERE id=$1',[b.id]); return json({ok:true}); }
      case '/api/admin/client-toggle': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||typeof b.blocked!=='boolean') throw new HttpError(400,'bad_request','Client invalide.'); await pool.query('UPDATE users SET account_blocked=$1,failed_attempts=0 WHERE id=$2',[b.blocked,b.id]); if(b.blocked) await pool.query('DELETE FROM sessions WHERE user_id=$1',[b.id]); return json({ok:true}); }
      case '/api/admin/order-delete': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||!b.id.trim()) throw new HttpError(400,'bad_request','Commande invalide.'); const hasPay=await pool.query('SELECT 1 FROM payments WHERE order_id=$1 LIMIT 1',[b.id]); if(hasPay.rowCount) throw new HttpError(409,'order_has_payments','Impossible de supprimer une commande qui a un historique de paiement.'); const result=await pool.query('DELETE FROM orders WHERE id=$1',[b.id]); if(!result.rowCount) throw new HttpError(404,'order_not_found','Commande introuvable.'); return json({ok:true}); }
      case '/api/admin/order-status': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||!ORDER_STATUSES.includes(b.status)) throw new HttpError(400,'bad_request','Statut invalide.'); { const mo=(await pool.query('SELECT payment_method FROM orders WHERE id=$1',[b.id])).rows[0]; if(mo&&mo.payment_method==='cash'&&b.status==='Payée') throw new HttpError(409,'cash_order','Cette commande se paie en espèces à la réception : passe-la en « Expédiée » puis utilise « Enregistrer l’encaissement » une fois l’argent reçu.'); }
 if(b.status==='Payée'||b.status==='En attente'){ const {rows:pc}=await pool.query("SELECT COUNT(*)::int AS n, COUNT(*) FILTER (WHERE status='success')::int AS ok FROM payments WHERE order_id=$1",[b.id]); const n=pc[0]?.n||0, ok=pc[0]?.ok||0; if(b.status==='Payée'&&n>0&&!ok) throw new HttpError(409,'payment_not_confirmed','Le statut « Payée » est réservé aux paiements confirmés par l’opérateur. Utilise « Revérifier » dans l’onglet Paiements.'); if(b.status==='En attente'&&ok) throw new HttpError(409,'already_paid','Cette commande est déjà payée.'); } const st=await setOrderStatus(b.id,b.status); await logOrderEvent(b.id,'status',`Statut de la commande : ${st.previous} → ${b.status}`); if(st.previous==='En attente'&&st.method!=='cash'&&PAID_ORDER_STATUSES.includes(b.status)) await sendOrderConfirmation(b.id); return json({ok:true}); }
      case '/api/admin/order-tracking': { const b=await readJson(req); requireAdmin(req,admin,true); if(typeof b.id!=='string'||typeof b.trackingCode!=='string'||b.trackingCode.length>100) throw new HttpError(400,'bad_request','Code de suivi invalide.'); await pool.query('UPDATE orders SET tracking_code=$1 WHERE id=$2',[b.trackingCode.trim(),b.id]); return json({ok:true}); }
      default: break;
    }
    switch(url.pathname){
      case '/api/favorites/toggle': {
        const b=await readJson(req); requireAuth(req,auth,true); const uid=auth.row.user_id, pid=String(b.productId||'').slice(0,60);
        if(!(await pool.query('SELECT 1 FROM products WHERE id=$1 AND active=TRUE',[pid])).rowCount) throw new HttpError(404,'product_not_found','Article introuvable.');
        const cur=(await pool.query('SELECT 1 FROM favorites WHERE user_id=$1 AND product_id=$2',[uid,pid])).rowCount>0, on=typeof b.on==='boolean'?b.on:!cur;
        if(on&&!cur) await pool.query('INSERT INTO favorites (user_id,product_id,created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',[uid,pid,Date.now()]);
        if(!on&&cur) await pool.query('DELETE FROM favorites WHERE user_id=$1 AND product_id=$2',[uid,pid]);
        return json({on},200,cookies);
      }
      case '/api/favorites/sync': {
        const b=await readJson(req); requireAuth(req,auth,true); const uid=auth.row.user_id;
        const ids=Array.isArray(b.ids)?[...new Set(b.ids.map(x=>String(x).slice(0,60)))].slice(0,100):[];
        if(ids.length) await pool.query('INSERT INTO favorites (user_id,product_id,created_at) SELECT $1::text,id,$3::bigint FROM products WHERE id=ANY($2::text[]) AND active=TRUE ON CONFLICT DO NOTHING',[uid,ids,Date.now()]);
        const {rows}=await pool.query('SELECT product_id FROM favorites WHERE user_id=$1 ORDER BY created_at DESC',[uid]); return json({ids:rows.map(r=>r.product_id)},200,cookies);
      }
      case '/api/cart/sync': {
        const b=await readJson(req); requireAuth(req,auth,true); const uid=auth.row.user_id;
        if(!allow('cart:'+uid,300,HOUR)) throw new HttpError(429,'rate_limited','Trop de requêtes.');
        const items=(Array.isArray(b.items)?b.items:[]).slice(0,30).map(i=>({id:String(i?.id??'').slice(0,60),size:String(i?.size??'').slice(0,10),qty:Number(i?.qty)})).filter(i=>i.id&&i.size&&Number.isInteger(i.qty)&&i.qty>=1&&i.qty<=20);
        if(!items.length) await pool.query('DELETE FROM carts WHERE user_id=$1',[uid]);
        else await pool.query('INSERT INTO carts (user_id,items,updated_at) VALUES ($1,$2::jsonb,$3) ON CONFLICT (user_id) DO UPDATE SET items=EXCLUDED.items, updated_at=EXCLUDED.updated_at',[uid,JSON.stringify(items),Date.now()]);
        return json({ok:true},200,cookies);
      }
      case '/api/reviews': {
        const b=await readJson(req); requireAuth(req,auth,true); const uid=auth.row.user_id;
        if(!allow('review:'+uid,20,DAY)) throw new HttpError(429,'rate_limited','Trop d’avis aujourd’hui. Réessaie demain.');
        const orderId=String(b.orderId||''), productId=String(b.productId||''), rating=Number(b.rating), comment=txt(b.comment,1000);
        if(!Number.isInteger(rating)||rating<1||rating>5) throw new HttpError(400,'invalid_rating','Choisis une note de 1 à 5.');
        const o=(await pool.query('SELECT * FROM orders WHERE id=$1 AND user_id=$2',[orderId,uid])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
        if(!orderIsPaid(o)||!(o.items||[]).some(i=>String(i.id)===productId&&!i.cancelled)) throw new HttpError(403,'not_purchased','Seuls les clients ayant acheté cet article peuvent donner leur avis.');
        const u=(await pool.query('SELECT first_name,last_name FROM users WHERE id=$1',[uid])).rows[0];
        try { await pool.query("INSERT INTO reviews (id,product_id,order_id,user_id,author,rating,comment,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'published',$8)",[crypto.randomUUID(),productId,orderId,uid,reviewAuthor(u),rating,comment,Date.now()]); }
        catch(e) { if(e.code==='23505') throw new HttpError(409,'already_reviewed','Tu as déjà donné ton avis sur cet article pour cette commande.'); throw e; }
        return json({ok:true},201,cookies);
      }
      case '/api/reviews/report': {
        const b=await readJson(req); requireAuth(req,auth,true); const uid=auth.row.user_id;
        if(!allow('report:'+uid,20,DAY)) throw new HttpError(429,'rate_limited','Trop de signalements aujourd’hui.');
        const id=String(b.id||''), r=(await pool.query("SELECT reported_by FROM reviews WHERE id=$1 AND status='published'",[id])).rows[0]; if(!r) throw new HttpError(404,'review_not_found','Avis introuvable.');
        if(!(r.reported_by||[]).includes(uid)) await pool.query("UPDATE reviews SET reports=reports+1, reported_by=reported_by||to_jsonb($2::text), report_reason=CASE WHEN report_reason='' THEN $3 ELSE report_reason END WHERE id=$1",[id,uid,txt(b.reason,300)]);
        return json({ok:true},200,cookies);
      }
      case '/api/returns/request': {
        const b=await readJson(req); requireAuth(req,auth,true); const uid=auth.row.user_id;
        if(!allow('ret:'+uid,10,DAY)) throw new HttpError(429,'rate_limited','Trop de demandes aujourd’hui.');
        if(!['Retour','Échange'].includes(b.kind)) throw new HttpError(400,'bad_request','Choisis « Retour » ou « Échange ».');
        const reason=txt(b.reason,500); if(reason.length<5) throw new HttpError(400,'invalid_reason','Explique brièvement le motif de ta demande.');
        const o=(await pool.query('SELECT * FROM orders WHERE id=$1 AND user_id=$2',[String(b.orderId||''),uid])).rows[0]; if(!o) throw new HttpError(404,'order_not_found','Commande introuvable.');
        if(o.status!=='Livrée') throw new HttpError(409,'return_unavailable','Une demande n’est possible qu’une fois la commande livrée.');
        const days=Number(process.env.RETURN_WINDOW_DAYS||7); if(Date.now()-Number(o.delivered_at||o.created_at)>days*DAY) throw new HttpError(409,'return_expired',`Le délai de ${days} jours pour demander un retour ou un échange est dépassé.`);
        const it=(o.items||[]).find(i=>String(i.id)===String(b.productId)&&String(i.size)===String(b.size)&&!i.cancelled); if(!it) throw new HttpError(404,'item_not_found','Article introuvable dans cette commande.');
        if((await pool.query("SELECT 1 FROM returns WHERE order_id=$1 AND product_id=$2 AND size=$3 AND status NOT IN ('Refusée','Échange effectué','Remboursement effectué')",[o.id,String(it.id),String(it.size)])).rowCount) throw new HttpError(409,'already_requested','Une demande est déjà en cours pour cet article.');
        const now=Date.now(); await pool.query('INSERT INTO returns (id,order_id,user_id,kind,product_id,product_name,size,reason,status,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)',[crypto.randomUUID(),o.id,uid,b.kind,String(it.id),it.name,String(it.size),reason,'Demande reçue',now]);
        await logOrderEvent(o.id,'return',`Demande de ${b.kind.toLowerCase()} reçue du client : ${it.name} (${it.size}) — ${reason}`); return json({ok:true},201,cookies);
      }
      case '/api/profile': {
        const b=await readJson(req); requireAuth(req,auth,true);
        const wa=normalizeWhatsapp(b.whatsapp,false); if(!b.phone&&wa) b.phone=wa;
        const f=profileFields(b);
        const {rows}=await pool.query("UPDATE users SET first_name=$1,last_name=$2,post_name=$3,phone=$4,birth_date=$5,address=$6,whatsapp=COALESCE(NULLIF($8,''),whatsapp) WHERE id=$7 RETURNING *",[f.firstName,f.lastName,f.postName,f.phone,f.birthDate,f.address,auth.row.user_id,wa]);
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
        const ownWa=(await pool.query('SELECT whatsapp FROM users WHERE id=$1',[auth.row.user_id])).rows[0]?.whatsapp||'';
        const whatsapp=normalizeWhatsapp(b.whatsapp!==undefined?b.whatsapp:ownWa);
        const payMethod=b.paymentMethod==='cash'?'cash':'mobile_money';
        if(payMethod==='cash'){ const set=settingsFromValue((await pool.query('SELECT value FROM site_settings WHERE key=$1',[SETTINGS_KEY])).rows[0]?.value); if(set.codEnabled===false) throw new HttpError(400,'cash_disabled','Le paiement en espèces à la réception n’est pas disponible pour le moment.'); }
        if(address.length<8) throw new HttpError(400,'invalid_address','Entre une adresse de livraison complète.');
        if(!Array.isArray(b.items)||!b.items.length||b.items.length>30) throw new HttpError(400,'invalid_cart','Ton panier est vide ou invalide.');
        await sweepExpiredReservations(true);
        const dbIds=[...new Set(b.items.map(i=>String(i?.id)))];
        const dbRows=dbIds.length?(await pool.query('SELECT id,brand,name,price,quantity,sizes,size_stock,cost_price,supplier_id FROM products WHERE active=TRUE AND id=ANY($1::text[])',[dbIds])).rows:[];
        const dbMap=Object.fromEntries(dbRows.map(r=>[r.id,r]));
        const items=[];
        for(const i of b.items){
          const key=String(i?.id), p=dbMap[key], qty=Number(i?.qty), allowedSizes=p?.sizes&&Array.isArray(p.sizes)?p.sizes:['S','M','L','XL'], size=allowedSizes.includes(i?.size)?i.size:null;
          const stockMap=p?.size_stock&&typeof p.size_stock==='object'?p.size_stock:{}; const sizeQty=Object.keys(stockMap).length?Number(stockMap[i?.size]||0):Number(p?.quantity??1);
          if(!p||!size||!Number.isInteger(qty)||qty<1||qty>20||qty>sizeQty) throw new HttpError(400,'out_of_stock','Cette taille est en rupture de stock ou la quantité demandée est trop élevée. Recharge la page.');
          const unitPrice=Number(p.price);
          items.push({id:key,name:(p.brand?p.brand+' ':'')+p.name,size,qty,unitPrice,total:unitPrice*qty,unitCost:p.cost_price==null?null:Number(p.cost_price),supplierId:p.supplier_id||null});
        }
        const itemCount=items.reduce((s,x)=>s+x.qty,0); if(itemCount===3 && items.some(x=>x.unitPrice<19500)) throw new HttpError(400,'minimum_item_price','Pour une commande de 3 articles, chaque article doit coûter au moins 19 500 FC.'); const subtotal=items.reduce((s,x)=>s+x.total,0), delivery=itemCount>=4?0:6000, total=subtotal+delivery, id=crypto.randomUUID();
        // Réservation atomique : verrou des produits, vérification du stock réel, retenue et création de la commande dans UNE transaction.
        { const client=await pool.connect(); let destroy=false;
          try { await client.query('BEGIN'); await takeStock(client,items);
            const nowTs=Date.now();
            await client.query("INSERT INTO orders (id,user_id,customer_name,customer_email,phone,address,items,total,status,created_at,stock_state,reserved_until,whatsapp,payment_method) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,'reserved',$11,$12,$13)",[id,auth.row.user_id,fullName,auth.row.email,phone,address,JSON.stringify(items),total,'En attente',nowTs,payMethod==='cash'?null:nowTs+RESERVATION_MS,whatsapp,payMethod]);
            await client.query("UPDATE users SET whatsapp=$1 WHERE id=$2 AND whatsapp=''",[whatsapp,auth.row.user_id]); await client.query('DELETE FROM carts WHERE user_id=$1',[auth.row.user_id]);
            await client.query('COMMIT'); }
          catch(e) { try { await client.query('ROLLBACK'); } catch { destroy=true; } throw e; }
          finally { client.release(destroy); } }
        await notifyAdminOrder({ref:id.slice(0,8).toUpperCase(),customerName:fullName,email:auth.row.email,phone,address,items,total,paymentMethod:payMethod});
        if(payMethod==='cash') { await logOrderEvent(id,'order','Commande à payer en espèces à la réception'); await sendOrderConfirmation(id); }
        return json({ok:true,ref:id.slice(0,8).toUpperCase(),total,paymentMethod:payMethod},201,cookies);
      }
      case '/api/register': {
        if(!allow('reg:'+ip,5,HOUR)) throw new HttpError(429,'rate_limited','Trop de créations de compte. Réessaie plus tard.');
        const b=await readJson(req); const whatsapp=normalizeWhatsapp(b.whatsapp); if(!b.phone) b.phone=whatsapp; const prof=profileFields(b), firstName=prof.firstName, email=normEmail(b.email);
        
        if(!emailOk(email)) throw new HttpError(400,'invalid_email','Entre une adresse e-mail valide.');
        const problems=passwordProblems(b.password,{email,firstName}); if(problems.length) throw new HttpError(400,'password_policy',problems[0],problems);
        const exists=await pool.query('SELECT id FROM users WHERE email=$1',[email]); if(exists.rowCount) throw new HttpError(409,'email_taken','Un compte existe déjà avec cet e-mail. Connecte-toi.');
        const hash=await hashPassword(b.password), id=crypto.randomUUID();
        try { await pool.query('INSERT INTO users (id,email,first_name,last_name,post_name,phone,birth_date,address,password_hash,created_at,whatsapp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[id,email,firstName,prof.lastName,prof.postName,prof.phone,prof.birthDate,prof.address,hash,Date.now(),whatsapp]); }
        catch(e){if(e.code==='23505') throw new HttpError(409,'email_taken','Un compte existe déjà avec cet e-mail. Connecte-toi.');throw e;}
        const s=await createSession(id,b.remember===true,req); cookies.push(s.cookie); console.log(JSON.stringify({event:'register',ip}));
        return json({user:publicUser({first_name:firstName,email,last_name:prof.lastName,post_name:prof.postName,phone:prof.phone,whatsapp,birth_date:prof.birthDate,address:prof.address}),csrfToken:s.csrf},201,cookies);
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
