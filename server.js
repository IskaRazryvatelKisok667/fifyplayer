/*
  Бэкенд для вкладки «Канал». Node.js 18+, без зависимостей.
  Запуск:  BOT_TOKEN=123:ABC CHANNEL_ID=-1001234567890 ALLOWED_ORIGIN=https://ваш-сайт node server.js

  Что делает:
  1. Читает новые посты канала через getUpdates (бот должен быть админом канала).
  2. Хранит список аудио в tracks.json.
  3. GET /api/tracks  — список треков.
  4. GET /api/file/:id и /api/thumb/:id — стримит файл и обложку из Telegram (с Range, перемотка работает).
  5. Каждый запрос проверяется: подпись Telegram initData + членство пользователя в канале.
*/
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const { Readable } = require('stream');

const BOT_TOKEN = process.env.BOT_TOKEN;
const CHANNEL_ID = process.env.CHANNEL_ID;            // например -1001234567890
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ALLOWED_ORIGIN || '*';     // адрес, где лежит index.html
const DEV = process.env.DEV === '1';                  // DEV=1 отключает проверку (только для локальных тестов!)
const DB_FILE = process.env.DB_FILE || './tracks.json';
const MAX_AGE = 7 * 24 * 3600;                        // срок жизни initData, сек
const TG = 'https://api.telegram.org';

if (!BOT_TOKEN || !CHANNEL_ID) { console.error('Задайте переменные BOT_TOKEN и CHANNEL_ID'); process.exit(1); }

const sleep = ms => new Promise(r => setTimeout(r, ms));
const api = async (method, params = {}) => {
  const r = await fetch(`${TG}/bot${BOT_TOKEN}/${method}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(params)
  });
  return r.json();
};

/* ---------- Хранилище ---------- */
let db = { offset: 0, tracks: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db));

function addPost(m) {
  if (String(m.chat.id) !== String(CHANNEL_ID)) return;
  const a = m.audio || (m.document && /^audio\//.test(m.document.mime_type || '') ? m.document : null);
  if (!a) return;
  const title = a.title || (a.file_name || 'Без названия').replace(/\.[^.]+$/, '');
  db.tracks = db.tracks.filter(t => t.uid !== a.file_unique_id);
  db.tracks.unshift({
    uid: a.file_unique_id, fid: a.file_id, title, artist: a.performer || '', dur: a.duration || 0,
    thumb: (a.thumbnail || a.thumb || {}).file_id || null, mime: a.mime_type || 'audio/mpeg', mid: m.message_id
  });
  console.log('+ трек:', title);
}

async function poll() {
  await api('deleteWebhook');                          // getUpdates не работает вместе с вебхуком
  for (;;) {
    try {
      const r = await api('getUpdates', { offset: db.offset, timeout: 50, allowed_updates: ['channel_post'] });
      if (!r.ok) { console.error('getUpdates:', r.description); await sleep(5000); continue; }
      for (const u of r.result) { db.offset = u.update_id + 1; if (u.channel_post) addPost(u.channel_post); }
      if (r.result.length) save();
    } catch (e) { console.error('poll:', e.message); await sleep(5000); }
  }
}

/* ---------- Авторизация ---------- */
function validate(initData) {
  if (!initData) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get('hash'); if (!hash) return null;
  p.delete('hash');
  const str = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calc = crypto.createHmac('sha256', secret).update(str).digest('hex');
  if (calc.length !== hash.length || !crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(hash))) return null;
  if (Date.now() / 1000 - (+p.get('auth_date') || 0) > MAX_AGE) return null;
  try { return JSON.parse(p.get('user')); } catch (e) { return null; }
}
const members = new Map();
async function isMember(userId) {
  const c = members.get(userId);
  if (c && c.exp > Date.now()) return c.ok;
  const r = await api('getChatMember', { chat_id: CHANNEL_ID, user_id: userId });
  const ok = !!(r.ok && ['creator', 'administrator', 'member'].includes(r.result.status));
  members.set(userId, { ok, exp: Date.now() + 5 * 60 * 1000 });
  return ok;
}
async function guard(url, res) {
  if (DEV) return true;
  const user = validate(url.searchParams.get('auth'));
  if (!user) { send(res, 401, 'unauthorized'); return false; }
  if (!(await isMember(user.id))) { send(res, 403, 'not a channel member'); return false; }
  return true;
}

/* ---------- Прокси файлов ---------- */
const paths = new Map();
async function filePath(fid) {
  const c = paths.get(fid);
  if (c && c.exp > Date.now()) return c.p;
  const r = await api('getFile', { file_id: fid });
  if (!r.ok) { const e = new Error(r.description); e.big = /too big/i.test(r.description || ''); throw e; }
  paths.set(fid, { p: r.result.file_path, exp: Date.now() + 50 * 60 * 1000 }); // ссылка живёт ~1 час
  return r.result.file_path;
}
const cors = {
  'access-control-allow-origin': ORIGIN,
  'access-control-allow-headers': '*',
  'access-control-expose-headers': 'content-range,accept-ranges,content-length'
};
const send = (res, code, body, type = 'text/plain; charset=utf-8') => { res.writeHead(code, { ...cors, 'content-type': type }); res.end(body); };

async function proxy(req, res, fid, o) {
  let p;
  try { p = await filePath(fid); }
  catch (e) { return send(res, e.big ? 413 : 502, e.big ? 'file is too big (Bot API limit 20 MB)' : 'telegram error'); }
  const headers = {}; if (req.headers.range) headers.range = req.headers.range;
  const r = await fetch(`${TG}/file/bot${BOT_TOKEN}/${p}`, { headers });
  const out = { 'accept-ranges': 'bytes', 'content-type': o.type, 'cache-control': 'private, max-age=3600' };
  for (const k of ['content-length', 'content-range']) if (r.headers.get(k)) out[k] = r.headers.get(k);
  if (o.dl) out['content-disposition'] = `attachment; filename*=UTF-8''${encodeURIComponent(o.name)}`;
  res.writeHead(r.status, { ...cors, ...out });
  if (!r.body) return res.end();
  const stream = Readable.fromWeb(r.body);
  req.on('close', () => stream.destroy());
  stream.pipe(res);
}

/* ---------- HTTP ---------- */
http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return send(res, 204, '');
    const url = new URL(req.url, 'http://x');
    const m = url.pathname.match(/^\/api\/(tracks|file|thumb)(?:\/([\w-]+))?$/);
    if (!m) return send(res, 404, 'not found');
    if (!(await guard(url, res))) return;
    if (m[1] === 'tracks') {
      const tracks = db.tracks.map(t => ({ uid: t.uid, title: t.title, artist: t.artist, dur: t.dur, thumb: !!t.thumb }));
      return send(res, 200, JSON.stringify({ tracks }), 'application/json');
    }
    const t = db.tracks.find(x => x.uid === m[2]);
    if (!t) return send(res, 404, 'no such track');
    if (m[1] === 'thumb') {
      if (!t.thumb) return send(res, 404, 'no thumbnail');
      return proxy(req, res, t.thumb, { type: 'image/jpeg' });
    }
    return proxy(req, res, t.fid, {
      type: t.mime, dl: url.searchParams.get('dl') === '1',
      name: `${t.artist ? t.artist + ' - ' : ''}${t.title}.mp3`
    });
  } catch (e) { console.error(e); if (!res.headersSent) send(res, 500, 'server error'); }
}).listen(PORT, () => console.log('Сервер запущен на порту', PORT));

poll();
