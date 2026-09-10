import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { createHash, timingSafeEqual } from 'node:crypto';

const root = resolve('v43-site');
const ACCESS_HASH = 'c92652a11c8b84f07fd0a191c90c04c704725c032aa80412a819a05b7ac06578';
const port = Number(process.env.PORT || 10000);
const mime = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8'
};
const unauthorized = `<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Central QA protegido</title><style>body{font-family:system-ui;background:#07111f;color:#eef6ff;display:grid;place-items:center;min-height:100vh;margin:0;padding:24px}.c{max-width:520px;padding:28px;border:1px solid #334155;border-radius:24px;background:#0f172a;box-shadow:0 24px 80px #0008}p{color:#a8b3c7;line-height:1.6}</style><div class="c"><h1>Central WebOS V4.3 QA</h1><p>Ambiente privado de validação. Use o link autorizado para criar uma sessão temporária neste navegador.</p></div></html>`;

const sha256 = value => createHash('sha256').update(value).digest('hex');
const validAccess = value => {
  if (!value || typeof value !== 'string' || value.length > 256) return false;
  const actual = Buffer.from(sha256(value), 'hex');
  const expected = Buffer.from(ACCESS_HASH, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};
const parseCookies = header => Object.fromEntries((header || '').split(';').map(v => v.trim().split('=')).filter(v => v.length === 2).map(([k, v]) => [k, decodeURIComponent(v)]));

createServer(async (req, res) => {
  try {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    const url = new URL(req.url || '/', `https://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('ok');
      return;
    }

    const queryAccess = url.searchParams.get('access');
    if (validAccess(queryAccess)) {
      res.setHeader('Set-Cookie', `qa_access=${encodeURIComponent(queryAccess)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
      url.searchParams.delete('access');
      const location = url.pathname + (url.search ? url.search : '') + url.hash;
      res.writeHead(302, { Location: location || '/', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }

    const cookies = parseCookies(req.headers.cookie);
    if (!validAccess(cookies.qa_access)) {
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(unauthorized);
      return;
    }

    let pathname;
    try { pathname = decodeURIComponent(url.pathname); }
    catch { res.writeHead(400, { 'Cache-Control': 'no-store' }); res.end('Bad path'); return; }
    if (pathname === '/') pathname = '/index.html';
    let target = resolve(root, '.' + pathname);
    if (!(target === root || target.startsWith(root + '/'))) {
      res.writeHead(400, { 'Cache-Control': 'no-store' });
      res.end('Bad path');
      return;
    }

    try {
      if ((await stat(target)).isDirectory()) target = resolve(target, 'index.html');
    } catch {
      if ((req.headers.accept || '').includes('text/html')) target = resolve(root, 'index.html');
      else { res.writeHead(404, { 'Cache-Control': 'no-store' }); res.end('Not found'); return; }
    }

    const body = await readFile(target);
    const ext = extname(target).toLowerCase();
    const base = target.slice(root.length + 1);
    const noCache = base === 'index.html' || base === 'sw.js' || base === 'manifest.webmanifest';
    res.writeHead(200, {
      'Content-Type': mime[ext] || 'application/octet-stream',
      'Cache-Control': noCache ? 'no-cache, no-store, must-revalidate' : 'private, max-age=3600'
    });
    res.end(body);
  } catch (error) {
    console.error(error);
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end('QA server error');
  }
}).listen(port, '0.0.0.0', () => console.log(`Central WebOS V4.3 QA listening on ${port}`));
