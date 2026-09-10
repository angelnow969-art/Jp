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
const unauthorized = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>Central QA protegido</title><style>*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#07111f;color:#eef6ff;display:grid;place-items:center;min-height:100vh;min-height:100svh;margin:0;padding:24px}.c{width:min(100%,520px);padding:28px;border:1px solid #334155;border-radius:24px;background:#0f172a;box-shadow:0 24px 80px #0008}p{color:#a8b3c7;line-height:1.6}label{display:block;margin:20px 0 8px}input{width:100%;padding:14px 15px;border:1px solid #52627a;border-radius:12px;background:#07111f;color:#fff;font:inherit}button{width:100%;min-height:48px;margin-top:16px;border:0;border-radius:12px;background:#85e3ef;color:#06202a;font:700 16px system-ui;cursor:pointer}button:disabled{opacity:.55}#status{min-height:24px;font-size:14px}</style></head><body><main class="c"><h1>Central WebOS V4.3 QA</h1><p>Ambiente privado de validação. Digite o código temporário ou abra o link autorizado.</p><form id="login"><label for="access">Código de QA</label><input id="access" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required><button id="go" type="submit">Abrir Central</button></form><p id="status" role="status" aria-live="polite"></p></main><script>(()=>{'use strict';const form=document.getElementById('login'),field=document.getElementById('access'),status=document.getElementById('status'),button=document.getElementById('go');async function login(value){if(!value)return;button.disabled=true;status.textContent='Validando…';try{const r=await fetch('/__qa/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',cache:'no-store',body:JSON.stringify({access:String(value)})});if(!r.ok)throw new Error('Código de QA inválido.');history.replaceState(null,'',location.pathname+location.search);location.reload()}catch(e){status.textContent=e.message||'Não foi possível validar.';button.disabled=false;field.focus()}}form.addEventListener('submit',e=>{e.preventDefault();login(field.value)});const p=new URLSearchParams(location.hash.slice(1));const fromLink=p.get('access');if(fromLink){history.replaceState(null,'',location.pathname+location.search);login(fromLink)}})();</script></body></html>`;

const sha256 = value => createHash('sha256').update(value).digest('hex');
const validAccess = value => {
  if (!value || typeof value !== 'string' || value.length > 256) return false;
  const actual = Buffer.from(sha256(value), 'hex');
  const expected = Buffer.from(ACCESS_HASH, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};
const parseCookies = header => Object.fromEntries((header || '').split(';').map(v => v.trim().split('=')).filter(v => v.length === 2).map(([k, v]) => [k, decodeURIComponent(v)]));
const readBody = req => new Promise((resolveBody, reject) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', chunk => { body += chunk; if (body.length > 1024) reject(new Error('Body too large')); });
  req.on('end', () => resolveBody(body));
  req.on('error', reject);
});

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

    if (url.pathname === '/__qa/login') {
      if (req.method !== 'POST') { res.writeHead(405, { Allow: 'POST', 'Cache-Control': 'no-store' }); res.end(); return; }
      let submitted = '';
      try {
        const raw = await readBody(req);
        const parsed = JSON.parse(raw || '{}');
        submitted = typeof parsed.access === 'string' ? parsed.access : '';
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('{"ok":false}');
        return;
      }
      if (!validAccess(submitted)) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('{"ok":false}');
        return;
      }
      res.writeHead(204, {
        'Set-Cookie': `qa_access=${encodeURIComponent(submitted)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`,
        'Cache-Control': 'no-store'
      });
      res.end();
      return;
    }

    if (url.pathname === '/__qa/logout') {
      res.writeHead(204, { 'Set-Cookie': 'qa_access=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict', 'Cache-Control': 'no-store' });
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
