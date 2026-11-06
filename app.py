#!/usr/bin/env python3
"""One-click Katowice (GPU Server Hub) consent links for Decision Models accounts.

GET  /k/<token>   page; its script POSTs back at once (link scanners that only fetch do not consent)
POST /k/<token>   verifies the token and writes the consent row the gateway reads
GET  /healthz     liveness

token = v1.<account_id>.<token_id>.<expiry_unix_base36>.<sig>, sig = first 22 chars of
base64url(HMAC-SHA256(CONSENT_HMAC_KEY, "v1.<account_id>.<token_id>.<expiry>")).
"""
import base64, hashlib, hmac, html, json, os, re, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

KEY = os.environ['CONSENT_HMAC_KEY'].encode()
assert len(KEY) >= 32, 'CONSENT_HMAC_KEY too short'
MAIL_VERSION = 'mail-v2-20261106'
REVENUE_DB = os.environ['REVENUE_DB_URL']   # role may only INSERT/SELECT(few cols) node_provider_eligibility
CLICKS_DB = os.environ['CLICKS_DB_URL']     # own database, audit log of every request
PROVIDER, TIERS = 'gpuserverhub', ['eu', 'global']
TOKEN = re.compile(r'^v1\.(acct_[A-Za-z0-9_-]{8,64})\.([0-9a-f]{12})\.([0-9a-z]{1,10})\.([A-Za-z0-9_-]{22})$')


def sign(payload):
    return base64.urlsafe_b64encode(hmac.new(KEY, payload.encode(), hashlib.sha256).digest()).decode()[:22]


def verify(tok):
    m = TOKEN.match(tok or '')
    if not m:
        return None
    acct, tid, exp, sig = m.groups()
    if not hmac.compare_digest(sig, sign(f'v1.{acct}.{tid}.{exp}')):
        return None
    if int(exp, 36) < time.time():
        return 'expired'
    return acct, tid


def connect(url, timeout=5):
    return psycopg.connect(url, connect_timeout=timeout, prepare_threshold=None, autocommit=True,
                           options='-c statement_timeout=5000')


def log_click(method, tid, acct, ip, ua, result, lang, signals=''):
    try:
        with connect(CLICKS_DB, timeout=2) as c:
            c.execute('INSERT INTO clicks (method, tid, account_id, ip, ua, result, lang, signals) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                      (method, tid, acct, ip, ua, result, lang, signals))
    except Exception as e:  # the audit log must never block the consent itself
        print('click log failed:', type(e).__name__, flush=True)


def record(acct, tid, ip, ua, signals):
    """Returns 'recorded', 'already' or 'inactive' (a withdrawn consent or an active objection exists: left for a human)."""
    now = datetime.now(timezone.utc)
    evidence = (f'one-click consent link (consent.decisionmodels.io, katowice-consent-oneclick-20261106, {MAIL_VERSION}) '
                f'tid={tid} clicked={now.isoformat(timespec="seconds")} ip={ip} signals={signals[:80]} ua={ua[:200]}')
    with connect(REVENUE_DB) as c:
        # An active objection beats any consent in the gateway: never claim "recorded" then.
        if c.execute("SELECT 1 FROM node_provider_eligibility WHERE account_id=%s AND provider=%s AND kind='objection' AND active",
                     (acct, PROVIDER)).fetchone():
            return 'inactive'
        row = c.execute(
            'INSERT INTO node_provider_eligibility (account_id, provider, kind, tiers, eligible_from, active, evidence) '
            "VALUES (%s, %s, 'consent', %s, now(), true, %s) ON CONFLICT (account_id, provider, kind) DO NOTHING "
            'RETURNING account_id', (acct, PROVIDER, TIERS, evidence)).fetchone()
        if row:
            return 'recorded'
        prev = c.execute("SELECT active FROM node_provider_eligibility WHERE account_id=%s AND provider=%s AND kind='consent'",
                         (acct, PROVIDER)).fetchone()
        return 'already' if prev and prev[0] else 'inactive'


TEXT = {
    'en': {
        'title': 'Decision Models',
        'pending': 'Recording your consent …',
        'ok_h': 'Thank you, your consent is recorded',
        'ok': ('Decision Models may now also serve the API requests of your account from our EU GPU servers in Katowice, '
               'Poland (GPU Server Hub). Nothing else changes: the same data rules apply, request and response content is '
               'not stored, and your keys, prices and limits stay the same.'),
        'already': 'Your consent was already recorded. Nothing else to do.',
        'inactive': 'We have your click. Because of an earlier choice on your account, nothing changes yet: we will contact you by email before anything changes.',
        'proof': 'As proof we record the time, IP address and browser of this confirmation.',
        'withdraw': ('You can withdraw this at any time: reply to our email or write to '
                     '<a href="mailto:info@decisionmodels.io">info@decisionmodels.io</a>. Your right to object to the '
                     'sub-processor is not affected. Details: <a href="https://decisionmodels.io/legal/subprocessors">'
                     'decisionmodels.io/legal/subprocessors</a>.'),
        'bad_h': 'This link is not valid',
        'bad': ('The link is incomplete or has expired. If you would like to agree, simply reply to our email or write to '
                '<a href="mailto:info@decisionmodels.io">info@decisionmodels.io</a>.'),
        'err_h': 'Something went wrong',
        'err': ('Your consent could not be saved just now. Please try the button again in a minute, or reply to our email.'),
        'button': 'Confirm consent',
        'noscript': 'Please press the button to confirm:',
    },
    'de': {
        'title': 'Decision Models',
        'pending': 'Ihre Zustimmung wird gespeichert …',
        'ok_h': 'Danke, Ihre Zustimmung ist gespeichert',
        'ok': ('Decision Models darf die API-Anfragen Ihres Kontos ab jetzt auch auf unseren EU-GPU-Servern in Katowice, '
               'Polen (GPU Server Hub) verarbeiten. Sonst ändert sich nichts: Es gelten dieselben Datenregeln, Inhalte von '
               'Anfragen und Antworten werden nicht gespeichert, Ihre Schlüssel, Preise und Limits bleiben gleich.'),
        'already': 'Ihre Zustimmung war bereits gespeichert. Sie müssen nichts weiter tun.',
        'inactive': 'Wir haben Ihren Klick erhalten. Wegen einer früheren Entscheidung zu Ihrem Konto ändert sich noch nichts: Wir melden uns per E-Mail, bevor sich etwas ändert.',
        'proof': 'Als Nachweis speichern wir Zeitpunkt, IP-Adresse und Browser dieser Bestätigung.',
        'withdraw': ('Sie können das jederzeit widerrufen: Antworten Sie einfach auf unsere E-Mail oder schreiben Sie an '
                     '<a href="mailto:info@decisionmodels.io">info@decisionmodels.io</a>. Ihr Widerspruchsrecht gegen den '
                     'Unterauftragsverarbeiter bleibt unberührt. Details: <a href="https://decisionmodels.io/legal/subprocessors">'
                     'decisionmodels.io/legal/subprocessors</a>.'),
        'bad_h': 'Dieser Link ist nicht gültig',
        'bad': ('Der Link ist unvollständig oder abgelaufen. Wenn Sie zustimmen möchten, antworten Sie einfach auf unsere '
                'E-Mail oder schreiben Sie an <a href="mailto:info@decisionmodels.io">info@decisionmodels.io</a>.'),
        'err_h': 'Da ist etwas schiefgegangen',
        'err': 'Ihre Zustimmung konnte gerade nicht gespeichert werden. Bitte versuchen Sie es in einer Minute erneut oder antworten Sie auf unsere E-Mail.',
        'button': 'Zustimmung bestätigen',
        'noscript': 'Bitte bestätigen Sie mit dem Button:',
    },
}

CSS = ('body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f5f7;color:#1d2330;margin:0}'
       'main{max-width:560px;margin:56px auto;background:#fff;border-radius:12px;padding:36px 32px;box-shadow:0 1px 4px #0001}'
       'h1{font-size:22px;margin:0 0 16px}p{line-height:1.55;font-size:16px}.brand{font-weight:600;color:#3b5bdb;margin-bottom:20px}'
       'button{background:#3b5bdb;color:#fff;border:0;border-radius:8px;padding:14px 28px;font-size:17px;cursor:pointer}'
       '.small{font-size:14px;color:#555}a{color:#3b5bdb}')


def result_html(t, result, at):
    if result in ('recorded', 'already', 'inactive'):
        if result == 'inactive':
            return f'<h1>{t["title"]}</h1><p>{t["inactive"]}</p>'
        extra = f'<p>{t["already"]}</p>' if result == 'already' else ''
        stamp = f'<p class="small">{at}. {t["proof"]}</p>' if result == 'recorded' else ''
        return f'<h1>{t["ok_h"]}</h1><p>{t["ok"]}</p>{extra}{stamp}<p class="small">{t["withdraw"]}</p>'
    if result in ('invalid', 'expired'):
        return f'<h1>{t["bad_h"]}</h1><p>{t["bad"]}</p>'
    return f'<h1>{t["err_h"]}</h1><p>{t["err"]}</p>'


def page(t, lang, inner, script=''):
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">'
            f'<title>{t["title"]}</title><style>{CSS}</style></head><body><main><div class="brand">Decision Models</div>'
            f'<div id="r">{inner}</div></main>{script}</body></html>')


_hits, _lock = {}, threading.Lock()


def limited(ip):
    now = int(time.time() // 60)
    with _lock:
        if len(_hits) > 5000:
            _hits.clear()
        k = (ip, now)
        _hits[k] = _hits.get(k, 0) + 1
        return _hits[k] > 30


class H(BaseHTTPRequestHandler):
    timeout = 10
    server_version = 'dm-consent'
    sys_version = ''

    def log_message(self, fmt, *args):  # no tokens or IPs in container logs
        pass

    def _send(self, code, body, ctype='text/html; charset=utf-8'):
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "
                         "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _ctx(self):
        path, _, query = self.path.partition('?')
        lang = 'de' if re.search(r'(^|&)l=de(&|$)', query) else 'en'
        ip = (self.headers.get('X-Real-Ip') or self.client_address[0])[:64]
        ua = (self.headers.get('User-Agent') or '')[:300]
        return path, lang, TEXT[lang], ip, ua

    def do_HEAD(self):
        self._send(200, '')

    def do_GET(self):
        path, lang, t, ip, ua = self._ctx()
        if path == '/healthz':
            return self._send(200, 'ok', 'text/plain')
        if not path.startswith('/k/'):
            return self._send(404, page(t, lang, f'<h1>{t["bad_h"]}</h1>'))
        if limited(ip):
            return self._send(429, page(t, lang, f'<h1>{t["err_h"]}</h1><p>{t["err"]}</p>'))
        tok = path[3:]
        v = verify(tok)
        if not isinstance(v, tuple):
            log_click('GET', None, None, ip, ua, v or 'invalid', lang)
            return self._send(200 if v == 'expired' else 404, page(t, lang, result_html(t, v or 'invalid', '')))
        log_click('GET', v[1], v[0], ip, ua, 'page', lang)
        action = html.escape(self.path, quote=True)
        inner = (f'<p id="p">{t["pending"]}</p><noscript><p>{t["noscript"]}</p>'
                 f'<form method="post" action="{action}"><button type="submit">{t["button"]}</button></form></noscript>')
        form = (f'<form method="post" action="{action}"><button type="submit">{t["button"]}</button></form>')
        script = ('<script>(function(){var t0=Date.now(),done=false,R=document.getElementById("r");'
                  'function go(why){if(done)return;done=true;'
                  'fetch(location.pathname+location.search,{method:"POST",headers:{"X-Consent":"1","X-Signals":why+";ms="+(Date.now()-t0)}})'
                  '.then(function(r){return r.json()}).then(function(j){R.innerHTML=j.html||' + json.dumps(f'<p>{t["err"]}</p>') + '})'
                  '.catch(function(){R.innerHTML=' + json.dumps(f'<p>{t["err"]}</p>') + '})}'
                  'if(navigator.webdriver){R.innerHTML=' + json.dumps(f'<p>{t["noscript"]}</p>' + form) + ';return}'
                  '["pointerdown","pointermove","touchstart","keydown","scroll","wheel"].forEach(function(e){'
                  'addEventListener(e,function(ev){if(ev.isTrusted)go("event:"+e)},{passive:true,once:true})});'
                  'setTimeout(function(){if(document.visibilityState==="visible")go("timer")},800)})()</script>')
        self._send(200, page(t, lang, inner, script))

    def do_POST(self):
        path, lang, t, ip, ua = self._ctx()
        is_js = self.headers.get('X-Consent') == '1'
        signals = ('js:' + (self.headers.get('X-Signals') or '')[:60]) if is_js else 'form'
        if not path.startswith('/k/') or limited(ip):
            inner = result_html(t, 'error', '')
            if is_js:
                return self._send(429, json.dumps({'result': 'error', 'html': inner}), 'application/json')
            return self._send(429, page(t, lang, inner))
        v = verify(path[3:])
        if not isinstance(v, tuple):
            result = v or 'invalid'
            log_click('POST', None, None, ip, ua, result, lang)
        else:
            try:
                result = record(v[0], v[1], ip, ua, signals)
            except Exception as e:
                print('record failed:', type(e).__name__, flush=True)
                result = 'error'
            log_click('POST-js' if is_js else 'POST-form', v[1], v[0], ip, ua, result, lang, signals)
        at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        inner = result_html(t, result, at)
        code = 500 if result == 'error' else 200
        if is_js:
            return self._send(code, json.dumps({'result': result, 'html': inner}), 'application/json')
        self._send(code, page(t, lang, inner))


def init_db():
    for attempt in range(10):
        try:
            with connect(CLICKS_DB) as c:
                c.execute('CREATE TABLE IF NOT EXISTS clicks (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), '
                          'method text, tid text, account_id text, ip text, ua text, result text, lang text)')
                c.execute('ALTER TABLE clicks ADD COLUMN IF NOT EXISTS signals text')
            return
        except Exception as e:
            print('init_db retry:', type(e).__name__, flush=True)
            time.sleep(3)


if __name__ == '__main__':
    init_db()
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8080'))), H).serve_forever()
