(() => {
  'use strict';

  const PKG = 'sitescanner';
  const VERSION = '5.1.0';
  const GLOBAL_KEY = `__kali_pkg_${PKG}`;

  const DEFAULTS = Object.freeze({
    proxy: '',
    ipApi: 'http://ip-api.com/json/',
    dnsApi: 'https://dns.google/resolve?name=',
    ipinfoApi: 'https://ipinfo.io/{ip}/json',
    crtshApi: 'https://crt.sh/?q=%25.{domain}&output=json',
    waybackApi: 'https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=10&filter=statuscode:200',
    rdapApi: 'https://rdap.org/domain/{domain}',
    bufferoverApi: 'https://dns.bufferover.run/dns?q=.{domain}',
    hackertargetApi: 'https://api.hackertarget.com/hostsearch/?q={domain}',
    sslinfoApi: 'https://api.hackertarget.com/sslinfo/?q={domain}',
    timeout: 12000,
    useBuiltinProxies: false,
    proxyAttempts: 0,
    useDirectFetch: false
  });

  const manifest = Object.freeze({
    name: PKG,
    version: VERSION,
    description: 'Professional passive OSINT, DNS, web, TLS and security-posture scanner with modular analysis commands.',
    author: 'Mobin Vaghar Jalaliyeh (Kali Light)',
    help: `${PKG} help`,
    official: false,
    default: false,
    securityLevel: 'low',
    permissions: Object.freeze({
      storage: 'none',
      cookies: 'none',
      network: 'required',
      filesystem: 'none'
    }),
    commands: Object.freeze([PKG]),
    dependencies: Object.freeze([]),
    entry: 'install'
  });

  const COMMAND = Object.freeze({
    name: PKG,
    description: manifest.description,
    usage: 'sitescanner [command] [args]',
    aliases: Object.freeze([]),
    kind: 'flow',
    begin: dispatch
  });

  const state = {
    api: null,
    installed: false,
    settings: { ...DEFAULTS },
    proxyList: [],
    customProxy: null,
    proxyReady: false
  };

  const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const safeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => escapeMap[char]);
  const line = (text, cls = 'output') => ({ type: 'line', html: `<span class="${cls}">${safeHtml(text)}</span>` });
  const spacer = () => ({ type: 'spacer' });
  const kv = (key, value, cls = 'output') => line(`${key}: ${value}`, cls);
  const section = title => [spacer(), line(title, 'accent')];
  const fail = message => [line(message, 'danger')];

  function createAbortController(timeoutMs) {
    const controller = new AbortController();
    const timeout = Math.max(1000, Number(timeoutMs) || DEFAULTS.timeout);
    const timer = setTimeout(() => controller.abort(), timeout);
    return { controller, timer };
  }

  function isValidProxyTemplate(template) {
    return typeof template === 'string' && template.trim().length > 0 && template.includes('{url}');
  }

  const runWithTimeout = async (url, options = {}) => {
    const { controller, timer } = createAbortController(state.settings.timeout);
    try {
      return await fetch(url, { ...options, signal: controller.signal, mode: 'cors' });
    } finally {
      clearTimeout(timer);
    }
  };

  const proxied = (template, url) => {
    if (!isValidProxyTemplate(template)) throw new Error('Invalid proxy template');
    return template.replace('{url}', encodeURIComponent(String(url)));
  };

  function getFreeUserProxy() {
    try {
      return window.__FreeUserProxy || globalThis.__FreeUserProxy || null;
    } catch {
      return null;
    }
  }

  async function testCustomProxy(proxyTemplate, testUrl = 'https://httpbin.org/get') {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const url = proxied(proxyTemplate, testUrl);
      const res = await fetch(url, {
        method: 'HEAD',
        signal: controller.signal,
        mode: 'cors'
      });
      clearTimeout(timeout);
      return res.ok;
    } catch {
      return false;
    }
  }

  async function prepareProxyList(forceRefresh = false) {
    if (!forceRefresh && state.proxyReady && state.proxyList.length > 0) {
      return state.proxyList;
    }

    const fup = getFreeUserProxy();
    if (!fup || typeof fup.getWorkingProxies !== 'function') {
      throw new Error('FreeUserProxy is not available. Please ensure https://LightKALi.github.io/FreeUserProxy.js is loaded.');
    }

    let working = [];
    try {
      working = fup.getWorkingProxies() || [];
    } catch {
      working = [];
    }

    if (!Array.isArray(working)) working = [];

    if (state.customProxy && typeof state.customProxy === 'string' && state.customProxy.includes('{url}')) {
      const customOk = await testCustomProxy(state.customProxy);
      if (customOk) {
        const exists = working.some(p => p.template === state.customProxy);
        if (!exists) {
          working.push({ name: 'custom', template: state.customProxy });
        }
      }
    }

    if (working.length === 0) {
      throw new Error('No working proxies available. Please check your connection or set a custom proxy using "sitescanner setproxy <template>" command.');
    }

    state.proxyList = working;
    state.proxyReady = true;
    return working;
  }

  let proxyIndex = 0;
  function getNextProxy() {
    if (state.proxyList.length === 0) {
      throw new Error('No proxy available. Call prepareProxyList first.');
    }
    const proxy = state.proxyList[proxyIndex % state.proxyList.length];
    proxyIndex = (proxyIndex + 1) % state.proxyList.length;
    return proxy;
  }

  function getRandomUserAgent() {
    const fup = getFreeUserProxy();
    if (fup && typeof fup.getRandomUserAgent === 'function') {
      return fup.getRandomUserAgent();
    }
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
  }

  async function fetchWithProxy(url, options = {}) {
    let proxies = state.proxyList;
    if (proxies.length === 0) {
      proxies = await prepareProxyList();
    }

    const finalOptions = {
      ...options,
      headers: {
        'User-Agent': getRandomUserAgent(),
        ...(options.headers || {})
      }
    };

    const maxAttempts = Math.min(proxies.length, 3);
    let lastError = null;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const proxy = proxies[attempt % proxies.length];
      try {
        const proxyUrl = proxied(proxy.template, url);
        const res = await runWithTimeout(proxyUrl, finalOptions);
        if (res.ok || res.status < 400) {
          return res;
        }
        if (res.status === 429) {
          await sleep(1000);
        }
      } catch (err) {
        lastError = err;
      }
    }

    throw new Error(`Fetch failed for ${url}${lastError ? `: ${lastError.message}` : ''}`);
  }

  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

  async function fetchText(url, options = {}) {
    const response = await fetchWithProxy(url, options);
    return readResponseText(response);
  }

  async function fetchJSON(url, options = {}) {
    const response = await fetchWithProxy(url, options);
    const text = await readResponseText(response);
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`Invalid JSON response from ${url}`);
    }
  }

  async function readResponseText(response) {
    if (!response) throw new Error('Empty response');
    const text = await response.text();
    if (!response.ok) throw new Error(`HTTP ${response.status}${text ? `: ${text.slice(0, 160)}` : ''}`);
    return text;
  }

  const normalizeHeaders = headers => {
    const source = headers && typeof headers === 'object' ? headers : {};
    const result = {};
    for (const [key, value] of Object.entries(source)) {
      result[String(key).toLowerCase()] = { key: String(key), value: String(value ?? '') };
    }
    return result;
  };

  const headerValue = (headers, name) => {
    const normalized = normalizeHeaders(headers);
    return normalized[String(name).toLowerCase()]?.value || '';
  };

  const hasHeader = (headers, name) => {
    const normalized = normalizeHeaders(headers);
    return Object.prototype.hasOwnProperty.call(normalized, String(name).toLowerCase());
  };

  const findHeader = (headers, pattern) => {
    const normalized = normalizeHeaders(headers);
    const regex = pattern instanceof RegExp ? pattern : new RegExp(`^${String(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i');
    return Object.keys(normalized).find(key => regex.test(key));
  };

  const DNS_TYPES = Object.freeze(['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA', 'SRV', 'CAA', 'NAPTR', 'DS', 'DNSKEY', 'PTR']);

  function normalizeHostname(hostname) {
    return String(hostname || '').trim().replace(/\.$/, '').toLowerCase();
  }

  function isValidHostname(hostname) {
    const value = normalizeHostname(hostname);
    if (!value || value.length > 253) return false;
    return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value);
  }

  async function resolveDNS(hostname, type = 'A') {
    const host = normalizeHostname(hostname);
    const recordType = String(type || 'A').toUpperCase();
    if (!host) throw new Error('Hostname is required');
    if (!DNS_TYPES.includes(recordType)) throw new Error(`Unsupported DNS type: ${recordType}`);
    const endpoint = `${state.settings.dnsApi}${encodeURIComponent(host)}&type=${encodeURIComponent(recordType)}`;
    const data = await fetchJSON(endpoint);
    return Array.isArray(data?.Answer) ? data.Answer.map(record => ({ type: record.type, data: record.data, TTL: record.TTL })) : [];
  }

  async function resolveIP(hostname) {
    const records = await resolveDNS(hostname, 'A');
    return records.map(record => record.data).filter(Boolean);
  }

  async function resolveIPv6(hostname) {
    const records = await resolveDNS(hostname, 'AAAA');
    return records.map(record => record.data).filter(Boolean);
  }

  async function resolvePTR(ip) {
    const value = String(ip || '').trim();
    const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Pattern.test(value)) return [];
    const parts = value.split('.').map(Number);
    if (parts.some(part => part < 0 || part > 255)) return [];
    const arpa = `${parts.reverse().join('.')}.in-addr.arpa`;
    const records = await resolveDNS(arpa, 'PTR');
    return records.map(record => record.data).filter(Boolean);
  }

  async function getIPInfoPrimary(ip) {
    const value = String(ip || '').trim();
    if (!value) return null;
    return fetchJSON(`${state.settings.ipApi}${encodeURIComponent(value)}`);
  }

  async function getIPInfoSecondary(ip) {
    const value = String(ip || '').trim();
    if (!value) return null;
    return fetchJSON(state.settings.ipinfoApi.replace('{ip}', encodeURIComponent(value)));
  }

  async function checkDNSBL(ip) {
    const value = String(ip || '').trim();
    const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Pattern.test(value)) return 'Unknown';
    const parts = value.split('.').map(Number);
    if (parts.some(part => part < 0 || part > 255)) return 'Unknown';
    const reversed = parts.reverse().join('.');
    const domain = `${reversed}.zen.spamhaus.org`;
    try {
      const data = await fetchJSON(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
      const listed = Array.isArray(data?.Answer) && data.Answer.some(record => String(record.data).startsWith('127.'));
      return listed ? 'Listed (Spamhaus ZEN)' : 'Not listed';
    } catch { return 'Unknown'; }
  }

  async function getSSLCert(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return null;
      const url = state.settings.crtshApi.replace('{domain}', encodeURIComponent(safeDomain));
      const data = await fetchJSON(url);
      const entries = Array.isArray(data) ? data.filter(Boolean) : [];
      if (!entries.length) return null;
      return [...entries].sort((a, b) => {
        const aTime = Date.parse(a?.entry_timestamp || a?.not_before || '') || Number(a?.id) || 0;
        const bTime = Date.parse(b?.entry_timestamp || b?.not_before || '') || Number(b?.id) || 0;
        return bTime - aTime;
      })[0] || null;
    } catch { return null; }
  }

  async function getSSLInfo(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return null;
      const text = await fetchText(state.settings.sslinfoApi.replace('{domain}', encodeURIComponent(safeDomain)));
      const rows = text.split(/\r?\n/).map(row => row.trim()).filter(Boolean);
      const info = {};
      for (const row of rows) {
        const separator = row.indexOf(':');
        if (separator <= 0) continue;
        const key = row.slice(0, separator).trim().toLowerCase();
        const value = row.slice(separator + 1).trim();
        if (key && value) info[key] = value;
      }
      return Object.keys(info).length ? info : null;
    } catch { return null; }
  }

  async function fetchWaybackCount(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return 0;
      const url = state.settings.waybackApi.replace('{domain}', encodeURIComponent(safeDomain));
      const data = await fetchJSON(url);
      return Array.isArray(data) ? data.length : 0;
    } catch { return 0; }
  }

  async function fetchRDAP(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return null;
      return await fetchJSON(state.settings.rdapApi.replace('{domain}', encodeURIComponent(safeDomain)));
    } catch { return null; }
  }

  function cleanHostname(value) {
    let host = String(value || '').trim().toLowerCase();
    if (!host) return null;
    host = host.replace(/^\*\.\s*/, '');
    try { if (host.includes('://')) host = new URL(host).hostname; } catch {}
    host = host.replace(/\.$/, '');
    return host || null;
  }

  function isSubdomainOf(hostname, domain) {
    const host = cleanHostname(hostname);
    const base = normalizeHostname(domain);
    if (!host || !base) return false;
    return host === base || host.endsWith(`.${base}`);
  }

  async function fetchSubdomainsFromBufferOver(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return [];
      const data = await fetchJSON(state.settings.bufferoverApi.replace('{domain}', encodeURIComponent(safeDomain)));
      const rows = Array.isArray(data?.FDNS_A) ? data.FDNS_A : [];
      return rows.map(entry => String(entry).split(',')[0].trim()).map(cleanHostname).filter(host => isSubdomainOf(host, safeDomain));
    } catch { return []; }
  }

  async function fetchSubdomainsFromHackerTarget(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return [];
      const text = await fetchText(state.settings.hackertargetApi.replace('{domain}', encodeURIComponent(safeDomain)));
      return text.split(/\r?\n/).map(row => row.trim()).filter(Boolean).map(row => row.split(',')[0]).map(cleanHostname).filter(host => isSubdomainOf(host, safeDomain));
    } catch { return []; }
  }

  function parseHTML(html, baseUrl = '') {
    const source = String(html || '');
    const doc = new DOMParser().parseFromString(source, 'text/html');
    const count = selector => doc.querySelectorAll(selector).length;
    const getMeta = name => doc.querySelector(`meta[name="${name}"]`)?.getAttribute('content') || '';
    const getMetaProperty = property => doc.querySelector(`meta[property="${property}"]`)?.getAttribute('content') || '';
    let base;
    try { base = new URL(baseUrl); } catch { base = null; }
    const resolveLink = raw => {
      const value = String(raw || '').trim();
      if (!value) return null;
      try {
        if (base) return new URL(value, base.href).href;
        return new URL(value).href;
      } catch { return value; }
    };
    const links = [...doc.querySelectorAll('a[href]')].map(a => resolveLink(a.getAttribute('href'))).filter(Boolean);
    const baseHostname = base?.hostname?.toLowerCase() || '';
    const internalLinks = links.filter(href => {
      try {
        const url = new URL(href);
        return baseHostname && url.hostname.toLowerCase() === baseHostname;
      } catch { return false; }
    });
    const externalLinks = links.filter(href => {
      try {
        const url = new URL(href);
        return !baseHostname || url.hostname.toLowerCase() !== baseHostname;
      } catch { return false; }
    });
    const doctype = doc.doctype?.name?.toLowerCase() || 'html';
    let htmlVersion = 'Unknown';
    if (doctype === 'html') htmlVersion = 'HTML5';
    else if (doctype.includes('html')) htmlVersion = 'HTML';
    else if (doctype.includes('xhtml')) htmlVersion = 'XHTML';
    else htmlVersion = doctype;
    return {
      title: doc.querySelector('title')?.textContent?.trim() || '(none)',
      metaDescription: getMeta('description'),
      metaKeywords: getMeta('keywords'),
      metaAuthor: getMeta('author'),
      metaGenerator: getMeta('generator'),
      canonical: doc.querySelector('link[rel="canonical"]')?.getAttribute('href') || '',
      charset: doc.characterSet || doc.querySelector('meta[charset]')?.getAttribute('charset') || '',
      lang: doc.documentElement?.getAttribute('lang') || '',
      htmlVersion,
      headings: { h1: count('h1'), h2: count('h2'), h3: count('h3'), h4: count('h4'), h5: count('h5'), h6: count('h6') },
      images: count('img'),
      links: links.length,
      internalLinks: internalLinks.length,
      externalLinks: externalLinks.length,
      scripts: count('script[src]'),
      inlineScripts: count('script:not([src])'),
      stylesheets: count('link[rel="stylesheet"]'),
      forms: count('form'),
      ogTitle: getMetaProperty('og:title'),
      ogDescription: getMetaProperty('og:description'),
      ogImage: getMetaProperty('og:image'),
      twitterCard: getMeta('twitter:card'),
      twitterTitle: getMeta('twitter:title'),
      twitterDescription: getMeta('twitter:description')
    };
  }

  function detectTech(headersObj, html) {
    const headers = normalizeHeaders(headersObj);
    const body = String(html || '').toLowerCase();
    const found = new Set();
    const add = (condition, value) => { if (condition) found.add(value); };
    add(hasHeader(headers, 'x-powered-by'), `X-Powered-By: ${headerValue(headers, 'x-powered-by')}`);
    add(hasHeader(headers, 'server'), `Server: ${headerValue(headers, 'server')}`);
    add(hasHeader(headers, 'x-aspnet-version'), 'ASP.NET');
    add(hasHeader(headers, 'x-generator'), `Generator: ${headerValue(headers, 'x-generator')}`);
    add(body.includes('wp-content'), 'WordPress');
    add(body.includes('drupal'), 'Drupal');
    add(body.includes('joomla'), 'Joomla');
    add(body.includes('shopify'), 'Shopify');
    add(body.includes('magento'), 'Magento');
    add(body.includes('squarespace'), 'Squarespace');
    add(body.includes('wix.com'), 'Wix');
    add(body.includes('jquery'), 'jQuery');
    add(body.includes('react'), 'React');
    add(body.includes('vue'), 'Vue.js');
    add(body.includes('angular'), 'Angular');
    add(body.includes('svelte'), 'Svelte');
    add(body.includes('bootstrap'), 'Bootstrap');
    add(body.includes('tailwind'), 'Tailwind CSS');
    add(body.includes('font-awesome'), 'Font Awesome');
    add(body.includes('moment.js'), 'Moment.js');
    add(body.includes('chart.js'), 'Chart.js');
    add(body.includes('three.js'), 'Three.js');
    add(body.includes('socket.io'), 'Socket.IO');
    add(body.includes('gsap'), 'GSAP');
    add(body.includes('lodash'), 'Lodash');
    add(body.includes('underscore.js'), 'Underscore.js');
    add(body.includes('d3.js'), 'D3.js');
    add(body.includes('highcharts'), 'Highcharts');
    add(body.includes('googletagmanager') || body.includes('gtag'), 'Google Analytics');
    add(body.includes('googlesyndication') || body.includes('adsbygoogle'), 'Google AdSense');
    add(body.includes('facebook.net') || body.includes('connect.facebook'), 'Facebook Pixel');
    add(body.includes('hotjar'), 'Hotjar');
    add(body.includes('intercom'), 'Intercom');
    add(body.includes('matomo'), 'Matomo');
    add(body.includes('mixpanel'), 'Mixpanel');
    add(body.includes('clarity.ms'), 'Microsoft Clarity');
    add(body.includes('doubleclick.net'), 'DoubleClick');
    add(body.includes('adroll'), 'AdRoll');
    add(hasHeader(headers, 'cf-ray'), 'Cloudflare');
    add(hasHeader(headers, 'x-amz-cf-id'), 'AWS CloudFront');
    add(hasHeader(headers, 'x-akamai-transformed'), 'Akamai');
    add(hasHeader(headers, 'x-served-by') && hasHeader(headers, 'x-cache'), 'Fastly');
    add(hasHeader(headers, 'x-cdn'), 'Generic CDN');
    add(body.includes('cloudflare'), 'Cloudflare (script)');
    add(body.includes('aws.amazon.com'), 'AWS');
    add(body.includes('recaptcha') || body.includes('grecaptcha'), 'reCAPTCHA');
    add(body.includes('hcaptcha'), 'hCaptcha');
    add(body.includes('stripe.com') || body.includes('js.stripe'), 'Stripe');
    add(body.includes('paypal.com') || body.includes('paypalobjects'), 'PayPal');
    add(body.includes('braintree'), 'Braintree');
    add(body.includes('squareup.com'), 'Square');
    add(body.includes('disqus'), 'Disqus');
    add(body.includes('zendesk'), 'Zendesk');
    add(body.includes('sentry.io'), 'Sentry');
    add(body.includes('statuspage.io'), 'StatusPage');
    return [...found].filter(Boolean).sort();
  }

  function detectWAF(headersObj, html) {
    const headers = normalizeHeaders(headersObj);
    const body = String(html || '').toLowerCase();
    const found = new Set();
    const add = (condition, name) => { if (condition) found.add(name); };
    add(hasHeader(headers, 'cf-ray') || body.includes('cf-browser-verification'), 'Cloudflare');
    add(hasHeader(headers, 'x-sucuri-id') || body.includes('sucuri/cloudproxy'), 'Sucuri');
    add(hasHeader(headers, 'x-iinfo'), 'Imperva/Incapsula');
    add(hasHeader(headers, 'x-amz-cf-id'), 'AWS WAF / CloudFront');
    add(hasHeader(headers, 'x-akamai-transformed'), 'Akamai');
    add(Boolean(findHeader(headers, /^x-f5-/i)), 'F5 BIG-IP');
    add(Boolean(findHeader(headers, /^x-fortigate-/i)), 'Fortinet');
    add(Boolean(findHeader(headers, /^x-barracuda-/i)), 'Barracuda');
    add(hasHeader(headers, 'x-cdn-request-id') && hasHeader(headers, 'x-iinfo'), 'Incapsula');
    add(body.includes('mod_security') || body.includes('modsecurity'), 'ModSecurity');
    add(body.includes('webknight'), 'WebKnight');
    add(body.includes('nsfocus'), 'NSFOCUS');
    add(body.includes('blocked by waf'), 'Generic WAF');
    add(hasHeader(headers, 'x-dwaf-request-id'), 'Distil WAF');
    return found.size ? [...found].sort() : ['None'];
  }

  function analyzeSecurityHeaders(headersObj) {
    const headers = normalizeHeaders(headersObj);
    const security = ['content-security-policy', 'content-security-policy-report-only', 'x-content-type-options', 'x-frame-options', 'strict-transport-security', 'referrer-policy', 'permissions-policy', 'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'x-xss-protection', 'x-download-options', 'x-permitted-cross-domain-policies', 'expect-ct', 'nel', 'report-to'];
    const result = {};
    for (const h of security) result[h] = hasHeader(headers, h) ? headerValue(headers, h) : 'missing';
    return result;
  }

  function analyzeCookieFlags(headersObj) {
    const normalized = normalizeHeaders(headersObj);
    const rawSetCookie = normalized['set-cookie']?.value || '';
    const cookies = Array.isArray(rawSetCookie) ? rawSetCookie : rawSetCookie ? [rawSetCookie] : [];
    const details = cookies.map(cookie => {
      const parts = String(cookie).split(';').map(part => part.trim()).filter(Boolean);
      if (!parts.length) return null;
      const first = parts.shift();
      const name = first.split('=')[0].trim();
      const attrs = {};
      for (const part of parts) {
        const separator = part.indexOf('=');
        if (separator === -1) { attrs[part.toLowerCase()] = true; continue; }
        const key = part.slice(0, separator).trim().toLowerCase();
        const value = part.slice(separator + 1).trim();
        attrs[key] = value || true;
      }
      const lower = String(cookie).toLowerCase();
      const sameSiteMatch = lower.match(/samesite\s*=\s*(strict|lax|none)/i);
      return {
        name: name || '(unknown)',
        secure: /\bsecure\b/i.test(lower),
        httpOnly: /\bhttponly\b/i.test(lower),
        sameSite: sameSiteMatch?.[1] ? sameSiteMatch[1].charAt(0).toUpperCase() + sameSiteMatch[1].slice(1).toLowerCase() : 'Missing',
        attrs
      };
    }).filter(Boolean);
    return {
      total: details.length,
      secure: details.length > 0 && details.every(cookie => cookie.secure),
      httpOnly: details.length > 0 && details.every(cookie => cookie.httpOnly),
      sameSite: details.length === 0 ? 'Unavailable' : details.every(cookie => cookie.sameSite === details[0].sameSite) ? details[0].sameSite : 'Mixed',
      details,
      unavailableInBrowser: !normalized['set-cookie']
    };
  }

  async function checkDNSSEC(domain) {
    try {
      const safeDomain = normalizeHostname(domain);
      if (!isValidHostname(safeDomain)) return false;
      const ds = await resolveDNS(safeDomain, 'DS');
      return ds.length > 0;
    } catch { return false; }
  }

  async function checkZoneTransfer(domain) {
    try {
      const text = await fetchText(`https://api.hackertarget.com/zonetransfer/?q=${domain}`);
      return text.trim() !== 'API access restricted' ? text : null;
    } catch { return null; }
  }

  async function fetchRobots(url) {
    try {
      return await fetchText(new URL('/robots.txt', url).href);
    } catch { return null; }
  }

  async function fetchSitemap(url) {
    try {
      return await fetchText(new URL('/sitemap.xml', url).href);
    } catch { return null; }
  }

  async function fetchSecurityTxt(url) {
    try {
      return await fetchText(new URL('/.well-known/security.txt', url).href);
    } catch {
      try {
        return await fetchText(new URL('/security.txt', url).href);
      } catch { return null; }
    }
  }

  async function fetchManifest(url) {
    try {
      return await fetchJSON(new URL('/manifest.json', url).href);
    } catch { return null; }
  }

  async function fullScan(rawUrl) {
    const scanStart = Date.now();
    const normalized = normalizeTarget(rawUrl);
    const normalizedUrl = normalized.href;
    const domain = normalizeHostname(normalized.hostname);
    const cache = new Map();
    const once = (key, factory) => {
      if (!cache.has(key)) cache.set(key, Promise.resolve().then(factory));
      return cache.get(key);
    };

    const getIPv4 = () => once('ipv4', () => resolveIP(domain).catch(() => []));
    const getIPv6 = () => once('ipv6', () => resolveIPv6(domain).catch(() => []));
    const getPrimaryIP = async () => {
      const ips = await getIPv4();
      return ips[0] || null;
    };

    const getMainPage = once('main-page', async () => {
      const started = Date.now();
      try {
        const response = await fetchWithProxy(normalizedUrl);
        const html = await response.text();
        const headersObj = {};
        response.headers.forEach((value, key) => {
          headersObj[String(key).toLowerCase()] = String(value);
        });
        return {
          ok: true,
          status: response.status,
          html,
          headersObj,
          finalUrl: response.url || normalizedUrl,
          responseTime: Date.now() - started,
          redirected: Boolean(response.redirected)
        };
      } catch (e) {
        return { ok: false, error: e?.message || 'Request failed', responseTime: Date.now() - started };
      }
    });

    const ipsPromise = getIPv4();
    const ipv6Promise = getIPv6();
    const primaryIPPromise = getPrimaryIP();
    const ptrPromise = primaryIPPromise.then(ip => ip ? resolvePTR(ip).catch(() => []) : []);
    const primaryInfoPromise = primaryIPPromise.then(ip => ip ? getIPInfoPrimary(ip).catch(() => null) : null);
    const secondaryInfoPromise = primaryIPPromise.then(ip => ip ? getIPInfoSecondary(ip).catch(() => null) : null);

    const dnsTypes = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA', 'SRV', 'CAA', 'NAPTR'];
    const dnsPromises = Object.fromEntries(dnsTypes.map(type => [type, once(`dns:${type}`, () => resolveDNS(domain, type).catch(() => []))]));

    const dnsSPFPromise = dnsPromises.TXT.then(records =>
      records.filter(record => String(record.data).toLowerCase().includes('v=spf1')).map(record => record.data)
    );
    const dnsDMARCPromise = once('dns:dmarc', () => resolveDNS(`_dmarc.${domain}`, 'TXT').catch(() => []))
      .then(records => records.filter(record => String(record.data).toUpperCase().startsWith('V=DMARC1')).map(record => record.data));
    const dnsDKIMPromise = once('dns:dkim', async () => {
      const selectors = ['google', 'default', 'mail', 'dkim', 'selector1', 'selector2'];
      const results = [];
      for (const selector of selectors) {
        try {
          const records = await resolveDNS(`${selector}._domainkey.${domain}`, 'TXT');
          for (const record of records) results.push({ selector, data: record.data });
        } catch {}
      }
      return results;
    });

    const dnssecPromise = checkDNSSEC(domain);
    const zoneTransferPromise = checkZoneTransfer(domain);

    const crtEntriesPromise = once('crt', async () => {
      try {
        const url = state.settings.crtshApi.replace('{domain}', encodeURIComponent(domain));
        const data = await fetchJSON(url);
        return Array.isArray(data) ? data : [];
      } catch { return []; }
    });

    const sslCertPromise = crtEntriesPromise.then(entries => {
      if (!entries.length) return null;
      const sorted = [...entries].filter(Boolean).sort((a, b) => {
        const aTime = Date.parse(a.entry_timestamp || a.not_before || '') || Number(a.id) || 0;
        const bTime = Date.parse(b.entry_timestamp || b.not_before || '') || Number(b.id) || 0;
        return bTime - aTime;
      });
      return sorted[0] || null;
    });

    const sslInfoPromise = getSSLInfo(domain);
    const waybackPromise = fetchWaybackCount(domain);
    const rdapPromise = fetchRDAP(domain);
    const bufferSubsPromise = fetchSubdomainsFromBufferOver(domain);
    const hackerSubsPromise = fetchSubdomainsFromHackerTarget(domain);
    const dnsblPromise = primaryIPPromise.then(ip => ip ? checkDNSBL(ip) : 'N/A');

    const [
      mainPage,
      ips,
      ipv6s,
      ptrRecords,
      ipInfoPrimary,
      ipInfoSecondary,
      dnsA,
      dnsAAAA,
      dnsMX,
      dnsNS,
      dnsCNAME,
      dnsTXT,
      dnsSOA,
      dnsSRV,
      dnsCAA,
      dnsNAPTR,
      dnsSPF,
      dnsDMARC,
      dnsDKIM,
      dnsbl,
      dnssec,
      zoneTransfer,
      crtEntries,
      sslCert,
      sslInfo,
      waybackCount,
      rdapData,
      bufferOverSubs,
      hackerTargetSubs
    ] = await Promise.all([
      getMainPage,
      ipsPromise,
      ipv6Promise,
      ptrPromise,
      primaryInfoPromise,
      secondaryInfoPromise,
      dnsPromises.A,
      dnsPromises.AAAA,
      dnsPromises.MX,
      dnsPromises.NS,
      dnsPromises.CNAME,
      dnsPromises.TXT,
      dnsPromises.SOA,
      dnsPromises.SRV,
      dnsPromises.CAA,
      dnsPromises.NAPTR,
      dnsSPFPromise,
      dnsDMARCPromise,
      dnsDKIMPromise,
      dnsblPromise,
      dnssecPromise,
      zoneTransferPromise,
      crtEntriesPromise,
      sslCertPromise,
      sslInfoPromise,
      waybackPromise,
      rdapPromise,
      bufferSubsPromise,
      hackerSubsPromise
    ]);

    const ipList = Array.isArray(ips) ? ips.filter(Boolean) : [];
    const ipv6List = Array.isArray(ipv6s) ? ipv6s.filter(Boolean) : [];
    const primaryIp = ipList[0] || 'N/A';
    const asn = ipInfoPrimary?.as || ipInfoPrimary?.asname || ipInfoSecondary?.org || 'N/A';

    const crtData = Array.isArray(crtEntries) ? crtEntries : [];
    const crtSubdomains = [...new Set(crtData.flatMap(entry => String(entry?.name_value || '').split(/\r?\n/)).map(cleanHostname).filter(Boolean).filter(host => isSubdomainOf(host, domain)))];
    const allSubdomains = [...new Set([...crtSubdomains, ...bufferOverSubs, ...hackerTargetSubs])].map(cleanHostname).filter(Boolean).filter(host => isSubdomainOf(host, domain)).sort();
    const relatedHostnames = [...new Set(crtData.map(entry => cleanHostname(entry?.common_name)).filter(Boolean).filter(host => isSubdomainOf(host, domain) || host === domain))].sort();

    const certificateDates = crtData.map(entry => {
      const value = entry?.entry_timestamp || entry?.not_before || '';
      const time = Date.parse(value);
      return Number.isFinite(time) ? time : null;
    }).filter(value => value !== null);
    const historicalFirst = certificateDates.length ? new Date(Math.min(...certificateDates)) : null;
    const historicalLast = certificateDates.length ? new Date(Math.max(...certificateDates)) : null;

    const abuseContact = ipInfoSecondary?.abuse?.email || 'N/A';
    const rdapInfo = rdapData ? {
      handle: rdapData.handle,
      name: rdapData.name,
      type: rdapData.type,
      status: rdapData.status,
      entities: rdapData.entities
    } : null;

    let html = '';
    let headersObj = {};
    let finalUrl = normalizedUrl;
    let status = 0;
    let targetError = null;
    if (mainPage.ok) {
      html = mainPage.html;
      headersObj = mainPage.headersObj;
      finalUrl = mainPage.finalUrl || normalizedUrl;
      status = mainPage.status;
    } else {
      targetError = mainPage.error;
    }

    const structure = parseHTML(html, finalUrl);
    const tech = detectTech(headersObj, html);
    const waf = detectWAF(headersObj, html);
    const secHeaders = analyzeSecurityHeaders(headersObj);
    const cookieFlags = analyzeCookieFlags(headersObj);
    const cors = {
      allowOrigin: headerValue(headersObj, 'access-control-allow-origin') || 'Not set',
      allowMethods: headerValue(headersObj, 'access-control-allow-methods') || 'Not set',
      allowHeaders: headerValue(headersObj, 'access-control-allow-headers') || 'Not set',
      allowCredentials: headerValue(headersObj, 'access-control-allow-credentials') || 'Not set'
    };

    const finalIsHTTPS = finalUrl.startsWith('https://');
    const redirectChain = mainPage.ok && finalUrl !== normalizedUrl ? [normalizedUrl, finalUrl] : [normalizedUrl];
    const scanTime = Date.now() - scanStart;

    const [robots, sitemap, securityTxt, webManifest] = await Promise.all([
      fetchRobots(normalizedUrl).catch(() => null),
      fetchSitemap(normalizedUrl).catch(() => null),
      fetchSecurityTxt(normalizedUrl).catch(() => null),
      fetchManifest(normalizedUrl).catch(() => null)
    ]);

    return {
      scanTime,
      target: {
        original: rawUrl,
        normalized: normalizedUrl,
        domain,
        finalUrl,
        status,
        redirectChain,
        redirectCount: Math.max(0, redirectChain.length - 1),
        responseTime: mainPage.responseTime,
        httpsSupport: finalIsHTTPS,
        requestedHTTPS: normalized.protocol === 'https:',
        redirected: Boolean(mainPage.redirected),
        fetchError: targetError
      },
      network: {
        ipv4: ipList,
        ipv6: ipv6List,
        ptr: ptrRecords,
        ipInfo: { primary: ipInfoPrimary, secondary: ipInfoSecondary },
        asn,
        isp: ipInfoPrimary?.isp || ipInfoPrimary?.org || ipInfoSecondary?.org || 'N/A',
        netblock: ipInfoSecondary?.asn?.route || ipInfoPrimary?.as || 'N/A',
        geolocation: ipInfoPrimary && ipInfoPrimary.status !== 'fail' ? {
          country: ipInfoPrimary.country,
          countryCode: ipInfoPrimary.countryCode,
          region: ipInfoPrimary.regionName,
          city: ipInfoPrimary.city,
          coordinates: `${ipInfoPrimary.lat},${ipInfoPrimary.lon}`
        } : null
      },
      dns: {
        A: dnsA,
        AAAA: dnsAAAA,
        MX: dnsMX,
        NS: dnsNS,
        CNAME: dnsCNAME,
        TXT: dnsTXT,
        SOA: dnsSOA,
        SRV: dnsSRV,
        CAA: dnsCAA,
        NAPTR: dnsNAPTR,
        SPF: dnsSPF,
        DMARC: dnsDMARC,
        DKIM: dnsDKIM.map(item => `${item.selector}: ${item.data}`)
      },
      domainOSINT: {
        certificate: sslCert,
        sslInfo,
        subdomains: allSubdomains,
        relatedHostnames,
        historical: { count: crtData.length, firstSeen: historicalFirst, lastSeen: historicalLast },
        waybackSnapshots: waybackCount,
        rdap: rdapInfo,
        zoneTransfer
      },
      web: {
        headers: headersObj,
        cookies: cookieFlags,
        robots,
        sitemap,
        securityTxt,
        manifest: webManifest,
        structure
      },
      technology: tech,
      security: {
        headers: secHeaders,
        tls: sslCert ? {
          issuer: sslCert.issuer_name,
          validFrom: sslCert.not_before,
          validUntil: sslCert.not_after,
          subject: sslCert.name_value,
          sha1: sslCert.sha1,
          sslInfo
        } : null,
        cors,
        waf,
        cookieFlags,
        dnssec,
        emailSecurity: {
          spf: dnsSPF.length > 0,
          dmarc: dnsDMARC.length > 0,
          dkim: dnsDKIM.length > 0
        }
      },
      reputation: { dnsbl, abuseContact },
      correlation: {
        domainToIP: primaryIp,
        ipToASN: asn,
        domainToCert: sslCert?.common_name || sslCert?.name_value || 'N/A',
        certToHostnames: sslCert?.name_value ? String(sslCert.name_value).split(/\r?\n/) : [],
        domainToTech: tech,
        ipToGeolocation: ipInfoPrimary && ipInfoPrimary.status !== 'fail' ? {
          country: ipInfoPrimary.country,
          city: ipInfoPrimary.city
        } : null,
        asnToNetblock: ipInfoSecondary?.asn?.route || ipInfoPrimary?.as || 'N/A'
      }
    };
  }

  function renderReport(data) {
    const out = [];
    const t = (text, cls = 'output') => out.push(line(text, cls));
    const s = () => out.push(spacer());

    out.push(line('╔══════════════════════════════════════════════════╗', 'accent'));
    out.push(line('║          SITESCANNER v5.1.0 REPORT              ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════════════╝', 'accent'));
    s();

    t('├── 🌍 TARGET', 'accent');
    t(`│   ├── URL normalization: ${data.target.normalized}`);
    t(`│   ├── Domain extraction: ${data.target.domain}`);
    t(`│   ├── IP resolution: ${data.network.ipv4.join(', ') || 'none'}`);
    t(`│   ├── Observed redirect path: ${data.target.redirectChain.join(' → ')}`);
    t(`│   ├── Redirects observed: ${data.target.redirectCount}`);
    t(`│   ├── Requested HTTPS: ${data.target.requestedHTTPS ? 'Yes' : 'No'}`);
    t(`│   ├── Final HTTPS: ${data.target.httpsSupport ? 'Yes' : 'No'}`);
    t(`│   ├── Final URL: ${data.target.finalUrl}`);
    t(`│   ├── HTTP status code: ${data.target.status}`);
    t(`│   ├── Response time: ${data.target.responseTime}ms`);
    t(`│   ├── Redirect flag: ${data.target.redirected ? 'Yes' : 'No'}`);
    if (data.target.fetchError) t(`│   └── Fetch error: ${data.target.fetchError}`, 'danger');
    s();

    t('├── 🌐 NETWORK INTELLIGENCE', 'accent');
    t(`│   ├── IPv4 addresses: ${data.network.ipv4.join(', ') || 'none'}`);
    t(`│   ├── IPv6 addresses: ${data.network.ipv6.join(', ') || 'none'}`);
    t(`│   ├── ASN: ${data.network.asn}`);
    t(`│   ├── ISP: ${data.network.isp}`);
    t(`│   ├── Organization: ${data.network.ipInfo.primary?.org || 'N/A'}`);
    t(`│   ├── Netblock / CIDR: ${data.network.netblock}`);
    t(`│   ├── Reverse DNS (PTR): ${data.network.ptr.join(', ') || 'none'}`);
    if (data.network.geolocation) {
      const g = data.network.geolocation;
      t(`│   ├── Geolocation:`);
      t(`│   │   ├── Country: ${g.country} (${g.countryCode})`);
      t(`│   │   ├── Region: ${g.region}`);
      t(`│   │   ├── City: ${g.city}`);
      t(`│   │   └── Coordinates: ${g.coordinates}`);
    }
    t(`│   ├── Hosting provider: ${data.network.ipInfo.primary?.isp || data.network.ipInfo.secondary?.org || 'N/A'}`);
    t(`│   ├── Abuse contact: ${data.reputation.abuseContact}`);
    t(`│   └── BGP prefix: ${data.network.netblock}`);
    s();

    t('├── 🧬 DNS INTELLIGENCE', 'accent');
    const dnsSection = (label, records) => {
      if (!records || !records.length) return;
      t(`│   ├── ${label} records:`);
      records.forEach(r => t(`│   │   └── ${r.type} (TTL ${r.TTL}): ${r.data}`));
    };
    dnsSection('A', data.dns.A);
    dnsSection('AAAA', data.dns.AAAA);
    dnsSection('MX', data.dns.MX);
    dnsSection('NS', data.dns.NS);
    dnsSection('CNAME', data.dns.CNAME);
    dnsSection('TXT', data.dns.TXT);
    dnsSection('SOA', data.dns.SOA);
    dnsSection('SRV', data.dns.SRV);
    dnsSection('CAA', data.dns.CAA);
    dnsSection('NAPTR', data.dns.NAPTR);
    t(`│   ├── SPF: ${data.dns.SPF.length ? data.dns.SPF.join('; ') : 'Not found'}`);
    t(`│   ├── DMARC: ${data.dns.DMARC.length ? data.dns.DMARC.join('; ') : 'Not found'}`);
    t(`│   ├── DKIM: ${data.dns.DKIM.length ? data.dns.DKIM.join('; ') : 'Not found'}`);
    t(`│   ├── DNSSEC (DS record): ${data.security.dnssec ? 'Enabled ✅' : 'Not confirmed ❌'}`);
    if (data.domainOSINT.zoneTransfer) {
      t(`│   └── Zone transfer: possible (see details below)`);
      data.domainOSINT.zoneTransfer.split('\n').slice(0, 5).forEach(l => t(`│       ${l}`));
    } else {
      t(`│   └── Zone transfer: not detected`);
    }
    s();

    t('├── 🔍 DOMAIN OSINT', 'accent');
    if (data.domainOSINT.certificate) {
      const cert = data.domainOSINT.certificate;
      t(`│   ├── Certificate Transparency:`);
      t(`│   │   ├── Issuer: ${cert.issuer_name || 'N/A'}`);
      t(`│   │   ├── Subject: ${cert.name_value || 'N/A'}`);
      t(`│   │   ├── Serial: ${cert.serial_number || 'N/A'}`);
      t(`│   │   ├── SHA-1: ${cert.sha1 || 'N/A'}`);
      const from = cert.not_before ? new Date(cert.not_before).toLocaleString() : '?';
      const until = cert.not_after ? new Date(cert.not_after).toLocaleString() : '?';
      t(`│   │   ├── Valid from: ${from}`);
      t(`│   │   └── Valid until: ${until}`);
    } else {
      t(`│   ├── Certificate Transparency: none found`);
    }
    if (data.domainOSINT.sslInfo) {
      const info = data.domainOSINT.sslInfo;
      t(`│   ├── TLS details:`);
      if (info['subject']) t(`│   │   ├── Subject: ${info['subject']}`);
      if (info['issuer']) t(`│   │   ├── Issuer: ${info['issuer']}`);
      if (info['valid from']) t(`│   │   ├── Valid from: ${info['valid from']}`);
      if (info['valid until']) t(`│   │   ├── Valid until: ${info['valid until']}`);
      if (info['protocol']) t(`│   │   ├── Protocol: ${info['protocol']}`);
      if (info['cipher']) t(`│   │   ├── Cipher: ${info['cipher']}`);
    }
    t(`│   ├── Subdomains discovered: ${data.domainOSINT.subdomains.length}`);
    if (data.domainOSINT.subdomains.length > 0) {
      data.domainOSINT.subdomains.slice(0, 20).forEach(s => t(`│   │   ├── ${s}`));
      if (data.domainOSINT.subdomains.length > 20) t(`│   │   └── ... +${data.domainOSINT.subdomains.length - 20} more`);
    }
    t(`│   ├── Related hostnames: ${data.domainOSINT.relatedHostnames.length}`);
    if (data.domainOSINT.relatedHostnames.length > 0) {
      data.domainOSINT.relatedHostnames.slice(0, 10).forEach(h => t(`│   │   ├── ${h}`));
    }
    t(`│   ├── Historical intelligence: ${data.domainOSINT.historical.count} cert records`);
    if (data.domainOSINT.historical.firstSeen) {
      t(`│   │   ├── First seen: ${data.domainOSINT.historical.firstSeen.toISOString()}`);
      t(`│   │   └── Last seen: ${data.domainOSINT.historical.lastSeen.toISOString()}`);
    }
    t(`│   ├── Wayback Machine snapshots: ${data.domainOSINT.waybackSnapshots}`);
    if (data.domainOSINT.rdap) {
      const rdap = data.domainOSINT.rdap;
      t(`│   ├── Whois (RDAP):`);
      if (rdap.name) t(`│   │   ├── Name: ${rdap.name}`);
      if (rdap.handle) t(`│   │   ├── Handle: ${rdap.handle}`);
      if (rdap.type) t(`│   │   ├── Type: ${rdap.type}`);
      if (rdap.status) t(`│   │   ├── Status: ${rdap.status.join(', ')}`);
    }
    t(`│   └── DNS history: (not directly available)`);
    s();

    t('├── 🌐 WEB INTELLIGENCE', 'accent');
    t(`│   ├── HTTP Headers: ${Object.keys(data.web.headers).length} headers`);
    const headerGroups = {
      'Security': ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'],
      'Caching': ['cache-control', 'etag', 'expires', 'last-modified', 'vary'],
      'CORS': ['access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-allow-credentials'],
      'Content': ['content-type', 'content-length', 'content-encoding'],
      'Server': ['server', 'x-powered-by', 'x-aspnet-version'],
      'Custom': Object.keys(data.web.headers).filter(h =>
        !['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'cache-control', 'etag', 'expires', 'last-modified', 'vary', 'access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-allow-credentials', 'content-type', 'content-length', 'content-encoding', 'server', 'x-powered-by', 'x-aspnet-version'].includes(h.toLowerCase())
      )
    };
    for (const [group, headers] of Object.entries(headerGroups)) {
      if (headers.length) {
        t(`│   │   ├── ${group}:`);
        headers.forEach(h => t(`│   │   │   ├── ${h}: ${data.web.headers[h] || data.web.headers[Object.keys(data.web.headers).find(k => k.toLowerCase() === h.toLowerCase())] || 'N/A'}`));
      }
    }
    t(`│   ├── Cookies observed: ${data.web.cookies.total}`);
    if (data.web.cookies.unavailableInBrowser) t(`│   │   └── Set-Cookie: unavailable to browser JavaScript`);
    if (data.web.cookies.details.length) {
      t(`│   │   ├── Aggregate flags: Secure=${data.web.cookies.secure ? 'Yes' : 'No'}, HttpOnly=${data.web.cookies.httpOnly ? 'Yes' : 'No'}, SameSite=${data.web.cookies.sameSite}`);
      data.web.cookies.details.forEach(c => {
        t(`│   │   ├── Cookie: ${c.name}`);
        for (const [k, v] of Object.entries(c.attrs)) t(`│   │   │   ├── ${k}: ${v}`);
      });
    }
    t(`│   ├── Redirects observed: ${data.target.redirectCount} (path: ${data.target.redirectChain.join(' → ')})`);
    t(`│   ├── HTML analysis:`);
    const st = data.web.structure;
    t(`│   │   ├── Title: ${st.title}`);
    t(`│   │   ├── Meta description: ${st.metaDescription || 'missing'}`);
    t(`│   │   ├── Meta keywords: ${st.metaKeywords || 'missing'}`);
    t(`│   │   ├── Open Graph: title=${st.ogTitle}, desc=${st.ogDescription}`);
    t(`│   │   ├── Twitter card: ${st.twitterCard || 'missing'}`);
    t(`│   │   ├── Canonical: ${st.canonical || 'missing'}`);
    t(`│   │   ├── Charset: ${st.charset || 'unknown'}`);
    t(`│   │   ├── Language: ${st.lang || 'unknown'}`);
    t(`│   │   └── HTML version: ${st.htmlVersion}`);
    t(`│   ├── Links: total=${st.links}, internal=${st.internalLinks}, external=${st.externalLinks}`);
    t(`│   ├── Forms: ${st.forms}`);
    t(`│   ├── Metadata: generator=${st.metaGenerator || 'none'}, author=${st.metaAuthor || 'none'}`);
    t(`│   ├── robots.txt: ${data.web.robots ? 'found' : 'not found'}`);
    if (data.web.robots) {
      const disallow = data.web.robots.split('\n').filter(l => l.toLowerCase().startsWith('disallow:')).map(l => l.split(':')[1].trim());
      if (disallow.length) {
        t(`│   │   ├── Disallowed paths:`);
        disallow.slice(0, 5).forEach(p => t(`│   │   │   ├── ${p}`));
      }
    }
    t(`│   ├── sitemap.xml: ${data.web.sitemap ? 'found' : 'not found'}`);
    t(`│   ├── security.txt: ${data.web.securityTxt ? 'found' : 'not found'}`);
    if (data.web.securityTxt) {
      const contact = data.web.securityTxt.split('\n').find(l => l.toLowerCase().startsWith('contact:'));
      if (contact) t(`│   │   ├── Contact: ${contact.split(':')[1].trim()}`);
    }
    t(`│   └── manifest: ${data.web.manifest ? 'found' : 'not found'}`);
    s();

    t('├── ⚙️ TECHNOLOGY', 'accent');
    if (data.technology.length) {
      const categories = {
        'CMS': ['WordPress', 'Drupal', 'Joomla', 'Shopify', 'Magento', 'Wix', 'Squarespace'],
        'Frameworks': ['React', 'Angular', 'Vue.js', 'Svelte', 'Next.js', 'Nuxt.js', 'Django', 'Laravel', 'Ruby on Rails', 'Express.js'],
        'JS libraries': ['jQuery', 'Bootstrap', 'Tailwind CSS', 'Font Awesome', 'Moment.js', 'Chart.js', 'Three.js', 'Socket.IO', 'GSAP', 'Lodash', 'Underscore.js', 'D3.js', 'Highcharts'],
        'CDN': ['Cloudflare', 'Akamai', 'AWS CloudFront', 'Fastly', 'Generic CDN'],
        'Analytics': ['Google Analytics', 'Google Tag Manager', 'Facebook Pixel', 'Hotjar', 'Intercom', 'Matomo', 'Mixpanel', 'Microsoft Clarity'],
        'Advertising': ['Google AdSense', 'DoubleClick', 'AdRoll'],
        'Captcha': ['reCAPTCHA', 'hCaptcha'],
        'Payment': ['Stripe', 'PayPal', 'Braintree', 'Square'],
        'Other': []
      };
      const detectedCategories = {};
      for (const tech of data.technology) {
        let placed = false;
        for (const [cat, items] of Object.entries(categories)) {
          if (items.some(i => tech.includes(i) || i.includes(tech))) {
            detectedCategories[cat] = detectedCategories[cat] || [];
            detectedCategories[cat].push(tech);
            placed = true;
            break;
          }
        }
        if (!placed) detectedCategories['Other'].push(tech);
      }
      for (const [cat, techs] of Object.entries(detectedCategories)) {
        if (techs.length) {
          t(`│   ├── ${cat}:`);
          techs.forEach(tech => t(`│   │   ├── ${tech}`));
        }
      }
      const confidence = data.technology.length > 8 ? 'High' : data.technology.length > 3 ? 'Medium' : 'Low';
      t(`│   └── Fingerprints + confidence: ${confidence} (${data.technology.length} found)`);
    } else {
      t(`│   └── No technologies detected`);
    }
    s();

    t('├── 🛡️ SECURITY POSTURE', 'accent');
    t(`│   ├── Security headers:`);
    Object.entries(data.security.headers).forEach(([h, v]) => {
      const icon = v === 'missing' ? '❌' : '✅';
      t(`│   │   ├── ${icon} ${h}: ${v === 'missing' ? 'missing' : 'present'}`);
    });
    t(`│   ├── TLS / SSL:`);
    if (data.security.tls) {
      t(`│   │   ├── Certificate validity: valid`);
      t(`│   │   ├── Issuer: ${data.security.tls.issuer}`);
      t(`│   │   ├── Subject: ${data.security.tls.subject}`);
      if (data.security.tls.sslInfo) {
        if (data.security.tls.sslInfo['algorithm']) t(`│   │   ├── Algorithm: ${data.security.tls.sslInfo['algorithm']}`);
        if (data.security.tls.sslInfo['key size']) t(`│   │   ├── Key size: ${data.security.tls.sslInfo['key size']}`);
        if (data.security.tls.sslInfo['protocol']) t(`│   │   ├── TLS version: ${data.security.tls.sslInfo['protocol']}`);
        if (data.security.tls.sslInfo['cipher']) t(`│   │   ├── Cipher suite: ${data.security.tls.sslInfo['cipher']}`);
      }
    } else {
      t(`│   │   └── No certificate found`);
    }
    t(`│   ├── CORS:`);
    t(`│   │   ├── Allow-Origin: ${data.security.cors.allowOrigin}`);
    t(`│   │   ├── Allow-Methods: ${data.security.cors.allowMethods}`);
    t(`│   │   ├── Allow-Headers: ${data.security.cors.allowHeaders}`);
    t(`│   │   └── Allow-Credentials: ${data.security.cors.allowCredentials}`);
    t(`│   ├── WAF: ${data.security.waf.join(', ')}`);
    if (data.security.cookieFlags.unavailableInBrowser) t('│   ├── Cookie flags: unavailable to browser JavaScript');
    else t(`│   ├── Cookie flags: Secure=${data.security.cookieFlags.secure ? 'Yes' : 'No'}, HttpOnly=${data.security.cookieFlags.httpOnly ? 'Yes' : 'No'}, SameSite=${data.security.cookieFlags.sameSite}`);
    t(`│   ├── DNS security:`);
    t(`│   │   ├── DNSSEC (DS record): ${data.security.dnssec ? 'Present' : 'Not confirmed'}`);
    t(`│   │   ├── SPF: ${data.security.emailSecurity.spf ? 'Present' : 'Missing'}`);
    t(`│   │   ├── DMARC: ${data.security.emailSecurity.dmarc ? 'Present' : 'Missing'}`);
    t(`│   │   └── DKIM: ${data.security.emailSecurity.dkim ? 'Present' : 'Missing'}`);
    t(`│   └── Email security summary: ${data.security.emailSecurity.spf && data.security.emailSecurity.dmarc && data.security.emailSecurity.dkim ? 'Strong' : 'Weak'}`);
    s();

    t('├── 📊 REPUTATION', 'accent');
    t(`│   ├── DNSBL (Spamhaus ZEN): ${data.reputation.dnsbl}`);
    t(`│   ├── Public reputation: (not directly available)`);
    t(`│   ├── Abuse metadata:`);
    t(`│   │   ├── Abuse contact email: ${data.reputation.abuseContact}`);
    t(`│   │   └── Abuse contact phone: N/A`);
    t(`│   └── Blacklist status: (only Spamhaus checked)`);
    s();

    t('├── 🔗 CORRELATION', 'accent');
    t(`│   ├── Domain → IP: ${data.correlation.domainToIP}`);
    t(`│   ├── IP → ASN: ${data.correlation.ipToASN}`);
    t(`│   ├── Domain → Certificate: ${data.correlation.domainToCert}`);
    t(`│   ├── Certificate → Hostnames: ${data.correlation.certToHostnames.join(', ') || 'N/A'}`);
    t(`│   ├── Domain → Technologies: ${data.correlation.domainToTech.join(', ') || 'none'}`);
    if (data.correlation.ipToGeolocation) t(`│   ├── IP → Geolocation: ${data.correlation.ipToGeolocation.country}, ${data.correlation.ipToGeolocation.city}`);
    t(`│   ├── ASN → Netblock: ${data.correlation.asnToNetblock}`);
    t(`│   └── Infrastructure graph:`);
    t(`│       ├── Domain nodes: ${data.target.domain}`);
    t(`│       ├── IP nodes: ${data.network.ipv4.join(', ') || 'none'}`);
    t(`│       ├── ASN nodes: ${data.correlation.ipToASN}`);
    t(`│       └── Certificate nodes: ${data.correlation.domainToCert}`);
    s();

    t(`╰── ⏱ Scan completed in ${data.scanTime}ms`, 'muted');
    return out;
  }

  function normalizeTarget(rawUrl) {
    let value = String(rawUrl ?? '').trim();
    if (!value) throw new Error('URL is required');
    try { return new URL(value); } catch {
      value = `https://${value}`;
      try { return new URL(value); } catch { throw new Error('Invalid URL'); }
    }
  }

  async function fetchMainPage(rawUrl) {
    const target = normalizeTarget(rawUrl);
    const started = Date.now();
    const response = await fetchWithProxy(target.href);
    const html = await response.text();
    const headersObj = {};
    response.headers.forEach((value, key) => {
      headersObj[String(key).toLowerCase()] = String(value);
    });
    return {
      target,
      response,
      html,
      headersObj,
      finalUrl: response.url || target.href,
      status: response.status,
      responseTime: Date.now() - started,
      redirected: Boolean(response.redirected)
    };
  }

  function outputTitle(title, value = '') {
    const out = [
      line('╭──────────────────────────────────────────╮', 'accent'),
      line(`│ ${title}`, 'accent'),
      line('╰──────────────────────────────────────────╯', 'accent'),
      spacer()
    ];
    if (value) out.push(line(value));
    return out;
  }

  function printRecords(out, label, records) {
    if (!records?.length) { out.push(line(`${label}: none`)); return; }
    out.push(line(`${label}:`));
    records.forEach(r => out.push(line(`  ${r.type ?? ''}${r.TTL != null ? ` (TTL ${r.TTL})` : ''}: ${r.data ?? r}`)));
  }

  function getDomain(rawUrl) {
    const url = normalizeTarget(rawUrl);
    const hostname = normalizeHostname(url.hostname);
    if (!isValidHostname(hostname)) throw new Error(`Invalid hostname: ${hostname}`);
    return hostname;
  }

  async function getPrimaryIP(rawUrl) {
    const domain = getDomain(rawUrl);
    const ips = await resolveIP(domain).catch(() => []);
    return ips[0] || null;
  }

  async function cmdTarget({ args }) {
    if (!args[1]) return fail('Usage: sitescanner target <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const original = data.target.href;
      const finalUrl = data.finalUrl || original;
      const observedPath = finalUrl !== original ? [original, finalUrl] : [original];
      return [
        ...outputTitle('SITESCANNER · TARGET'),
        kv('Original', args[1]),
        kv('Normalized', original),
        kv('Domain', data.target.hostname),
        kv('Final URL', finalUrl),
        kv('HTTP status', data.status),
        kv('Requested HTTPS', data.target.protocol === 'https:' ? 'Yes' : 'No'),
        kv('Final HTTPS', finalUrl.startsWith('https://') ? 'Yes' : 'No'),
        kv('Redirect observed', data.redirected ? 'Yes' : 'No'),
        kv('Response time', `${data.responseTime}ms`),
        kv('Observed path', observedPath.join(' → '))
      ];
    } catch (e) {
      return fail(`Target check failed: ${e.message}`);
    }
  }

  async function cmdHeaders({ args }) {
    if (!args[1]) return fail('Usage: sitescanner headers <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const out = [
        ...outputTitle('SITESCANNER · HEADERS'),
        kv('URL', data.finalUrl),
        kv('Status', data.status),
        kv('Header count', Object.keys(data.headersObj).length)
      ];
      Object.entries(data.headersObj).sort(([a], [b]) => a.localeCompare(b))
        .forEach(([key, value]) => out.push(line(`${key}: ${value}`)));
      return out;
    } catch (e) {
      return fail(`Headers check failed: ${e.message}`);
    }
  }

  async function cmdHtml({ args }) {
    if (!args[1]) return fail('Usage: sitescanner html <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const structure = parseHTML(data.html, data.finalUrl);
      return [
        ...outputTitle('SITESCANNER · HTML'),
        kv('Title', structure.title),
        kv('Description', structure.metaDescription || 'missing'),
        kv('Keywords', structure.metaKeywords || 'missing'),
        kv('Author', structure.metaAuthor || 'missing'),
        kv('Generator', structure.metaGenerator || 'missing'),
        kv('Canonical', structure.canonical || 'missing'),
        kv('Charset', structure.charset || 'unknown'),
        kv('Language', structure.lang || 'unknown'),
        kv('HTML version', structure.htmlVersion),
        kv('H1', structure.headings.h1),
        kv('H2', structure.headings.h2),
        kv('H3', structure.headings.h3),
        kv('H4', structure.headings.h4),
        kv('H5', structure.headings.h5),
        kv('H6', structure.headings.h6),
        kv('Images', structure.images),
        kv('Scripts', structure.scripts),
        kv('Inline scripts', structure.inlineScripts),
        kv('Stylesheets', structure.stylesheets),
        kv('Forms', structure.forms),
        kv('OpenGraph title', structure.ogTitle || 'missing'),
        kv('OpenGraph description', structure.ogDescription || 'missing'),
        kv('Twitter card', structure.twitterCard || 'missing')
      ];
    } catch (e) {
      return fail(`HTML analysis failed: ${e.message}`);
    }
  }

  async function cmdLinks({ args }) {
    if (!args[1]) return fail('Usage: sitescanner links <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const structure = parseHTML(data.html, data.finalUrl);
      return [
        ...outputTitle('SITESCANNER · LINKS'),
        kv('Total links', structure.links),
        kv('Internal links', structure.internalLinks),
        kv('External links', structure.externalLinks),
        kv('Forms', structure.forms),
        kv('Images', structure.images),
        kv('Scripts', structure.scripts),
        kv('Stylesheets', structure.stylesheets),
        line('No crawling performed; only the supplied page was analyzed.', 'muted')
      ];
    } catch (e) {
      return fail(`Links analysis failed: ${e.message}`);
    }
  }

  async function cmdTech({ args }) {
    if (!args[1]) return fail('Usage: sitescanner tech <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const tech = detectTech(data.headersObj, data.html);
      const out = [
        ...outputTitle('SITESCANNER · TECHNOLOGY'),
        kv('Detected', tech.length)
      ];
      if (!tech.length) out.push(line('No technologies detected.'));
      else tech.forEach(item => out.push(line(`• ${item}`)));
      return out;
    } catch (e) {
      return fail(`Technology detection failed: ${e.message}`);
    }
  }

  async function cmdWaf({ args }) {
    if (!args[1]) return fail('Usage: sitescanner waf <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const waf = detectWAF(data.headersObj, data.html);
      return [
        ...outputTitle('SITESCANNER · WAF'),
        kv('Detection', waf.join(', '))
      ];
    } catch (e) {
      return fail(`WAF detection failed: ${e.message}`);
    }
  }

  async function cmdSecurity({ args }) {
    if (!args[1]) return fail('Usage: sitescanner security <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const result = analyzeSecurityHeaders(data.headersObj);
      const out = [
        ...outputTitle('SITESCANNER · SECURITY HEADERS')
      ];
      Object.entries(result).forEach(([key, value]) =>
        out.push(line(`${value === 'missing' ? '❌' : '✅'} ${key}: ${value}`))
      );
      return out;
    } catch (e) {
      return fail(`Security analysis failed: ${e.message}`);
    }
  }

  async function cmdCookies({ args }) {
    if (!args[1]) return fail('Usage: sitescanner cookies <url>');
    try {
      const data = await fetchMainPage(args[1]);
      const cookies = analyzeCookieFlags(data.headersObj);
      const out = [
        ...outputTitle('SITESCANNER · COOKIES'),
        kv('Total', cookies.total),
        kv('Secure', cookies.secure ? 'Yes' : 'No'),
        kv('HttpOnly', cookies.httpOnly ? 'Yes' : 'No'),
        kv('SameSite', cookies.sameSite)
      ];
      if (cookies.details.length) {
        out.push(spacer(), line('Cookie details:', 'accent'));
        cookies.details.forEach(cookie => {
          out.push(line(`• ${cookie.name}`));
          Object.entries(cookie.attrs).forEach(([key, value]) => out.push(line(`  ${key}: ${value}`)));
        });
      }
      return out;
    } catch (e) {
      return fail(`Cookie analysis failed: ${e.message}`);
    }
  }

  async function cmdNetwork({ args }) {
    if (!args[1]) return fail('Usage: sitescanner network <url>');
    try {
      const domain = getDomain(args[1]);
      const ipv4 = await resolveIP(domain).catch(() => []);
      const ipv6Promise = resolveIPv6(domain).catch(() => []);
      const primaryIp = ipv4[0] || null;
      const [ipv6, ptr, primary, secondary] = await Promise.all([
        ipv6Promise,
        primaryIp ? resolvePTR(primaryIp).catch(() => []) : Promise.resolve([]),
        primaryIp ? getIPInfoPrimary(primaryIp).catch(() => null) : Promise.resolve(null),
        primaryIp ? getIPInfoSecondary(primaryIp).catch(() => null) : Promise.resolve(null)
      ]);
      const geo = primary?.status === 'success' ? [primary.country, primary.regionName, primary.city].filter(Boolean).join(', ') || 'N/A' : 'N/A';
      return [
        ...outputTitle('SITESCANNER · NETWORK'),
        kv('Domain', domain),
        kv('IPv4', ipv4.join(', ') || 'none'),
        kv('IPv6', ipv6.join(', ') || 'none'),
        kv('PTR', ptr.join(', ') || 'none'),
        kv('ASN', primary?.as || primary?.asname || secondary?.org || 'N/A'),
        kv('ISP', primary?.isp || primary?.org || secondary?.org || 'N/A'),
        kv('Netblock', secondary?.asn?.route || primary?.as || 'N/A'),
        kv('Geolocation', geo),
        kv('Abuse contact', secondary?.abuse?.email || 'N/A')
      ];
    } catch (e) {
      return fail(`Network analysis failed: ${e.message}`);
    }
  }

  async function cmdDNS({ args }) {
    if (!args[1]) return fail('Usage: sitescanner dns <url> [type]');
    const type = String(args[2] || 'A').toUpperCase();
    const allowed = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA', 'SRV', 'CAA', 'NAPTR', 'DS', 'DNSKEY', 'PTR'];
    if (!allowed.includes(type)) return fail(`Unsupported DNS type: ${type}. Allowed: ${allowed.join(', ')}`);
    try {
      const domain = getDomain(args[1]);
      const records = await resolveDNS(domain, type);
      const out = [
        ...outputTitle(`SITESCANNER · DNS ${type}`),
        kv('Domain', domain),
        kv('Type', type)
      ];
      printRecords(out, 'Records', records);
      return out;
    } catch (e) {
      return fail(`DNS query failed: ${e.message}`);
    }
  }

  async function cmdDNSSEC({ args }) {
    if (!args[1]) return fail('Usage: sitescanner dnssec <url>');
    try {
      const domain = getDomain(args[1]);
      const enabled = await checkDNSSEC(domain);
      return [
        ...outputTitle('SITESCANNER · DNSSEC'),
        kv('Domain', domain),
        kv('DNSSEC', enabled ? 'Enabled' : 'Disabled')
      ];
    } catch (e) {
      return fail(`DNSSEC check failed: ${e.message}`);
    }
  }

  async function cmdEmail({ args }) {
    if (!args[1]) return fail('Usage: sitescanner email <url>');
    try {
      const domain = getDomain(args[1]);
      const [txt, dmarc, dkim] = await Promise.all([
        resolveDNS(domain, 'TXT').catch(() => []),
        resolveDNS(`_dmarc.${domain}`, 'TXT').catch(() => []),
        (async () => {
          const selectors = ['google', 'default', 'mail', 'dkim', 'selector1', 'selector2'];
          const result = [];
          for (const selector of selectors) {
            try {
              const rows = await resolveDNS(`${selector}._domainkey.${domain}`, 'TXT');
              rows.forEach(r => result.push(`${selector}: ${r.data}`));
            } catch {}
          }
          return result;
        })()
      ]);
      const spf = txt.filter(r => String(r.data).includes('v=spf1')).map(r => r.data);
      const dmarcRows = dmarc.filter(r => String(r.data).startsWith('v=DMARC1')).map(r => r.data);
      return [
        ...outputTitle('SITESCANNER · EMAIL SECURITY'),
        kv('Domain', domain),
        kv('SPF', spf.length ? spf.join('; ') : 'Not found'),
        kv('DMARC', dmarcRows.length ? dmarcRows.join('; ') : 'Not found'),
        kv('DKIM', dkim.length ? dkim.join('; ') : 'Not found')
      ];
    } catch (e) {
      return fail(`Email security check failed: ${e.message}`);
    }
  }

  async function cmdSSL({ args }) {
    if (!args[1]) return fail('Usage: sitescanner ssl <url>');
    try {
      const domain = getDomain(args[1]);
      const [sslCert, sslInfo] = await Promise.all([
        getSSLCert(domain).catch(() => null),
        getSSLInfo(domain).catch(() => null)
      ]);
      const out = [
        ...outputTitle('SITESCANNER · SSL / TLS'),
        kv('Domain', domain)
      ];
      if (sslCert) {
        out.push(
          kv('Issuer', sslCert.issuer_name || 'N/A'),
          kv('Subject', sslCert.name_value || 'N/A'),
          kv('Valid from', sslCert.not_before || 'N/A'),
          kv('Valid until', sslCert.not_after || 'N/A'),
          kv('SHA-1', sslCert.sha1 || 'N/A')
        );
      } else {
        out.push(line('Certificate Transparency data not found.'));
      }
      if (sslInfo) {
        out.push(spacer(), line('TLS details:', 'accent'));
        Object.entries(sslInfo).forEach(([key, value]) => out.push(line(`${key}: ${value}`)));
      }
      return out;
    } catch (e) {
      return fail(`SSL analysis failed: ${e.message}`);
    }
  }

  async function cmdCert({ args }) {
    if (!args[1]) return fail('Usage: sitescanner cert <url>');
    try {
      const domain = getDomain(args[1]);
      const cert = await getSSLCert(domain).catch(() => null);
      if (!cert) return [...outputTitle('SITESCANNER · CERTIFICATE'), line('No certificate entry found.')];
      return [
        ...outputTitle('SITESCANNER · CERTIFICATE'),
        kv('Domain', domain),
        kv('Issuer', cert.issuer_name || 'N/A'),
        kv('Subject', cert.name_value || 'N/A'),
        kv('Serial', cert.serial_number || 'N/A'),
        kv('SHA-1', cert.sha1 || 'N/A'),
        kv('Valid from', cert.not_before || 'N/A'),
        kv('Valid until', cert.not_after || 'N/A'),
        kv('Common name', cert.common_name || 'N/A')
      ];
    } catch (e) {
      return fail(`Certificate lookup failed: ${e.message}`);
    }
  }

  async function cmdOSINT({ args }) {
    if (!args[1]) return fail('Usage: sitescanner osint <url>');
    try {
      const domain = getDomain(args[1]);
      const [cert, wayback, rdap] = await Promise.all([
        getSSLCert(domain).catch(() => null),
        fetchWaybackCount(domain),
        fetchRDAP(domain)
      ]);
      return [
        ...outputTitle('SITESCANNER · OSINT'),
        kv('Domain', domain),
        kv('Latest certificate', cert?.name_value || 'N/A'),
        kv('Certificate issuer', cert?.issuer_name || 'N/A'),
        kv('Wayback snapshots', wayback),
        kv('RDAP name', rdap?.name || 'N/A'),
        kv('RDAP handle', rdap?.handle || 'N/A'),
        kv('RDAP type', rdap?.type || 'N/A'),
        kv('RDAP status', Array.isArray(rdap?.status) ? rdap.status.join(', ') : 'N/A')
      ];
    } catch (e) {
      return fail(`OSINT check failed: ${e.message}`);
    }
  }

  async function cmdSubdomains({ args }) {
    if (!args[1]) return fail('Usage: sitescanner subdomains <url>');
    try {
      const domain = getDomain(args[1]);
      const [crtData, bufferOver, hackerTarget] = await Promise.all([
        fetchJSON(state.settings.crtshApi.replace('{domain}', encodeURIComponent(domain))).catch(() => []),
        fetchSubdomainsFromBufferOver(domain),
        fetchSubdomainsFromHackerTarget(domain)
      ]);
      const crtEntries = Array.isArray(crtData) ? crtData : [];
      const crtSubs = crtEntries.flatMap(entry => String(entry?.name_value || '').split(/\r?\n/))
        .map(cleanHostname).filter(Boolean).filter(host => isSubdomainOf(host, domain));
      const all = [...new Set([...crtSubs, ...bufferOver, ...hackerTarget])]
        .map(cleanHostname).filter(Boolean).filter(host => isSubdomainOf(host, domain)).sort();
      const out = [
        ...outputTitle('SITESCANNER · SUBDOMAINS'),
        kv('Domain', domain),
        kv('Certificate Transparency', crtSubs.length),
        kv('BufferOver', bufferOver.length),
        kv('HackerTarget', hackerTarget.length),
        kv('Unique discovered', all.length)
      ];
      if (!all.length) out.push(line('No passive subdomains found.'));
      else all.forEach(host => out.push(line(host)));
      return out;
    } catch (e) {
      return fail(`Subdomain enumeration failed: ${e.message}`);
    }
  }

  async function cmdRDAP({ args }) {
    if (!args[1]) return fail('Usage: sitescanner rdap <url>');
    try {
      const domain = getDomain(args[1]);
      const data = await fetchRDAP(domain);
      if (!data) return [...outputTitle('SITESCANNER · RDAP'), line('No RDAP data returned.')];
      const out = [
        ...outputTitle('SITESCANNER · RDAP'),
        kv('Domain', domain),
        kv('Handle', data.handle || 'N/A'),
        kv('Name', data.name || 'N/A'),
        kv('Type', data.type || 'N/A'),
        kv('Status', Array.isArray(data.status) ? data.status.join(', ') : 'N/A')
      ];
      if (Array.isArray(data.entities)) out.push(kv('Entities', data.entities.length));
      return out;
    } catch (e) {
      return fail(`RDAP lookup failed: ${e.message}`);
    }
  }

  async function cmdReputation({ args }) {
    if (!args[1]) return fail('Usage: sitescanner reputation <url>');
    try {
      const domain = getDomain(args[1]);
      const ip = await getPrimaryIP(args[1]);
      if (!ip) return [...outputTitle('SITESCANNER · REPUTATION'), kv('Domain', domain), kv('Primary IP', 'N/A'), kv('DNSBL', 'N/A')];
      const [dnsbl, secondary] = await Promise.all([
        checkDNSBL(ip),
        getIPInfoSecondary(ip).catch(() => null)
      ]);
      return [
        ...outputTitle('SITESCANNER · REPUTATION'),
        kv('Domain', domain),
        kv('Primary IP', ip),
        kv('DNSBL', dnsbl),
        kv('Abuse contact', secondary?.abuse?.email || 'N/A'),
        kv('Organization', secondary?.org || 'N/A')
      ];
    } catch (e) {
      return fail(`Reputation check failed: ${e.message}`);
    }
  }

  async function cmdScan({ args }) {
    if (!args[1]) return fail('Usage: sitescanner scan <url>');
    const url = args[1];
    try {
      const result = await fullScan(url);
      return renderReport(result);
    } catch (e) {
      return fail(`Scan failed: ${e.message}`);
    }
  }

  async function cmdSetProxy({ args }) {
    if (!args[1]) return fail('Usage: sitescanner setproxy <template>');
    const template = args[1].trim();
    if (!isValidProxyTemplate(template)) {
      return fail('Invalid proxy template. Must contain "{url}" placeholder.');
    }
    state.customProxy = template;
    state.proxyList = [];
    state.proxyReady = false;
    return [
      line('Custom proxy set successfully.', 'accent'),
      line(`Template: ${template}`, 'muted'),
      line('It will be tested and added to the working proxy list on next request.', 'muted')
    ];
  }

  async function dispatch({ args = [] }) {
    const cmd = String(args[0] ?? '').toLowerCase();

    if (!cmd) {
      return [
        line('╭──────────────────────────────────────────╮', 'accent'),
        line('│         SITESCANNER v5.1.0              │', 'accent'),
        line('╰──────────────────────────────────────────╯', 'accent'),
        spacer(),
        line('Available commands:', 'muted'),
        line('  sitescanner scan <url>'),
        line('  sitescanner target <url>'),
        line('  sitescanner headers <url>'),
        line('  sitescanner html <url>'),
        line('  sitescanner links <url>'),
        line('  sitescanner tech <url>'),
        line('  sitescanner waf <url>'),
        line('  sitescanner security <url>'),
        line('  sitescanner cookies <url>'),
        line('  sitescanner network <url>'),
        line('  sitescanner dns <url> [type]'),
        line('  sitescanner dnssec <url>'),
        line('  sitescanner email <url>'),
        line('  sitescanner ssl <url>'),
        line('  sitescanner cert <url>'),
        line('  sitescanner osint <url>'),
        line('  sitescanner subdomains <url>'),
        line('  sitescanner rdap <url>'),
        line('  sitescanner reputation <url>'),
        line('  sitescanner setproxy <template>'),
        line('  sitescanner help'),
        line('  sitescanner version')
      ];
    }

    if (cmd === 'help') {
      return [
        line('╭──────────────────────────────────────────╮', 'accent'),
        line('│         SITESCANNER v5.1.0              │', 'accent'),
        line('╰──────────────────────────────────────────╯', 'accent'),
        spacer(),
        line('FULL SCAN', 'accent'),
        line('  sitescanner scan <url>  — Full passive analysis across all available modules', 'muted'),
        spacer(),
        line('TARGET / WEB', 'accent'),
        line('  sitescanner target <url>  — Target URL, status, redirects and HTTPS', 'muted'),
        line('  sitescanner headers <url>  — HTTP response headers only', 'muted'),
        line('  sitescanner html <url>  — HTML structure and metadata analysis', 'muted'),
        line('  sitescanner links <url>  — Link and form counts from the page', 'muted'),
        spacer(),
        line('TECHNOLOGY / SECURITY', 'accent'),
        line('  sitescanner tech <url>  — Technology fingerprinting', 'muted'),
        line('  sitescanner waf <url>  — WAF detection', 'muted'),
        line('  sitescanner security <url>  — Security header analysis', 'muted'),
        line('  sitescanner cookies <url>  — Cookie security flags', 'muted'),
        spacer(),
        line('NETWORK / DNS', 'accent'),
        line('  sitescanner network <url>  — IPv4, IPv6, PTR, ASN and geolocation', 'muted'),
        line('  sitescanner dns <url> [type]  — Query one DNS record type', 'muted'),
        line('  sitescanner dnssec <url>  — DNSSEC status', 'muted'),
        line('  sitescanner email <url>  — SPF, DMARC and common DKIM selectors', 'muted'),
        spacer(),
        line('SSL / OSINT', 'accent'),
        line('  sitescanner ssl <url>  — TLS/SSL details', 'muted'),
        line('  sitescanner cert <url>  — Latest Certificate Transparency entry', 'muted'),
        line('  sitescanner osint <url>  — RDAP, Wayback and certificate OSINT', 'muted'),
        line('  sitescanner subdomains <url>  — Passive subdomain collection', 'muted'),
        line('  sitescanner rdap <url>  — RDAP domain information', 'muted'),
        line('  sitescanner reputation <url>  — DNSBL and abuse metadata', 'muted'),
        spacer(),
        line('PROXY MANAGEMENT', 'accent'),
        line('  sitescanner setproxy <template>  — Set custom proxy (must contain {url})', 'muted'),
        spacer(),
        line('Examples:', 'accent'),
        line('  sitescanner target example.com'),
        line('  sitescanner headers example.com'),
        line('  sitescanner dns example.com MX'),
        line('  sitescanner tech example.com'),
        line('  sitescanner security example.com'),
        line('  sitescanner subdomains example.com'),
        line('  sitescanner scan https://example.com'),
        line('  sitescanner setproxy https://myproxy.com/?url={url}')
      ];
    }

    if (cmd === 'version') {
      return [line(`SITESCANNER v${VERSION}`, 'accent'), line('Advanced OSINT & Security Web Scanner · Kali Light', 'muted')];
    }

    const handlers = {
      scan: cmdScan,
      target: cmdTarget,
      headers: cmdHeaders,
      html: cmdHtml,
      links: cmdLinks,
      tech: cmdTech,
      waf: cmdWaf,
      security: cmdSecurity,
      cookies: cmdCookies,
      network: cmdNetwork,
      dns: cmdDNS,
      dnssec: cmdDNSSEC,
      email: cmdEmail,
      ssl: cmdSSL,
      cert: cmdCert,
      osint: cmdOSINT,
      subdomains: cmdSubdomains,
      rdap: cmdRDAP,
      reputation: cmdReputation,
      setproxy: cmdSetProxy
    };

    const handler = handlers[cmd];
    if (!handler) return fail(`Unknown command: ${cmd}. Use "sitescanner help".`);

    try {
      if (cmd !== 'setproxy' && cmd !== 'help' && cmd !== 'version') {
        try {
          await prepareProxyList(false);
        } catch (e) {
          return fail(`Proxy error: ${e.message}`);
        }
      }
      return await handler({ args });
    } catch (e) {
      return fail(`Command failed: ${e.message}`);
    }
  }

  function validateApi(api) {
    if (!api || typeof api !== 'object') throw new Error('PACKAGE_BRIDGE_UNAVAILABLE');
    const required = ['registerCommand', 'unregisterCommand', 'line', 'spacer', 'snapshot', 'getMode'];
    for (const method of required) {
      if (typeof api[method] !== 'function') throw new Error(`PACKAGE_BRIDGE_${method.toUpperCase()}_UNAVAILABLE`);
    }
  }

  async function install(api) {
    validateApi(api);
    state.api = api;
    try {
      const registered = api.registerCommand(PKG, {
        description: COMMAND.description,
        usage: COMMAND.usage,
        aliases: COMMAND.aliases,
        kind: COMMAND.kind,
        begin: COMMAND.begin
      }, { source: 'package', packageKey: PKG });
      if (registered === false) throw new Error('PACKAGE_COMMAND_REGISTRATION_FAILED');
      state.installed = true;
      return [];
    } catch (e) {
      try { api.unregisterCommand(PKG); } catch {}
      state.installed = false;
      state.api = null;
      throw new Error('PACKAGE_INSTALL_FAILED');
    }
  }

  async function uninstall(api) {
    const bridge = api || state.api;
    try {
      if (bridge && typeof bridge.unregisterCommand === 'function') bridge.unregisterCommand(PKG);
    } finally {
      state.installed = false;
      state.api = null;
    }
    return [];
  }

  const packageModule = Object.freeze({ manifest, install, uninstall });
  window[GLOBAL_KEY] = packageModule;
})();