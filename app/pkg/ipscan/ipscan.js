(() => {
  'use strict';

  const PKG = 'ipscan';
  const VERSION = '8.1.2';
  const GLOBAL_KEY = `__kali_pkg_${PKG}`;
  const AUTHOR = 'Mobin Vaghar Jalaliyeh (Kali Light)';

  const CONFIG = Object.freeze({
    MAX_CONCURRENCY: 500,
    MAX_RETRIES: 6,
    REQUEST_TIMEOUT_MS: 30000,
    RETRY_BASE_DELAY_MS: 500,
    MAX_BACKOFF_DELAY_MS: 8000,
    CACHE_TTL_MS: 60000,
    CACHE_MAX_ENTRIES: 1000,
    REQUIRE_PROXY: true,
    ALLOW_DIRECT_FALLBACK: false,
    ACTIVE_HTTP_CHECKS: true,
    ACTIVE_TLS_CHECKS: true,
    ACTIVE_REACHABILITY_CHECKS: true,
    MAX_REDIRECTS: 5,
    MAX_RECORDS_PER_SECTION: 200,
    MAX_DOMAINS_PER_SOURCE: 200,
    MAX_HISTORY_EVENTS: 300,
    MAX_BGP_EVENTS: 300,
    MAX_ASN_PEERS: 200,
    REQUEST_JITTER_MS: 50,
    PROXY_FAILURE_COOLDOWN_MS: 5000,
    PROXY_MAX_CONSECUTIVE_FAILURES: 3,
    ENABLE_HACKERTARGET: true,
    ENABLE_RIPESTAT: true,
    ENABLE_RDAP: true,
    ENABLE_DNS: true,
    ENABLE_GEO: true,
    ENABLE_CT: true,
    ENABLE_REPUTATION: true,
    ENABLE_THREAT_INTEL: true,
    ENABLE_REVERSE_IP: true,
    ENABLE_ABUSE_CONTACTS: true,
    ENABLE_PORT_SCAN: true,
    ENABLE_COOKIE_EXTRACT: false,
    ENABLE_HEADER_ANALYSIS: true,
    ENABLE_DOMAIN_WHOIS: true,
    ENABLE_EMAIL_REP: false,
    ENABLE_PHONE_LOOKUP: false,
    ENABLE_LEAK_LOOKUP: false,
    ENABLE_IP_STATUS: true,
    ENABLE_SERVER_STATUS: false,
    DEBUG_DEFAULT: false,
    OPTIONAL_API_KEYS: Object.freeze({
      ipinfo: '',
      abuseipdb: '',
      greynoise: '',
      virustotal: '',
      shodan: '',
      viewdns: '',
      securitytrails: '',
      ipstack: '',
      ipgeolocation: '',
      ipqualityscore: '',
      hunter: '',
      emailrep: '',
      dehashed: '',
      hibp: '',
      checkhost: '',
      getipintel: ''
    }),
    SOURCE_APP: 'ipscan-atlas'
  });

  const manifest = Object.freeze({
    name: PKG,
    version: VERSION,
    description: 'Defensive IP intelligence package with normalized routing, registration, DNS, certificate, reputation, reachability and attribution-safe reporting.',
    author: AUTHOR,
    help: `${PKG} help`,
    official: false,
    default: false,
    securityLevel: 'medium',
    permissions: Object.freeze({
      storage: 'none',
      cookies: 'none',
      network: 'read',
      filesystem: 'none'
    }),
    commands: Object.freeze([PKG]),
    dependencies: Object.freeze([]),
    entry: 'install'
  });

  const state = {
    api: null,
    installed: false,
    workingProxies: [],
    customProxy: null,
    proxyReady: false
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
    return typeof api.spacer === 'function' ? api.spacer() : api.line('', 'output');
  };

  const getSnapshot = () => {
    const api = state.api;
    if (!api || typeof api.snapshot !== 'function') return null;
    try { return api.snapshot(); } catch { return null; }
  };

  const getMode = () => {
    const api = state.api;
    if (!api || typeof api.getMode !== 'function') return 'unknown';
    try { return String(api.getMode()); } catch { return 'unknown'; }
  };

  const generateId = (prefix = 'req') =>
    `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;

  const sleep = ms => new Promise(resolve => setTimeout(resolve, Math.max(0, Number(ms) || 0)));

  const jitter = () => CONFIG.REQUEST_JITTER_MS > 0 ? Math.floor(Math.random() * CONFIG.REQUEST_JITTER_MS) : 0;

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
    if (!forceRefresh && state.proxyReady && state.workingProxies.length > 0) {
      return state.workingProxies;
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
      throw new Error('No working proxies available. Please check your connection or set a custom proxy using "ipscan setproxy <template>" command.');
    }

    state.workingProxies = working;
    state.proxyReady = true;
    return working;
  }

  let proxyIndex = 0;
  function getNextProxy() {
    if (state.workingProxies.length === 0) {
      throw new Error('No proxy available. Call prepareProxyList first.');
    }
    const proxy = state.workingProxies[proxyIndex % state.workingProxies.length];
    proxyIndex = (proxyIndex + 1) % state.workingProxies.length;
    return proxy;
  }

  function selectUserAgent() {
    const fup = getFreeUserProxy();
    if (fup && typeof fup.getRandomUserAgent === 'function') {
      return fup.getRandomUserAgent();
    }
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
  }

  const isValidIPv4 = ip => {
    if (typeof ip !== 'string') return false;
    const p = ip.trim().split('.');
    return p.length === 4 && p.every(x =>
      /^\d{1,3}$/.test(x) && !(x.length > 1 && x.startsWith('0')) &&
      Number(x) >= 0 && Number(x) <= 255
    );
  };

  const expandIPv6 = ip => {
    if (typeof ip !== 'string' || !ip || !ip.includes(':')) return null;
    let v = ip.trim().toLowerCase();
    if (v.includes('%')) return null;
    if (v.includes('.')) {
      const m = /^(.*):(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v);
      if (!m || !isValidIPv4(m[2])) return null;
      const o = m[2].split('.').map(Number);
      v = `${m[1]}:${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
    }
    const dc = (v.match(/::/g) || []).length;
    if (dc > 1) return null;
    const h = v.split('::');
    const l = h[0] ? h[0].split(':') : [];
    const r = h[1] ? h[1].split(':') : [];
    if (l.concat(r).some(x => !/^[0-9a-f]{1,4}$/.test(x))) return null;
    const total = l.length + r.length;
    if (dc === 0 && total !== 8) return null;
    if (dc === 1 && total >= 8) return null;
    return [...l, ...Array(8 - total).fill('0'), ...r].map(x => x.padStart(4, '0')).join('');
  };

  const isValidIPv6 = ip => Boolean(expandIPv6(ip));

  const getIpVersion = ip => isValidIPv4(ip) ? 4 : isValidIPv6(ip) ? 6 : null;

  const classifyIPv4 = ip => {
    const [a, b, c, d] = ip.split('.').map(Number);
    if (a === 0) return 'SPECIAL';
    if (a === 10) return 'PRIVATE';
    if (a === 100 && b >= 64 && b <= 127) return 'CGNAT';
    if (a === 127) return 'LOOPBACK';
    if (a === 169 && b === 254) return 'LINK_LOCAL';
    if (a === 172 && b >= 16 && b <= 31) return 'PRIVATE';
    if (a === 192 && b === 0 && c === 0) return 'SPECIAL';
    if (a === 192 && b === 0 && c === 2) return 'DOCUMENTATION';
    if (a === 192 && b === 0 && (c === 9 || c === 10)) return 'SPECIAL';
    if (a === 192 && b === 168) return 'PRIVATE';
    if (a === 192 && b === 18 && c <= 1) return 'BENCHMARK';
    if (a === 198 && b === 18) return 'BENCHMARK';
    if (a === 198 && b === 51 && c === 100) return 'DOCUMENTATION';
    if (a === 203 && b === 0 && c === 113) return 'DOCUMENTATION';
    if (a >= 224 && a <= 239) return 'MULTICAST';
    if (a >= 240 || (a === 255 && b === 255 && c === 255 && d === 255)) return 'RESERVED';
    return 'PUBLIC';
  };

  const classifyIPv6 = ip => {
    const e = expandIPv6(String(ip).toLowerCase().replace(/^\[/, '').replace(/\]$/, ''));
    if (!e) return 'UNKNOWN';
    if (e === '00000000000000000000000000000000') return 'UNSPECIFIED';
    if (e === '00000000000000000000000000000001') return 'LOOPBACK';
    if (e.startsWith('ff')) return 'MULTICAST';
    if (e.startsWith('fc') || e.startsWith('fd')) return 'UNIQUE_LOCAL';
    if (e.startsWith('fe8')) return 'LINK_LOCAL';
    if (e.startsWith('20010db8')) return 'DOCUMENTATION';
    if (e.startsWith('00000000000000000000ffff')) return 'IPV4_MAPPED';
    if (e.startsWith('2002')) return '6TO4';
    return 'PUBLIC';
  };

  const classifyIp = ip => {
    const v = getIpVersion(ip);
    return v === 4 ? classifyIPv4(ip) : v === 6 ? classifyIPv6(ip) : 'UNKNOWN';
  };

  const validateTarget = input => {
    const target = String(input ?? '').trim();
    const version = getIpVersion(target);
    if (!version) throw new Error(`INVALID_INPUT: not a valid IPv4/IPv6 address (${target})`);
    return Object.freeze({
      input: target,
      ip: target,
      version,
      type: classifyIp(target)
    });
  };

  const normalizeDomain = input => {
    const raw = String(input ?? '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    if (!raw) return null;
    try {
      return new URL(`http://${raw}`).hostname.toLowerCase().replace(/\.$/, '');
    } catch {
      const s = raw.replace(/[^a-z0-9.-]/g, '').replace(/\.{2,}/g, '.');
      return s || null;
    }
  };

  const normalizeHeaderMap = headers => {
    const o = {};
    if (headers && typeof headers.forEach === 'function') {
      headers.forEach((v, k) => o[String(k).toLowerCase()] = String(v));
    }
    return o;
  };

  const parseJsonSafely = text => {
    try { return JSON.parse(text); } catch { return null; }
  };

  const mapHttpError = status => {
    if (status === 400) return 'INVALID_INPUT';
    if (status === 401) return 'AUTH_REQUIRED';
    if (status === 403) return 'FORBIDDEN';
    if (status === 404) return 'NO_DATA';
    if (status === 408) return 'TIMEOUT';
    if (status === 409) return 'CONFLICT';
    if (status === 413) return 'PAYLOAD_TOO_LARGE';
    if (status === 422) return 'INVALID_INPUT';
    if (status === 429) return 'RATE_LIMITED';
    if (status >= 500) return 'HTTP_ERROR';
    return 'HTTP_ERROR';
  };

  const parseRetryAfter = headers => {
    const v = headers?.['retry-after'];
    if (!v) return null;
    const n = Number(v);
    if (Number.isFinite(n)) return Math.min(n * 1000, CONFIG.MAX_BACKOFF_DELAY_MS);
    const d = Date.parse(v);
    return Number.isNaN(d) ? null : Math.min(Math.max(d - Date.now(), 0), CONFIG.MAX_BACKOFF_DELAY_MS);
  };

  const computeBackoff = (n, headers) => {
    const r = parseRetryAfter(headers);
    if (r !== null) return r + jitter();
    return Math.min(CONFIG.RETRY_BASE_DELAY_MS * 2 ** Math.max(0, n - 1) + jitter(), CONFIG.MAX_BACKOFF_DELAY_MS);
  };

  const readResponse = async (response, type) => {
    if (response.status === 204 || response.status === 205) return null;
    const ct = response.headers.get('content-type') || '';
    const text = await response.text();
    if (type === 'text') return text;
    if (type === 'json' || (type === 'auto' && /json/i.test(ct))) {
      if (!text) return null;
      const parsed = parseJsonSafely(text);
      if (parsed === null) {
        const e = new Error('Invalid JSON response');
        e.code = 'PARSE_ERROR';
        throw e;
      }
      return parsed;
    }
    return text;
  };

  class Semaphore {
    constructor(max) {
      this.max = Math.max(1, Number(max) || 1);
      this.active = 0;
      this.queue = [];
    }
    async run(task) {
      if (this.active >= this.max) {
        await new Promise(r => this.queue.push(r));
      }
      this.active++;
      try {
        return await task();
      } finally {
        this.active--;
        const n = this.queue.shift();
        if (n) n();
      }
    }
  }

  class CacheStore {
    constructor(ttl, max) {
      this.ttl = Math.max(0, Number(ttl) || 0);
      this.maxEntries = Math.max(1, Number(max) || 1);
      this.data = new Map();
    }
    get(k) {
      if (!this.ttl) return null;
      const i = this.data.get(k);
      if (!i) return null;
      if (Date.now() - i.createdAt > this.ttl) {
        this.data.delete(k);
        return null;
      }
      return i.value;
    }
    set(k, v) {
      if (!this.ttl) return;
      if (this.data.size >= this.maxEntries && !this.data.has(k)) {
        this.data.delete(this.data.keys().next().value);
      }
      this.data.set(k, { createdAt: Date.now(), value: v });
    }
    clear() { this.data.clear(); }
    size() { return this.data.size; }
  }

  class EvidenceStore {
    constructor() {
      this.records = [];
    }
    add(record) {
      const e = {
        id: record.id || generateId('ev'),
        category: record.category || 'other',
        type: record.type || 'observation',
        source: record.source || 'unknown',
        sourceType: record.sourceType || 'inference',
        observedAt: record.observedAt || new Date().toISOString(),
        requestId: record.requestId || null,
        status: record.status || 'OK',
        rawValue: record.rawValue ?? null,
        normalizedValue: record.normalizedValue ?? null,
        value: record.value ?? null,
        confidence: record.confidence || 'NONE',
        note: record.note || '',
        metadata: record.metadata || {}
      };
      this.records.push(e);
      return e;
    }
    all() { return this.records.slice(); }
    size() { return this.records.length; }
  }

  const limitation = (source, status, note, meta = {}) => ({
    category: 'limitation',
    type: 'limitation',
    source,
    sourceType: 'diagnostic',
    observedAt: new Date().toISOString(),
    status,
    value: null,
    rawValue: null,
    normalizedValue: null,
    confidence: 'NONE',
    note,
    metadata: meta
  });

  const normalizeGeoData = (source, data) => {
    const country = data?.country || data?.country_name || data?.countryName || data?.country_code || data?.countryCode || null;
    const region = data?.region || data?.regionName || data?.region_name || data?.region_code || data?.regionCode || null;
    const city = data?.city || null;
    const latitude = data?.latitude ?? data?.lat ?? null;
    const longitude = data?.longitude ?? data?.lon ?? data?.lng ?? null;
    const timezone = typeof data?.timezone === 'string' ? data.timezone : data?.timezone?.id || data?.timeZone || null;
    const connection = data?.connection || {};
    const isp = data?.isp || connection?.isp || null;
    const organization = data?.org || data?.organization || connection?.org || null;
    const asn = data?.as || data?.asn || connection?.asn || null;
    const asName = data?.asname || data?.asnname || connection?.asname || null;
    const proxy = data?.proxy ?? connection?.proxy ?? null;
    const hosting = data?.hosting ?? connection?.hosting ?? null;
    const mobile = data?.mobile ?? connection?.mobile ?? null;
    const reverse = data?.reverse || data?.hostname || null;

    if (!country && !region && !city && !isp && !organization && !asn && latitude === null && longitude === null) return null;

    return {
      category: 'geolocation',
      type: 'geo',
      source,
      sourceType: 'public-api',
      observedAt: new Date().toISOString(),
      confidence: 'MEDIUM',
      status: 'OK',
      value: {
        country,
        region,
        city,
        latitude,
        longitude,
        timezone,
        isp,
        organization,
        asn,
        asName,
        proxy,
        hosting,
        mobile,
        reverse
      },
      rawValue: data,
      normalizedValue: {
        country,
        region,
        city,
        latitude,
        longitude,
        timezone,
        isp,
        organization,
        asn,
        asName,
        proxy,
        hosting,
        mobile,
        reverse
      },
      note: `Normalized geolocation from ${source}`,
      requestId: null
    };
  };

  const requestManager = (() => {
    const semaphore = new Semaphore(CONFIG.MAX_CONCURRENCY);
    const cache = new CacheStore(CONFIG.CACHE_TTL_MS, CONFIG.CACHE_MAX_ENTRIES);

    const buildProxyUrl = (endpoint, proxy) => {
      const url = String(endpoint || '').trim();
      if (!url) throw new Error('INVALID_ENDPOINT');
      if (!proxy) {
        if (CONFIG.REQUIRE_PROXY) {
          const e = new Error('No usable proxy is available while proxy mode is required.');
          e.code = 'PROXY_REQUIRED';
          throw e;
        }
        return url;
      }
      if (!proxy.template || !proxy.template.includes('{url}')) {
        const e = new Error(`Invalid proxy template: ${proxy.name || 'unknown'}`);
        e.code = 'PROXY_CONFIGURATION_ERROR';
        throw e;
      }
      const out = proxy.template.replace('{url}', encodeURIComponent(url));
      try {
        const u = new URL(out);
        if (!/^https?:$/i.test(u.protocol)) throw 0;
      } catch {
        const e = new Error(`Invalid generated proxy URL for ${proxy.name || 'unknown'}`);
        e.code = 'PROXY_CONFIGURATION_ERROR';
        throw e;
      }
      return out;
    };

    const executeAttempt = async ({
      endpoint,
      method,
      headers,
      timeout,
      requestId,
      attempt,
      proxy,
      provider,
      responseType
    }) => {
      const startedAt = Date.now();
      const controller = new AbortController();
      const h = { ...headers };
      if (!h['User-Agent'] && !h['user-agent']) h['User-Agent'] = selectUserAgent();

      let actualUrl = endpoint;
      try {
        actualUrl = buildProxyUrl(endpoint, proxy);
      } catch (e) {
        return {
          requestId,
          attempt,
          ok: false,
          status: 0,
          errorType: e.code || 'PROXY_CONFIGURATION_ERROR',
          errorMessage: e.message,
          provider,
          endpoint,
          requestedUrl: actualUrl,
          proxy: proxy?.name || 'none',
          attemptedAt: new Date(startedAt).toISOString(),
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
          headers: {},
          finalURL: null,
          redirected: false,
          data: null,
          transportStatus: 'FAILED',
          providerStatus: e.code || 'PROXY_CONFIGURATION_ERROR'
        };
      }

      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, timeout);

      try {
        const response = await fetch(actualUrl, {
          method,
          headers: h,
          signal: controller.signal,
          redirect: CONFIG.MAX_REDIRECTS > 0 ? 'follow' : 'manual'
        });
        clearTimeout(timer);

        const headersOut = normalizeHeaderMap(response.headers);
        let data = null;
        try {
          data = await readResponse(response, responseType);
        } catch (e) {
          return {
            requestId,
            attempt,
            ok: false,
            status: response.status,
            errorType: e.code === 'PARSE_ERROR' ? 'INVALID_RESPONSE' : 'HTTP_ERROR',
            errorMessage: e.message,
            provider,
            endpoint,
            requestedUrl: actualUrl,
            proxy: proxy?.name || 'none',
            attemptedAt: new Date(startedAt).toISOString(),
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startedAt,
            headers: headersOut,
            finalURL: response.url || actualUrl,
            redirected: Boolean(response.redirected),
            data: null,
            transportStatus: 'SUCCESS',
            providerStatus: e.code === 'PARSE_ERROR' ? 'INVALID_RESPONSE' : 'HTTP_ERROR'
          };
        }

        const result = {
          requestId,
          attempt,
          ok: response.ok,
          status: response.status,
          errorType: response.ok ? null : mapHttpError(response.status),
          errorMessage: response.ok ? null : `HTTP ${response.status}`,
          provider,
          endpoint,
          requestedUrl: actualUrl,
          proxy: proxy?.name || 'none',
          attemptedAt: new Date(startedAt).toISOString(),
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
          headers: headersOut,
          finalURL: response.url || actualUrl,
          redirected: Boolean(response.redirected),
          data: null,
          transportStatus: 'SUCCESS',
          providerStatus: response.ok ? 'SUCCESS' : mapHttpError(response.status)
        };
        result.data = data;

        if (proxy && response.status === 403) result.providerStatus = 'FORBIDDEN';
        if (proxy && response.status === 429) result.providerStatus = 'RATE_LIMITED';
        if (proxy && response.status >= 500) result.providerStatus = 'PROXY_NETWORK_ERROR';
        if (!response.ok) result.errorType = result.providerStatus;

        return result;
      } catch (e) {
        clearTimeout(timer);
        const type = timedOut ? 'PROXY_TIMEOUT' :
          e?.name === 'AbortError' ? 'PROXY_TIMEOUT' :
          'PROXY_NETWORK_ERROR';
        return {
          requestId,
          attempt,
          ok: false,
          status: 0,
          errorType: type,
          errorMessage: e?.message || 'Request failed',
          provider,
          endpoint,
          requestedUrl: actualUrl,
          proxy: proxy?.name || 'none',
          attemptedAt: new Date(startedAt).toISOString(),
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
          headers: {},
          finalURL: null,
          redirected: false,
          data: null,
          transportStatus: 'FAILED',
          providerStatus: type
        };
      }
    };

    const request = async (endpoint, options = {}) => {
      const url = String(endpoint || '').trim();
      if (!url) throw new Error('INVALID_ENDPOINT');

      const method = String(options.method || 'GET').toUpperCase();
      const provider = String(options.provider || 'unknown');
      const timeout = Math.max(1000, Number(options.timeout || CONFIG.REQUEST_TIMEOUT_MS));
      const maxAttempts = Math.max(1, Number(options.retries ?? CONFIG.MAX_RETRIES) + 1);
      const responseType = options.responseType || 'auto';
      const cacheKey = options.cacheKey || `${method}:${url}`;

      const cached = method === 'GET' ? cache.get(cacheKey) : null;
      if (cached) return { ...cached, cached: true };

      const requestId = generateId('req');
      const startedAt = Date.now();
      const attempts = [];
      let finalResult = null;

      const useProxy = options.useProxy !== undefined ? Boolean(options.useProxy) : true;
      if (CONFIG.REQUIRE_PROXY && !useProxy) {
        return {
          requestId,
          ok: false,
          status: 0,
          errorType: 'DIRECT_REQUEST_DISABLED',
          errorMessage: 'Direct requests are disabled because REQUIRE_PROXY is enabled.',
          provider,
          endpoint: url,
          requestedUrl: url,
          proxy: 'none',
          attempts: [],
          totalDurationMs: 0,
          cached: false,
          data: null
        };
      }

      let proxies = state.workingProxies;
      if (proxies.length === 0) {
        try {
          proxies = await prepareProxyList();
        } catch (e) {
          return {
            requestId,
            ok: false,
            status: 0,
            errorType: 'PROXY_REQUIRED',
            errorMessage: e.message || 'No proxy available.',
            provider,
            endpoint: url,
            requestedUrl: url,
            proxy: 'none',
            attempts: [],
            totalDurationMs: 0,
            cached: false,
            data: null
          };
        }
      }

      const maxRetries = Math.min(proxies.length, 3);
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        const proxy = proxies[(attempt - 1) % proxies.length];
        const result = await semaphore.run(() =>
          executeAttempt({
            endpoint: url,
            method,
            headers: { ...(options.headers || {}) },
            timeout,
            requestId,
            attempt,
            proxy,
            provider,
            responseType
          })
        );
        attempts.push(result);
        finalResult = result;

        if (result.ok) break;
        if (result.status === 429) {
          await sleep(computeBackoff(attempt, result.headers));
        }
        if (attempt >= maxRetries) break;
      }

      const response = {
        ...(finalResult || {
          requestId,
          ok: false,
          status: 0,
          errorType: 'REQUEST_FAILED',
          errorMessage: 'No result was produced.',
          data: null
        }),
        attempts,
        requestId,
        totalDurationMs: Date.now() - startedAt,
        cached: false
      };

      if (response.ok && method === 'GET') cache.set(cacheKey, response);
      return response;
    };

    return Object.freeze({
      request,
      semaphore,
      cache
    });
  })();

  const createGeoProvider = (id, name, builder, validator) => ({
    id,
    name,
    category: 'geolocation',
    enabled: true,
    async execute(ctx) {
      const result = await requestManager.request(builder(ctx.ip), {
        provider: id,
        responseType: 'json'
      });
      if (!result.ok) {
        return {
          raw: [result],
          records: [limitation(name, result.errorType || 'UNAVAILABLE', result.errorMessage || result.errorType, {
            transport: result.transportStatus,
            provider: result.providerStatus
          })]
        };
      }
      if (validator && !validator(result.data)) {
        return {
          raw: [result],
          records: [limitation(name, 'INVALID_RESPONSE', 'Provider payload did not contain expected fields.', {
            transport: result.transportStatus,
            provider: result.providerStatus
          })]
        };
      }
      const r = normalizeGeoData(name, result.data);
      return r ? {
        raw: [result],
        records: [r]
      } : {
        raw: [result],
        records: [limitation(name, 'NO_DATA', 'No usable geolocation fields returned.')]
      };
    }
  });

  const geoProviders = [
    createGeoProvider('geo_ipwhois', 'ipwho.is',
      ip => `https://ipwho.is/${encodeURIComponent(ip)}`,
      d => d && d.success !== false
    ),
    createGeoProvider('geo_ipapi', 'ipapi.co',
      ip => `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      d => d && !d.error
    ),
    createGeoProvider('geo_ip_api_com', 'ip-api.com',
      ip => `https://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`,
      d => d?.status === 'success'
    ),
    createGeoProvider('geo_freeipapi', 'freeipapi.com',
      ip => `https://freeipapi.com/api/json/${encodeURIComponent(ip)}`,
      d => Boolean(d?.ip || d?.countryCode)
    ),
    createGeoProvider('geo_ipinfo', 'ipinfo.io',
      ip => {
        const t = CONFIG.OPTIONAL_API_KEYS.ipinfo;
        return t ? `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(t)}` :
          `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
      },
      d => Boolean(d?.ip)
    )
  ];

  const ripeRequest = (endpoint, resource, params = {}) => {
    const q = new URLSearchParams({
      resource,
      sourceapp: CONFIG.SOURCE_APP,
      ...params
    });
    return requestManager.request(
      `https://stat.ripe.net/data/${endpoint}/data.json?${q.toString()}`,
      { provider: `RIPEstat:${endpoint}`, responseType: 'json' }
    );
  };

  const providersBase = {
    rdap: {
      id: 'rdap',
      name: 'RDAP / RIR',
      category: 'registration',
      enabled: CONFIG.ENABLE_RDAP,
      async execute(ctx) {
        const eps = [
          ['ARIN', `https://rdap.arin.net/registry/ip/${encodeURIComponent(ctx.ip)}`],
          ['RIPE', `https://rdap.db.ripe.net/ip/${encodeURIComponent(ctx.ip)}`],
          ['APNIC', `https://rdap.apnic.net/ip/${encodeURIComponent(ctx.ip)}`],
          ['AFRINIC', `https://rdap.afrinic.net/rdap/ip/${encodeURIComponent(ctx.ip)}`],
          ['LACNIC', `https://rdap.lacnic.net/rdap/ip/${encodeURIComponent(ctx.ip)}`]
        ];
        const results = await Promise.all(eps.map(([name, endpoint]) =>
          requestManager.request(endpoint, { provider: `RDAP:${name}`, responseType: 'json' })
          .then(result => ({ name, result }))
        ));
        const records = [];
        const raw = results.map(x => x.result);
        for (const { name, result } of results) {
          if (!result.ok || !result.data) continue;
          const d = result.data;
          records.push({
            category: 'registration',
            type: 'rdap',
            source: `RDAP:${name}`,
            sourceType: 'authoritative',
            observedAt: result.completedAt,
            confidence: 'HIGH',
            status: 'OK',
            value: {
              rir: name,
              name: d?.name || null,
              handle: d?.handle || null,
              startAddress: d?.startAddress || null,
              endAddress: d?.endAddress || null,
              ipVersion: d?.ipVersion || null,
              country: d?.country || null,
              status: Array.isArray(d?.status) ? d.status : [],
              entities: Array.isArray(d?.entities) ? d.entities.map(e => ({
                handle: e?.handle || null,
                roles: Array.isArray(e?.roles) ? e.roles : [],
                name: Array.isArray(e?.vcardArray?.[1]) ?
                  e.vcardArray[1].find(x => x?.[0] === 'fn')?.[3] || null :
                  null
              })).slice(0, CONFIG.MAX_RECORDS_PER_SECTION) : []
            },
            rawValue: d,
            normalizedValue: null,
            note: 'Authoritative RIR RDAP observation.',
            requestId: result.requestId
          });
        }
        if (!records.length) {
          records.push(limitation('RDAP/RIR', 'NO_DATA', 'No authoritative RDAP result was returned.'));
        }
        return { raw, records };
      }
    },
    ripestatWhois: {
      id: 'ripestat_whois',
      name: 'RIPEstat Whois',
      category: 'registration',
      enabled: CONFIG.ENABLE_RIPESTAT,
      async execute(ctx) {
        const r = await ripeRequest('whois', ctx.ip);
        if (!r.ok || !r.data) {
          return {
            raw: [r],
            records: [limitation('RIPEstat Whois', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const d = r.data?.data || r.data || {};
        const records = Array.isArray(d.records) ? d.records : [];
        return {
          raw: [r],
          records: [{
            category: 'registration',
            type: 'ripestat_whois',
            source: 'RIPEstat Whois',
            sourceType: 'registry',
            observedAt: r.completedAt,
            confidence: 'HIGH',
            status: records.length ? 'AVAILABLE' : 'NO_DATA',
            value: {
              authorities: Array.isArray(d.authorities) ? d.authorities : [],
              records: records.slice(0, CONFIG.MAX_RECORDS_PER_SECTION),
              resource: d.resource || ctx.ip
            },
            rawValue: d,
            normalizedValue: null,
            note: 'RIPE registry observation.',
            requestId: r.requestId
          }]
        };
      }
    },
    ripestatNetwork: {
      id: 'ripestat_network',
      name: 'RIPEstat Network Info',
      category: 'network',
      enabled: CONFIG.ENABLE_RIPESTAT,
      async execute(ctx) {
        const r = await ripeRequest('network-info', ctx.ip);
        if (!r.ok || !r.data) {
          return {
            raw: [r],
            records: [limitation('RIPEstat Network Info', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const d = r.data?.data || r.data || {};
        const asns = Array.isArray(d.asns) ? d.asns : [];
        return {
          raw: [r],
          records: [{
            category: 'network',
            type: 'ripestat_network',
            source: 'RIPEstat Network Info',
            sourceType: 'authoritative-routing-view',
            observedAt: r.completedAt,
            confidence: 'HIGH',
            status: asns.length || d.prefix ? 'ANNOUNCED' : 'NOT_ANNOUNCED',
            value: {
              prefix: d.prefix || null,
              asns: asns.slice(0, CONFIG.MAX_ASN_PEERS),
              announced: Boolean(d.prefix || asns.length)
            },
            rawValue: d,
            normalizedValue: null,
            note: 'Current route information from RIPEstat.',
            requestId: r.requestId
          }]
        };
      }
    },
    ripestatPrefix: {
      id: 'ripestat_prefix',
      name: 'RIPEstat Prefix Overview',
      category: 'network',
      enabled: CONFIG.ENABLE_RIPESTAT,
      async execute(ctx) {
        const n = await ripeRequest('network-info', ctx.ip);
        if (!n.ok || !n.data) {
          return {
            raw: [n],
            records: [limitation('RIPEstat Prefix Overview', n.errorType || 'UNAVAILABLE', n.errorMessage || n.errorType)]
          };
        }
        const nd = n.data?.data || n.data || {};
        const prefix = nd.prefix;
        if (!prefix) {
          return {
            raw: [n],
            records: [limitation('RIPEstat Prefix Overview', 'NO_DATA', 'No encompassing routed prefix returned.')]
          };
        }
        const r = await ripeRequest('prefix-overview', prefix, {
          max_related: '100',
          min_peers_seeing: '1'
        });
        if (!r.ok || !r.data) {
          return {
            raw: [n, r],
            records: [limitation('RIPEstat Prefix Overview', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const d = r.data?.data || r.data || {};
        const asns = Array.isArray(d.asns) ? d.asns : [];
        return {
          raw: [n, r],
          records: [{
            category: 'network',
            type: 'prefix_overview',
            source: 'RIPEstat Prefix Overview',
            sourceType: 'routing-observation',
            observedAt: r.completedAt,
            confidence: 'HIGH',
            status: d.announced === true ? 'ANNOUNCED' : 'NOT_ANNOUNCED',
            value: {
              prefix: d.resource || prefix,
              announced: d.announced ?? false,
              holders: asns.map(x => ({
                asn: x?.asn ?? null,
                holder: x?.holder ?? null
              })),
              relatedPrefixes: Array.isArray(d.related_prefixes) ?
                d.related_prefixes.slice(0, CONFIG.MAX_RECORDS_PER_SECTION) : []
            },
            rawValue: d,
            normalizedValue: null,
            note: 'Current prefix overview.',
            requestId: r.requestId
          }]
        };
      }
    },
    lookingGlass: {
      id: 'looking_glass',
      name: 'RIPEstat Looking Glass',
      category: 'routing',
      enabled: CONFIG.ENABLE_RIPESTAT,
      async execute(ctx) {
        const r = await ripeRequest('looking-glass', ctx.ip, { look_back_limit: '86400' });
        if (!r.ok || !r.data) {
          return {
            raw: [r],
            records: [limitation('RIPEstat Looking Glass', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const rr = r.data?.data?.rrcs || r.data?.rrcs || {};
        const records = [];
        for (const [id, x] of Object.entries(rr)) {
          const entries = Array.isArray(x?.entries) ? x.entries : Array.isArray(x?.peers) ? x.peers : [];
          for (const e of entries.slice(0, CONFIG.MAX_ASN_PEERS)) {
            records.push({
              category: 'routing',
              type: 'looking_glass',
              source: 'RIPEstat Looking Glass',
              sourceType: 'near-realtime-routing',
              observedAt: r.completedAt,
              confidence: 'HIGH',
              status: 'OBSERVED',
              value: {
                rrc: id,
                prefix: e?.prefix || null,
                origin: e?.asn_origin ?? e?.origin ?? null,
                peer: e?.peer ?? null,
                asPath: e?.as_path ?? e?.asPath ?? null
              },
              rawValue: e,
              normalizedValue: null,
              note: 'Observed route path.',
              requestId: r.requestId
            });
          }
        }
        return {
          raw: [r],
          records: records.length ? records : [limitation('RIPEstat Looking Glass', 'NO_DATA', 'No route entries returned.')]
        };
      }
    },
    bgplay: {
      id: 'bgplay',
      name: 'RIPEstat BGPlay',
      category: 'history',
      enabled: CONFIG.ENABLE_RIPESTAT,
      async execute(ctx) {
        const end = new Date();
        const start = new Date(end.getTime() - 7 * 86400000);
        const r = await ripeRequest('bgplay', ctx.ip, {
          starttime: start.toISOString(),
          endtime: end.toISOString()
        });
        if (!r.ok || !r.data) {
          return {
            raw: [r],
            records: [limitation('RIPEstat BGPlay', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const d = r.data?.data || r.data || {};
        const events = Array.isArray(d.events) ? d.events : [];
        const normalized = events.slice(0, CONFIG.MAX_BGP_EVENTS).map(e => ({
          timestamp: e?.timestamp || e?.time || null,
          type: e?.type || null,
          prefix: e?.target || e?.attrs?.prefix || null,
          origin: e?.attrs?.origin || e?.origin || null,
          path: e?.attrs?.as_path || e?.attrs?.asPath || e?.as_path || null
        }));
        return {
          raw: [r],
          records: [{
            category: 'history',
            type: 'bgplay',
            source: 'RIPEstat BGPlay',
            sourceType: 'historical-routing',
            observedAt: r.completedAt,
            confidence: 'HIGH',
            status: normalized.length ? 'AVAILABLE' : 'NO_EVENTS',
            value: {
              windowStart: start.toISOString(),
              windowEnd: end.toISOString(),
              events: normalized
            },
            rawValue: d,
            normalizedValue: null,
            note: 'Historical BGP events.',
            requestId: r.requestId
          }]
        };
      }
    },
    dns: {
      id: 'dns',
      name: 'Google Public DNS',
      category: 'dns',
      enabled: CONFIG.ENABLE_DNS,
      async execute(ctx) {
        const raw = [];
        const records = [];
        const ptr = ctx.version === 4 ?
          `${ctx.ip.split('.').reverse().join('.')}.in-addr.arpa` :
          expandIPv6(ctx.ip);
        if (!ptr) {
          return {
            raw,
            records: [limitation('DNS', 'INVALID_INPUT', 'Reverse DNS name could not be generated.')]
          };
        }
        const r = await requestManager.request(
          `https://dns.google/resolve?name=${encodeURIComponent(ptr)}&type=PTR`,
          { provider: 'Google Public DNS PTR', responseType: 'json' }
        );
        raw.push(r);
        if (!r.ok || !r.data) {
          return {
            raw,
            records: [limitation('Google Public DNS', 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const answers = Array.isArray(r.data.Answer) ? r.data.Answer : [];
        if (answers.length) {
          answers.slice(0, CONFIG.MAX_RECORDS_PER_SECTION).forEach(a => {
            records.push({
              category: 'dns',
              type: 'ptr',
              source: 'Google Public DNS',
              sourceType: 'observed',
              observedAt: r.completedAt,
              confidence: 'HIGH',
              status: 'OK',
              value: {
                name: ptr,
                value: String(a.data).replace(/\.$/, '')
              },
              rawValue: a.data,
              normalizedValue: normalizeDomain(a.data),
              note: 'PTR record observed.',
              requestId: r.requestId
            });
          });
        } else {
          records.push({
            category: 'dns',
            type: 'dns_status',
            source: 'Google Public DNS',
            sourceType: 'observed',
            observedAt: r.completedAt,
            confidence: 'LOW',
            status: r.data.Status === 3 ? 'NXDOMAIN' : r.data.Status === 2 ? 'SERVFAIL' : 'NO_ANSWER',
            value: {
              name: ptr,
              status: r.data.Status === 3 ? 'NXDOMAIN' : r.data.Status === 2 ? 'SERVFAIL' : 'NO_ANSWER'
            },
            rawValue: null,
            normalizedValue: null,
            note: 'Reverse DNS query result.',
            requestId: r.requestId
          });
        }
        return { raw, records };
      }
    },
    ct: {
      id: 'ct',
      name: 'Certificate Transparency',
      category: 'certificate',
      enabled: CONFIG.ENABLE_CT,
      async execute(ctx) {
        const r = await requestManager.request(
          `https://crt.sh/?q=${encodeURIComponent(ctx.ip)}&output=json`,
          { provider: 'crt.sh', responseType: 'json' }
        );
        if (!r.ok) {
          return {
            raw: [r],
            records: [limitation('crt.sh', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const entries = Array.isArray(r.data) ? r.data : [];
        const records = entries.slice(0, CONFIG.MAX_RECORDS_PER_SECTION).map(e => ({
          category: 'certificate',
          type: 'ct',
          source: 'crt.sh',
          sourceType: 'historical',
          observedAt: r.completedAt,
          confidence: 'MEDIUM',
          status: 'OBSERVED',
          value: {
            issuer: e?.issuer_name || null,
            subject: e?.subject_dn || null,
            san: String(e?.name_value || '').split(/\r?\n/).map(normalizeDomain).filter(Boolean),
            notBefore: e?.not_before || null,
            notAfter: e?.not_after || null
          },
          rawValue: e,
          normalizedValue: null,
          note: 'Certificate Transparency association.',
          requestId: r.requestId
        }));
        return {
          raw: [r],
          records: records.length ? records : [limitation('crt.sh', 'NO_DATA', 'No certificate transparency entries returned.')]
        };
      }
    },
    bgpview: {
      id: 'bgpview',
      name: 'BGPView',
      category: 'network',
      enabled: true,
      async execute(ctx) {
        const r = await requestManager.request(
          `https://api.bgpview.io/ip/${encodeURIComponent(ctx.ip)}`,
          { provider: 'BGPView', responseType: 'json' }
        );
        if (!r.ok || !r.data) {
          return {
            raw: [r],
            records: [limitation('BGPView', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const p = Array.isArray(r.data?.data?.prefixes) ? r.data.data.prefixes : [];
        const records = p.slice(0, CONFIG.MAX_RECORDS_PER_SECTION).map(x => ({
          category: 'network',
          type: 'bgp',
          source: 'BGPView',
          sourceType: 'public-routing-api',
          observedAt: r.completedAt,
          confidence: 'HIGH',
          status: 'CURRENT',
          value: {
            prefix: x?.prefix || null,
            asn: x?.asn?.asn ?? null,
            asName: x?.asn?.name || null,
            country: x?.country_code || null
          },
          rawValue: x,
          normalizedValue: null,
          note: 'Current BGP prefix observation.',
          requestId: r.requestId
        }));
        return {
          raw: [r],
          records: records.length ? records : [limitation('BGPView', 'NO_DATA', 'No current BGP prefixes returned.')]
        };
      }
    },
    reverseIp: {
      id: 'reverse_ip',
      name: 'HackerTarget Reverse IP',
      category: 'domains',
      enabled: CONFIG.ENABLE_REVERSE_IP,
      async execute(ctx) {
        if (ctx.version !== 4) {
          return {
            raw: [],
            records: [limitation('HackerTarget Reverse IP', 'UNSUPPORTED', 'Free endpoint supports IPv4 targets only.')]
          };
        }
        const r = await requestManager.request(
          `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ctx.ip)}`,
          { provider: 'HackerTarget Reverse IP', responseType: 'text' }
        );
        if (!r.ok) {
          return {
            raw: [r],
            records: [limitation('HackerTarget Reverse IP', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const text = String(r.data || '');
        if (/^error/i.test(text) || /^quota/i.test(text)) {
          return {
            raw: [r],
            records: [limitation('HackerTarget Reverse IP', 'PROVIDER_ERROR', text.slice(0, 500))]
          };
        }
        const domains = text.split(/\r?\n/)
          .map(normalizeDomain)
          .filter(Boolean)
          .filter((v, i, a) => a.indexOf(v) === i)
          .slice(0, CONFIG.MAX_DOMAINS_PER_SOURCE);
        return {
          raw: [r],
          records: [{
            category: 'domains',
            type: 'reverse_ip',
            source: 'HackerTarget Reverse IP',
            sourceType: 'public-dataset',
            observedAt: r.completedAt,
            confidence: domains.length ? 'MEDIUM' : 'LOW',
            status: domains.length ? 'FOUND' : 'NO_DATA',
            value: { domains },
            rawValue: text,
            normalizedValue: domains,
            note: 'Reverse-IP domain observations.',
            requestId: r.requestId
          }]
        };
      }
    },
    geoHacker: {
      id: 'geo_hackertarget',
      name: 'HackerTarget GeoIP',
      category: 'geolocation',
      enabled: true,
      async execute(ctx) {
        const r = await requestManager.request(
          `https://api.hackertarget.com/geoip/?q=${encodeURIComponent(ctx.ip)}`,
          { provider: 'HackerTarget GeoIP', responseType: 'text' }
        );
        if (!r.ok) {
          return {
            raw: [r],
            records: [limitation('HackerTarget GeoIP', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const parsed = {};
        for (const lineText of String(r.data || '').split(/\r?\n/)) {
          const i = lineText.indexOf(':');
          if (i > 0) {
            const key = lineText.slice(0, i).trim().toLowerCase().replace(/\s+/g, '_');
            const value = lineText.slice(i + 1).trim();
            parsed[key] = value;
          }
        }
        return {
          raw: [r],
          records: Object.keys(parsed).length ? [{
            category: 'geolocation',
            type: 'geo_hackertarget',
            source: 'HackerTarget GeoIP',
            sourceType: 'public-api',
            observedAt: r.completedAt,
            confidence: 'LOW',
            status: 'OBSERVED',
            value: parsed,
            rawValue: r.data,
            normalizedValue: null,
            note: 'Independent geolocation reference.',
            requestId: r.requestId
          }] : [limitation('HackerTarget GeoIP', 'NO_DATA', 'No structured geolocation fields returned.')]
        };
      }
    },
    asHacker: {
      id: 'as_hackertarget',
      name: 'HackerTarget AS Lookup',
      category: 'network',
      enabled: true,
      async execute(ctx) {
        const r = await requestManager.request(
          `https://api.hackertarget.com/aslookup/?q=${encodeURIComponent(ctx.ip)}&output=json&details=true`,
          { provider: 'HackerTarget AS', responseType: 'auto' }
        );
        if (!r.ok) {
          return {
            raw: [r],
            records: [limitation('HackerTarget AS', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        const d = typeof r.data === 'string' ? (parseJsonSafely(r.data) || {}) : r.data || {};
        return {
          raw: [r],
          records: [{
            category: 'network',
            type: 'aslookup',
            source: 'HackerTarget AS',
            sourceType: 'public-api',
            observedAt: r.completedAt,
            confidence: 'MEDIUM',
            status: d.asn ? 'FOUND' : 'NO_DATA',
            value: {
              asn: d.asn || null,
              asnName: d.asn_name || null,
              range: d.asn_range || null,
              organization: d.organization || null,
              description: d.description || null
            },
            rawValue: d,
            normalizedValue: null,
            note: 'Independent ASN lookup.',
            requestId: r.requestId
          }]
        };
      }
    },
    reputation: {
      id: 'dnsbl',
      name: 'Public DNSBL Cross-Check',
      category: 'reputation',
      enabled: CONFIG.ENABLE_REPUTATION,
      async execute(ctx) {
        if (ctx.version !== 4) {
          return {
            raw: [],
            records: [limitation('DNSBL', 'UNSUPPORTED', 'Configured blocklists are IPv4-oriented.')]
          };
        }
        const rev = ctx.ip.split('.').reverse().join('.');
        const zones = [
          ['Spamhaus ZEN', `${rev}.zen.spamhaus.org`],
          ['Barracuda Central', `${rev}.b.barracudacentral.org`],
          ['SpamCop', `${rev}.bl.spamcop.net`]
        ];
        const results = await Promise.all(zones.map(async ([name, domain]) => ({
          name,
          result: await requestManager.request(
            `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
            { provider: `DNSBL:${name}`, responseType: 'json' }
          )
        })));
        const records = [];
        for (const { name, result } of results) {
          let status = 'UNKNOWN';
          let evidence = null;
          if (result.ok && result.data) {
            const a = Array.isArray(result.data.Answer) ? result.data.Answer : [];
            if (a.length) {
              status = 'LISTED';
              evidence = a.map(v => v.data).join(', ');
            } else if (result.data.Status === 3) {
              status = 'NOT_LISTED';
            } else if (result.data.Status === 2) {
              status = 'SERVFAIL';
            } else {
              status = 'NO_ANSWER';
            }
          } else {
            status = result.errorType || 'UNKNOWN';
          }
          records.push({
            category: 'reputation',
            type: 'dnsbl',
            source: name,
            sourceType: 'public-dnsbl',
            observedAt: result.completedAt,
            confidence: status === 'LISTED' ? 'HIGH' : status === 'NOT_LISTED' ? 'MEDIUM' : 'LOW',
            status,
            value: { status, evidence },
            rawValue: null,
            normalizedValue: status,
            note: `DNSBL result from ${name}`,
            requestId: result.requestId
          });
        }
        return {
          raw: results.map(x => x.result),
          records
        };
      }
    },
    threat: {
      id: 'threat',
      name: 'OTX AlienVault',
      category: 'threat_intel',
      enabled: CONFIG.ENABLE_THREAT_INTEL,
      async execute(ctx) {
        const r = await requestManager.request(
          `https://otx.alienvault.com/api/v1/indicators/${ctx.version === 4 ? 'IPv4' : 'IPv6'}/${encodeURIComponent(ctx.ip)}/general`,
          { provider: 'OTX AlienVault', responseType: 'json' }
        );
        if (!r.ok) {
          return {
            raw: [r],
            records: [limitation('OTX AlienVault', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        return {
          raw: [r],
          records: [{
            category: 'threat_intel',
            type: 'threat_intel',
            source: 'OTX AlienVault',
            sourceType: 'public-api',
            observedAt: r.completedAt,
            confidence: 'MEDIUM',
            status: 'AVAILABLE',
            value: r.data,
            rawValue: r.data,
            normalizedValue: null,
            note: 'OTX response observed.',
            requestId: r.requestId
          }]
        };
      }
    },
    http: {
      id: 'http',
      name: 'Active HTTP/HTTPS',
      category: 'services',
      enabled: CONFIG.ACTIVE_HTTP_CHECKS,
      async execute(ctx) {
        const raw = [];
        const records = [];
        const schemes = [
          ['http', 80],
          ['https', 443]
        ];
        const results = await Promise.all(schemes.map(async ([scheme, port]) => ({
          scheme,
          port,
          result: await requestManager.request(`${scheme}://${ctx.ip}/`, {
            provider: `HTTP:${scheme}`,
            responseType: 'text'
          })
        })));
        for (const { scheme, port, result } of results) {
          raw.push(result);
          if (!result.ok) {
            records.push(limitation(`HTTP ${scheme.toUpperCase()}`,
              result.errorType || 'UNAVAILABLE',
              result.errorMessage || result.errorType, {
                transport: result.transportStatus,
                provider: result.providerStatus
              }
            ));
            continue;
          }
          const headers = result.headers || {};
          const body = String(result.data || '');
          records.push({
            category: 'services',
            type: 'http',
            source: `active-${scheme}`,
            sourceType: 'observed',
            observedAt: result.completedAt,
            confidence: 'HIGH',
            status: 'OBSERVED',
            value: {
              scheme,
              port,
              status: result.status,
              finalURL: result.finalURL,
              redirected: result.redirected,
              server: headers.server || null,
              contentType: headers['content-type'] || null,
              title: (/<title[^>]*>([\s\S]*?)<\/title>/i.exec(body)?.[1] || '').replace(/\s+/g, ' ').trim() || null,
              technologies: detectTech(headers, body)
            },
            rawValue: CONFIG.ENABLE_HEADER_ANALYSIS ? { headers } : null,
            normalizedValue: null,
            note: 'Direct public web observation through configured proxy.',
            requestId: result.requestId
          });
        }
        return { raw, records };
      }
    },
    tls: {
      id: 'tls',
      name: 'TLS Endpoint',
      category: 'tls',
      enabled: CONFIG.ACTIVE_TLS_CHECKS,
      async execute(ctx) {
        const r = await requestManager.request(`https://${ctx.ip}/`, {
          provider: 'TLS Endpoint',
          responseType: 'text'
        });
        if (!r.ok) {
          return {
            raw: [r],
            records: [limitation('TLS Endpoint', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
          };
        }
        return {
          raw: [r],
          records: [{
            category: 'tls',
            type: 'tls_endpoint',
            source: 'HTTPS Fetch',
            sourceType: 'observed',
            observedAt: r.completedAt,
            confidence: 'MEDIUM',
            status: 'HTTPS_REACHABLE',
            value: {
              reachable: true,
              finalURL: r.finalURL,
              server: r.headers?.server || null,
              hsts: Boolean(r.headers?.['strict-transport-security'])
            },
            rawValue: null,
            normalizedValue: null,
            note: 'HTTPS endpoint responded.',
            requestId: r.requestId
          }]
        };
      }
    },
    ports: {
      id: 'ports',
      name: 'Port Intelligence',
      category: 'ports',
      enabled: CONFIG.ENABLE_PORT_SCAN,
      async execute(ctx) {
        if (CONFIG.OPTIONAL_API_KEYS.shodan) {
          const r = await requestManager.request(
            `https://api.shodan.io/shodan/host/${encodeURIComponent(ctx.ip)}?key=${encodeURIComponent(CONFIG.OPTIONAL_API_KEYS.shodan)}`,
            { provider: 'Shodan', responseType: 'json' }
          );
          if (!r.ok) {
            return {
              raw: [r],
              records: [limitation('Shodan', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
            };
          }
          const ports = Array.isArray(r.data?.ports) ? r.data.ports : [];
          return {
            raw: [r],
            records: [{
              category: 'ports',
              type: 'scan',
              source: 'Shodan',
              sourceType: 'passive-scan',
              observedAt: r.completedAt,
              confidence: 'HIGH',
              status: 'SCANNED',
              value: { ports, openPorts: ports },
              rawValue: null,
              normalizedValue: ports,
              note: 'Passive port observation from Shodan.',
              requestId: r.requestId
            }]
          };
        }
        if (CONFIG.OPTIONAL_API_KEYS.viewdns) {
          const r = await requestManager.request(
            `https://api.viewdns.info/portscan/?host=${encodeURIComponent(ctx.ip)}&apikey=${encodeURIComponent(CONFIG.OPTIONAL_API_KEYS.viewdns)}&output=json`,
            { provider: 'ViewDNS', responseType: 'json' }
          );
          if (!r.ok) {
            return {
              raw: [r],
              records: [limitation('ViewDNS', r.errorType || 'UNAVAILABLE', r.errorMessage || r.errorType)]
            };
          }
          return {
            raw: [r],
            records: [{
              category: 'ports',
              type: 'scan',
              source: 'ViewDNS',
              sourceType: 'active-scan',
              observedAt: r.completedAt,
              confidence: 'MEDIUM',
              status: 'SCANNED',
              value: {
                ports: r.data?.response?.ports || r.data?.ports || [],
                openPorts: r.data?.response?.ports || r.data?.ports || []
              },
              rawValue: null,
              normalizedValue: null,
              note: 'Active port scan.',
              requestId: r.requestId
            }]
          };
        }
        return {
          raw: [],
          records: [limitation('Port Intelligence', 'NOT_CONFIGURED', 'No port-scanning API is configured.')]
        };
      }
    },
    ipStatus: {
      id: 'ip_status',
      name: 'IP Status',
      category: 'ip_status',
      enabled: CONFIG.ENABLE_IP_STATUS,
      async execute(ctx) {
        const sources = [{
          name: 'ProxyCheck',
          endpoint: `https://proxycheck.io/v2/${encodeURIComponent(ctx.ip)}?vpn=1&asn=1&risk=1`
        }];
        const results = await Promise.all(sources.map(async s => ({
          s,
          result: await requestManager.request(s.endpoint, {
            provider: s.name,
            responseType: 'json'
          })
        })));
        const records = [];
        for (const { s, result } of results) {
          if (!result.ok) {
            records.push(limitation(s.name, result.errorType || 'UNAVAILABLE', result.errorMessage || result.errorType));
            continue;
          }
          const d = result.data || {};
          const message = String(d.message || '').toLowerCase();
          const status = String(d.status || '').toLowerCase();
          const providerStatus = /(rate|exhaust|limit|queries exhausted|quota)/.test(`${status} ${message}`) ?
            'RATE_LIMITED' :
            status === 'denied' ? 'DENIED' :
            status === 'ok' || d.success === true ? 'AVAILABLE' :
            'UNKNOWN';
          records.push({
            category: 'ip_status',
            type: 'ip_status',
            source: s.name,
            sourceType: 'public-api',
            observedAt: result.completedAt,
            confidence: providerStatus === 'AVAILABLE' ? 'MEDIUM' : 'LOW',
            status: providerStatus,
            value: d,
            rawValue: null,
            normalizedValue: providerStatus,
            note: `Transport=${result.transportStatus || 'UNKNOWN'} Provider=${providerStatus}`,
            requestId: result.requestId
          });
        }
        return {
          raw: results.map(x => x.result),
          records
        };
      }
    },
    serverStatus: {
      id: 'server_status',
      name: 'Global Server Availability',
      category: 'server_status',
      enabled: CONFIG.ENABLE_SERVER_STATUS,
      async execute() {
        return {
          raw: [],
          records: [limitation('Global Server Availability', 'NOT_CONFIGURED', 'Distributed server checks are not configured.')]
        };
      }
    },
    domainsWhois: {
      id: 'domain_whois',
      name: 'Domain Whois',
      category: 'domain_whois',
      enabled: CONFIG.ENABLE_DOMAIN_WHOIS,
      async execute(ctx) {
        const domains = Array.isArray(ctx.domains) ? ctx.domains : [];
        if (!domains.length) {
          return {
            raw: [],
            records: [limitation('Domain Whois', 'NO_DATA', 'No observed domains were available.')]
          };
        }
        const records = [];
        const raw = [];
        for (const d of domains.slice(0, CONFIG.MAX_DOMAINS_PER_SOURCE)) {
          const r = await requestManager.request(
            `https://api.hackertarget.com/whois/?q=${encodeURIComponent(d)}`,
            { provider: `Whois:${d}`, responseType: 'text' }
          );
          raw.push(r);
          if (r.ok && r.data) {
            records.push({
              category: 'domain_whois',
              type: 'whois',
              source: 'HackerTarget Whois',
              sourceType: 'public-api',
              observedAt: r.completedAt,
              confidence: 'MEDIUM',
              status: 'AVAILABLE',
              value: { domain: d, whois: String(r.data) },
              rawValue: null,
              normalizedValue: null,
              note: 'Public domain WHOIS observation.',
              requestId: r.requestId
            });
          }
        }
        return {
          raw,
          records: records.length ? records : [limitation('Domain Whois', 'NO_DATA', 'No WHOIS response returned.')]
        };
      }
    },
    emails: {
      id: 'email_rep',
      name: 'Email Reputation',
      category: 'email',
      enabled: CONFIG.ENABLE_EMAIL_REP,
      async execute() {
        return {
          raw: [],
          records: [limitation('Email Reputation', 'NOT_CONFIGURED', 'Email reputation is disabled until an authenticated provider is configured.')]
        };
      }
    },
    leaks: {
      id: 'leak',
      name: 'Leak Intelligence',
      category: 'leaked',
      enabled: CONFIG.ENABLE_LEAK_LOOKUP,
      async execute() {
        return {
          raw: [],
          records: [limitation('Leak Intelligence', 'NOT_CONFIGURED', 'Leak intelligence is disabled until an authenticated provider is configured.')]
        };
      }
    }
  };

  const detectTech = (headers, html) => {
    const a = [];
    const server = String(headers?.server || '').toLowerCase();
    const powered = String(headers?.['x-powered-by'] || '').toLowerCase();
    const body = String(html || '').toLowerCase();

    if (server.includes('cloudflare') || headers?.['cf-ray']) a.push('Cloudflare');
    if (server.includes('nginx')) a.push('Nginx');
    if (server.includes('apache')) a.push('Apache');
    if (server.includes('iis')) a.push('IIS');
    if (powered.includes('php')) a.push('PHP');
    if (powered.includes('asp.net')) a.push('ASP.NET');
    if (body.includes('wp-content') || body.includes('wordpress')) a.push('WordPress');
    if (body.includes('/_next/')) a.push('Next.js');
    if (body.includes('react')) a.push('React');
    if (body.includes('vue')) a.push('Vue.js');
    if (body.includes('angular')) a.push('Angular');

    return [...new Set(a)];
  };

  const providers = Object.freeze([
    providersBase.rdap,
    providersBase.ripestatWhois,
    providersBase.ripestatNetwork,
    providersBase.ripestatPrefix,
    providersBase.lookingGlass,
    providersBase.bgplay,
    providersBase.dns,
    providersBase.ct,
    providersBase.bgpview,
    providersBase.reverseIp,
    providersBase.geoHacker,
    providersBase.asHacker,
    providersBase.reputation,
    providersBase.threat,
    providersBase.http,
    providersBase.tls,
    providersBase.ports,
    providersBase.ipStatus,
    providersBase.serverStatus,
    providersBase.domainsWhois,
    providersBase.emails,
    providersBase.leaks,
    ...geoProviders
  ]);

  const classifyProviderResult = result => {
    const records = Array.isArray(result.records) ? result.records : [];
    const lim = records.filter(r => r.category === 'limitation');
    const successRecords = records.filter(r => r.category !== 'limitation' && r.category !== 'diagnostic');
    const statuses = lim.map(r => String(r.status || 'UNAVAILABLE'));
    const raw = Array.isArray(result.raw) ? result.raw : [];
    const attempts = raw.flatMap(r => Array.isArray(r?.attempts) ? r.attempts : [r]).filter(Boolean);
    const errors = attempts.map(a => a.providerStatus || a.errorType).filter(Boolean);

    if (successRecords.length && !lim.length) return 'SUCCESS';
    if (successRecords.length && lim.length) return 'PARTIAL';
    if (statuses.some(s => s === 'RATE_LIMITED') || errors.some(s => s === 'RATE_LIMITED')) return 'RATE_LIMITED';
    if (statuses.some(s => s === 'AUTH_REQUIRED') || errors.some(s => s === 'AUTH_REQUIRED')) return 'AUTH_REQUIRED';
    if (statuses.some(s => s === 'FORBIDDEN') || errors.some(s => s === 'FORBIDDEN')) return 'FORBIDDEN';
    if (statuses.some(s => s === 'INVALID_RESPONSE') || errors.some(s => s === 'INVALID_RESPONSE')) return 'INVALID_RESPONSE';
    if (statuses.some(s => s === 'NOT_CONFIGURED')) return 'NOT_CONFIGURED';
    if (statuses.some(s => s === 'NO_DATA')) return 'NO_DATA';
    return result.ok ? 'PARTIAL' : 'UNAVAILABLE';
  };

  const buildDiagnostics = results => {
    const counts = {
      queried: results.length,
      successful: 0,
      partial: 0,
      rateLimited: 0,
      authRequired: 0,
      invalidResponses: 0,
      unavailable: 0,
      notConfigured: 0
    };
    const issues = [];
    for (const r of results) {
      const health = r.health || classifyProviderResult(r);
      if (health === 'SUCCESS') counts.successful++;
      else if (health === 'PARTIAL') counts.partial++;
      else if (health === 'RATE_LIMITED') {
        counts.rateLimited++;
        issues.push({ provider: r.name, status: health });
      } else if (health === 'AUTH_REQUIRED') {
        counts.authRequired++;
        issues.push({ provider: r.name, status: health });
      } else if (health === 'INVALID_RESPONSE') {
        counts.invalidResponses++;
        issues.push({ provider: r.name, status: health });
      } else if (health === 'NOT_CONFIGURED') {
        counts.notConfigured++;
      } else {
        counts.unavailable++;
      }
      if (['FORBIDDEN', 'NO_DATA'].includes(health)) {
        issues.push({ provider: r.name, status: health });
      }
    }
    return { ...counts, issues };
  };

  const pickRegistration = records => {
    const rdap = records.filter(r => r.category === 'registration' && r.type === 'rdap');
    const preferred = rdap.find(r => r.value?.name && r.value?.startAddress);
    return preferred || rdap[0] || null;
  };

  const buildRegistration = records => {
    const r = pickRegistration(records);
    if (!r) return null;
    const v = r.value || {};
    const entity = Array.isArray(v.entities) ? v.entities.find(e => e?.name)?.name || null : null;
    return {
      registry: v.rir || r.source.replace(/^RDAP:/, ''),
      name: v.name || null,
      handle: v.handle || null,
      organization: entity || v.name || null,
      country: v.country || null,
      startAddress: v.startAddress || null,
      endAddress: v.endAddress || null,
      status: Array.isArray(v.status) ? v.status : [],
      source: r.source
    };
  };

  const buildNetwork = records => {
    const n = records.find(r => r.type === 'ripestat_network') ||
      records.find(r => r.type === 'prefix_overview') ||
      records.find(r => r.type === 'bgp') ||
      records.find(r => r.type === 'aslookup');
    const bgps = records.filter(r => r.category === 'network' && (r.type === 'bgp' || r.type === 'ripestat_network' || r.type === 'aslookup'));
    const asns = [...new Set(bgps.flatMap(r => Array.isArray(r.value?.asns) ? r.value.asns : [r.value?.asn]).filter(Boolean)
      .map(x => typeof x === 'object' ? x.asn : x).map(String)
    )];
    const geo = records.find(r => r.category === 'geolocation' && r.type === 'geo');
    const prefix = n?.value?.prefix || records.map(r => r.value?.prefix).find(Boolean) || null;
    const originSet = [...new Set(records.filter(r => r.type === 'looking_glass').map(r => r.value?.origin).filter(Boolean).map(String))];
    const org = n?.value?.asName || records.find(r => r.type === 'aslookup')?.value?.organization || geo?.value?.organization || null;
    return {
      announced: n?.value?.announced ?? Boolean(prefix || asns.length),
      asn: asns[0] || records.find(r => r.type === 'aslookup')?.value?.asn || geo?.value?.asn || null,
      asns,
      prefix,
      organization: org,
      isp: geo?.value?.isp || null,
      country: geo?.value?.country || null,
      multipleOrigin: asns.length > 1,
      origins: originSet
    };
  };

  const buildRouting = (records, network) => {
    const lg = records.filter(r => r.type === 'looking_glass').map(r => r.value || {});
    const origins = [...new Set(lg.map(x => x.origin).filter(Boolean).map(String))];
    const peers = [...new Set(lg.map(x => x.peer).filter(Boolean))];
    const prefix = lg.map(x => x.prefix).find(Boolean) || network.prefix || null;
    const expected = new Set((network.asns || []).map(String));
    const validation = origins.length && expected.size ?
      origins.some(x => expected.has(String(x))) ? 'CONSISTENT' : 'CONFLICT' :
      origins.length ? 'PARTIAL' : 'UNKNOWN';
    return {
      state: origins.length || prefix ? 'ROUTED' : 'UNKNOWN',
      prefix,
      origins,
      peerCount: peers.length,
      peerList: peers,
      validation
    };
  };

  const buildDNS = records => {
    const ptr = records.filter(r => r.category === 'dns' && r.type === 'ptr')
      .map(r => r.normalizedValue || normalizeDomain(r.value?.value))
      .filter(Boolean);
    const statuses = records.filter(r => r.category === 'dns' && r.type === 'dns_status').map(r => r.value);
    return { ptr: [...new Set(ptr)], statuses };
  };

  const buildCertificates = records => records.filter(r => r.category === 'certificate' && r.type === 'ct').map(r => r.value);

  const buildDomains = (dns, certs, records) => {
    const all = new Set([
      ...dns.ptr,
      ...certs.flatMap(c => c.san || []),
      ...records.filter(r => r.type === 'reverse_ip').flatMap(r => r.value?.domains || [])
    ]);
    return [...all].map(normalizeDomain).filter(Boolean).slice(0, CONFIG.MAX_DOMAINS_PER_SOURCE);
  };

  const consensus = values => {
    const vals = values.filter(Boolean).map(v => String(v));
    if (!vals.length) return { value: null, confidence: 'NONE', conflict: false };
    const c = {};
    for (const v of vals) c[v] = (c[v] || 0) + 1;
    const s = Object.entries(c).sort((a, b) => b[1] - a[1]);
    const [value, count] = s[0];
    const ratio = count / vals.length;
    return {
      value,
      confidence: ratio === 1 && count >= 3 ? 'HIGH' : ratio >= 0.66 ? 'MEDIUM' : ratio >= 0.5 ? 'LOW' : 'NONE',
      conflict: s.length > 1
    };
  };

  const buildGeo = records => {
    const ps = records.filter(r => r.category === 'geolocation').map(r => r.value || {});
    const country = consensus(ps.map(x => x.country));
    const region = consensus(ps.map(x => x.region));
    const city = consensus(ps.map(x => x.city));
    const coords = ps.filter(x => x.latitude !== null && x.longitude !== null);
    const latitude = coords.length ? coords.reduce((a, x) => a + Number(x.latitude), 0) / coords.length : null;
    const longitude = coords.length ? coords.reduce((a, x) => a + Number(x.longitude), 0) / coords.length : null;
    return {
      providers: ps,
      consensus: {
        country: country.value,
        region: region.value,
        city: city.value,
        latitude,
        longitude,
        confidence: country.confidence,
        conflict: country.conflict || region.conflict || city.conflict,
        status: country.value && city.value && !country.conflict ? 'CONSENSUS' : 'PARTIAL_CONSENSUS'
      }
    };
  };

  const buildHistory = records => {
    const events = records.filter(r => r.category === 'history' && r.type === 'bgplay')
      .flatMap(r => r.value?.events || [])
      .filter(e => e.timestamp);
    const sorted = events.slice().sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const first = sorted[0]?.timestamp || null;
    const last = sorted.at(-1)?.timestamp || null;
    const unique = [...new Set(sorted.map(e => new Date(e.timestamp).toISOString().slice(0, 16)))];
    const states = [];
    let prev = null;
    for (const e of sorted) {
      const key = JSON.stringify({
        origin: e.origin || null,
        path: e.path || null,
        prefix: e.prefix || null
      });
      if (key !== prev) {
        states.push({
          timestamp: e.timestamp,
          origin: e.origin || null,
          path: e.path || null,
          prefix: e.prefix || null,
          type: e.type || null
        });
        prev = key;
      }
    }
    return {
      status: events.length ? 'AVAILABLE' : 'UNAVAILABLE',
      eventCount: events.length,
      firstSeen: first,
      lastSeen: last,
      uniqueTimestamps: unique.length,
      sources: [...new Set(records.filter(r => r.category === 'history').map(r => r.source))],
      transitions: states.slice(0, 50),
      rawEvents: events
    };
  };

  const buildAvailability = records => {
    const web = records.filter(r => r.category === 'services' && r.type === 'http').map(r => r.value || {});
    const http = web.filter(x => x.scheme === 'http');
    const https = web.filter(x => x.scheme === 'https');
    return {
      http: http.length ? 'REACHABLE' : 'NOT_OBSERVED',
      https: https.length ? 'REACHABLE' : 'NOT_OBSERVED',
      publicWeb: http.length || https.length ? 'CONFIRMED' : 'NOT_CONFIRMED'
    };
  };

  const buildReputation = records => records.filter(r => r.category === 'reputation').map(r => ({
    source: r.source,
    status: r.value?.status || r.status,
    evidence: r.value?.evidence || null
  }));

  const buildThreat = records => records.filter(r => r.category === 'threat_intel').map(r => ({
    source: r.source,
    status: r.status,
    value: r.value
  }));

  const buildPorts = records => {
    const scans = records.filter(r => r.category === 'ports' && r.type === 'scan');
    const configured = scans.some(r => !['NOT_CONFIGURED', 'NO_DATA'].includes(r.status));
    const open = [...new Set(scans.flatMap(r => r.value?.openPorts || r.value?.ports || []).map(Number).filter(Number.isFinite))];
    return {
      status: configured ? 'SCANNED' : 'NOT_CONFIGURED',
      openPorts: open,
      scans: scans.map(r => ({ source: r.source, status: r.status, ports: r.value?.ports || [] }))
    };
  };

  const buildIpStatus = records => records.filter(r => r.category === 'ip_status').map(r => ({
    source: r.source,
    status: r.status,
    transport: r.metadata?.transport || null,
    data: r.value
  }));

  const normalizeText = v => String(v || '').toLowerCase().replace(/[^a-z0-9]+/g, '');

  const buildCrossValidation = (canonical) => {
    const out = [];
    const reg = normalizeText(canonical.registration?.organization);
    const org = normalizeText(canonical.network.organization);
    if (reg && org) {
      out.push({ name: 'Registration ↔ BGP', status: reg === org ? 'CONSISTENT' : 'CONFLICT' });
    } else {
      out.push({ name: 'Registration ↔ BGP', status: 'UNKNOWN' });
    }
    out.push({ name: 'Geolocation', status: canonical.geolocation.consensus.status });
    out.push({ name: 'BGP Origin', status: canonical.routing.validation });
    const listed = canonical.reputation.filter(x => x.status === 'LISTED').length;
    out.push({ name: 'Reputation', status: listed ? 'FLAGGED' : 'NOT_FLAGGED' });
    return out;
  };

  const buildFindings = canonical => {
    const f = [];
    if (canonical.network.asn || canonical.network.prefix) f.push({ name: 'Network identity', status: 'CONFIRMED' });
    if (canonical.registration?.organization) f.push({ name: 'Registration', status: 'CONFIRMED' });
    if (canonical.dns.ptr.length) f.push({ name: 'Reverse DNS', status: 'CONFIRMED' });
    if (canonical.certificates.length) f.push({ name: 'Certificate association', status: 'OBSERVED' });
    if (canonical.availability.publicWeb === 'CONFIRMED') f.push({ name: 'Public Web Service', status: 'CONFIRMED' });
    else f.push({ name: 'Public Web Service', status: 'NOT_CONFIRMED' });
    if (canonical.ports.openPorts.length) f.push({ name: 'Open Ports', status: 'OBSERVED' });
    else if (canonical.ports.status === 'SCANNED') f.push({ name: 'Open Ports', status: 'NONE_OBSERVED' });
    f.push({ name: 'Person Attribution', status: 'NOT_ESTABLISHED' });
    return f;
  };

  const buildCanonical = (ctx, store, results) => {
    const records = store.all();
    const registration = buildRegistration(records);
    const network = buildNetwork(records);
    const routing = buildRouting(records, network);
    const dns = buildDNS(records);
    const certificates = buildCertificates(records);
    const domains = buildDomains(dns, certificates, records);
    const geo = buildGeo(records);
    const history = buildHistory(records);
    const availability = buildAvailability(records);
    const reputation = buildReputation(records);
    const threat = buildThreat(records);
    const ports = buildPorts(records);
    const ipStatus = buildIpStatus(records);
    const diagnostics = buildDiagnostics(results);

    const canonical = {
      target: ctx,
      registration,
      network,
      routing,
      dns,
      certificates,
      domains,
      geolocation: geo,
      reputation,
      threat,
      availability,
      ports,
      ipStatus,
      history,
      diagnostics,
      sourceObservations: new Set(records.filter(r => r.category !== 'limitation').map(r => r.source)).size
    };
    canonical.crossValidation = buildCrossValidation(canonical);
    canonical.findings = buildFindings(canonical);
    canonical.limitations = records.filter(r => r.category === 'limitation');
    return canonical;
  };

  const runProvider = async (provider, ctx, store) => {
    try {
      const result = await provider.execute(ctx);
      (result.records || []).forEach(r => store.add(r));
      return {
        id: provider.id,
        name: provider.name,
        category: provider.category,
        ok: true,
        raw: result.raw || [],
        records: result.records || [],
        health: classifyProviderResult({ ok: true, ...result })
      };
    } catch (e) {
      const r = limitation(provider.name, 'PROVIDER_ERROR', e?.message || String(e));
      store.add(r);
      return {
        id: provider.id,
        name: provider.name,
        category: provider.category,
        ok: false,
        raw: [],
        records: [r],
        health: 'UNAVAILABLE',
        error: {
          type: 'PROVIDER_ERROR',
          message: e?.message || String(e)
        }
      };
    }
  };

  const scan = async ctx => {
    const store = new EvidenceStore();
    const enabled = providers.filter(p => p.enabled !== false);
    const results = await Promise.all(enabled.map(p => runProvider(p, ctx, store)));
    const canonical = buildCanonical(ctx, store, results);
    return {
      canonical,
      providers: results,
      evidenceCount: store.size()
    };
  };

  const node = (label, value = null, children = [], cls = 'output') => ({ label, value, children, cls });

  const renderTree = (nodes, prefix = '') => {
    const out = [];
    nodes.forEach((n, i) => {
      const last = i === nodes.length - 1;
      const branch = last ? '└── ' : '├── ';
      const next = prefix + (last ? '    ' : '│   ');
      const text = n.value === null || n.value === undefined || n.value === '' ?
        n.label :
        `${n.label}: ${n.value}`;
      out.push(line(prefix + branch + text, n.cls || 'output'));
      if (n.children?.length) out.push(...renderTree(n.children, next));
    });
    return out;
  };

  const fmtDate = v => v ? new Date(v).toISOString().replace('T', ' ').slice(0, 16) : 'Unknown';

  const reportTree = (c, verbose = false) => {
    const p = c.proxy || { total: 0, active: 0 };
    const d = c.diagnostics;
    const h = c.history;
    const r = c.routing;

    const main = [
      node('Target', null, [
        node('IP', c.target.ip, '', 'cyan-light'),
        node('Version', c.target.version === 4 ? 'IPv4' : 'IPv6', '', 'cyan-light'),
        node('Type', c.target.type, '', 'cyan-light')
      ]),
      node('Proxy', null, [
        node('Required', CONFIG.REQUIRE_PROXY ? 'YES' : 'NO'),
        node('Pool', p.total),
        node('Available', p.active),
        node('Healthy', p.active),
        node('Status', p.active ? 'READY' : 'DEGRADED')
      ]),
      node('Sources', null, [
        node('Queried', d.queried),
        node('Successful', d.successful),
        node('Partial', d.partial),
        node('Rate Limited', d.rateLimited),
        node('Auth Required', d.authRequired),
        node('Invalid Responses', d.invalidResponses),
        node('Unavailable', d.unavailable)
      ]),
      node('Network Identity', null, [
        node('Announced', c.network.announced ? 'YES' : 'UNKNOWN'),
        node('ASN', c.network.asn || 'UNKNOWN'),
        node('Prefix', c.network.prefix || 'UNKNOWN'),
        node('Organization', c.network.organization || 'UNKNOWN'),
        node('ISP', c.network.isp || c.network.organization || 'UNKNOWN'),
        node('Country', c.network.country || 'UNKNOWN'),
        node('Multiple Origin', c.network.multipleOrigin ? 'YES' : 'NO')
      ]),
      node('Routing', null, [
        node('State', r.state),
        node('Prefix', r.prefix || 'UNKNOWN'),
        node('Origins', r.origins.join(', ') || 'UNKNOWN'),
        node('Peer Count', r.peerCount),
        node('BGP Validation', r.validation)
      ]),
      node('Registration', null, [
        node('Registry', c.registration?.registry || 'UNKNOWN'),
        node('Range', c.registration?.startAddress && c.registration?.endAddress ?
          `${c.registration.startAddress} - ${c.registration.endAddress}` :
          'UNKNOWN'),
        node('Organization', c.registration?.organization || 'UNKNOWN'),
        node('Status', c.registration?.status?.join(', ') || 'UNKNOWN')
      ]),
      node('DNS', null, [
        node('PTR', c.dns.ptr.join(', ') || 'None'),
        node('Related Domains', c.domains.length ? c.domains.join(', ') : 'None')
      ]),
      node('TLS / Certificates', null, [
        node('CT Entries', c.certificates.length)
      ]),
      node('Geolocation', null, [
        node('Country', c.geolocation.consensus.country || 'UNKNOWN'),
        node('Region', c.geolocation.consensus.region || 'UNKNOWN'),
        node('City', c.geolocation.consensus.city || 'UNKNOWN'),
        node('Coordinates', c.geolocation.consensus.latitude !== null && c.geolocation.consensus.longitude !== null ?
          `${c.geolocation.consensus.latitude}, ${c.geolocation.consensus.longitude}` :
          'UNKNOWN'),
        node('Confidence', c.geolocation.consensus.confidence),
        node('Provider Consensus', c.geolocation.consensus.status)
      ]),
      node('IP Reputation', null, c.reputation.map(x => node(x.source, x.status))),
      node('Threat Intelligence', null, c.threat.map(x => node(x.source, x.status))),
      node('Public Web Service', null, [
        node('HTTP', c.availability.http),
        node('HTTPS', c.availability.https),
        node('Status', c.availability.publicWeb)
      ]),
      node('Ports / Services', null, [
        node('Status', c.ports.status),
        node('Open Ports', c.ports.openPorts.length ? c.ports.openPorts.join(', ') : 'None observed')
      ]),
      node('IP Status', null, c.ipStatus.map(x => node(x.source, x.status))),
      node('IP History', null, [
        node('Status', h.status),
        node('BGP Events', h.eventCount),
        node('First Seen', fmtDate(h.firstSeen)),
        node('Last Seen', fmtDate(h.lastSeen)),
        node('Unique Timestamps', h.uniqueTimestamps),
        node('Sources', h.sources.join(', ') || 'None')
      ]),
      node('Cross Validation', null, c.crossValidation.map(x => node(x.name, x.status))),
      node('Findings', null, c.findings.map(x =>
        node(x.name, x.status,
          x.status === 'NOT_ESTABLISHED' ? [] : '',
          x.status === 'CONFIRMED' ? 'success' :
          x.status === 'NOT_ESTABLISHED' ? 'muted' : 'output'
        )
      )),
      node('Attribution', null, [
        node('Network Attribution', c.network.asn ?
          `${c.network.asn} / ${c.network.organization || 'UNKNOWN'}` :
          'NOT_ESTABLISHED'),
        node('Person Attribution', 'NOT_ESTABLISHED')
      ])
    ];

    if (h.transitions.length) {
      main.push(node('BGP History', null,
        h.transitions.slice(0, 20).map(t =>
          node(fmtDate(t.timestamp), null, [
            node('Origin', t.origin || 'UNKNOWN'),
            node('Type', t.type || 'UNKNOWN')
          ])
        )
      ));
    }

    if (verbose) {
      main.push(node('Source Details', null,
        c.diagnostics.issues.map(x => node(x.provider, x.status))
      ));
      main.push(node('Peer Details', null,
        c.routing.peerList.slice(0, CONFIG.MAX_RECORDS_PER_SECTION).map(x => node(String(x)))
      ));
      main.push(node('Geolocation Providers', null,
        c.geolocation.providers.map(x =>
          node(x.source, [x.country, x.region, x.city].filter(Boolean).join(', ') || 'UNKNOWN')
        )
      ));
      main.push(node('Provider Diagnostics', null,
        c.diagnostics.issues.map(x => node(x.provider, x.status))
      ));
    }

    return main;
  };

  const renderReport = (c, verbose = false) => [
    line('IP OSINT', 'accent'),
    line(`Target: ${c.target.ip}`, 'cyan-light'),
    line(`Evidence Observations: ${c.sourceObservations}`, 'muted'),
    spacer(),
    ...renderTree(reportTree(c, verbose))
  ];

  const proxyInfo = (verbose = false) => {
    const proxies = state.workingProxies || [];
    const out = [
      line('Proxy', 'accent'),
      line(`Required: ${CONFIG.REQUIRE_PROXY ? 'YES' : 'NO'}`),
      line(`Pool: ${proxies.length}`),
      line(`Available: ${proxies.length}`),
      line(`Healthy: ${proxies.length}`),
      line(`Status: ${proxies.length ? 'READY' : 'DEGRADED'}`)
    ];
    if (verbose && proxies.length) {
      const details = proxies.map((p, i) =>
        node(`${i+1}. ${p.name || 'proxy'}`, p.template)
      );
      out.push(...renderTree([node('Proxy Details', null, details)]));
    }
    return out;
  };

  const help = () => [
    line(`Package: ${manifest.name}`, 'accent'),
    line(`Version: ${manifest.version}`),
    line(`Usage: ${PKG} <ip-address>`, 'user'),
    line(`       ${PKG} scan <ip-address>`, 'user'),
    line(`       ${PKG} proxy [--verbose]`, 'user'),
    line(`       ${PKG} selftest [--verbose]`, 'user'),
    line(`       ${PKG} providers`, 'user'),
    line(`       ${PKG} info`, 'user'),
    line(`       ${PKG} setproxy <template>`, 'user'),
    spacer(),
    line(`Proxy required: ${CONFIG.REQUIRE_PROXY ? 'yes' : 'no'}`),
    line(`Direct fallback: ${CONFIG.ALLOW_DIRECT_FALLBACK ? 'yes' : 'no'}`)
  ];

  const info = () => [
    line('Package Information', 'accent'),
    line(`Name: ${manifest.name}`),
    line(`Version: ${manifest.version}`),
    line(`Mode: ${getMode()}`),
    line(`Providers: ${providers.length}`),
    line(`Proxy Pool: ${state.workingProxies.length}`),
    line(`Active Proxies: ${state.workingProxies.length}`),
    line(`Cache Entries: ${requestManager.cache.size()}`)
  ];

  const providersInfo = () => [
    line('Provider Registry', 'accent'),
    ...providers.map(p =>
      line(`[${p.enabled === false ? 'OFF' : 'ON '}] ${p.id} :: ${p.name} :: ${p.category}`,
        p.enabled === false ? 'muted' : 'output'
      )
    ),
    line(`Total: ${providers.length}`, 'success')
  ];

  const selftest = () => {
    const out = [];
    let ok = true;
    const check = (n, c, v = '') => {
      if (!c) ok = false;
      out.push(line(`[${c ? 'PASS' : 'FAIL'}] ${n}${v ? ` - ${v}` : ''}`, c ? 'success' : 'danger'));
    };
    check('Package bridge', Boolean(state.api));
    check('Manifest', manifest.name === PKG);
    check('IPv4', isValidIPv4('8.8.8.8'));
    check('IPv6', isValidIPv6('2001:4860:4860::8888'));
    check('Proxy pool', state.workingProxies.length > 0, String(state.workingProxies.length));
    check('Proxy availability', state.workingProxies.length > 0, String(state.workingProxies.length));
    check('Request manager', typeof requestManager.request === 'function');
    check('Provider registry', providers.length > 0, String(providers.length));
    out.push(line(`Result: ${ok ? 'PASS' : 'FAIL'}`, ok ? 'success' : 'danger'));
    return out;
  };

  const cmdSetProxy = async ({ args }) => {
    if (!args[1]) return [line('Usage: ipscan setproxy <template>', 'danger')];
    const template = args[1].trim();
    if (!template || !template.includes('{url}')) {
      return [line('Invalid proxy template. Must contain "{url}" placeholder.', 'danger')];
    }
    state.customProxy = template;
    state.workingProxies = [];
    state.proxyReady = false;
    return [
      line('Custom proxy set successfully.', 'accent'),
      line(`Template: ${template}`, 'muted'),
      line('It will be tested and added to the working proxy list on next request.', 'muted')
    ];
  };

  const runCommand = async ({ args = [] } = {}) => {
    const input = Array.isArray(args) ? args.map(x => String(x ?? '').trim()).filter(Boolean) : [];
    const debug = input.includes('--debug') || input.includes('--verbose');
    const clean = input.filter(x => x !== '--debug' && x !== '--verbose');
    const first = String(clean[0] || '').toLowerCase();

    if (!first || ['help', '--help', '-h'].includes(first)) return help();
    if (first === 'info') return info();
    if (first === 'providers') return providersInfo();
    if (first === 'selftest') return selftest();
    if (first === 'proxy') return proxyInfo(debug);
    if (first === 'setproxy') return cmdSetProxy({ args: clean });

    const target = first === 'scan' ? clean[1] : clean[0];
    if (!target) return help();

    try {
      await prepareProxyList();
      const ctx = validateTarget(target);
      const result = await scan(ctx);
      if (debug) {
        line(`[debug] providers=${result.providers.length} observations=${result.evidenceCount}`, 'muted');
      }
      return renderReport(result.canonical, debug);
    } catch (e) {
      return [
        line(`${PKG}: ${e.message || 'analysis failed'}`, 'danger'),
        line(`Use "${manifest.help}" for usage.`, 'muted')
      ];
    }
  };

  const COMMAND = Object.freeze({
    name: PKG,
    description: 'Structured defensive IP intelligence analysis with normalized reporting and separated diagnostics.',
    usage: `${PKG} <ip-address> | ${PKG} scan <ip-address> | ${PKG} proxy | ${PKG} selftest | ${PKG} setproxy <template>`,
    aliases: Object.freeze(['iposint', 'ipintel', 'ipinfox']),
    kind: 'async',
    run: runCommand
  });

  const validateApi = api => {
    if (!api || typeof api !== 'object') throw new Error('PACKAGE_BRIDGE_UNAVAILABLE');
    for (const m of ['registerCommand', 'unregisterCommand', 'line', 'spacer', 'snapshot', 'getMode']) {
      if (typeof api[m] !== 'function') {
        throw new Error(`PACKAGE_BRIDGE_${m.toUpperCase()}_UNAVAILABLE`);
      }
    }
  };

  const install = async api => {
    validateApi(api);
    state.api = api;
    const snap = getSnapshot();
    const registered = Array.isArray(snap?.commands) && snap.commands.includes(COMMAND.name);
    const installed = Array.isArray(snap?.installed) && snap.installed.includes(PKG);
    if (registered && installed) {
      state.installed = true;
      return [];
    }
    try {
      const r = api.registerCommand(COMMAND.name, {
        description: COMMAND.description,
        usage: COMMAND.usage,
        aliases: COMMAND.aliases,
        kind: COMMAND.kind,
        run: COMMAND.run
      }, { source: 'package', packageKey: PKG });
      if (r === false) throw new Error('PACKAGE_COMMAND_REGISTRATION_FAILED');
      state.installed = true;
      return [];
    } catch {
      try { api.unregisterCommand(COMMAND.name); } catch {}
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
      requestManager.cache.clear();
    }
    return [];
  };

  globalThis[GLOBAL_KEY] = Object.freeze({
    manifest,
    install,
    uninstall
  });
})();