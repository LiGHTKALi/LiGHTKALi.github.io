(function() {
  'use strict';

  const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.52",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0"
  ];

  const PRIMARY_PROXIES = [
    { name: 'primary-https', template: 'https://proxy.kalilightstudio.workers.dev/?url={url}' },
    { name: 'primary-http', template: 'http://proxy.kalilightstudio.workers.dev/?url={url}' },
    { name: 'primary-www-http', template: 'http://www.proxy.kalilightstudio.workers.dev/?url={url}' },
    { name: 'primary-www-https', template: 'https://www.proxy.kalilightstudio.workers.dev/?url={url}' }
  ];

const FALLBACK_PROXIES = [
  { name: 'corsproxy.io (query)', template: 'https://corsproxy.io/?{url}' },
  { name: 'allorigins.win (raw)', template: 'https://api.allorigins.win/raw?url={url}' },
  { name: 'cloudflare-cors-anywhere (worker)', template: 'https://cloudflare-cors-anywhere.queakchannel42.workers.dev/?{url}' },
  { name: 'cors-proxy.htmldriven.com', template: 'https://cors-proxy.htmldriven.com/?url={url}' },
  { name: 'api.codetabs.com', template: 'https://api.codetabs.com/v1/proxy?quest={url}' },
  { name: 'cors.lol (api)', template: 'https://api.cors.lol/?url={url}' },
  { name: 'whateverorigin.org', template: 'https://whateverorigin.org/get?url={url}' },
  { name: 'proxy.cors.sh', template: 'https://proxy.cors.sh/{url}' },
  { name: 'cors-anywhere.herokuapp.com', template: 'https://cors-anywhere.herokuapp.com/{url}' },
  { name: 'thingproxy.freeboard.io', template: 'https://thingproxy.freeboard.io/fetch/{url}' },
  { name: 'cors.bridged.cc', template: 'https://cors.bridged.cc/{url}' },
  { name: 'yacdn.org', template: 'https://yacdn.org/proxy/{url}' },
  { name: 'cors.x2u.in', template: 'https://cors.x2u.in/{url}' },
  { name: 'corsproxy.io (path)', template: 'https://corsproxy.io/{url}' },
  { name: 'cors.sh', template: 'https://cors.sh/{url}' },
  { name: 'corsfix.com', template: 'https://corsfix.com/{url}' },
  { name: 'thebugging.com', template: 'https://thebugging.com/cors/{url}' },
  { name: 'corsproxy.io/get', template: 'https://corsproxy.io/get/{url}' },
  { name: 'corsproxy.io/fetch', template: 'https://corsproxy.io/fetch/{url}' },
  { name: 'corsproxy.io/api', template: 'https://corsproxy.io/api/{url}' },
  { name: 'allorigins.win (get)', template: 'https://api.allorigins.win/get?url={url}' },
  { name: 'allorigins.win (json)', template: 'https://api.allorigins.win/json?url={url}' },
  { name: 'cors-anywhere.queakchannel42', template: 'https://cors-anywhere.queakchannel42.workers.dev/?{url}' },
  { name: 'cors-anywhere.onrender.com', template: 'https://cors-anywhere.onrender.com/{url}' },
  { name: 'cors-proxy.cyclic.app', template: 'https://cors-proxy.cyclic.app/{url}' },
  { name: 'cors-bypass.herokuapp.com', template: 'https://cors-bypass.herokuapp.com/{url}' },
  { name: 'proxy.cors.sh/api', template: 'https://proxy.cors.sh/api/{url}' },
  { name: 'cors.lol/proxy', template: 'https://cors.lol/proxy/{url}' },
  { name: 'crossorigin.me', template: 'https://crossorigin.me/{url}' },
  { name: 'cors-relay.herokuapp.com', template: 'https://cors-relay.herokuapp.com/{url}' },
  { name: 'corsproxy.io/proxy', template: 'https://corsproxy.io/proxy/{url}' },
  { name: 'corsproxy.io/request', template: 'https://corsproxy.io/request/{url}' },
  { name: 'cors-anywhere.glitch.me', template: 'https://cors-anywhere.glitch.me/{url}' },
  { name: 'cors-anywhere.vercel.app', template: 'https://cors-anywhere.vercel.app/{url}' },
  { name: 'cors-proxy.vercel.app', template: 'https://cors-proxy.vercel.app/{url}' },
  { name: 'cors-anywhere.cyclic.app', template: 'https://cors-anywhere.cyclic.app/{url}' },
  { name: 'cors-bypass.herokuapp.com/proxy', template: 'https://cors-bypass.herokuapp.com/proxy/{url}' },
  { name: 'cors-relay.herokuapp.com/fetch', template: 'https://cors-relay.herokuapp.com/fetch/{url}' },
  { name: 'crossorigin.me/fetch', template: 'https://crossorigin.me/fetch/{url}' },
  { name: 'thingproxy.freeboard.io/get', template: 'https://thingproxy.freeboard.io/get/{url}' },
  { name: 'cors.bridged.cc/proxy', template: 'https://cors.bridged.cc/proxy/{url}' },
  { name: 'yacdn.org/fetch', template: 'https://yacdn.org/fetch/{url}' },
  { name: 'cors.x2u.in/fetch', template: 'https://cors.x2u.in/fetch/{url}' },
  { name: 'corsfix.com/get', template: 'https://corsfix.com/get/{url}' },
  { name: 'thebugging.com/proxy', template: 'https://thebugging.com/proxy/{url}' },
  { name: 'allorigins.win/proxy', template: 'https://api.allorigins.win/proxy?url={url}' },
  { name: 'cors.lol/get', template: 'https://cors.lol/get?url={url}' },
  { name: 'proxy.cors.sh/fetch', template: 'https://proxy.cors.sh/fetch/{url}' },
  { name: 'cors.sh/get', template: 'https://cors.sh/get/{url}' },
  { name: 'cors-anywhere.workers.dev', template: 'https://cors-anywhere.workers.dev/?{url}' },
  { name: 'cors-proxy.herokuapp.com', template: 'https://cors-proxy.herokuapp.com/{url}' },
  { name: 'cors-proxy.herokuapp.com/get', template: 'https://cors-proxy.herokuapp.com/get/{url}' },
  { name: 'cors-proxy.herokuapp.com/fetch', template: 'https://cors-proxy.herokuapp.com/fetch/{url}' },
  { name: 'corsproxy.herokuapp.com', template: 'https://corsproxy.herokuapp.com/{url}' },
  { name: 'corsproxy.herokuapp.com/proxy', template: 'https://corsproxy.herokuapp.com/proxy/{url}' },
  { name: 'cors-proxy.onrender.com', template: 'https://cors-proxy.onrender.com/{url}' },
  { name: 'cors-proxy.onrender.com/get', template: 'https://cors-proxy.onrender.com/get/{url}' },
  { name: 'cors-proxy.glitch.me', template: 'https://cors-proxy.glitch.me/{url}' },
  { name: 'cors-proxy.glitch.me/fetch', template: 'https://cors-proxy.glitch.me/fetch/{url}' },
  { name: 'corsproxy.vercel.app', template: 'https://corsproxy.vercel.app/{url}' },
  { name: 'corsproxy.vercel.app/api', template: 'https://corsproxy.vercel.app/api/{url}' },
  { name: 'cors-proxy.workers.dev', template: 'https://cors-proxy.workers.dev/{url}' },
  { name: 'cors-proxy.workers.dev/get', template: 'https://cors-proxy.workers.dev/get/{url}' },
  { name: 'corsproxy.workers.dev', template: 'https://corsproxy.workers.dev/{url}' },
  { name: 'corsproxy.workers.dev/fetch', template: 'https://corsproxy.workers.dev/fetch/{url}' },
  { name: 'cors-anywhere.eu.org', template: 'https://cors-anywhere.eu.org/{url}' },
  { name: 'cors-anywhere.eu.org/proxy', template: 'https://cors-anywhere.eu.org/proxy/{url}' },
  { name: 'cors-proxy.eu.org', template: 'https://cors-proxy.eu.org/{url}' },
  { name: 'cors-proxy.eu.org/get', template: 'https://cors-proxy.eu.org/get/{url}' },
  { name: 'corsproxy.eu.org', template: 'https://corsproxy.eu.org/{url}' },
  { name: 'corsproxy.eu.org/fetch', template: 'https://corsproxy.eu.org/fetch/{url}' },
  { name: 'cors.5apps.com', template: 'https://cors.5apps.com/{url}' },
  { name: 'cors.5apps.com/get', template: 'https://cors.5apps.com/get/{url}' },
  { name: 'cors.nova.workers.dev', template: 'https://cors.nova.workers.dev/{url}' },
  { name: 'cors.nova.workers.dev/get', template: 'https://cors.nova.workers.dev/get/{url}' },
  { name: 'corsproxy.cyclic.app', template: 'https://corsproxy.cyclic.app/{url}' },
  { name: 'corsproxy.cyclic.app/proxy', template: 'https://corsproxy.cyclic.app/proxy/{url}' },
  { name: 'cors-anywhere.herokuapp.com/get', template: 'https://cors-anywhere.herokuapp.com/get/{url}' },
  { name: 'cors-anywhere.herokuapp.com/fetch', template: 'https://cors-anywhere.herokuapp.com/fetch/{url}' },
  { name: 'cors-anywhere.herokuapp.com/proxy', template: 'https://cors-anywhere.herokuapp.com/proxy/{url}' },
  { name: 'cors-anywhere.cyclic.app/get', template: 'https://cors-anywhere.cyclic.app/get/{url}' },
  { name: 'cors-anywhere.cyclic.app/fetch', template: 'https://cors-anywhere.cyclic.app/fetch/{url}' },
  { name: 'cors-anywhere.cyclic.app/proxy', template: 'https://cors-anywhere.cyclic.app/proxy/{url}' },
  { name: 'cors-anywhere.onrender.com/get', template: 'https://cors-anywhere.onrender.com/get/{url}' },
  { name: 'cors-anywhere.onrender.com/fetch', template: 'https://cors-anywhere.onrender.com/fetch/{url}' },
  { name: 'cors-anywhere.onrender.com/proxy', template: 'https://cors-anywhere.onrender.com/proxy/{url}' },
  { name: 'cors-anywhere.vercel.app/get', template: 'https://cors-anywhere.vercel.app/get/{url}' },
  { name: 'cors-anywhere.vercel.app/fetch', template: 'https://cors-anywhere.vercel.app/fetch/{url}' },
  { name: 'cors-anywhere.vercel.app/proxy', template: 'https://cors-anywhere.vercel.app/proxy/{url}' },
  { name: 'cors-anywhere.glitch.me/get', template: 'https://cors-anywhere.glitch.me/get/{url}' },
  { name: 'cors-anywhere.glitch.me/fetch', template: 'https://cors-anywhere.glitch.me/fetch/{url}' },
  { name: 'cors-anywhere.glitch.me/proxy', template: 'https://cors-anywhere.glitch.me/proxy/{url}' },
  { name: 'cors-anywhere.workers.dev/get', template: 'https://cors-anywhere.workers.dev/get/{url}' },
  { name: 'cors-anywhere.workers.dev/fetch', template: 'https://cors-anywhere.workers.dev/fetch/{url}' },
  { name: 'cors-anywhere.workers.dev/proxy', template: 'https://cors-anywhere.workers.dev/proxy/{url}' },
  { name: 'cloudflare-cors-anywhere.queakchannel42.workers.dev/get', template: 'https://cloudflare-cors-anywhere.queakchannel42.workers.dev/get/{url}' },
  { name: 'cloudflare-cors-anywhere.queakchannel42.workers.dev/fetch', template: 'https://cloudflare-cors-anywhere.queakchannel42.workers.dev/fetch/{url}' },
  { name: 'proxy.cors.sh/raw', template: 'https://proxy.cors.sh/raw/{url}' },
  { name: 'cors.sh/raw', template: 'https://cors.sh/raw/{url}' },
  { name: 'cors.lol/raw', template: 'https://cors.lol/raw/{url}' }
];

  const PROXIES = [...PRIMARY_PROXIES, ...FALLBACK_PROXIES];
  let workingProxies = [];
  let initialized = false;

  async function testProxy(proxy, testUrl, timeoutMs) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const url = proxy.template.replace('{url}', encodeURIComponent(testUrl));
      const res = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        mode: 'cors'
      });
      clearTimeout(timer);
      return res.ok || res.status === 403;
    } catch {
      return false;
    }
  }

  async function scanProxies() {
    const testUrl = 'https://LightKali.github.io';
    const start = Date.now();
    
    const primaryPromises = PRIMARY_PROXIES.map(proxy => 
      testProxy(proxy, testUrl, 5000).then(ok => ok ? proxy : null)
    );
    
    const primaryResults = await Promise.all(primaryPromises);
    const primaryWorking = primaryResults.filter(p => p !== null);

    if (primaryWorking.length > 0) {
      workingProxies = primaryWorking;
      initialized = true;
      console.log(`FreeUserProxy: ${workingProxies.length} primary proxies working (${Date.now() - start}ms)`);
      return;
    }

    console.warn('FreeUserProxy: Primary proxies failed after 5s. Scanning fallbacks...');
    const fallbackPromises = FALLBACK_PROXIES.map(proxy => 
      testProxy(proxy, testUrl, 3000).then(ok => ok ? proxy : null)
    );
    
    const fallbackResults = await Promise.all(fallbackPromises);
    workingProxies = fallbackResults.filter(p => p !== null);
    initialized = true;
    console.log(`FreeUserProxy: ${workingProxies.length} fallback proxies working. Total time: ${Date.now() - start}ms`);
  }

  const FreeUserProxy = {
    userAgents: USER_AGENTS,
    proxies: PROXIES,
    getRandomUserAgent() {
      return this.userAgents[Math.floor(Math.random() * this.userAgents.length)];
    },
    getAllProxies() {
      return PROXIES;
    },
    getWorkingProxies() {
      return workingProxies || [];
    },
    getRandomWorkingProxy() {
      const list = this.getWorkingProxies();
      if (list.length === 0) return null;
      return list[Math.floor(Math.random() * list.length)];
    },
    isAvailable() {
      return initialized && workingProxies.length > 0;
    }
  };

  scanProxies();

  window.__FreeUserProxy = FreeUserProxy;
  if (typeof globalThis !== 'undefined') {
    globalThis.__FreeUserProxy = FreeUserProxy;
  }
})();