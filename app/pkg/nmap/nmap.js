(() => {
  'use strict';
  const manifest = Object.freeze({
    name: 'nmap',
    version: '4.3.0',
    description: 'Ultra-fast browser network scanner with HTTP probing, text-file discovery and CORS analysis',
    author: 'Mobin',
    help: 'nmap <target> [options]',
    official: false,
    default: false,
    securityLevel: 'low',
    permissions: Object.freeze({
      storage: 'none',
      cookies: 'none',
      network: 'none',
      filesystem: 'none'
    }),
    commands: Object.freeze(['nmap']),
    dependencies: Object.freeze([]),
    entry: 'install'
  });
  const TOP_PORTS = Object.freeze([
    20,21,22,23,25,53,67,68,69,80,88,110,111,123,135,137,138,139,143,161,162,389,443,445,465,500,514,515,587,636,873,902,989,990,993,995,1080,1194,1433,1521,1723,1883,2049,2375,2376,3000,3128,3306,3389,4000,4443,5000,5001,5432,5433,5900,5985,5986,6379,6443,7001,7002,8000,8001,8002,8003,8008,8009,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8180,8280,8443,8444,8484,8585,8686,8787,8880,8888,8889,8999,9000,9001,9002,9003,9004,9005,9006,9007,9008,9009,9010,9090,9091,9092,9200,9300,9418,11211,27017
  ]);
  const TEXT_FILES = Object.freeze([
    'robots.txt',
    'sitemap.xml',
    'sitemap_index.xml',
    'crossdomain.xml',
    'clientaccesspolicy.xml',
    'ReadMe.txt',
    'readme.txt',
    'ReadMe.md',
    'readme.md',
    'README.txt',
    'README.md',
    'LICENSE',
    'LICENSE.txt',
    'license.txt',
    'LICENSE.md',
    'license.md',
    'LICENCE',
    'LICENCE.txt',
    'LICENCE.md',
    'COPYING',
    'COPYING.txt',
    'NOTICE',
    'NOTICE.txt',
    'NOTICE.md',
    'SECURITY',
    'SECURITY.txt',
    'SECURITY.md',
    'security.txt',
    'security.md',
    'CHANGELOG',
    'CHANGELOG.txt',
    'CHANGELOG.md',
    'Changelog.txt',
    'Changelog.md',
    'CONTRIBUTING',
    'CONTRIBUTING.txt',
    'CONTRIBUTING.md',
    'AUTHORS',
    'AUTHORS.txt',
    'AUTHOR',
    'AUTHOR.txt',
    'HISTORY',
    'HISTORY.txt',
    'HISTORY.md',
    'CREDITS',
    'CREDITS.txt',
    'humans.txt',
    'ads.txt',
    'security.txt',
    '.well-known/security.txt'
  ]);
  const COMMANDS = Object.freeze({
    nmap: {
      description: 'Ultra-fast browser network scanner with HTTP probing, text-file discovery and CORS analysis',
      usage: 'nmap <target> [options]',
      aliases: ['scan', 'portscan'],
      kind: 'plain',
      run: async ({ args = [], api } = {}) => {
        const showHelp = () => [
          api.line('Nmap - Network Scanner (Browser Edition)', 'accent'),
          api.spacer(),
          api.line('Usage:', 'accent'),
          api.line('  nmap <target> [options]', 'muted'),
          api.spacer(),
          api.line('Options:', 'accent'),
          api.line('  -p, --ports <range>       Scan specific ports (e.g. 80,443,8080 or 1-1000)', 'muted'),
          api.line('  --top-ports <number>      Scan top common ports', 'muted'),
          api.line('  --exclude-ports <ports>   Exclude specific ports', 'muted'),
          api.line('  --open                    Show only open ports', 'muted'),
          api.line('  --concurrency <number>    Set concurrency level (default: 5000)', 'muted'),
          api.line('  --timeout <ms>            Set request timeout (default: 1000)', 'muted'),
          api.line('  --version                 Show version information', 'muted'),
          api.line('  --help                    Show this help message', 'muted'),
          api.spacer(),
          api.line('Default mode:', 'accent'),
          api.line('  nmap <target> scans TCP ports 1-65535 using browser HTTP(S) reachability probes', 'muted'),
          api.spacer(),
          api.line('Examples:', 'accent'),
          api.line('  nmap example.com', 'muted'),
          api.line('  nmap example.com --top-ports 100', 'muted'),
          api.line('  nmap example.com -p 80,443 --open', 'muted'),
          api.line('  nmap example.com -p 1-1000 --concurrency 5000 --timeout 1000', 'muted')
        ];
        if (!args || args.length === 0 || args.includes('--help') || args.includes('-h')) {
          return showHelp();
        }
        const target = String(args[0] || '').trim();
        const options = {
          ports: null,
          topPorts: null,
          excludePorts: [],
          openOnly: false,
          concurrency: 5000,
          timeout: 1000,
          version: false
        };
        for (let i = 1; i < args.length; i++) {
          const arg = String(args[i] || '');
          if ((arg === '-p' || arg === '--ports') && i + 1 < args.length) {
            const value = String(args[++i] || '').trim();
            if (value.includes('-')) {
              const parts = value.split('-');
              const start = Number(parts[0]);
              const end = Number(parts[1]);
              if (Number.isInteger(start) && Number.isInteger(end) && start >= 1 && end >= start) {
                options.ports = [];
                for (let port = start; port <= end && port <= 65535; port++) {
                  options.ports.push(port);
                }
              }
            } else {
              options.ports = [...new Set(
                value.split(',').map(Number).filter(port => Number.isInteger(port) && port >= 1 && port <= 65535)
              )];
            }
          } else if (arg === '--top-ports' && i + 1 < args.length) {
            const value = parseInt(args[++i], 10);
            if (Number.isInteger(value) && value > 0) {
              options.topPorts = value;
            }
          } else if (arg === '--exclude-ports' && i + 1 < args.length) {
            options.excludePorts = [...new Set(
              String(args[++i] || '')
                .split(',')
                .map(Number)
                .filter(port => Number.isInteger(port) && port >= 1 && port <= 65535)
            )];
          } else if (arg === '--open') {
            options.openOnly = true;
          } else if (arg === '--concurrency' && i + 1 < args.length) {
            const value = parseInt(args[++i], 10);
            if (Number.isInteger(value) && value > 0) {
              options.concurrency = value;
            }
          } else if (arg === '--timeout' && i + 1 < args.length) {
            const value = parseInt(args[++i], 10);
            if (Number.isInteger(value) && value > 0) {
              options.timeout = value;
            }
          } else if (arg === '--version' || arg === '-V') {
            options.version = true;
          }
        }
        if (options.version) {
          return [api.line(`nmap version ${manifest.version}`, 'accent')];
        }
        let baseUrl;
        try {
          baseUrl = normalizeUrl(target);
        } catch {
          return [api.line('Invalid target URL.', 'danger')];
        }
        const live = (text, tone = 'muted') => {
          api.append([api.line(text, tone)]);
        };
        const spacer = () => {
          api.append([api.spacer()]);
        };
        const startedAt = Date.now();
        let selectedPorts;
        if (options.ports !== null) {
          selectedPorts = [...options.ports];
        } else if (options.topPorts !== null) {
          selectedPorts = TOP_PORTS.slice(0, Math.min(options.topPorts, TOP_PORTS.length));
        } else {
          selectedPorts = Array.from({ length: 65535 }, (_, index) => index + 1);
        }
        if (options.excludePorts.length > 0) {
          const excluded = new Set(options.excludePorts);
          selectedPorts = selectedPorts.filter(port => !excluded.has(port));
        }
        if (selectedPorts.length === 0) {
          return [api.line('No ports selected for scanning.', 'warning')];
        }
        const totalPorts = selectedPorts.length;
        live(`[Nmap] Scan started: ${baseUrl}`, 'accent');
        live(`Mode: browser HTTP(S) scanner | Timeout: ${options.timeout}ms | Concurrency: ${options.concurrency}`, 'muted');
        live(`Port range: 1-65535 by default | Selected: ${totalPorts}`, 'muted');
        spacer();
        const serviceDbPromise = loadPorts();
        const phase1Start = Date.now();
        live('[Phase 1/3] Discovering text and documentation files', 'accent');
        live(`  Target: ${baseUrl}`, 'muted');
        live(`  Candidates: ${TEXT_FILES.length} | Timeout: ${options.timeout}ms`, 'muted');
        const discoveredFiles = await discoverTextFiles(baseUrl, options);
        const phase1Time = ((Date.now() - phase1Start) / 1000).toFixed(2);
        if (discoveredFiles.length === 0) {
          live('  No verifiable text files were found.', 'warning');
        } else {
          live(`  ${discoveredFiles.length} verified file(s) found:`, 'success');
          for (const file of discoveredFiles) {
            live(`    ${file}`, 'muted');
          }
        }
        live(`  Phase 1 complete. Time: ${phase1Time}s`, 'success');
        spacer();
        const phase2Start = Date.now();
        live(`[Phase 2/3] Scanning ${totalPorts} ports`, 'accent');
        live(`  Concurrency: ${options.concurrency} | Timeout: ${options.timeout}ms`, 'muted');
        live('  Scan order is deterministic; final port results are sorted numerically.', 'muted');
        const scanResults = await scanPorts(baseUrl, selectedPorts, options, live);
        const serviceDb = await serviceDbPromise;
        const openPorts = scanResults.openPorts.sort((a, b) => a.port - b.port);
        if (openPorts.length === 0) {
          live('  No responsive HTTP(S) ports were detected.', 'warning');
        } else {
          live(`  ${openPorts.length} responsive open port(s) detected:`, 'success');
          for (const item of openPorts) {
            const service = getServiceName(item.port, serviceDb);
            live(`    ${item.port}/tcp open  ${service}`, 'success');
          }
        }
        if (!options.openOnly) {
          live(`  Closed/Timeout: ${scanResults.closedCount}`, 'muted');
          if (scanResults.errorCount > 0) {
            live(`  Probe errors: ${scanResults.errorCount}`, 'danger');
          }
        }
        const phase2Time = ((Date.now() - phase2Start) / 1000).toFixed(2);
        live(`  Phase 2 complete. Time: ${phase2Time}s`, 'success');
        spacer();
        const phase3Start = Date.now();
        live(`[Phase 3/3] Analyzing HTTP status and CORS`, 'accent');
        if (openPorts.length === 0) {
          live('  Skipped: no responsive ports were detected.', 'muted');
        } else {
          const analysis = await analyzePorts(baseUrl, openPorts.map(item => item.port), options);
          for (const result of analysis) {
            live(`  Port ${result.port}: ${result.status} | ${result.cors}`, 'muted');
          }
        }
        const phase3Time = ((Date.now() - phase3Start) / 1000).toFixed(2);
        live(`  Phase 3 complete. Time: ${phase3Time}s`, 'success');
        spacer();
        const totalTime = ((Date.now() - startedAt) / 1000).toFixed(2);
        live('[Summary]', 'accent');
        live(`  Target: ${baseUrl}`, 'muted');
        live(`  Ports scanned: ${totalPorts}`, 'muted');
        live(`  Responsive open ports: ${openPorts.length}`, openPorts.length > 0 ? 'success' : 'muted');
        live(`  Verified text/documentation files: ${discoveredFiles.length}`, 'muted');
        live(`  Total time: ${totalTime}s`, 'muted');
        return [];
      }
    }
  });
  const normalizeUrl = target => {
    let value = String(target || '').trim();
    if (!value) {
      throw new Error('EMPTY_TARGET');
    }
    if (!/^https?:\/\//i.test(value)) {
      value = `https://${value}`;
    }
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('UNSUPPORTED_PROTOCOL');
    }
    if (!url.pathname) {
      url.pathname = '/';
    }
    return url.href;
  };
  const fetchVerifiedFile = async (url, timeout) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-store',
        redirect: 'follow',
        headers: {
          Accept: 'text/plain, text/markdown, application/xml, text/xml, application/xhtml+xml, */*'
        }
      });
      if (!response.ok || response.status < 200 || response.status >= 300) {
        return null;
      }
      const text = await response.text();
      if (!text || !text.trim()) {
        return null;
      }
      return text;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };
  const isHtmlErrorPage = text => {
    const value = String(text || '').trim().slice(0, 1200).toLowerCase();
    if (!value) {
      return true;
    }
    if (value.startsWith('<!doctype html') || value.startsWith('<html') || value.includes('<html lang=')) {
      return true;
    }
    if (value.includes('<head>') && value.includes('<body>')) {
      return true;
    }
    return false;
  };
  const verifyFile = (file, text) => {
    const lower = file.toLowerCase();
    if (isHtmlErrorPage(text)) {
      return false;
    }
    if (lower === 'robots.txt') {
      return /(^|\n)\s*user-agent\s*:|(^|\n)\s*sitemap\s*:|(^|\n)\s*disallow\s*:/im.test(text);
    }
    if (lower === 'sitemap.xml' || lower === 'sitemap_index.xml') {
      return /<urlset\b|<sitemapindex\b|<url\b|<sitemap\b/i.test(text);
    }
    if (lower === '.well-known/security.txt' || lower === 'security.txt' || lower === 'security.md' || lower === 'security') {
      return /contact\s*:|expires\s*:|canonical\s*:|policy\s*:/i.test(text) || text.trim().length >= 20;
    }
    return text.trim().length >= 2;
  };
  const discoverTextFiles = async (baseUrl, options) => {
    const timeout = Math.max(1, Number(options.timeout) || 1000);
    const results = await Promise.all(
      TEXT_FILES.map(async file => {
        const url = new URL(file, baseUrl).href;
        const text = await fetchVerifiedFile(url, timeout);
        if (!text) {
          return null;
        }
        if (!verifyFile(file, text)) {
          return null;
        }
        return url;
      })
    );
    return [...new Set(results.filter(Boolean))];
  };
  const probeReachability = async (url, timeout) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        credentials: 'omit',
        mode: 'no-cors',
        cache: 'no-store',
        redirect: 'follow',
        headers: {
          Accept: '*/*'
        }
      });
      return {
        reachable: true,
        type: response.type
      };
    } catch {
      return {
        reachable: false,
        type: 'error'
      };
    } finally {
      clearTimeout(timer);
    }
  };
  const scanPorts = async (baseUrl, ports, options, live) => {
    const openMap = new Map();
    let closedCount = 0;
    let errorCount = 0;
    let nextIndex = 0;
    let completed = 0;
    let lastProgress = -1;
    const timeout = Math.max(1, Number(options.timeout) || 1000);
    const concurrency = Math.max(1, Math.min(Number(options.concurrency) || 5000, 8000));
    const buildUrl = port => {
      const source = new URL(baseUrl);
      return `${source.protocol}//${source.hostname}:${port}${source.pathname || '/'}`;
    };
    const worker = async () => {
      while (true) {
        const index = nextIndex++;
        if (index >= ports.length) {
          return;
        }
        const port = ports[index];
        try {
          const result = await probeReachability(buildUrl(port), timeout);
          if (result.reachable) {
            openMap.set(port, {
              port,
              method: result.type === 'opaque' ? 'reachable' : 'reachable'
            });
          } else {
            closedCount++;
          }
        } catch {
          errorCount++;
        } finally {
          completed++;
          const progress = Math.floor((completed / ports.length) * 100);
          if (progress !== lastProgress && (progress % 5 === 0 || progress === 100)) {
            lastProgress = progress;
            live(`  Progress: ${progress}% (${completed}/${ports.length})`, 'muted');
          }
        }
      }
    };
    const workers = [];
    const workerCount = Math.min(concurrency, ports.length);
    for (let i = 0; i < workerCount; i++) {
      workers.push(worker());
    }
    await Promise.all(workers);
    return {
      openPorts: [...openMap.values()],
      closedCount,
      errorCount
    };
  };
  const requestCorsInfo = async (url, timeout) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-store',
        redirect: 'follow',
        headers: {
          Accept: '*/*'
        }
      });
      const allowOrigin = response.headers.get('access-control-allow-origin');
      const allowCredentials = response.headers.get('access-control-allow-credentials');
      return {
        status: `HTTP ${response.status}`,
        cors: allowOrigin
          ? allowCredentials === 'true'
            ? `CORS: ${allowOrigin} | credentials=true`
            : `CORS: ${allowOrigin}`
          : 'CORS: not set'
      };
    } catch {
      return {
        status: 'HTTP status unavailable',
        cors: 'CORS: blocked or unavailable'
      };
    } finally {
      clearTimeout(timer);
    }
  };
  const analyzePorts = async (baseUrl, ports, options) => {
    const timeout = Math.max(1, Number(options.timeout) || 1000);
    const concurrency = Math.max(1, Math.min(ports.length, 200));
    const results = [];
    let nextIndex = 0;
    const worker = async () => {
      while (true) {
        const index = nextIndex++;
        if (index >= ports.length) {
          return;
        }
        const port = ports[index];
        const source = new URL(baseUrl);
        const url = `${source.protocol}//${source.hostname}:${port}/`;
        const result = await requestCorsInfo(url, timeout);
        results.push({
          port,
          status: result.status,
          cors: result.cors
        });
      }
    };
    const workers = [];
    for (let i = 0; i < concurrency; i++) {
      workers.push(worker());
    }
    await Promise.all(workers);
    return results.sort((a, b) => a.port - b.port);
  };
  const loadPorts = async () => {
    if (PORT_DB_CACHE !== null) {
      return PORT_DB_CACHE;
    }
    try {
      const response = await fetch('https://lightkali.github.io/app/pkg/ports.compact.json', {
        method: 'GET',
        cache: 'force-cache',
        credentials: 'omit',
        mode: 'cors',
        headers: {
          Accept: 'application/json'
        }
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('INVALID_PORT_DATABASE');
      }
      PORT_DB_CACHE = data;
      return data;
    } catch {
      PORT_DB_CACHE = {};
      return PORT_DB_CACHE;
    }
  };
  let PORT_DB_CACHE = null;
  const getServiceName = (port, db) => {
    if (db && Object.prototype.hasOwnProperty.call(db, port)) {
      const value = db[port];
      if (value !== null && value !== undefined && String(value).trim()) {
        return String(value);
      }
    }
    const fallback = {
      20: 'ftp-data',
      21: 'ftp',
      22: 'ssh',
      23: 'telnet',
      25: 'smtp',
      53: 'dns',
      67: 'dhcp',
      68: 'dhcp-client',
      80: 'http',
      110: 'pop3',
      111: 'rpcbind',
      123: 'ntp',
      135: 'msrpc',
      137: 'netbios-ns',
      138: 'netbios-dgm',
      139: 'netbios-ssn',
      143: 'imap',
      161: 'snmp',
      389: 'ldap',
      443: 'https',
      445: 'smb',
      465: 'smtps',
      587: 'submission',
      636: 'ldaps',
      873: 'rsync',
      989: 'ftps-data',
      990: 'ftps',
      993: 'imaps',
      995: 'pop3s',
      1433: 'mssql',
      1521: 'oracle',
      1723: 'pptp',
      1883: 'mqtt',
      2049: 'nfs',
      2375: 'docker',
      2376: 'docker-tls',
      3000: 'http-alt',
      3306: 'mysql',
      3389: 'rdp',
      5432: 'postgresql',
      5433: 'postgresql-alt',
      5900: 'vnc',
      6379: 'redis',
      6443: 'kubernetes',
      7001: 'weblogic',
      8000: 'http-alt',
      8008: 'http-alt',
      8080: 'http-proxy',
      8081: 'http-alt',
      8443: 'https-alt',
      8888: 'http-alt',
      9000: 'http-alt',
      9090: 'prometheus',
      9200: 'elasticsearch',
      9300: 'elasticsearch-node',
      11211: 'memcached',
      27017: 'mongodb'
    };
    return fallback[port] || 'unknown';
  };
  const install = async api => {
    for (const [name, definition] of Object.entries(COMMANDS)) {
      if (!manifest.commands.includes(name)) {
        throw new Error(`COMMAND_NOT_DECLARED:${name}`);
      }
      const registered = api.registerCommand(name, definition);
      if (registered === false) {
        throw new Error(`PACKAGE_COMMAND_REGISTRATION_FAILED:${name}`);
      }
    }
    return [];
  };
  const uninstall = async api => {
    for (const name of manifest.commands) {
      api.unregisterCommand(name);
    }
    return [];
  };
  window.__kali_pkg_nmap = Object.freeze({
    manifest,
    install,
    uninstall
  });
})();
