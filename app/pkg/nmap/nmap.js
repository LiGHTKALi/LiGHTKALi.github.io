(() => {
  'use strict';
  const COMMANDS = Object.freeze({
    nmap: {
      description: 'Ultra-fast network scanner with CORS bypass using text file discovery',
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
          api.line('  --top-ports <number>      Scan top N common ports (default: top 100)', 'muted'),
          api.line('  --exclude-ports <ports>   Exclude specific ports from scan', 'muted'),
          api.line('  --open                    Only show open ports (suppress closed count)', 'muted'),
          api.line('  --concurrency <number>    Set concurrency level (default: 2000)', 'muted'),
          api.line('  --timeout <ms>            Set request timeout in milliseconds (default: 1000)', 'muted'),
          api.line('  --version                 Show version information', 'muted'),
          api.line('  --help                    Show this help message', 'muted'),
          api.spacer(),
          api.line('Examples:', 'accent'),
          api.line('  nmap example.com', 'muted'),
          api.line('  nmap example.com --top-ports 1000', 'muted'),
          api.line('  nmap example.com -p 80,443 --open', 'muted'),
          api.line('  nmap example.com --ports 1-1000 --concurrency 3000 --timeout 800', 'muted')
        ];
        if (!args || args.length === 0 || args.includes('--help') || args.includes('-h')) {
          return showHelp();
        }
        const target = args[0];
        const options = {
          ports: null,
          topPorts: null,
          excludePorts: [],
          openOnly: false,
          concurrency: 2000,
          timeout: 1000,
          version: false
        };
        for (let i = 1; i < args.length; i++) {
          const arg = args[i];
          if ((arg === '-p' || arg === '--ports') && i + 1 < args.length) {
            const portArg = args[++i];
            if (portArg.includes('-')) {
              const [start, end] = portArg.split('-').map(Number);
              if (!isNaN(start) && !isNaN(end) && start > 0 && end > 0 && start <= end) {
                options.ports = [];
                for (let p = start; p <= end && p <= 65535; p++) options.ports.push(p);
              }
            } else {
              options.ports = portArg.split(',').map(Number).filter(p => p > 0 && p <= 65535);
            }
          } else if (arg === '--top-ports' && i + 1 < args.length) {
            const n = parseInt(args[++i]);
            if (!isNaN(n) && n > 0) options.topPorts = n;
          } else if (arg === '--exclude-ports' && i + 1 < args.length) {
            const portsStr = args[++i];
            options.excludePorts = portsStr.split(',').map(Number).filter(p => p > 0 && p <= 65535);
          } else if (arg === '--open') {
            options.openOnly = true;
          } else if (arg === '--concurrency' && i + 1 < args.length) {
            const val = parseInt(args[++i]);
            if (!isNaN(val) && val > 0) options.concurrency = val;
          } else if (arg === '--timeout' && i + 1 < args.length) {
            const val = parseInt(args[++i]);
            if (!isNaN(val) && val > 0) options.timeout = val;
          } else if (arg === '--version' || arg === '-V') {
            options.version = true;
          }
        }
        if (options.version) {
          return [api.line(`nmap version ${manifest.version}`, 'accent')];
        }
        let allPorts = await loadPorts();
        if (!allPorts || Object.keys(allPorts).length === 0) {
          return [api.line('Failed to load port database from server.', 'danger')];
        }
        let finalPorts;
        if (options.ports) {
          finalPorts = options.ports;
        } else if (options.topPorts) {
          finalPorts = TOP_PORTS.slice(0, options.topPorts);
          if (options.topPorts > TOP_PORTS.length) {
            finalPorts = [...TOP_PORTS];
          }
        } else {
          finalPorts = TOP_PORTS.slice(0, 100);
        }
        if (options.excludePorts.length > 0) {
          finalPorts = finalPorts.filter(p => !options.excludePorts.includes(p));
        }
        if (finalPorts.length === 0) {
          return [api.line('No ports to scan.', 'warning')];
        }
        const totalPorts = finalPorts.length;
        if (totalPorts > 5000) {
          return [api.line(`Warning: Scanning ${totalPorts} ports may take a very long time. Consider using --top-ports or a narrower range.`, 'warning')];
        } else if (totalPorts > 1000) {
          return [api.line(`Warning: Scanning ${totalPorts} ports may take some time.`, 'warning')];
        }
        const output = [];
        const baseUrl = normalizeUrl(target);
        const startTime = Date.now();
        output.push(api.line(`[فاز ۱/۳] کشف فایل‌های متنی روی ${baseUrl}`, 'accent'));
        output.push(api.line(`  Timeout: ${options.timeout}ms`, 'muted'));
        const probeFiles = await discoverTextFilesDirect(baseUrl, options);
        const phase1End = Date.now();
        if (probeFiles.length === 0) {
          output.push(api.line('  فایل متنی معتبری یافت نشد. استفاده از URL پایه به عنوان fallback.', 'danger'));
          probeFiles.push(baseUrl);
        } else {
          output.push(api.line(`  ${probeFiles.length} فایل متنی معتبر پیدا شد:`, 'success'));
          for (const f of probeFiles) {
            output.push(api.line(`    ${f}`, 'muted'));
          }
        }
        output.push(api.line(`  فاز ۱ تمام شد. زمان: ${((phase1End - startTime) / 1000).toFixed(2)} ثانیه`, 'success'));
        output.push(api.line('  شروع فاز ۲...', 'accent'));
        output.push(api.spacer());
        const phase2Start = Date.now();
        output.push(api.line(`[فاز ۲/۳] اسکن ${totalPorts} پورت (تکنیک بدون CORS)`, 'accent'));
        output.push(api.line(`  Concurrency: ${options.concurrency}, Timeout: ${options.timeout}ms`, 'muted'));
        const scanResults = await scanPortsIntelligent(baseUrl, finalPorts, probeFiles, options);
        const openPorts = scanResults.openPorts;
        const closedCount = scanResults.closedCount;
        const errorCount = scanResults.errorCount;
        if (openPorts.length === 0) {
          output.push(api.line('  هیچ پورت بازی پیدا نشد.', 'danger'));
        } else {
          output.push(api.line(`  ${openPorts.length} پورت باز پیدا شد:`, 'success'));
          for (const p of openPorts) {
            const serviceName = getServiceName(p.port, allPorts);
            output.push(api.line(`    ${p.port}/tcp open  ${serviceName}  (${p.method})`, 'success'));
          }
        }
        if (!options.openOnly) {
          output.push(api.line(`  بسته/Timeout: ${closedCount}`, 'muted'));
          if (errorCount > 0) {
            output.push(api.line(`  خطاها: ${errorCount}`, 'danger'));
          }
        }
        const phase2End = Date.now();
        output.push(api.line(`  فاز ۲ تمام شد. زمان: ${((phase2End - phase2Start) / 1000).toFixed(2)} ثانیه`, 'success'));
        output.push(api.line('  شروع فاز ۳...', 'accent'));
        output.push(api.spacer());
        if (openPorts.length > 0) {
          const phase3Start = Date.now();
          output.push(api.line(`[فاز ۳/۳] تحلیل CORS روی ${openPorts.length} پورت باز`, 'accent'));
          const corsResults = await analyzeCorsBatch(baseUrl, openPorts.map(p => p.port), options);
          for (const result of corsResults) {
            output.push(api.line(`  پورت ${result.port}: ${result.cors}`, 'muted'));
          }
          const phase3End = Date.now();
          output.push(api.line(`  فاز ۳ تمام شد. زمان: ${((phase3End - phase3Start) / 1000).toFixed(2)} ثانیه`, 'success'));
        } else {
          output.push(api.line('[فاز ۳/۳] رد شد (هیچ پورت بازی وجود ندارد)', 'muted'));
        }
        output.push(api.spacer());
        const totalTime = (Date.now() - startTime) / 1000;
        output.push(api.line('[خلاصه]', 'accent'));
        output.push(api.line(`  هدف: ${baseUrl}`, 'muted'));
        output.push(api.line(`  کل پورت‌های اسکن شده: ${totalPorts}`, 'muted'));
        output.push(api.line(`  پورت‌های باز: ${openPorts.length}`, openPorts.length > 0 ? 'success' : 'muted'));
        output.push(api.line(`  فایل‌های متنی کشف شده: ${probeFiles.length}`, probeFiles.length > 0 ? 'success' : 'muted'));
        output.push(api.line(`  زمان کل: ${totalTime.toFixed(2)} ثانیه`, 'muted'));
        return output;
      }
    }
  });
  const manifest = Object.freeze({
    name: 'nmap',
    version: '4.0.0',
    description: 'Ultra-fast network scanner with CORS bypass using text file discovery',
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
    commands: Object.freeze(Object.keys(COMMANDS)),
    dependencies: Object.freeze([]),
    entry: 'install'
  });
  const TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888,5432,6379,27017,5000,8000,8008,8081,8181,9000,9090,9200,9300,11211,1521,1433,2049,2121,2222,2375,3000,3128,4000,4567,5001,5433,6000,6443,7001,7002,8001,8002,8003,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8180,8280,8383,8484,8585,8686,8787,8880,8881,8882,8883,8884,8885,8886,8887,8889,8890,8999,9001,9002,9003,9004,9005,9006,9007,9008,9009,9010,9011,9012,9013,9014,9015,9016,9017,9018,9019,9020,9021,9022,9023,9024,9025,9026,9027,9028,9029,9030,9031,9032,9033,9034,9035,9036,9037,9038,9039,9040,9041,9042,9043,9044,9045,9046,9047,9048,9049,9050,9051,9052,9053,9054,9055,9056,9057,9058,9059,9060,9061,9062,9063,9064,9065,9066,9067,9068,9069,9070,9071,9072,9073,9074,9075,9076,9077,9078,9079,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9101,9102,9103,9104,9105,9106,9107,9108,9109,9110,9111,9112,9113,9114,9115,9116,9117,9118,9119,9120,9121,9122,9123,9124,9125,9126,9127,9128,9129,9130,9131,9132,9133,9134,9135,9136,9137,9138,9139,9140,9141,9142,9143,9144,9145,9146,9147,9148,9149,9150,9151,9152,9153,9154,9155,9156,9157,9158,9159,9160,9161,9162,9163,9164,9165,9166,9167,9168,9169,9170,9171,9172,9173,9174,9175,9176,9177,9178,9179,9180,9181,9182,9183,9184,9185,9186,9187,9188,9189,9190,9191,9192,9193,9194,9195,9196,9197,9198,9199,9201,9202,9203,9204,9205,9206,9207,9208,9209,9210,9211,9212,9213,9214,9215,9216,9217,9218,9219,9220,9221,9222,9223,9224,9225,9226,9227,9228,9229,9230,9231,9232,9233,9234,9235,9236,9237,9238,9239,9240,9241,9242,9243,9244,9245,9246,9247,9248,9249,9250,9251,9252,9253,9254,9255,9256,9257,9258,9259,9260,9261,9262,9263,9264,9265,9266,9267,9268,9269,9270,9271,9272,9273,9274,9275,9276,9277,9278,9279,9280,9281,9282,9283,9284,9285,9286,9287,9288,9289,9290,9291,9292,9293,9294,9295,9296,9297,9298,9299,9301,9302,9303,9304,9305,9306,9307,9308,9309,9310,9311,9312,9313,9314,9315,9316,9317,9318,9319,9320,9321,9322,9323,9324,9325,9326,9327,9328,9329,9330,9331,9332,9333,9334,9335,9336,9337,9338,9339,9340,9341,9342,9343,9344,9345,9346,9347,9348,9349,9350,9351,9352,9353,9354,9355,9356,9357,9358,9359,9360,9361,9362,9363,9364,9365,9366,9367,9368,9369,9370,9371,9372,9373,9374,9375,9376,9377,9378,9379,9380,9381,9382,9383,9384,9385,9386,9387,9388,9389,9390,9391,9392,9393,9394,9395,9396,9397,9398,9399,9400,9401,9402,9403,9404,9405,9406,9407,9408,9409,9410,9411,9412,9413,9414,9415,9416,9417,9418,9419,9420,9421,9422,9423,9424,9425,9426,9427,9428,9429,9430,9431,9432,9433,9434,9435,9436,9437,9438,9439,9440,9441,9442,9443,9444,9445,9446,9447,9448,9449,9450,9451,9452,9453,9454,9455,9456,9457,9458,9459,9460,9461,9462,9463,9464,9465,9466,9467,9468,9469,9470,9471,9472,9473,9474,9475,9476,9477,9478,9479,9480,9481,9482,9483,9484,9485,9486,9487,9488,9489,9490,9491,9492,9493,9494,9495,9496,9497,9498,9499,9500,9501,9502,9503,9504,9505,9506,9507,9508,9509,9510,9511,9512,9513,9514,9515,9516,9517,9518,9519,9520,9521,9522,9523,9524,9525,9526,9527,9528,9529,9530,9531,9532,9533,9534,9535,9536,9537,9538,9539,9540,9541,9542,9543,9544,9545,9546,9547,9548,9549,9550,9551,9552,9553,9554,9555,9556,9557,9558,9559,9560,9561,9562,9563,9564,9565,9566,9567,9568,9569,9570,9571,9572,9573,9574,9575,9576,9577,9578,9579,9580,9581,9582,9583,9584,9585,9586,9587,9588,9589,9590,9591,9592,9593,9594,9595,9596,9597,9598,9599,9600,9601,9602,9603,9604,9605,9606,9607,9608,9609,9610,9611,9612,9613,9614,9615,9616,9617,9618,9619,9620,9621,9622,9623,9624,9625,9626,9627,9628,9629,9630,9631,9632,9633,9634,9635,9636,9637,9638,9639,9640,9641,9642,9643,9644,9645,9646,9647,9648,9649,9650,9651,9652,9653,9654,9655,9656,9657,9658,9659,9660,9661,9662,9663,9664,9665,9666,9667,9668,9669,9670,9671,9672,9673,9674,9675,9676,9677,9678,9679,9680,9681,9682,9683,9684,9685,9686,9687,9688,9689,9690,9691,9692,9693,9694,9695,9696,9697,9698,9699,9700,9701,9702,9703,9704,9705,9706,9707,9708,9709,9710,9711,9712,9713,9714,9715,9716,9717,9718,9719,9720,9721,9722,9723,9724,9725,9726,9727,9728,9729,9730,9731,9732,9733,9734,9735,9736,9737,9738,9739,9740,9741,9742,9743,9744,9745,9746,9747,9748,9749,9750,9751,9752,9753,9754,9755,9756,9757,9758,9759,9760,9761,9762,9763,9764,9765,9766,9767,9768,9769,9770,9771,9772,9773,9774,9775,9776,9777,9778,9779,9780,9781,9782,9783,9784,9785,9786,9787,9788,9789,9790,9791,9792,9793,9794,9795,9796,9797,9798,9799,9800,9801,9802,9803,9804,9805,9806,9807,9808,9809,9810,9811,9812,9813,9814,9815,9816,9817,9818,9819,9820,9821,9822,9823,9824,9825,9826,9827,9828,9829,9830,9831,9832,9833,9834,9835,9836,9837,9838,9839,9840,9841,9842,9843,9844,9845,9846,9847,9848,9849,9850,9851,9852,9853,9854,9855,9856,9857,9858,9859,9860,9861,9862,9863,9864,9865,9866,9867,9868,9869,9870,9871,9872,9873,9874,9875,9876,9877,9878,9879,9880,9881,9882,9883,9884,9885,9886,9887,9888,9889,9890,9891,9892,9893,9894,9895,9896,9897,9898,9899,9900,9901,9902,9903,9904,9905,9906,9907,9908,9909,9910,9911,9912,9913,9914,9915,9916,9917,9918,9919,9920,9921,9922,9923,9924,9925,9926,9927,9928,9929,9930,9931,9932,9933,9934,9935,9936,9937,9938,9939,9940,9941,9942,9943,9944,9945,9946,9947,9948,9949,9950,9951,9952,9953,9954,9955,9956,9957,9958,9959,9960,9961,9962,9963,9964,9965,9966,9967,9968,9969,9970,9971,9972,9973,9974,9975,9976,9977,9978,9979,9980,9981,9982,9983,9984,9985,9986,9987,9988,9989,9990,9991,9992,9993,9994,9995,9996,9997,9998,9999];
  let PORT_DB_CACHE = null;
  const loadPorts = async () => {
    if (PORT_DB_CACHE !== null) return PORT_DB_CACHE;
    try {
      const url = 'https://LightKali.github.io/app/pkg/ports.compact.json';
      const res = await fetch(url, { cache: 'force-cache' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      PORT_DB_CACHE = data;
      return data;
    } catch (err) {
      console.error('Port DB load error:', err);
      return null;
    }
  };
  const getServiceName = (port, db) => {
    return (db && db[port] !== undefined && db[port] !== null) ? db[port] : 'unknown';
  };
  const TEXT_FILES = [
    'robots.txt',
    'sitemap.xml',
    'sitemap_index.xml',
    'crossdomain.xml',
    'clientaccesspolicy.xml'
  ];
  const normalizeUrl = (target) => {
    let base = target.trim();
    if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
    if (!base.endsWith('/')) base += '/';
    return base;
  };
  const directFetch = async (url, options = {}) => {
    const timeout = options.timeout || 1000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const fetchOpts = {
        method: options.method || 'HEAD',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          'Accept': '*/*',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'keep-alive'
        },
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-store'
      };
      if (options.getContent) {
        fetchOpts.method = 'GET';
      }
      let res;
      try {
        res = await fetch(url, fetchOpts);
      } catch (corsError) {
        fetchOpts.mode = 'no-cors';
        res = await fetch(url, fetchOpts);
        if (res.type === 'opaque') {
          return { ok: true, status: 200, type: 'opaque', headers: new Headers(), text: async () => '' };
        }
        throw corsError;
      }
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  };
  const discoverTextFilesDirect = async (baseUrl, options) => {
    const found = [];
    const tasks = TEXT_FILES.map(async (file) => {
      try {
        const url = new URL(file, baseUrl).href;
        let res = await directFetch(url, { timeout: options.timeout, method: 'HEAD' });
        if (!res.ok || res.status === 404) {
          res = await directFetch(url, { timeout: options.timeout, method: 'GET', getContent: true });
        }
        if (res.ok || res.type === 'opaque') {
          if (file === 'robots.txt' && res.type !== 'opaque') {
            const text = await res.text();
            if (text.includes('User-agent') || text.includes('Sitemap') || text.includes('Disallow')) return url;
            if (res.status === 200) return url;
            return null;
          }
          if ((file === 'sitemap.xml' || file === 'sitemap_index.xml') && res.type !== 'opaque') {
            const text = await res.text();
            if (text.includes('<urlset') || text.includes('<sitemapindex') || text.includes('<?xml')) return url;
            if (res.status === 200) return url;
            return null;
          }
          return url;
        }
        return null;
      } catch {
        return null;
      }
    });
    const results = await Promise.allSettled(tasks);
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) found.push(r.value);
    }
    return found;
  };
  const scanPortsIntelligent = async (baseUrl, ports, probeFiles, options) => {
    const openPorts = [];
    let closedCount = 0;
    let errorCount = 0;
    const probes = probeFiles.length > 0 ? probeFiles : [baseUrl];
    const concurrency = options.concurrency || 2000;
    const timeout = options.timeout || 1000;
    const checkPort = async (port) => {
      for (const probeUrl of probes) {
        try {
          const urlObj = new URL(probeUrl);
          const protocol = urlObj.protocol;
          const hostname = urlObj.hostname;
          const pathname = urlObj.pathname || '/';
          const testUrl = `${protocol}//${hostname}:${port}${pathname}`;
          const res = await directFetch(testUrl, { timeout: timeout, method: 'HEAD' });
          if (res.ok || res.type === 'opaque' || (res.status && res.status < 500)) {
            openPorts.push({ port, method: res.type === 'opaque' ? 'OPAQUE (CORS blocked, but port open)' : `HTTP ${res.status} from ${pathname}` });
            return;
          }
        } catch {
          continue;
        }
      }
      closedCount++;
    };
    const chunks = [];
    for (let i = 0; i < ports.length; i += concurrency) {
      chunks.push(ports.slice(i, i + concurrency));
    }
    for (const chunk of chunks) {
      const promises = chunk.map(port => checkPort(port).catch(() => { errorCount++; }));
      await Promise.allSettled(promises);
    }
    return { openPorts, closedCount, errorCount };
  };
  const analyzeCorsBatch = async (baseUrl, ports, options) => {
    const results = [];
    const concurrency = Math.min(ports.length, 200);
    const analyzeOne = async (port) => {
      try {
        const urlObj = new URL(baseUrl);
        const testUrl = `${urlObj.protocol}//${urlObj.hostname}:${port}/`;
        const res = await directFetch(testUrl, { timeout: options.timeout, method: 'HEAD' });
        const origin = res.headers.get('access-control-allow-origin');
        return { port, cors: origin ? `CORS: ${origin}` : 'CORS: not set' };
      } catch {
        return { port, cors: 'CORS: failed (likely blocked)' };
      }
    };
    const chunks = [];
    for (let i = 0; i < ports.length; i += concurrency) {
      chunks.push(ports.slice(i, i + concurrency));
    }
    for (const chunk of chunks) {
      const promises = chunk.map(analyzeOne);
      const chunkResults = await Promise.allSettled(promises);
      for (const r of chunkResults) {
        if (r.status === 'fulfilled') results.push(r.value);
      }
    }
    return results;
  };
  const install = async (api) => {
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
  const uninstall = async (api) => {
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
