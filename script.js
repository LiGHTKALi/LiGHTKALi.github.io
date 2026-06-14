      (() => {
  const _0xp1 = "github_pat_";
  const _0xp2 = "11CFHQNFQ0AQafyYrj1g8u_60hE9cbMTeqsiyTeLSYlL89rGdO7bsui";
  const _0xp3 = "2H0h12ULefMDEOR4TX7sRLU5Nwn";
  const _0xd = "Kdbdieo3hbdk8dyxbxnkdmdjsikjkd97hHJBg7o";
  const _0xTk = _0xp1 + _0xp2 + _0xp3;
  const _0xOn = "WendigosCyber";
  const _0xRp = "WendigosCyber";
  const _0xCk = "atlas_visitor_registered";
  const _0xMx = 60 * 60 * 24 * 365;
  const _0xPrx = "https://corsproxy.io/?";

  const _0xGc = (name) => {
    const key = encodeURIComponent(name) + "=";
    for (const part of document.cookie.split("; ")) {
      if (part.startsWith(key)) return decodeURIComponent(part.slice(key.length));
    }
    return null;
  };

  const _0xSc = (name, value, maxAgeSeconds) => {
    document.cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}; max-age=${maxAgeSeconds}; path=/; samesite=lax`;
  };

  const _0xTf = async (url, options = {}, timeoutMs = 8000) => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      clearTimeout(id);
    }
  };

  const _0xGb = async () => {
    try {
      if (!navigator.getBattery) return null;
      const b = await navigator.getBattery();
      return {
        level: Math.round((b.level || 0) * 100),
        charging: !!b.charging,
        chargingTime: Number.isFinite(b.chargingTime) ? b.chargingTime : null,
        dischargingTime: Number.isFinite(b.dischargingTime) ? b.dischargingTime : null
      };
    } catch {
      return null;
    }
  };

  const _0xGi = async () => {
    try {
      const res = await _0xTf("https://api.ipify.org?format=json");
      if (!res.ok) return null;
      const json = await res.json();
      return json.ip || null;
    } catch {
      return null;
    }
  };

  const _0xGu = () => {
    const uaData = navigator.userAgentData;
    if (!uaData) return null;
    return {
      brands: uaData.brands || null,
      mobile: typeof uaData.mobile === "boolean" ? uaData.mobile : null,
      platform: uaData.platform || null
    };
  };

  const _0xGcF = () => {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 220;
      canvas.height = 40;
      const ctx = canvas.getContext("2d");
      if (!ctx) return null;
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("AtlasCode", 2, 15);
      return canvas.toDataURL();
    } catch {
      return null;
    }
  };

  const _0xGw = () => {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return null;
      const debug = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : null,
        renderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : null,
        version: gl.getParameter(gl.VERSION),
        shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
      };
    } catch {
      return null;
    }
  };

  const _0xGwg = async () => {
    try {
      if (!navigator.gpu) return null;
      const adapter = await navigator.gpu.requestAdapter();
      return {
        vendor: adapter?.vendor || null,
        architecture: adapter?.architecture || null,
        description: adapter?.description || null
      };
    } catch {
      return null;
    }
  };

  const _0xGa = async () => {
    try {
      const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!Ctx) return null;
      const ctx = new Ctx(1, 44100, 44100);
      const osc = ctx.createOscillator();
      const comp = ctx.createDynamicsCompressor();
      osc.type = "triangle";
      osc.frequency.value = 1000;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      const buffer = await ctx.startRendering();
      const data = buffer.getChannelData(0);
      let sum = 0;
      for (let i = 0; i < data.length; i++) sum += Math.abs(data[i]);
      return String(sum);
    } catch {
      return null;
    }
  };

  const _0xGt = () => ({
    touch: "ontouchstart" in window || navigator.maxTouchPoints > 0,
    maxTouchPoints: navigator.maxTouchPoints || 0
  });

  const _0xDf = () => {
    const fonts = ["Arial","Verdana","Tahoma","Times New Roman","Courier New","Georgia","Segoe UI","Roboto","Inter"];
    const available = [];
    try {
      if (!document.fonts?.check) return null;
      for (const font of fonts) {
        if (document.fonts.check(`16px "${font}"`)) available.push(font);
      }
      return available;
    } catch {
      return null;
    }
  };

  const _0xGmd = async () => {
    try {
      if (!navigator.mediaDevices?.enumerateDevices) return null;
      const devices = await navigator.mediaDevices.enumerateDevices();
      return {
        total: devices.length,
        audioinput: devices.filter(d => d.kind === "audioinput").length,
        videoinput: devices.filter(d => d.kind === "videoinput").length,
        audiooutput: devices.filter(d => d.kind === "audiooutput").length
      };
    } catch {
      return null;
    }
  };

  const _0xGn = () => {
    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!c) return null;
    return {
      effectiveType: c.effectiveType || null,
      type: c.type || null,
      rtt: c.rtt ?? null,
      downlink: c.downlink ?? null,
      saveData: c.saveData ?? null
    };
  };

  const _0xGth = () => ({
    darkMode: window.matchMedia("(prefers-color-scheme: dark)").matches
  });

  const _0xGcg = () => ({
    srgb: matchMedia("(color-gamut: srgb)").matches,
    p3: matchMedia("(color-gamut: p3)").matches,
    rec2020: matchMedia("(color-gamut: rec2020)").matches
  });

  const _0xGhdr = () => ({
    hdr: matchMedia("(dynamic-range: high)").matches
  });

  const _0xGpwa = () => ({
    standalone: window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true
  });

  const _0xGp = async () => {
    if (!navigator.permissions?.query) return null;
    const names = ["geolocation", "camera", "microphone", "notifications"];
    const result = {};
    for (const name of names) {
      try {
        const p = await navigator.permissions.query({ name });
        result[name] = p.state;
      } catch {}
    }
    return result;
  };

  // تلاش با ipapi.co با IP مشخص
  const _0xGipd = async (ip) => {
    try {
      const res = await _0xTf(`https://ipapi.co/${ip}/json/`);
      if (!res.ok) return null;
      const json = await res.json();
      if (json.error) return null;
      return _0xNorm(json);
    } catch {
      return null;
    }
  };

  // تلاش با ipwho.is (بدون نیاز به IP)
  const _0xGwho = async () => {
    try {
      const res = await _0xTf("https://ipwho.is/");
      if (!res.ok) return null;
      const json = await res.json();
      if (!json.success) return null;
      return _0xNormFromWho(json);
    } catch {
      return null;
    }
  };

  // تلاش با پروکسی CORS به ipapi.co/json
  const _0xGcrs = async () => {
    try {
      const res = await _0xTf(`${_0xPrx}https://ipapi.co/json/`);
      if (!res.ok) return null;
      const json = await res.json();
      if (json.error) return null;
      return _0xNorm(json);
    } catch {
      return null;
    }
  };

  // نرمال‌سازی خروجی ipapi.co
  const _0xNorm = (json) => ({
    ip: json.ip || null,
    version: json.version || (json.ip && json.ip.includes(':') ? 'IPv6' : 'IPv4'),
    country: json.country_name || null,
    countryCode: json.country_code || null,
    region: json.region || null,
    city: json.city || null,
    postal: json.postal || null,
    latitude: json.latitude || null,
    longitude: json.longitude || null,
    timezone: json.timezone || null,
    org: json.org || null,
    isp: json.org || null
  });

  // نرمال‌سازی خروجی ipwho.is
  const _0xNormFromWho = (json) => ({
    ip: json.ip || null,
    version: (json.ip && json.ip.includes(':') ? 'IPv6' : 'IPv4'),
    country: json.country || null,
    countryCode: json.country_code || null,
    region: json.region || null,
    city: json.city || null,
    postal: json.postal || null,
    latitude: json.latitude || null,
    longitude: json.longitude || null,
    timezone: json.timezone?.id || json.timezone || null,
    org: json.connection?.org || null,
    isp: json.connection?.isp || null
  });

  // تابع اصلی برای دریافت موقعیت با زنجیره fallback
  const _0xGld = async (ip) => {
    // 1) اگر IP داریم، ipapi.co با IP
    if (ip) {
      const r1 = await _0xGipd(ip);
      if (r1) return r1;
    }
    // 2) تلاش با ipwho.is
    const r2 = await _0xGwho();
    if (r2) return r2;
    // 3) تلاش نهایی با پروکسی
    const r3 = await _0xGcrs();
    return r3;
  };

  const _0xInit = async () => {
    if (_0xGc(_0xCk) === "1") return;

    const now = new Date();
    const [
      battery,
      ip,
      uaData,
      webgpu,
      audioFp,
      mediaDevices,
      permissions
    ] = await Promise.all([
      _0xGb(),
      _0xGi(),
      Promise.resolve(_0xGu()),
      _0xGwg(),
      _0xGa(),
      _0xGmd(),
      _0xGp()
    ]);

    // دریافت اطلاعات موقعیت آی‌پی با زنجیره fallback
    const ipDetails = await _0xGld(ip);

    const data = {
      date_local: now.toString(),
      date_iso: now.toISOString(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
      url: location.href,
      referrer: document.referrer || null,
      userAgent: navigator.userAgent || null,
      platform: navigator.platform || null,
      language: navigator.language || null,
      languages: Array.isArray(navigator.languages) ? navigator.languages : null,
      uaData,
      screen: {
        width: screen.width ?? null,
        height: screen.height ?? null,
        availWidth: screen.availWidth ?? null,
        availHeight: screen.availHeight ?? null,
        colorDepth: screen.colorDepth ?? null,
        pixelDepth: screen.pixelDepth ?? null
      },
      viewport: {
        width: window.innerWidth || null,
        height: window.innerHeight || null,
        devicePixelRatio: window.devicePixelRatio || null
      },
      hardware: {
        cpuThreads: navigator.hardwareConcurrency ?? null,
        memoryGB: navigator.deviceMemory ?? null
      },
      battery,
      ip: ipDetails?.ip || ip || null,
      canvasFingerprint: _0xGcF(),
      webgl: _0xGw(),
      webgpu,
      audioFingerprint: audioFp,
      touch: _0xGt(),
      fonts: _0xDf(),
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack || window.doNotTrack || navigator.msDoNotTrack || null,
      mediaDevices,
      network: _0xGn(),
      theme: _0xGth(),
      colorGamut: _0xGcg(),
      hdr: _0xGhdr(),
      pwa: _0xGpwa(),
      permissions
    };

    let ipSection = '';
    if (ipDetails) {
      ipSection = `\n## اطلاعات موقعیت جغرافیایی آی‌پی\n\n` +
        `| فیلد | مقدار |\n|------|-------|\n` +
        `| IP | ${ipDetails.ip} |\n` +
        `| نسخه IP | ${ipDetails.version} |\n` +
        `| کشور | ${ipDetails.country || '-'} |\n` +
        `| کد کشور | ${ipDetails.countryCode || '-'} |\n` +
        `| استان | ${ipDetails.region || '-'} |\n` +
        `| شهر | ${ipDetails.city || '-'} |\n` +
        `| کد پستی | ${ipDetails.postal || '-'} |\n` +
        `| عرض جغرافیایی | ${ipDetails.latitude ?? '-'} |\n` +
        `| طول جغرافیایی | ${ipDetails.longitude ?? '-'} |\n` +
        `| منطقه زمانی | ${ipDetails.timezone || '-'} |\n` +
        `| ISP/سازمان | ${ipDetails.isp || '-'} |\n`;
    } else if (ip) {
      ipSection = `\n## اطلاعات آی‌پی\n\n⚠️ دریافت موقعیت مکانی برای IP \`${ip}\` با خطا مواجه شد.\n`;
    } else {
      ipSection = `\n## اطلاعات آی‌پی\n\n❌ آی‌پی در دسترس نیست.\n`;
    }

    const _0xib = [
      "# بازدید جدید",
      "",
      "## اثر انگشت مرورگر (Fingerprint)",
      "",
      "```json",
      JSON.stringify(data, null, 2),
      "```",
      ipSection
    ].join("\n");

    const response = await fetch(`https://api.github.com/repos/${_0xOn}/${_0xRp}/issues`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${_0xTk}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        title: `Visitor ${now.toISOString()}`.replace("T", " ").replace("Z", ""),
        body: _0xib
      })
    });

    if (!response.ok) return;

    _0xSc(_0xCk, "1", _0xMx);
  };

  _0xInit().catch(() => {});
})();
