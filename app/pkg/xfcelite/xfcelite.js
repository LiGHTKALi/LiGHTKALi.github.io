(() => {
  'use strict';

  const PKG = 'xfcelite';
  const KEY = `__kali_pkg_${PKG}`;
  const STORAGE_KEY = 'kali-pkg-xfcelite-settings:v2';
  const VALID_BACKGROUNDS = Object.freeze([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]);
  const MAX_HISTORY = 24;

  const THEME_KEYS = Object.freeze([
    '--000', '--bf0000', '--c90000', '--00bf00', '--00bd00', '--bf6900',
    '--0000ff', '--0000b7', '--bf00ff', '--a900a9', '--00aaaa', '--aaa',
    '--595959', '--ff8080', '--ff5555', '--80ff80', '--55ff55', '--ffc680',
    '--ffff55', '--8080ff', '--5555ff', '--df80ff', '--ff55ff', '--55ffff',
    '--fff', '--d41919', '--707070'
  ]);

  const DARK_THEME = Object.freeze({
    '--000': '#000',
    '--bf0000': '#bf0000',
    '--c90000': '#c90000',
    '--00bf00': '#00bf00',
    '--00bd00': '#00bd00',
    '--bf6900': '#bf6900',
    '--0000ff': '#0000ff',
    '--0000b7': '#0000b7',
    '--bf00ff': '#bf00ff',
    '--a900a9': '#a900a9',
    '--00aaaa': '#00aaaa',
    '--aaa': '#aaa',
    '--595959': '#595959',
    '--ff8080': '#ff8080',
    '--ff5555': '#ff5555',
    '--80ff80': '#80ff80',
    '--55ff55': '#55ff55',
    '--ffc680': '#ffc680',
    '--ffff55': '#ffff55',
    '--8080ff': '#8080ff',
    '--5555ff': '#5555ff',
    '--df80ff': '#df80ff',
    '--ff55ff': '#ff55ff',
    '--55ffff': '#55ffff',
    '--fff': '#fff',
    '--d41919': '#d41919',
    '--707070': '#707070'
  });

  const LIGHT_THEME = Object.freeze({
    '--000': '#fff',
    '--bf0000': '#a00000',
    '--c90000': '#a80000',
    '--00bf00': '#008000',
    '--00bd00': '#007d00',
    '--bf6900': '#995200',
    '--0000ff': '#0000a8',
    '--0000b7': '#00008f',
    '--bf00ff': '#8700b8',
    '--a900a9': '#7f007f',
    '--00aaaa': '#007777',
    '--aaa': '#595959',
    '--595959': '#aaa',
    '--ff8080': '#a00000',
    '--ff5555': '#b00000',
    '--80ff80': '#008000',
    '--55ff55': '#007000',
    '--ffc680': '#8a5600',
    '--ffff55': '#8a8a00',
    '--8080ff': '#0000a8',
    '--5555ff': '#00008f',
    '--df80ff': '#8700b8',
    '--ff55ff': '#920092',
    '--55ffff': '#007777',
    '--fff': '#000',
    '--d41919': '#a00000',
    '--707070': '#707070'
  });

  const DEFAULTS = Object.freeze({
    enablePersistence: true,
    requireRootForChange: true,
    allowInfoForAll: true,
    allowPreviewForAll: false,
    cycleWrap: true,
    background: null,
    blur: 0,
    previewBackground: null,
    previewActive: false,
    theme: 'dark',
    lastAction: 'none',
    lastResult: 'never'
  });

  const manifest = Object.freeze({
    name: PKG,
    version: '7.0.1',
    description: 'Kali Light XFCE Lite background and terminal theme manager with persistent runtime state.',
    author: 'Mobin Vaghar Jalaliyeh (Kali Light)',
    entry: 'install',
    dependencies: Object.freeze([]),
    permissions: Object.freeze({
      storage: 'write',
      cookies: 'none',
      network: 'none',
      filesystem: 'none'
    }),
    commands: Object.freeze([
      Object.freeze({ name: 'help', kind: 'plain', usage: 'xfcelite help', description: 'Show package documentation.', group: 'docs' }),
      Object.freeze({ name: 'info', kind: 'plain', usage: 'xfcelite info', description: 'Show package and runtime information.', group: 'runtime' }),
      Object.freeze({ name: 'manifest', kind: 'plain', usage: 'xfcelite manifest', description: 'Print the internal package manifest.', group: 'docs' }),
      Object.freeze({ name: 'policy', kind: 'plain', usage: 'xfcelite policy', description: 'Show permissions and runtime policy.', group: 'docs' }),
      Object.freeze({ name: 'state', kind: 'plain', usage: 'xfcelite state', description: 'Show current package state and settings.', group: 'runtime' }),
      Object.freeze({ name: 'commands', kind: 'plain', usage: 'xfcelite commands', description: 'List available package tags.', group: 'docs' }),
      Object.freeze({ name: 'mode', kind: 'plain', usage: 'xfcelite mode', description: 'Show current terminal mode.', group: 'runtime' }),
      Object.freeze({ name: 'version', kind: 'plain', usage: 'xfcelite version', description: 'Show package version.', group: 'runtime' }),
      Object.freeze({ name: 'set', kind: 'plain', usage: 'xfcelite set <1-25>', description: 'Set a background image.', group: 'wallpaper' }),
      Object.freeze({ name: 'blur', kind: 'plain', usage: 'xfcelite blur <0-100>', description: 'Set background blur intensity.', group: 'wallpaper' }),
      Object.freeze({ name: 'reset', kind: 'plain', usage: 'xfcelite reset', description: 'Reset background and blur.', group: 'wallpaper' }),
      Object.freeze({ name: 'preview', kind: 'plain', usage: 'xfcelite preview <1-25|off>', description: 'Preview a background without saving it.', group: 'wallpaper' }),
      Object.freeze({ name: 'next', kind: 'plain', usage: 'xfcelite next', description: 'Select the next background.', group: 'wallpaper' }),
      Object.freeze({ name: 'prev', kind: 'plain', usage: 'xfcelite prev', description: 'Select the previous background.', group: 'wallpaper' }),
      Object.freeze({ name: 'random', kind: 'plain', usage: 'xfcelite random', description: 'Select a random background.', group: 'wallpaper' }),
      Object.freeze({ name: 'list', kind: 'plain', usage: 'xfcelite list', description: 'List available backgrounds.', group: 'wallpaper' }),
      Object.freeze({ name: 'theme', kind: 'plain', usage: 'xfcelite theme <dark|light>', description: 'Switch terminal interface between dark and light mode. Root required.', group: 'appearance' }),
      Object.freeze({ name: 'save', kind: 'plain', usage: 'xfcelite save', description: 'Persist current package state.', group: 'storage' }),
      Object.freeze({ name: 'load', kind: 'plain', usage: 'xfcelite load', description: 'Load saved package state.', group: 'storage' }),
      Object.freeze({ name: 'history', kind: 'plain', usage: 'xfcelite history', description: 'Show recent package actions.', group: 'runtime' }),
      Object.freeze({ name: 'config', kind: 'plain', usage: 'xfcelite config <show|set|reset|help> [key] [value]', description: 'Inspect or change package configuration.', group: 'utility' }),
      Object.freeze({ name: 'clearcache', kind: 'plain', usage: 'xfcelite clearcache', description: 'Clear persistent package state.', group: 'utility' })
    ])
  });

  const state = {
    api: null,
    settings: { ...DEFAULTS },
    history: [],
    loadToken: 0
  };

  const safeHtml = (text) =>
    String(text ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

  const line = (text, cls = 'output') => ({
    type: 'line',
    html: `<span class="${safeHtml(cls)}">${safeHtml(text)}</span>`
  });

  const block = (text, cls = 'output') => ({
    type: 'line',
    html: `<pre class="${safeHtml(cls)}">${safeHtml(text)}</pre>`
  });

  const spacer = () => ({ type: 'spacer' });
  const kv = (key, value, cls = 'output') => line(`${key}: ${value}`, cls);
  const boolText = (value) => value ? 'true' : 'false';

  const toInt = (value) => {
    const n = Number.parseInt(String(value ?? ''), 10);
    return Number.isFinite(n) ? n : null;
  };

  const clamp = (value, min, max) => {
    const n = Number(value);
    if (!Number.isFinite(n)) return min;
    return Math.min(max, Math.max(min, n));
  };

  const normalizeBool = (value) => {
    const v = String(value ?? '').trim().toLowerCase();
    if (['1', 'true', 'yes', 'on', 'enable', 'enabled'].includes(v)) return true;
    if (['0', 'false', 'no', 'off', 'disable', 'disabled'].includes(v)) return false;
    return null;
  };

  const getApi = () => state.api;

  const snapshot = () => {
    const api = getApi();
    if (!api || typeof api.snapshot !== 'function') {
      return { mode: 'user', cwd: '/', history: [], commands: [], installed: [] };
    }
    try {
      return api.snapshot() || { mode: 'user', cwd: '/', history: [], commands: [], installed: [] };
    } catch {
      return { mode: 'user', cwd: '/', history: [], commands: [], installed: [] };
    }
  };

  const getMode = () => {
    const snap = snapshot();
    const value = String(snap.mode || '').toLowerCase();
    if (['user', 'root', 'ghost'].includes(value)) return value;
    const api = getApi();
    if (api && typeof api.getMode === 'function') {
      try {
        const fallback = String(api.getMode() || '').toLowerCase();
        if (['user', 'root', 'ghost'].includes(fallback)) return fallback;
      } catch {}
    }
    return 'user';
  };

  const isRoot = () => getMode() === 'root';

  const backgroundName = (value) =>
    value === null || value === undefined ? 'none' : `wallpaper(${value}).png`;

  const validBackground = (value) => {
    const n = toInt(value);
    return n !== null && VALID_BACKGROUNDS.includes(n) ? n : null;
  };

  const getVisibleBackground = () =>
    state.settings.previewActive
      ? state.settings.previewBackground
      : state.settings.background;

  const getBasePath = () =>
    String(window.location.href || '')
      .split('?')[0]
      .split('#')[0]
      .replace(/\/[^/]*$/, '/');

  const resolveImageUrl = (value) =>
    `${getBasePath()}pkg/${PKG}/wallpaper(${value}).png`;

  const bgLayer = () => document.getElementById('bgLayer');

  const pushHistory = (action, detail = '') => {
    state.history.push({
      at: new Date().toISOString(),
      action: String(action),
      detail: String(detail)
    });
    if (state.history.length > MAX_HISTORY) {
      state.history.splice(0, state.history.length - MAX_HISTORY);
    }
  };

  const resetSettings = () => {
    state.settings = { ...DEFAULTS };
  };

  const applyTheme = (theme, persistState = true) => {
    const normalized = String(theme || '').trim().toLowerCase();
    if (!['dark', 'light'].includes(normalized)) return false;

    const palette = normalized === 'dark' ? DARK_THEME : LIGHT_THEME;
    const root = document.documentElement;

    if (!root) return false;

    for (const key of THEME_KEYS) {
      if (Object.prototype.hasOwnProperty.call(palette, key)) {
        root.style.setProperty(key, palette[key]);
      }
    }

    root.dataset.kaliTheme = normalized;
    root.dataset.theme = normalized;
    state.settings.theme = normalized;
    state.settings.lastResult = 'theme-updated';

    if (persistState) {
      pushHistory('theme', `Interface theme changed to ${normalized} mode.`);
      persist();
    }

    return true;
  };

  const restoreTheme = () => {
    const theme = ['dark', 'light'].includes(state.settings.theme)
      ? state.settings.theme
      : DEFAULTS.theme;
    return applyTheme(theme, false);
  };

  const persist = () => {
    if (!state.settings.enablePersistence) return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        settings: {
          enablePersistence: state.settings.enablePersistence,
          requireRootForChange: state.settings.requireRootForChange,
          allowInfoForAll: state.settings.allowInfoForAll,
          allowPreviewForAll: state.settings.allowPreviewForAll,
          cycleWrap: state.settings.cycleWrap,
          background: state.settings.background,
          blur: state.settings.blur,
          theme: state.settings.theme,
          lastAction: state.settings.lastAction,
          lastResult: state.settings.lastResult
        },
        history: state.history.slice(-MAX_HISTORY)
      }));
    } catch {}
  };

  const loadPersisted = () => {
    resetSettings();
    state.history = [];
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        restoreTheme();
        return;
      }
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') {
        restoreTheme();
        return;
      }
      const stored = parsed.settings;
      if (stored && typeof stored === 'object') {
        if (typeof stored.enablePersistence === 'boolean') state.settings.enablePersistence = stored.enablePersistence;
        if (typeof stored.requireRootForChange === 'boolean') state.settings.requireRootForChange = stored.requireRootForChange;
        if (typeof stored.allowInfoForAll === 'boolean') state.settings.allowInfoForAll = stored.allowInfoForAll;
        if (typeof stored.allowPreviewForAll === 'boolean') state.settings.allowPreviewForAll = stored.allowPreviewForAll;
        if (typeof stored.cycleWrap === 'boolean') state.settings.cycleWrap = stored.cycleWrap;
        state.settings.background = stored.background === null ? null : validBackground(stored.background);
        state.settings.blur = clamp(toInt(stored.blur) ?? 0, 0, 100);
        if (stored.theme === 'dark' || stored.theme === 'light') state.settings.theme = stored.theme;
        if (typeof stored.lastAction === 'string') state.settings.lastAction = stored.lastAction;
        if (typeof stored.lastResult === 'string') state.settings.lastResult = stored.lastResult;
      }
      if (Array.isArray(parsed.history)) {
        state.history = parsed.history.filter(Boolean).slice(-MAX_HISTORY);
      }
    } catch {}
    restoreTheme();
  };

  const resetVisuals = () => {
    const el = bgLayer();
    if (!el) return;
    el.style.backgroundImage = '';
    el.style.backgroundSize = '';
    el.style.backgroundPosition = '';
    el.style.backgroundRepeat = '';
    el.style.backgroundColor = '';
    el.style.filter = '';
  };

  const preloadImage = (url) =>
    new Promise((resolve) => {
      const image = new Image();
      image.onload = () => resolve(true);
      image.onerror = () => resolve(false);
      image.src = url;
    });

  const applyVisuals = async () => {
    const el = bgLayer();
    if (!el) return;

    const current = getVisibleBackground();

    if (current === null) {
      resetVisuals();
      return;
    }

    const token = ++state.loadToken;
    const url = resolveImageUrl(current);
    const loaded = await preloadImage(url);

    if (token !== state.loadToken) return;

    if (!loaded) {
      if (state.settings.previewActive) {
        state.settings.previewActive = false;
        state.settings.previewBackground = null;
        state.settings.lastResult = 'preview-load-failed';
      } else {
        state.settings.background = null;
        state.settings.blur = 0;
        state.settings.lastResult = 'background-load-failed';
      }
      resetVisuals();
      pushHistory('load-failed', `Asset unavailable: wallpaper(${current}).png`);
      persist();
      return;
    }

    const blurPx = (clamp(state.settings.blur, 0, 100) / 100) * 20;

    el.style.backgroundImage = `url("${url}")`;
    el.style.backgroundSize = 'cover';
    el.style.backgroundPosition = 'center';
    el.style.backgroundRepeat = 'no-repeat';
    el.style.backgroundColor = 'transparent';
    el.style.filter = blurPx > 0
      ? `blur(${blurPx}px) saturate(.92) contrast(.98) brightness(1)`
      : 'saturate(.92) contrast(.98) brightness(1)';
  };

  const setBackground = async (value, options = {}) => {
    const background = validBackground(value);
    if (background === null) return false;

    if (options.preview) {
      state.settings.previewActive = true;
      state.settings.previewBackground = background;
      state.settings.lastResult = 'preview-active';
      pushHistory('preview', options.note || `Previewed wallpaper(${background}).png`);
    } else {
      state.settings.previewActive = false;
      state.settings.previewBackground = null;
      state.settings.background = background;
      state.settings.lastResult = 'success';
      pushHistory('set', options.note || `Selected wallpaper(${background}).png`);
    }

    await applyVisuals();

    if (!options.preview && options.persistState !== false) {
      persist();
    }

    return true;
  };

  const setBlur = async (value) => {
    const n = toInt(value);
    if (n === null || n < 0 || n > 100) return false;
    state.settings.blur = n;
    state.settings.lastResult = 'success';
    pushHistory('blur', `Blur changed to ${n}%`);
    await applyVisuals();
    persist();
    return true;
  };

  const clearPreview = () => {
    state.settings.previewActive = false;
    state.settings.previewBackground = null;
  };

  const requireRoot = (label) => {
    if (!state.settings.requireRootForChange || isRoot()) return null;
    return [
      line(`E: ${label} requires root mode`, 'danger'),
      line('Hint: use su or sudo before running this command.', 'muted')
    ];
  };

  const renderManifest = () => [
    line('Internal manifest', 'accent'),
    kv('name', manifest.name),
    kv('version', manifest.version),
    kv('entry', manifest.entry),
    kv('author', manifest.author),
    kv('description', manifest.description),
    kv('dependencies', manifest.dependencies.length ? manifest.dependencies.join(', ') : '(none)'),
    kv('permissions.storage', manifest.permissions.storage),
    kv('permissions.cookies', manifest.permissions.cookies),
    kv('permissions.network', manifest.permissions.network),
    kv('permissions.filesystem', manifest.permissions.filesystem),
    kv('command count', String(manifest.commands.length))
  ];

  const renderPolicy = () => [
    line('Runtime policy', 'accent'),
    kv('storage', manifest.permissions.storage),
    kv('cookies', manifest.permissions.cookies),
    kv('network', manifest.permissions.network),
    kv('filesystem', manifest.permissions.filesystem),
    kv('root required for changes', boolText(state.settings.requireRootForChange)),
    kv('theme changes require root', 'true'),
    kv('info allowed for all', boolText(state.settings.allowInfoForAll)),
    kv('preview allowed for all', boolText(state.settings.allowPreviewForAll)),
    spacer(),
    line('Theme changes modify the terminal color variables only.', 'muted'),
    line('The prompt identity and root name remain unchanged.', 'muted'),
    line('No network, cookie, or arbitrary filesystem access is required.', 'muted')
  ];

  const describeCommand = (cmd) =>
    `${cmd.usage} — ${cmd.description} | kind=${cmd.kind || 'plain'}`;

  const renderCommands = () => {
    const output = [line('Command catalog', 'accent')];
    for (const cmd of manifest.commands) {
      output.push(kv(cmd.name, describeCommand(cmd)));
    }
    return output;
  };

  const renderTags = () => {
    const groups = new Map();
    for (const cmd of manifest.commands) {
      const group = cmd.group || 'utility';
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group).push(cmd.name);
    }

    const labels = {
      docs: 'Docs',
      runtime: 'Runtime',
      wallpaper: 'Wallpaper',
      appearance: 'Appearance',
      storage: 'Storage',
      utility: 'Utility'
    };

    const output = [line('Available xfcelite tags', 'accent')];

    for (const group of ['docs', 'runtime', 'wallpaper', 'appearance', 'storage', 'utility']) {
      const names = groups.get(group);
      if (names?.length) output.push(kv(labels[group] || group, names.join(', ')));
    }

    output.push(spacer());
    output.push(line('Examples', 'accent'));
    output.push(line('xfcelite', 'output'));
    output.push(line('xfcelite info', 'output'));
    output.push(line('xfcelite theme dark', 'output'));
    output.push(line('xfcelite theme light', 'output'));
    output.push(line('xfcelite set 4', 'output'));
    return output;
  };

  const renderHelp = () => [
    line('XFCE Lite background manager', 'accent'),
    line('xfcelite provides background, blur, preview, persistence, and terminal theme controls for Kali Light.', 'muted'),
    spacer(),
    ...renderTags(),
    spacer(),
    line('Background controls', 'accent'),
    line('xfcelite set <1-25>        select and apply a background', 'output'),
    line('xfcelite blur <0-100>      set background blur', 'output'),
    line('xfcelite reset             restore default visuals', 'output'),
    line('xfcelite preview <n|off>   preview without saving', 'output'),
    line('xfcelite next              select next background', 'output'),
    line('xfcelite prev              select previous background', 'output'),
    line('xfcelite random            select random background', 'output'),
    spacer(),
    line('Appearance', 'accent'),
    line('xfcelite theme dark        switch to dark mode', 'output'),
    line('xfcelite theme light       switch to light mode', 'output'),
    line('Theme changes require root mode.', 'muted'),
    spacer(),
    line('Inspection', 'accent'),
    line('xfcelite info              show runtime information', 'output'),
    line('xfcelite state             show package state', 'output'),
    line('xfcelite list              list background slots', 'output'),
    line('xfcelite history           show recent actions', 'output'),
    line('xfcelite commands          show command catalog', 'output'),
    line('xfcelite manifest          show package manifest', 'output'),
    line('xfcelite policy            show runtime policy', 'output'),
    line('xfcelite mode              show terminal mode', 'output'),
    line('xfcelite version           show package version', 'output'),
    spacer(),
    line('Configuration', 'accent'),
    line('xfcelite config show', 'output'),
    line('xfcelite config set <key> <value>', 'output'),
    line('xfcelite config reset', 'output'),
    line('xfcelite config help', 'output')
  ];

  const cmdRoot = () => {
    state.settings.lastAction = PKG;
    return [
      line(`Package ${manifest.name} ${manifest.version}`, 'accent'),
      line(manifest.description, 'muted'),
      spacer(),
      kv('saved background', backgroundName(state.settings.background)),
      kv('visible background', backgroundName(getVisibleBackground())),
      kv('blur', `${state.settings.blur}%`),
      kv('theme', state.settings.theme),
      kv('preview active', boolText(state.settings.previewActive)),
      kv('mode', getMode()),
      spacer(),
      line('Type "xfcelite help" for documentation.', 'muted')
    ];
  };

  const cmdHelp = () => {
    state.settings.lastAction = `${PKG} help`;
    return renderHelp();
  };

  const cmdInfo = () => {
    state.settings.lastAction = `${PKG} info`;

    if (!state.settings.allowInfoForAll && !isRoot()) {
      return [
        line('E: xfcelite info is restricted', 'danger'),
        line('Hint: use root mode to inspect package state.', 'muted')
      ];
    }

    const snap = snapshot();

    return [
      line('Runtime information', 'accent'),
      kv('package', manifest.name),
      kv('version', manifest.version),
      kv('mode', getMode()),
      kv('theme', state.settings.theme),
      kv('cwd', snap.cwd || '/'),
      kv('saved background', backgroundName(state.settings.background)),
      kv('visible background', backgroundName(getVisibleBackground())),
      kv('blur', `${state.settings.blur}%`),
      kv('preview active', boolText(state.settings.previewActive)),
      kv('installed packages', String(Array.isArray(snap.installed) ? snap.installed.length : 0)),
      kv('registered commands', String(Array.isArray(snap.commands) ? snap.commands.length : 0)),
      kv('history length', String(Array.isArray(snap.history) ? snap.history.length : 0)),
      kv('last action', state.settings.lastAction),
      kv('last result', state.settings.lastResult),
      spacer(),
      line('Theme control changes color variables only.', 'muted'),
      line('Prompt identity, username, and root name remain unchanged.', 'muted')
    ];
  };

  const cmdManifest = () => {
    state.settings.lastAction = `${PKG} manifest`;
    return [...renderManifest(), spacer(), block(JSON.stringify(manifest, null, 2))];
  };

  const cmdPolicy = () => {
    state.settings.lastAction = `${PKG} policy`;
    return renderPolicy();
  };

  const cmdState = () => {
    state.settings.lastAction = `${PKG} state`;
    return [
      line('Package state', 'accent'),
      kv('saved background', backgroundName(state.settings.background)),
      kv('visible background', backgroundName(getVisibleBackground())),
      kv('preview background', backgroundName(state.settings.previewBackground)),
      kv('preview active', boolText(state.settings.previewActive)),
      kv('blur', `${state.settings.blur}%`),
      kv('theme', state.settings.theme),
      kv('terminal mode', getMode()),
      spacer(),
      line('Configuration', 'accent'),
      kv('enablePersistence', boolText(state.settings.enablePersistence)),
      kv('requireRootForChange', boolText(state.settings.requireRootForChange)),
      kv('allowInfoForAll', boolText(state.settings.allowInfoForAll)),
      kv('allowPreviewForAll', boolText(state.settings.allowPreviewForAll)),
      kv('cycleWrap', boolText(state.settings.cycleWrap)),
      spacer(),
      line('Runtime', 'accent'),
      kv('lastAction', state.settings.lastAction),
      kv('lastResult', state.settings.lastResult),
      kv('history entries', String(state.history.length))
    ];
  };

  const cmdCommands = () => {
    state.settings.lastAction = `${PKG} commands`;
    return renderCommands();
  };

  const cmdMode = () => {
    state.settings.lastAction = `${PKG} mode`;
    const current = getMode();
    return [
      line('Current terminal mode', 'accent'),
      kv('mode', current, current === 'root' ? 'danger' : 'output'),
      kv('root access', boolText(current === 'root')),
      kv('can change background', boolText(!state.settings.requireRootForChange || current === 'root')),
      kv('can change theme', boolText(current === 'root'))
    ];
  };

  const cmdVersion = () => {
    state.settings.lastAction = `${PKG} version`;
    return [
      line('Package version', 'accent'),
      kv('name', manifest.name),
      kv('version', manifest.version),
      kv('entry', manifest.entry),
      kv('author', manifest.author)
    ];
  };

  const cmdTheme = ({ args }) => {
    state.settings.lastAction = `${PKG} theme`;
    const denied = requireRoot('xfcelite theme');
    if (denied) return denied;

    const requested = String(args[1] ?? '').trim().toLowerCase();

    if (!requested || !['dark', 'light'].includes(requested)) {
      return [
        line('Usage: xfcelite theme <dark|light>', 'danger'),
        line(`Current theme: ${state.settings.theme}`, 'muted')
      ];
    }

    if (requested === state.settings.theme) {
      return [
        line(`Theme already set to ${requested} mode.`, 'accent'),
        line('No color changes were required.', 'muted')
      ];
    }

    const changed = applyTheme(requested, false);

    if (!changed) {
      return [
        line('E: failed to apply terminal theme.', 'danger')
      ];
    }

    state.settings.lastResult = 'theme-updated';
    pushHistory('theme', `Theme changed to ${requested} mode.`);
    persist();

    return [
      line(`Terminal theme switched to ${requested} mode.`, 'accent'),
      line('Interface colors were updated successfully.', 'muted'),
      line('Root identity and prompt name remain unchanged.', 'muted')
    ];
  };

  const cmdSet = async ({ args }) => {
    state.settings.lastAction = `${PKG} set`;
    const denied = requireRoot('xfcelite set');
    if (denied) return denied;

    const value = validBackground(args[1]);

    if (value === null) {
      return [line('Usage: xfcelite set <1-25>', 'danger')];
    }

    const ok = await setBackground(value, {
      persistState: true,
      preview: false,
      note: `Selected wallpaper(${value}).png`
    });

    return ok
      ? [
          line(`Background set to wallpaper(${value}).png`, 'accent'),
          line('The selection was applied and persisted successfully.', 'muted')
        ]
      : [
          line('E: background could not be applied.', 'danger'),
          line(`Check that pkg/${PKG}/wallpaper(${value}).png exists.`, 'muted')
        ];
  };

  const cmdBlur = async ({ args }) => {
    state.settings.lastAction = `${PKG} blur`;
    const denied = requireRoot('xfcelite blur');
    if (denied) return denied;

    const value = toInt(args[1]);

    if (value === null || value < 0 || value > 100) {
      return [line('Usage: xfcelite blur <0-100>', 'danger')];
    }

    const ok = await setBlur(value);

    return ok
      ? [
          line(`Blur set to ${value}%`, 'accent'),
          line('The visual filter was applied to the current background.', 'muted')
        ]
      : [line('E: invalid blur value.', 'danger')];
  };

  const cmdReset = async () => {
    state.settings.lastAction = `${PKG} reset`;
    const denied = requireRoot('xfcelite reset');
    if (denied) return denied;

    state.loadToken += 1;
    clearPreview();
    state.settings.background = null;
    state.settings.blur = 0;
    state.settings.lastResult = 'reset';

    pushHistory('reset', 'Background and blur restored to default visuals.');
    resetVisuals();
    persist();

    return [
      line('Background reset to default.', 'accent'),
      line('The visual layer has been cleared and blur set to zero.', 'muted')
    ];
  };

  const cmdPreview = async ({ args }) => {
    state.settings.lastAction = `${PKG} preview`;

    if (!state.settings.allowPreviewForAll && !isRoot()) {
      return [
        line('E: xfcelite preview is restricted', 'danger'),
        line('Hint: use root mode to access preview actions.', 'muted')
      ];
    }

    const target = String(args[1] ?? '').trim().toLowerCase();

    if (['off', 'none', 'clear'].includes(target)) {
      clearPreview();
      state.settings.lastResult = 'preview-off';
      pushHistory('preview-off', 'Preview disabled and saved background restored.');
      await applyVisuals();

      return [
        line('Preview disabled.', 'accent'),
        line(`Visible background restored to ${backgroundName(state.settings.background)}`, 'output')
      ];
    }

    const value = validBackground(args[1]);

    if (value === null) {
      return [line('Usage: xfcelite preview <1-25|off>', 'danger')];
    }

    const ok = await setBackground(value, {
      preview: true,
      persistState: false,
      note: `Previewed wallpaper(${value}).png`
    });

    return ok
      ? [
          line(`Previewing wallpaper(${value}).png`, 'accent'),
          line('Preview mode is active and the saved background was not changed.', 'muted')
        ]
      : [
          line('E: background preview failed.', 'danger'),
          line(`Check that pkg/${PKG}/wallpaper(${value}).png exists.`, 'muted')
        ];
  };

  const cmdNext = async () => {
    state.settings.lastAction = `${PKG} next`;
    const denied = requireRoot('xfcelite next');
    if (denied) return denied;

    const current = getVisibleBackground() ?? state.settings.background ?? 1;
    const index = VALID_BACKGROUNDS.indexOf(current);
    const next = state.settings.cycleWrap
      ? VALID_BACKGROUNDS[(index + 1) % VALID_BACKGROUNDS.length]
      : VALID_BACKGROUNDS[Math.min(index + 1, VALID_BACKGROUNDS.length - 1)];

    const ok = await setBackground(next, {
      persistState: true,
      preview: false,
      note: `Advanced to wallpaper(${next}).png`
    });

    return ok
      ? [line(`Background advanced to wallpaper(${next}).png`, 'accent')]
      : [line('E: unable to advance to the next background.', 'danger')];
  };

  const cmdPrev = async () => {
    state.settings.lastAction = `${PKG} prev`;
    const denied = requireRoot('xfcelite prev');
    if (denied) return denied;

    const current = getVisibleBackground() ?? state.settings.background ?? 1;
    const index = VALID_BACKGROUNDS.indexOf(current);
    const previous = state.settings.cycleWrap
      ? VALID_BACKGROUNDS[(index - 1 + VALID_BACKGROUNDS.length) % VALID_BACKGROUNDS.length]
      : VALID_BACKGROUNDS[Math.max(index - 1, 0)];

    const ok = await setBackground(previous, {
      persistState: true,
      preview: false,
      note: `Moved to wallpaper(${previous}).png`
    });

    return ok
      ? [line(`Background moved to wallpaper(${previous}).png`, 'accent')]
      : [line('E: unable to move to the previous background.', 'danger')];
  };

  const cmdRandom = async () => {
    state.settings.lastAction = `${PKG} random`;
    const denied = requireRoot('xfcelite random');
    if (denied) return denied;

    const current = state.settings.background;
    const available = VALID_BACKGROUNDS.filter(value => value !== current);
    const value = available[Math.floor(Math.random() * available.length)];

    const ok = await setBackground(value, {
      persistState: true,
      preview: false,
      note: `Randomly selected wallpaper(${value}).png`
    });

    return ok
      ? [line(`Random background selected: wallpaper(${value}).png`, 'accent')]
      : [line('E: failed to select a random background.', 'danger')];
  };

  const cmdList = () => {
    state.settings.lastAction = `${PKG} list`;

    if (!state.settings.allowInfoForAll && !isRoot()) {
      return [
        line('E: xfcelite list is restricted', 'danger'),
        line('Hint: use root mode to inspect the background catalog.', 'muted')
      ];
    }

    const current = getVisibleBackground();
    const output = [
      line('Available backgrounds', 'accent'),
      kv('saved', backgroundName(state.settings.background)),
      kv('visible', backgroundName(current), state.settings.previewActive ? 'accent' : 'output'),
      spacer()
    ];

    for (const value of VALID_BACKGROUNDS) {
      const marker = value === current
        ? ' [visible]'
        : value === state.settings.background
          ? ' [saved]'
          : '';
      output.push(line(`wallpaper(${value}).png${marker}`, value === current ? 'accent' : 'output'));
    }

    return output;
  };

  const cmdSave = () => {
    state.settings.lastAction = `${PKG} save`;
    const denied = requireRoot('xfcelite save');
    if (denied) return denied;

    persist();
    state.settings.lastResult = 'saved';
    pushHistory('save', 'Current package state persisted.');

    return [
      line('Package state saved.', 'accent'),
      kv('background', backgroundName(state.settings.background)),
      kv('blur', `${state.settings.blur}%`),
      kv('theme', state.settings.theme)
    ];
  };

  const cmdLoad = async () => {
    state.settings.lastAction = `${PKG} load`;
    const denied = requireRoot('xfcelite load');
    if (denied) return denied;

    loadPersisted();
    clearPreview();
    restoreTheme();
    state.settings.lastResult = 'loaded';
    pushHistory('load', 'Persisted package state loaded.');
    await applyVisuals();

    return [
      line('Package state loaded.', 'accent'),
      kv('background', backgroundName(state.settings.background)),
      kv('blur', `${state.settings.blur}%`),
      kv('theme', state.settings.theme)
    ];
  };

  const cmdHistory = () => {
    state.settings.lastAction = `${PKG} history`;
    const recent = state.history.slice(-10);
    const output = [
      line('Recent xfcelite history', 'accent'),
      kv('stored events', String(state.history.length))
    ];

    if (!recent.length) {
      output.push(line('(none)', 'muted'));
      return output;
    }

    for (const entry of recent) {
      output.push(line(`${entry.at} | ${entry.action} | ${entry.detail}`, 'output'));
    }

    return output;
  };

  const cmdConfig = ({ args }) => {
    state.settings.lastAction = `${PKG} config`;
    const sub = String(args[0] ?? 'show').toLowerCase();

    const allowedKeys = new Set([
      'enablePersistence',
      'requireRootForChange',
      'allowInfoForAll',
      'allowPreviewForAll',
      'cycleWrap'
    ]);

    const renderCurrent = () => [
      line('Current configuration', 'accent'),
      kv('enablePersistence', boolText(state.settings.enablePersistence)),
      kv('requireRootForChange', boolText(state.settings.requireRootForChange)),
      kv('allowInfoForAll', boolText(state.settings.allowInfoForAll)),
      kv('allowPreviewForAll', boolText(state.settings.allowPreviewForAll)),
      kv('cycleWrap', boolText(state.settings.cycleWrap)),
      kv('theme', state.settings.theme)
    ];

    const renderConfigHelp = () => [
      line('xfcelite config usage', 'accent'),
      line('xfcelite config show', 'output'),
      line('xfcelite config set <key> <value>', 'output'),
      line('xfcelite config reset', 'output'),
      line('xfcelite config help', 'output'),
      line(`Allowed: ${Array.from(allowedKeys).join(', ')}`, 'muted')
    ];

    if (sub === 'help') return renderConfigHelp();
    if (sub === 'show') return renderCurrent();

    if (sub === 'reset') {
      const denied = requireRoot('xfcelite config reset');
      if (denied) return denied;

      state.settings.enablePersistence = DEFAULTS.enablePersistence;
      state.settings.requireRootForChange = DEFAULTS.requireRootForChange;
      state.settings.allowInfoForAll = DEFAULTS.allowInfoForAll;
      state.settings.allowPreviewForAll = DEFAULTS.allowPreviewForAll;
      state.settings.cycleWrap = DEFAULTS.cycleWrap;

      state.settings.lastResult = 'config-reset';
      persist();

      return [line('Configuration reset to defaults.', 'accent'), ...renderCurrent()];
    }

    if (sub === 'set') {
      const denied = requireRoot('xfcelite config set');
      if (denied) return denied;

      const key = String(args[1] ?? '').trim();
      const value = String(args.slice(2).join(' ') ?? '').trim();

      if (!key || !allowedKeys.has(key)) {
        return [
          line(`Unknown config key: ${key || '(empty)'}`, 'danger'),
          line(`Allowed: ${Array.from(allowedKeys).join(', ')}`, 'muted')
        ];
      }

      const parsed = normalizeBool(value);

      if (parsed === null) {
        return [line(`${key} expects a boolean value.`, 'danger')];
      }

      state.settings[key] = parsed;
      state.settings.lastResult = 'config-updated';
      persist();

      return [
        line(`Updated ${key}.`, 'accent'),
        kv(key, boolText(state.settings[key]))
      ];
    }

    return [
      line(`Unknown config subcommand: ${sub}`, 'danger'),
      ...renderConfigHelp()
    ];
  };

  const cmdClearCache = () => {
    state.settings.lastAction = `${PKG} clearcache`;

    const denied = requireRoot('xfcelite clearcache');
    if (denied) return denied;

    state.loadToken += 1;
    state.history = [];
    resetSettings();
    resetVisuals();

    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {}

    restoreTheme();

    return [
      line('Package state cleared.', 'accent'),
      line('Background, blur, theme, preview, and history state were reset.', 'muted')
    ];
  };

  const dispatch = ({ args }) => {
    const sub = String(args[0] ?? '').toLowerCase();

    if (!sub) return cmdRoot();
    if (sub === 'help') return cmdHelp();
    if (sub === 'info') return cmdInfo();
    if (sub === 'manifest') return cmdManifest();
    if (sub === 'policy') return cmdPolicy();
    if (sub === 'state') return cmdState();
    if (sub === 'commands') return cmdCommands();
    if (sub === 'mode') return cmdMode();
    if (sub === 'version') return cmdVersion();
    if (sub === 'theme') return cmdTheme({ args });
    if (sub === 'set') return cmdSet({ args });
    if (sub === 'blur') return cmdBlur({ args });
    if (sub === 'reset') return cmdReset();
    if (sub === 'preview') return cmdPreview({ args });
    if (sub === 'next') return cmdNext();
    if (sub === 'prev') return cmdPrev();
    if (sub === 'random') return cmdRandom();
    if (sub === 'list') return cmdList();
    if (sub === 'save') return cmdSave();
    if (sub === 'load') return cmdLoad();
    if (sub === 'history') return cmdHistory();
    if (sub === 'config') return cmdConfig({ args: args.slice(1) });
    if (sub === 'clearcache') return cmdClearCache();

    return [
      line(`Unknown tag: ${sub}`, 'danger'),
      line('Run "xfcelite" to list available tags or "xfcelite help" for documentation.', 'muted')
    ];
  };

  function install(api) {
    state.api = api || null;

    if (!state.api || typeof state.api.registerCommand !== 'function') {
      state.api = null;
      return false;
    }

    loadPersisted();

    try {
      if (typeof state.api.unregisterCommand === 'function') {
        state.api.unregisterCommand(PKG);
      }
    } catch {}

    try {
      state.api.registerCommand(PKG, {
        kind: 'plain',
        description: 'XFCE Lite background and terminal theme manager for Kali Light.',
        usage: 'xfcelite [help|info|manifest|policy|state|commands|mode|version|theme|set|blur|reset|preview|next|prev|random|list|save|load|history|config|clearcache]',
        run: ({ args }) => dispatch({ args })
      });
    } catch {
      state.api = null;
      return false;
    }

    restoreTheme();
    resetVisuals();

    if (state.settings.background !== null || state.settings.blur !== 0) {
      applyVisuals().catch(() => {});
    }

    if (typeof state.api.append === 'function') {
      state.api.append([
        line(`Package ${manifest.name} ${manifest.version} installed.`, 'accent'),
        line('Type "xfcelite" to inspect the current state.', 'output'),
        line('Type "xfcelite help" for package documentation.', 'muted'),
        kv('theme', `${state.settings.theme}`),
        kv('background', backgroundName(state.settings.background)),
        kv('blur', `${state.settings.blur}%`)
      ]);
    }

    persist();
    return true;
  }

  function uninstall(api) {
    const hostApi = api || state.api;

    if (hostApi && typeof hostApi.unregisterCommand === 'function') {
      try {
        hostApi.unregisterCommand(PKG);
      } catch {}
    }

    state.loadToken += 1;
    state.history = [];
    resetSettings();
    resetVisuals();

    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {}

    restoreTheme();

    if (hostApi && typeof hostApi.append === 'function') {
      hostApi.append([
        line(`Package ${manifest.name} removed.`, 'muted')
      ]);
    }

    state.api = null;
    return true;
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
    getState: () => ({
      settings: { ...state.settings },
      background: state.settings.background,
      blur: state.settings.blur,
      theme: state.settings.theme,
      previewBackground: state.settings.previewBackground,
      previewActive: state.settings.previewActive,
      history: state.history.slice(),
      mode: getMode()
    }),
    settings: state.settings
  });

  window[KEY] = exported;
})();
