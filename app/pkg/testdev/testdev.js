/*
 * ============================================================================
 * Kali Light Package Developer Signature & Color Reference
 * ============================================================================
 *
 * Studio:
 *   Kali Light Coding Studio
 *
 * Kali Light Developer:
 *   Mobin
 *
 * Package Development Notes:
 *   - Kali Light package names are case-sensitive.
 *   - Package names should use English/ASCII characters only.
 *   - Recommended package naming style:
 *       lowercase English letters + numbers + "-" or "_"
 *   - Do not use Persian, Arabic, emoji, spaces or other Unicode characters
 *     in package names.
 *   - Keep package names short, unique and stable.
 *   - Changing the package name after release may create a different package
 *     identity in the Kali Light package registry.
 *
 * Example:
 *   Correct:
 *     testdev
 *     network-tool
 *     package_v2
 *
 *   Avoid:
 *     TestDev
 *     test dev
 *     پکیج
 *     test.dev
 *
 * ============================================================================
 * Kali Light Allowed Output Colors
 * ============================================================================
 *
 * Developers must use the English class name when selecting a color.
 *
 * black        = #000
 * red          = #c90000
 * green        = #00bd00
 * success      = #00bd00
 * yellow-dark  = #bf6900
 * blue         = #0000b7
 * purple       = #bf00ff
 * ghost        = #bf00ff
 * cyan         = #00aaaa
 *
 * white        = #fff
 * muted        = #aaa
 * gray         = #595959
 * red-light    = #ff5555
 * green-light  = #55ff55
 * yellow-light = #ffff55
 * accent       = #ffff55
 * blue-light   = #5555ff
 * path         = #5555ff
 * purple-light = #ff55ff
 * cyan-light   = #55ffff
 * user         = #55ffff
 * white-light  = #fff
 * symbol       = #fff
 * output       = #fff
 * root         = #d41919
 * danger       = #d41919
 * dim          = #707070
 *
 * Example:
 *   api.line('Hello', 'cyan');
 *   api.line('Warning', 'danger');
 *   api.line('Path: /home/kali', 'path');
 *
 * Important:
 *   The color identifiers are case-sensitive.
 *
 * ============================================================================
 * Manifest Overview
 * ============================================================================
 *
 * The manifest is the package identity and metadata declaration.
 *
 * name:
 *   Unique package name.
 *   Must use English/ASCII naming.
 *   Recommended: lowercase.
 *
 * version:
 *   Package version.
 *   Use a stable semantic-style version such as:
 *     1.0.0
 *     1.2.5
 *     2.0.0
 *
 * description:
 *   Human-readable package description.
 *
 * author:
 *   Package developer or development studio.
 *
 * help:
 *   Main help command for the package.
 *
 * official:
 *   true  = official/trusted system-level package.
 *   false = normal developer package.
 *
 * default:
 *   true  = default package managed as a core/default package.
 *   false = normal optional package.
 *
 * securityLevel:
 *   Declares the package security level.
 *
 * permissions:
 *   Declares requested runtime capabilities.
 *   Supported categories:
 *     storage
 *     cookies
 *     network
 *     filesystem
 *
 * commands:
 *   Lists commands registered by the package.
 *
 * dependencies:
 *   Lists package dependencies.
 *
 * entry:
 *   Identifies the package initialization entry point.
 *   Kali Light packages use:
 *     install
 *
 * ============================================================================
 * Package Lifecycle
 * ============================================================================
 *
 * install():
 *   - Validate the Kali Light bridge.
 *   - Register package-owned commands.
 *   - Initialize package-local state.
 *   - Do not print installation progress.
 *
 * uninstall():
 *   - Unregister package-owned commands.
 *   - Clear package-local state.
 *   - Do not print uninstall progress.
 *
 * The Kali Light Core owns lifecycle output.
 *
 * ============================================================================
 * Studio:
 *   Kali Light Coding Studio
 *
 * Kali Light Developer:
 *   Mobin
 * ============================================================================
 */

(() => {
  'use strict';

  /*
   * --------------------------------------------------------------------------
   * Package Identity
   * --------------------------------------------------------------------------
   */

  const PKG = 'testdev';
  const VERSION = '1.1.3';
  const GLOBAL_KEY = `__kali_pkg_${PKG}`;

  /*
   * Package names are case-sensitive.
   *
   * This validation intentionally accepts only:
   *   - English ASCII letters
   *   - numbers
   *   - underscore
   *   - hyphen
   *
   * The package must begin with an English letter.
   *
   * Lowercase package names are strongly recommended for stable package
   * identity and to avoid confusion between names such as:
   *
   *   TestDev
   *   testdev
   *
   * Those two names are treated as different identities.
   */
  const isValidPackageName = name => {
    const value = String(name ?? '').trim();

    return (
      /^[a-zA-Z][a-zA-Z0-9_-]*$/.test(value) &&
      /[A-Za-z]/.test(value)
    );
  };

  /*
   * Kali Light strongly recommends lowercase package identifiers.
   *
   * This does not silently modify the package name. The package developer
   * must intentionally choose the correct identity.
   */
  const isRecommendedPackageName = name => {
    const value = String(name ?? '').trim();

    return (
      isValidPackageName(value) &&
      value === value.toLowerCase()
    );
  };

  if (!isValidPackageName(PKG)) {
    throw new Error(
      'INVALID_PACKAGE_NAME: Package names must use English ASCII letters, numbers, "-" or "_".'
    );
  }

  if (!isRecommendedPackageName(PKG)) {
    throw new Error(
      'INVALID_PACKAGE_NAME_CASE: Kali Light recommends lowercase package names.'
    );
  }

  /*
   * --------------------------------------------------------------------------
   * Allowed Kali Light Colors
   * --------------------------------------------------------------------------
   *
   * These are documentation metadata for package developers.
   * The actual rendering class is still provided by the Kali Light Core.
   */
  const KALI_LIGHT_COLORS = Object.freeze({
    black: '000',
    red: 'c90000',
    green: '00bd00',
    success: '00bd00',
    'yellow-dark': 'bf6900',
    blue: '0000b7',
    purple: 'bf00ff',
    ghost: 'bf00ff',
    cyan: '00aaaa',
    white: 'fff',
    muted: 'aaa',
    gray: '595959',
    'red-light': 'ff5555',
    'green-light': '55ff55',
    'yellow-light': 'ffff55',
    accent: 'ffff55',
    'blue-light': '5555ff',
    path: '5555ff',
    'purple-light': 'ff55ff',
    'cyan-light': '55ffff',
    user: '55ffff',
    'white-light': 'fff',
    symbol: 'fff',
    output: 'fff',
    root: 'd41919',
    danger: 'd41919',
    dim: '707070'
  });

  /*
   * --------------------------------------------------------------------------
   * Package Manifest
   * --------------------------------------------------------------------------
   *
   * The manifest is the official metadata declaration for this package.
   *
   * Each property has a specific purpose:
   *
   * name:
   *   The canonical package identity.
   *
   * version:
   *   The current package release.
   *
   * description:
   *   Short human-readable description.
   *
   * author:
   *   Developer or studio responsible for the package.
   *
   * help:
   *   Primary command used to access package help.
   *
   * official:
   *   Marks official packages.
   *
   * default:
   *   Marks packages that are part of the default package set.
   *
   * securityLevel:
   *   Describes the expected package security level.
   *
   * permissions:
   *   Declares requested runtime capabilities.
   *
   * commands:
   *   Declares package-owned commands.
   *
   * dependencies:
   *   Declares package dependencies.
   *
   * entry:
   *   Defines the package initialization entry point.
   */
  const manifest = Object.freeze({
    name: PKG,
    version: VERSION,

    description:
      'Kali Light package for validating package installation, command registration and package lifecycle handling.',

    author:
      'Mobin Vaghar Jalaliyeh (Kali Light)',

    help:
      `${PKG} help`,

    official: false,
    default: false,

    securityLevel: 'low',

    /*
     * Permissions describe what the package expects to access.
     *
     * "none" means the package does not request that capability.
     */
    permissions: Object.freeze({
      storage: 'none',
      cookies: 'none',
      network: 'none',
      filesystem: 'none'
    }),

    /*
     * Every command declared here should be owned by the package.
     */
    commands: Object.freeze([PKG]),

    /*
     * Dependency list.
     *
     * Keep this empty when the package does not depend on another package.
     */
    dependencies: Object.freeze([]),

    /*
     * Package initialization entry point.
     */
    entry: 'install'
  });

  /*
   * --------------------------------------------------------------------------
   * Command Metadata
   * --------------------------------------------------------------------------
   *
   * A package command should have:
   *   - name
   *   - description
   *   - usage
   *   - aliases
   *   - kind
   */
  const COMMAND = Object.freeze({
    name: PKG,

    description:
      'Kali Light package test and diagnostic command.',

    usage:
      `${PKG} [help|info|commands|manifest|policy|selftest|version|colors]`,

    aliases:
      Object.freeze([]),

    kind:
      'plain'
  });

  const state = {
    api: null,
    installed: false
  };

  /*
   * --------------------------------------------------------------------------
   * Bridge Helpers
   * --------------------------------------------------------------------------
   */

  const getApi = () => {
    if (!state.api) {
      throw new Error('PACKAGE_BRIDGE_UNAVAILABLE');
    }

    return state.api;
  };

  const line = (text, cls = 'output') => {
    const api = getApi();

    if (typeof api.line !== 'function') {
      throw new Error('PACKAGE_BRIDGE_LINE_UNAVAILABLE');
    }

    return api.line(
      String(text ?? ''),
      cls
    );
  };

  const spacer = () => {
    const api = getApi();

    if (typeof api.spacer !== 'function') {
      throw new Error('PACKAGE_BRIDGE_SPACER_UNAVAILABLE');
    }

    return api.spacer();
  };

  const getSnapshot = () => {
    const api = state.api;

    if (!api || typeof api.snapshot !== 'function') {
      return null;
    }

    try {
      return api.snapshot();
    } catch {
      return null;
    }
  };

  const getMode = () => {
    const api = state.api;

    if (!api || typeof api.getMode !== 'function') {
      return 'unknown';
    }

    try {
      return String(api.getMode());
    } catch {
      return 'unknown';
    }
  };

  const getInstalledState = () => {
    const snapshot = getSnapshot();

    return Array.isArray(snapshot?.installed)
      ? snapshot.installed.includes(PKG)
      : state.installed;
  };

  const isCommandRegistered = () => {
    const snapshot = getSnapshot();

    return Array.isArray(snapshot?.commands)
      ? snapshot.commands.includes(COMMAND.name)
      : false;
  };

  const getPackageRecord = () => {
    const snapshot = getSnapshot();

    if (!Array.isArray(snapshot?.packages)) {
      return null;
    }

    return snapshot.packages.find(
      pkg =>
        String(pkg?.key ?? pkg?.name ?? '').trim() === PKG
    ) || null;
  };

  /*
   * --------------------------------------------------------------------------
   * Help
   * --------------------------------------------------------------------------
   */

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
    line('  Show the package manifest and manifest documentation.', 'muted'),

    line(`${PKG} policy`),
    line('  Show the declared permission policy.', 'muted'),

    line(`${PKG} selftest`),
    line('  Run package bridge and lifecycle diagnostics.', 'muted'),

    line(`${PKG} version`),
    line('  Show package version.', 'muted'),

    line(`${PKG} colors`),
    line('  Show the allowed Kali Light output color classes.', 'muted')
  ];

  /*
   * --------------------------------------------------------------------------
   * Package Information
   * --------------------------------------------------------------------------
   */

  const info = () => {
    const installed = getInstalledState();
    const registered = isCommandRegistered();
    const record = getPackageRecord();

    return [
      line('Package Information', 'accent'),
      spacer(),

      line(`Name         : ${manifest.name}`),
      line(`Version      : ${manifest.version}`),
      line(`Author       : ${manifest.author}`),

      line(
        `Description  : ${manifest.description}`,
        'muted'
      ),

      line(
        `Help         : ${manifest.help}`,
        'muted'
      ),

      line(`Entry        : ${manifest.entry}`),

      line(
        `Security     : ${manifest.securityLevel.toUpperCase()}`
      ),

      line(
        `Official     : ${manifest.official ? 'yes' : 'no'}`
      ),

      line(
        `Default      : ${manifest.default ? 'yes' : 'no'}`
      ),

      line(
        `Dependencies : ${manifest.dependencies.length}`
      ),

      line(
        `Commands     : ${manifest.commands.length}`
      ),

      line(
        `Installed    : ${installed ? 'yes' : 'no'}`,
        installed ? 'accent' : 'danger'
      ),

      line(
        `Registered   : ${registered ? 'yes' : 'no'}`,
        registered ? 'accent' : 'danger'
      ),

      line(
        `Status       : ${
          record?.status ||
          (installed ? 'enabled' : 'inactive')
        }`,
        installed ? 'accent' : 'muted'
      ),

      line(`Mode         : ${getMode()}`)
    ];
  };

  /*
   * --------------------------------------------------------------------------
   * Command Information
   * --------------------------------------------------------------------------
   */

  const commands = () => {
    const registered = isCommandRegistered();

    return [
      line('Package Command Registration', 'accent'),
      spacer(),

      line(`Command     : ${COMMAND.name}`),
      line(`Usage       : ${COMMAND.usage}`, 'muted'),
      line(`Description : ${COMMAND.description}`),
      line(
        `Aliases     : ${
          COMMAND.aliases.length
            ? COMMAND.aliases.join(', ')
            : 'none'
        }`
      ),
      line(`Kind        : ${COMMAND.kind}`),
      line('Source      : package'),

      line(
        `Registered  : ${registered ? 'yes' : 'no'}`,
        registered ? 'accent' : 'danger'
      ),

      spacer(),

      line('Supported subcommands:', 'accent'),

      line('  help       Show package help.'),
      line('  info       Show package information.'),
      line('  commands   Show command registration information.'),
      line('  manifest   Show the package manifest and its rules.'),
      line('  policy     Show the declared permission policy.'),
      line('  selftest   Validate package bridge and lifecycle state.'),
      line('  version    Show package version.'),
      line('  colors     Show allowed Kali Light output colors.')
    ];
  };

  /*
   * --------------------------------------------------------------------------
   * Manifest Documentation
   * --------------------------------------------------------------------------
   *
   * This command is intentionally educational.
   * It explains what each manifest property means so package developers can
   * inspect the manifest directly from the Kali Light terminal.
   */
  const manifestInfo = () => [
    line('Package Manifest Documentation', 'accent'),
    spacer(),

    line(`name         : ${manifest.name}`),
    line(
      '  Canonical package identity. English/ASCII characters are required.',
      'muted'
    ),
    line(
      '  Package names are case-sensitive. Lowercase is strongly recommended.',
      'muted'
    ),
    spacer(),

    line(`version      : ${manifest.version}`),
    line(
      '  Package release version. Use a stable semantic version format.',
      'muted'
    ),
    spacer(),

    line(`description  : ${manifest.description}`),
    line(
      '  Short human-readable description of the package.',
      'muted'
    ),
    spacer(),

    line(`author       : ${manifest.author}`),
    line(
      '  Developer, team or studio responsible for the package.',
      'muted'
    ),
    spacer(),

    line(`help         : ${manifest.help}`),
    line(
      '  Primary command used to display package help.',
      'muted'
    ),
    spacer(),

    line(`official     : ${manifest.official}`),
    line(
      '  true means official. false means a normal developer package.',
      'muted'
    ),
    spacer(),

    line(`default      : ${manifest.default}`),
    line(
      '  true means a default/core package. false means optional package.',
      'muted'
    ),
    spacer(),

    line(`securityLevel: ${manifest.securityLevel}`),
    line(
      '  Declares the package security level.',
      'muted'
    ),
    spacer(),

    line(`entry        : ${manifest.entry}`),
    line(
      '  Package initialization entry point. Kali Light uses "install".',
      'muted'
    ),
    spacer(),

    line(
      `dependencies : ${
        manifest.dependencies.length
          ? manifest.dependencies.join(', ')
          : 'none'
      }`
    ),
    line(
      '  Other packages required by this package.',
      'muted'
    ),
    spacer(),

    line(
      `commands     : ${
        manifest.commands.length
          ? manifest.commands.join(', ')
          : 'none'
      }`
    ),
    line(
      '  Commands owned and registered by this package.',
      'muted'
    ),
    spacer(),

    line(
      `permissions  : storage=${manifest.permissions.storage}, cookies=${manifest.permissions.cookies}, network=${manifest.permissions.network}, filesystem=${manifest.permissions.filesystem}`
    ),
    line(
      '  Declares the runtime capabilities requested by the package.',
      'muted'
    ),
    spacer(),

    line('Naming Rules', 'accent'),
    line(
      '  Package names must use English/ASCII characters.',
      'muted'
    ),
    line(
      '  Recommended: lowercase English letters, numbers, "-" or "_".',
      'muted'
    ),
    line(
      '  Do not use spaces, Persian/Arabic characters or emoji.',
      'muted'
    ),
    line(
      '  Kali Light is case-sensitive: testdev != TestDev.',
      'danger'
    ),
    line(
      '  Choose the package name carefully because it defines package identity.',
      'muted'
    )
  ];

  /*
   * --------------------------------------------------------------------------
   * Color Documentation
   * --------------------------------------------------------------------------
   *
   * The developer enters the English class name, not the hexadecimal value.
   */
  const colors = () => {
    const entries = Object.entries(KALI_LIGHT_COLORS);

    return [
      line('Kali Light Allowed Colors', 'accent'),
      line(
        'Use the English class name when calling api.line().',
        'muted'
      ),
      line(
        'Color identifiers are case-sensitive.',
        'danger'
      ),
      spacer(),

      ...entries.map(
        ([name, hex]) =>
          line(`${name.padEnd(14, ' ')} #${hex}`)
      ),

      spacer(),

      line(
        "Example: api.line('Hello', 'cyan')",
        'muted'
      ),
      line(
        "Example: api.line('Warning', 'danger')",
        'muted'
      ),
      line(
        "Example: api.line('Path: /home/kali', 'path')",
        'muted'
      )
    ];
  };

  /*
   * --------------------------------------------------------------------------
   * Permission Policy
   * --------------------------------------------------------------------------
   */

  const policy = () => [
    line('Permission Policy', 'accent'),
    spacer(),

    line(
      `storage    : ${manifest.permissions.storage}`
    ),

    line(
      `cookies    : ${manifest.permissions.cookies}`
    ),

    line(
      `network    : ${manifest.permissions.network}`
    ),

    line(
      `filesystem : ${manifest.permissions.filesystem}`
    ),

    spacer(),

    line(
      'This package does not request privileged runtime access.',
      'muted'
    ),

    line(
      'All package interaction occurs through the Kali Light package bridge.',
      'muted'
    )
  ];

  /*
   * --------------------------------------------------------------------------
   * Version
   * --------------------------------------------------------------------------
   */

  const version = () => [
    line(
      `${manifest.name} ${manifest.version}`,
      'accent'
    )
  ];

  /*
   * --------------------------------------------------------------------------
   * Self Test
   * --------------------------------------------------------------------------
   *
   * The self-test verifies that the package is correctly connected to the
   * Kali Light Core and that its manifest/command metadata is consistent.
   */
  const selfTest = () => {
    const api = state.api;
    const snapshot = getSnapshot();
    const checks = [];

    let passed = true;

    const check = (
      name,
      condition,
      detail = ''
    ) => {
      checks.push(
        line(
          `[${condition ? 'PASS' : 'FAIL'}] ${name}${
            detail ? ` — ${detail}` : ''
          }`,
          condition ? 'accent' : 'danger'
        )
      );

      if (!condition) {
        passed = false;
      }
    };

    check(
      'Package API',
      Boolean(api && typeof api === 'object'),
      'bridge available'
    );

    check(
      'registerCommand',
      typeof api?.registerCommand === 'function',
      'supported'
    );

    check(
      'unregisterCommand',
      typeof api?.unregisterCommand === 'function',
      'supported'
    );

    check(
      'line',
      typeof api?.line === 'function',
      'supported'
    );

    check(
      'spacer',
      typeof api?.spacer === 'function',
      'supported'
    );

    check(
      'snapshot',
      typeof api?.snapshot === 'function',
      'supported'
    );

    check(
      'getMode',
      typeof api?.getMode === 'function',
      'supported'
    );

    check(
      'Package Name Format',
      isValidPackageName(PKG),
      'English/ASCII package identity'
    );

    check(
      'Package Name Case',
      isRecommendedPackageName(PKG),
      'lowercase package name recommended'
    );

    const installed = getInstalledState();

    check(
      'Package State',
      installed,
      installed
        ? 'package is installed'
        : 'package is not installed'
    );

    check(
      'Manifest Identity',
      manifest.name === PKG &&
        manifest.version === VERSION,
      `${manifest.name} ${manifest.version}`
    );

    check(
      'Manifest Help',
      manifest.help === `${PKG} help`,
      manifest.help
    );

    check(
      'Manifest Author',
      manifest.author ===
        'Mobin Vaghar Jalaliyeh (Kali Light)',
      manifest.author
    );

    check(
      'Manifest Entry',
      manifest.entry === 'install',
      `entry=${manifest.entry}`
    );

    check(
      'Permissions',
      Object.values(
        manifest.permissions
      ).every(value => value === 'none'),
      'all permissions are none'
    );

    check(
      'Dependencies',
      Array.isArray(manifest.dependencies) &&
        manifest.dependencies.length === 0,
      'no dependencies'
    );

    check(
      'Command Metadata',
      manifest.commands.length === 1 &&
        manifest.commands[0] === COMMAND.name &&
        COMMAND.name === PKG &&
        COMMAND.kind === 'plain',
      'valid command metadata'
    );

    check(
      'Color Palette',
      Object.keys(KALI_LIGHT_COLORS).length > 0,
      'Kali Light color classes available'
    );

    if (snapshot) {
      const registered =
        Array.isArray(snapshot.commands) &&
        snapshot.commands.includes(
          COMMAND.name
        );

      const installedRegistry =
        Array.isArray(snapshot.installed) &&
        snapshot.installed.includes(PKG);

      check(
        'Command Registration',
        registered,
        registered
          ? `${PKG} is registered in Kali Light`
          : `${PKG} is missing from command registry`
      );

      check(
        'Installed Registry State',
        installedRegistry,
        installedRegistry
          ? `${PKG} is present in installed package registry`
          : `${PKG} is missing from installed package registry`
      );

      const record = getPackageRecord();

      if (record) {
        check(
          'Package Record',
          record.status !== 'corrupted' &&
            record.status !== 'blocked',
          `status=${record.status || 'unknown'}`
        );
      }
    } else {
      checks.push(
        line(
          '[INFO] Kali Light snapshot is unavailable.',
          'muted'
        )
      );
    }

    checks.push(spacer());

    checks.push(
      line(
        passed
          ? 'Self-test result: PASS'
          : 'Self-test result: FAIL',
        passed ? 'accent' : 'danger'
      )
    );

    return checks;
  };

  /*
   * --------------------------------------------------------------------------
   * Command Router
   * --------------------------------------------------------------------------
   */

  const run = ({ args = [] } = {}) => {
    const command = String(
      args[0] ?? ''
    ).trim().toLowerCase();

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

      case 'colors':
        return colors();

      default:
        return [
          line(
            `${PKG}: unknown command "${command}"`,
            'danger'
          ),

          line(
            `Use "${manifest.help}" for available commands.`,
            'muted'
          )
        ];
    }
  };

  /*
   * --------------------------------------------------------------------------
   * API Validation
   * --------------------------------------------------------------------------
   *
   * A package must never assume that the Core bridge is available.
   * Validate all required methods before registering the package command.
   */
  const validateApi = api => {
    if (!api || typeof api !== 'object') {
      throw new Error(
        'PACKAGE_BRIDGE_UNAVAILABLE'
      );
    }

    const required = [
      'registerCommand',
      'unregisterCommand',
      'line',
      'spacer',
      'snapshot',
      'getMode'
    ];

    for (const method of required) {
      if (typeof api[method] !== 'function') {
        throw new Error(
          `PACKAGE_BRIDGE_${method.toUpperCase()}_UNAVAILABLE`
        );
      }
    }
  };

  /*
   * ==========================================================================
   * INSTALL LIFECYCLE
   * ==========================================================================
   *
   * Important lifecycle rule:
   *
   * install() must:
   *   1. Validate the Kali Light package bridge.
   *   2. Save the bridge reference.
   *   3. Register package-owned commands.
   *   4. Initialize package-local state.
   *
   * install() must NOT:
   *   - Print installation progress.
   *   - Print lifecycle messages.
   *   - Call api.append() for installation status.
   *   - Generate uncontrolled global state.
   *
   * The Kali Light Core is responsible for installation output.
   *
   * In short:
   *
   *   install() = validate + initialize + register
   *
   *   install() !== print installation messages
   *
   * @param {object} api
   *   Kali Light package bridge.
   *
   * @returns {Promise<Array>}
   *   Empty output array after successful installation.
   *
   * @throws {Error}
   *   When the bridge or command registration is invalid.
   */
  const install = async api => {
    validateApi(api);

    state.api = api;

    /*
     * If the package is already correctly installed and registered,
     * do not duplicate command registration.
     */
    if (
      getInstalledState() &&
      isCommandRegistered()
    ) {
      state.installed = true;
      return [];
    }

    try {
      /*
       * Register only package-owned commands.
       *
       * source:
       *   Must remain "package" so the Kali Light Core knows that the command
       *   belongs to this package.
       *
       * packageKey:
       *   Must match the canonical package identity.
       */
      const registered =
        api.registerCommand(
          COMMAND.name,
          {
            description:
              COMMAND.description,

            usage:
              COMMAND.usage,

            aliases:
              COMMAND.aliases,

            kind:
              COMMAND.kind,

            run
          },
          {
            source: 'package',
            packageKey: PKG
          }
        );

      if (registered === false) {
        throw new Error(
          'PACKAGE_COMMAND_REGISTRATION_FAILED'
        );
      }

      state.installed = true;

      /*
       * Successful installation intentionally returns no terminal output.
       * The Core package manager owns lifecycle reporting.
       */
      return [];
    } catch {
      /*
       * If registration fails, attempt deterministic cleanup.
       */
      try {
        api.unregisterCommand(
          COMMAND.name
        );
      } catch {}

      state.installed = false;
      state.api = null;

      throw new Error(
        'PACKAGE_INSTALL_FAILED'
      );
    }
  };

  /*
   * ==========================================================================
   * UNINSTALL LIFECYCLE
   * ==========================================================================
   *
   * uninstall() must:
   *   - Remove package-owned commands.
   *   - Clear package-local state.
   *   - Leave Core-owned commands untouched.
   *   - Produce no lifecycle output.
   *
   * In short:
   *
   *   uninstall() = unregister + cleanup
   *
   *   uninstall() !== print uninstall messages
   *
   * @param {object|null} api
   *   Kali Light package bridge.
   *
   * @returns {Promise<Array>}
   *   Empty output array after cleanup.
   */
  const uninstall = async api => {
    const bridge =
      api || state.api;

    try {
      if (
        bridge &&
        typeof bridge.unregisterCommand ===
          'function'
      ) {
        bridge.unregisterCommand(
          COMMAND.name
        );
      }
    } finally {
      state.installed = false;
      state.api = null;
    }

    return [];
  };

  /*
   * --------------------------------------------------------------------------
   * Public Package Module
   * --------------------------------------------------------------------------
   *
   * The Core loader expects the package module to expose:
   *
   *   manifest
   *   install
   *   uninstall
   *
   * Keep this interface stable.
   */
  const packageModule =
    Object.freeze({
      manifest,
      install,
      uninstall
    });

  /*
   * --------------------------------------------------------------------------
   * Package Global Export
   * --------------------------------------------------------------------------
   *
   * The Kali Light package loader expects the package module at the generated
   * global key.
   */
  window[GLOBAL_KEY] = packageModule;
})();