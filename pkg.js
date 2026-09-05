window.LightKaliPackageCatalog = {
  name: "lightkali-package-catalog",
  version: "1.0.0",
  description: "LightKali package catalog",
  packages: [
    {
      name: "kalisecurity",
      version: "7.0.4-",
      description: "Official Kali Light default security package for package preflight validation, trusted package classification and static threat protection.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: true,
      default: true,
      securityLevel: "system",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "none",
        filesystem: "none"
      },
      commands: ["kalisecurity"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "attackkit",
      version: "5.1.0",
      description: "GodMode Ultimate – Guaranteed Attack Framework with DB Extraction & Strong XSS",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "high",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "required",
        filesystem: "none"
      },
      commands: ["attackkit"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "booster",
      version: "3.3.1",
      description: "Kali Light browser capability intelligence, adaptive rendering, scheduling, workers, GPU/WebGPU diagnostics, experimental-feature detection, isolation analysis, profiling, benchmarking, and safe runtime optimization.",
      author: "Mobin | Atlas Code (Kali Light)",
      official: false,
      default: false,
      securityLevel: "medium",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "none",
        filesystem: "none"
      },
      commands: ["booster"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "ipscan",
      version: "8.1.2",
      description: "Defensive IP intelligence package with normalized routing, registration, DNS, certificate, reputation, reachability and attribution-safe reporting.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "medium",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "read",
        filesystem: "none"
      },
      commands: ["ipscan"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "monitor",
      version: "7.0.3",
      description: "Advanced floating browser/runtime monitor with layered system metrics, live telemetry, network probes, charts and persistent settings.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "low",
      permissions: {
        storage: "read",
        cookies: "readwrite",
        network: "optional",
        filesystem: "none"
      },
      commands: ["monitor"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "sitescanner",
      version: "5.1.0",
      description: "Professional passive OSINT, DNS, web, TLS and security-posture scanner with modular analysis commands.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "low",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "required",
        filesystem: "none"
      },
      commands: ["sitescanner"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "testdev",
      version: "1.1.3",
      description: "Kali Light package for validating package installation, command registration and package lifecycle handling.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "low",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "none",
        filesystem: "none"
      },
      commands: ["testdev"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "xfcelite",
      version: "7.0.1",
      description: "Kali Light XFCE Lite background and terminal theme manager with persistent runtime state.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "medium",
      permissions: {
        storage: "write",
        cookies: "none",
        network: "none",
        filesystem: "none"
      },
      commands: ["xfcelite"],
      dependencies: [],
      entry: "install",
      source: "internal"
    },
    {
      name: "xsspectre",
      version: "1.6.0",
      description: "xsspectre - advanced XSS scanner with AI-style vulnerability reporting, payload generation and detection.",
      author: "Mobin Vaghar Jalaliyeh (Kali Light)",
      official: false,
      default: false,
      securityLevel: "medium",
      permissions: {
        storage: "none",
        cookies: "none",
        network: "full",
        filesystem: "none"
      },
      commands: ["xsspectre"],
      dependencies: [],
      entry: "install",
      source: "internal"
    }
  ]
};