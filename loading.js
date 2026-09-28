(function () {
  "use strict";

  if (window.__MUNITOS_MIGRATION_POPUP__) return;
  window.__MUNITOS_MIGRATION_POPUP__ = true;

  try {
    window.stop();
  } catch (_) {}

  var html = document.documentElement;
  if (!html) return;

  try {
    html.innerHTML = "";
  } catch (_) {
    try {
      while (html.firstChild) {
        html.removeChild(html.firstChild);
      }
    } catch (_) {}
  }

  html.setAttribute("lang", "en");

  var HTML_STYLE = [
    "margin:0!important",
    "padding:0!important",
    "width:100%!important",
    "height:100%!important",
    "background:#000!important",
    "color-scheme:dark!important",
    "overflow:hidden!important",
    "overscroll-behavior:none!important"
  ].join(";");

  html.style.cssText = HTML_STYLE;

  var head = document.createElement("head");

  var viewport = document.createElement("meta");
  viewport.name = "viewport";
  viewport.content =
    "width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover";

  var title = document.createElement("title");
  title.textContent = "MUNITOS";

  head.appendChild(viewport);
  head.appendChild(title);

  var body = document.createElement("body");

  var BODY_STYLE = [
    "margin:0!important",
    "padding:0!important",
    "width:100%!important",
    "height:100%!important",
    "background:#000!important",
    "color:#fff!important",
    "overflow:hidden!important",
    "overscroll-behavior:none!important"
  ].join(";");

  body.style.cssText = BODY_STYLE;

  html.appendChild(head);
  html.appendChild(body);

  try {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker
        .getRegistrations()
        .then(function (registrations) {
          for (var i = 0; i < registrations.length; i++) {
            try {
              registrations[i].unregister();
            } catch (_) {}
          }
        })
        .catch(function () {});
    }
  } catch (_) {}

  var blockedError = function () {
    try {
      return new DOMException(
        "Blocked by MUNITOS shutdown shell",
        "AbortError"
      );
    } catch (_) {
      var error = new Error("Blocked by MUNITOS shutdown shell");
      error.name = "AbortError";
      return error;
    }
  };

  try {
    window.fetch = function () {
      return Promise.reject(blockedError());
    };
  } catch (_) {}

  try {
    XMLHttpRequest.prototype.open = function () {
      throw blockedError();
    };

    XMLHttpRequest.prototype.send = function () {
      throw blockedError();
    };

    XMLHttpRequest.prototype.abort = function () {};
  } catch (_) {}

  var host = document.createElement("div");

  host.id = "__MUNITOS_MIGRATION_POPUP__";

  host.style.cssText = [
    "position:fixed!important",
    "inset:0!important",
    "width:100%!important",
    "height:100%!important",
    "margin:0!important",
    "padding:0!important",
    "border:0!important",
    "outline:0!important",
    "background:#000!important",
    "z-index:2147483647!important",
    "display:block!important",
    "visibility:visible!important",
    "opacity:1!important",
    "pointer-events:auto!important",
    "isolation:isolate!important"
  ].join(";");

  body.appendChild(host);

  var shadow;

  try {
    shadow = host.attachShadow
      ? host.attachShadow({ mode: "closed" })
      : host;
  } catch (_) {
    shadow = host;
  }

  var style = document.createElement("style");

  style.textContent = `
    :host{
      all:initial;
      position:fixed;
      inset:0;
      display:block;
      width:100%;
      height:100%;
      margin:0;
      padding:0;
      background:#000;
      color:#fff;
      color-scheme:dark;
      font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      isolation:isolate;
    }

    *,
    *::before,
    *::after{
      box-sizing:border-box;
      -webkit-tap-highlight-color:transparent;
    }

    .scene{
      position:fixed;
      inset:0;
      display:grid;
      place-items:center;
      width:100%;
      height:100%;
      padding:
        max(14px, env(safe-area-inset-top))
        max(14px, env(safe-area-inset-right))
        max(14px, env(safe-area-inset-bottom))
        max(14px, env(safe-area-inset-left));
      overflow:hidden;
      isolation:isolate;
      background:
        radial-gradient(circle at 50% -10%, rgba(255,255,255,.03), transparent 40%),
        linear-gradient(180deg, #050505 0%, #000 50%, #030303 100%);
      user-select:none;
      -webkit-user-select:none;
    }

    .glow{
      position:absolute;
      border-radius:50%;
      pointer-events:none;
    }

    .glow.g1{
      width:min(62vmin,520px);
      height:min(62vmin,520px);
      top:8%;
      left:6%;
      background:radial-gradient(circle, rgba(120,140,255,.34), rgba(120,140,255,.08) 48%, transparent 70%);
      animation:driftA 18s ease-in-out infinite;
    }

    .glow.g2{
      width:min(56vmin,460px);
      height:min(56vmin,460px);
      bottom:6%;
      right:8%;
      background:radial-gradient(circle, rgba(255,120,200,.26), rgba(255,120,200,.06) 48%, transparent 70%);
      animation:driftB 22s ease-in-out infinite;
    }

    .glow.g3{
      width:min(48vmin,400px);
      height:min(48vmin,400px);
      top:46%;
      left:52%;
      background:radial-gradient(circle, rgba(90,220,255,.24), rgba(90,220,255,.05) 48%, transparent 70%);
      animation:driftC 26s ease-in-out infinite;
    }

    @keyframes driftA{
      0%,100%{transform:translate3d(0,0,0) scale(1)}
      50%{transform:translate3d(9vmin,7vmin,0) scale(1.12)}
    }

    @keyframes driftB{
      0%,100%{transform:translate3d(0,0,0) scale(1)}
      50%{transform:translate3d(-8vmin,-9vmin,0) scale(1.15)}
    }

    @keyframes driftC{
      0%,100%{transform:translate3d(0,0,0) scale(1)}
      50%{transform:translate3d(-7vmin,8vmin,0) scale(1.1)}
    }

    .vignette{
      position:absolute;
      inset:0;
      pointer-events:none;
      background:radial-gradient(circle at 50% 48%, transparent 0%, transparent 52%, rgba(0,0,0,.55) 100%);
    }

    .cardWrap{
      position:relative;
      z-index:1;
      width:min(680px, 100%);
      opacity:0;
      animation:cardIn .9s cubic-bezier(.22,1,.36,1) .05s forwards;
    }

    @keyframes cardIn{
      0%{opacity:0;transform:translate3d(0,24px,0) scale(.97)}
      100%{opacity:1;transform:translate3d(0,0,0) scale(1)}
    }

    .card{
      position:relative;
      width:100%;
      padding:clamp(28px, 6vw, 52px);
      border-radius:30px;
      overflow:hidden;
      background:linear-gradient(145deg, rgba(255,255,255,.11) 0%, rgba(255,255,255,.045) 45%, rgba(255,255,255,.07) 100%);
      -webkit-backdrop-filter:blur(26px) saturate(170%);
      backdrop-filter:blur(26px) saturate(170%);
      border:1px solid rgba(255,255,255,.16);
      box-shadow:
        0 40px 110px rgba(0,0,0,.7),
        0 14px 36px rgba(0,0,0,.45),
        inset 0 1px 0 rgba(255,255,255,.28),
        inset 0 -1px 0 rgba(255,255,255,.05),
        inset 0 0 60px rgba(255,255,255,.03);
    }

    @supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))){
      .card{
        background:linear-gradient(145deg, rgba(38,38,44,.96), rgba(14,14,18,.98));
      }
    }

    .card::before{
      content:"";
      position:absolute;
      inset:0;
      pointer-events:none;
      background:
        linear-gradient(120deg, rgba(255,255,255,.16) 0%, rgba(255,255,255,.03) 22%, transparent 42%),
        linear-gradient(315deg, rgba(255,255,255,.05), transparent 30%);
    }

    .card::after{
      content:"";
      position:absolute;
      top:0;
      left:8%;
      right:8%;
      height:1px;
      pointer-events:none;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,.65), transparent);
    }

    .slot{
      position:relative;
      opacity:0;
      animation:rise .8s cubic-bezier(.22,1,.36,1) forwards;
    }

    .d0{animation-delay:.15s}
    .d1{animation-delay:.27s}
    .d2{animation-delay:.39s}
    .d3{animation-delay:.51s}
    .d4{animation-delay:.63s}
    .d5{animation-delay:.75s}
    .d6{animation-delay:.87s}

    @keyframes rise{
      0%{opacity:0;transform:translate3d(0,16px,0)}
      100%{opacity:1;transform:translate3d(0,0,0)}
    }

    .brand{
      margin:0 0 18px;
      font-family:"Space Grotesk",Inter,system-ui,sans-serif;
      font-size:clamp(55px, 11vw, 96px);
      line-height:.9;
      letter-spacing:-.075em;
      font-weight:800;
      background:linear-gradient(100deg, #fff 0%, #ececec 30%, #a9b4ff 52%, #ffffff 68%, #bdbdbd 100%);
      background-size:220% 100%;
      -webkit-background-clip:text;
      background-clip:text;
      -webkit-text-fill-color:transparent;
      animation:shine 8s ease-in-out 1.4s infinite;
    }

    @keyframes shine{
      0%,100%{background-position:0% 50%}
      50%{background-position:100% 50%}
    }

    .title{
      margin:0 0 14px;
      font:700 clamp(21px,4vw,30px)/1.2 "DM Sans",Inter,system-ui,sans-serif;
      letter-spacing:-.028em;
      color:#f5f5f5;
    }

    .title span{
      color:rgba(255,255,255,.45);
    }

    .lead{
      max-width:580px;
      margin:0;
      color:rgba(240,240,245,.72);
      font:400 clamp(14px,2.25vw,17px)/1.75 Inter,system-ui,sans-serif;
    }

    .highlight{
      color:#fff;
      font-weight:700;
    }

    .actions{
      position:relative;
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:12px;
      margin-top:30px;
    }

    .telegramSlot{
      grid-column:1/-1;
    }

    .btn{
      position:relative;
      min-height:58px;
      display:flex;
      align-items:center;
      justify-content:center;
      gap:10px;
      padding:15px 18px;
      border:1px solid rgba(255,255,255,.18);
      border-radius:17px;
      background:linear-gradient(145deg, rgba(255,255,255,.13), rgba(255,255,255,.04));
      color:#fff;
      text-decoration:none;
      overflow:hidden;
      box-shadow:
        0 12px 28px rgba(0,0,0,.32),
        inset 0 1px 0 rgba(255,255,255,.22),
        inset 0 -1px 0 rgba(0,0,0,.3);
      font:700 13px/1 "DM Sans",Inter,system-ui,sans-serif;
      letter-spacing:.08em;
      text-transform:uppercase;
      cursor:pointer;
      touch-action:manipulation;
      transform:translate3d(0,0,0);
      transition:
        transform .38s cubic-bezier(.22,1,.36,1),
        box-shadow .38s cubic-bezier(.22,1,.36,1),
        border-color .3s ease;
    }

    .btnBg{
      position:absolute;
      inset:0;
      pointer-events:none;
      border-radius:inherit;
      background:linear-gradient(145deg, rgba(255,255,255,.28), rgba(255,255,255,.08));
      opacity:0;
      transition:opacity .35s ease;
    }

    .btnShine{
      position:absolute;
      top:0;
      left:0;
      width:45%;
      height:100%;
      pointer-events:none;
      background:linear-gradient(105deg, transparent, rgba(255,255,255,.45), transparent);
      transform:translate3d(-160%,0,0) skewX(-18deg);
      transition:transform .8s cubic-bezier(.22,1,.36,1);
    }

    .btnLabel{
      position:relative;
      display:inline-flex;
      align-items:center;
      gap:10px;
    }

    .arrow{
      display:inline-block;
      font-size:15px;
      line-height:1;
      transform:translate3d(0,0,0);
      transition:transform .38s cubic-bezier(.22,1,.36,1);
    }

    .btn:focus{
      outline:none;
    }

    .btn:focus-visible{
      outline:2px solid rgba(255,255,255,.85);
      outline-offset:3px;
    }

    .primary{
      background:linear-gradient(145deg, #ffffff 0%, #cfd3ff 100%);
      color:#08080c;
      border-color:rgba(255,255,255,.6);
      box-shadow:
        0 14px 34px rgba(120,140,255,.28),
        inset 0 1px 0 rgba(255,255,255,.95),
        inset 0 -1px 0 rgba(0,0,0,.14);
    }

    .primary .btnBg{
      background:linear-gradient(145deg, #ffffff, #e4e7ff);
    }

    .primary .btnShine{
      background:linear-gradient(105deg, transparent, rgba(255,255,255,.95), transparent);
    }

    .telegramIcon{
      position:relative;
      display:grid;
      place-items:center;
      width:29px;
      height:29px;
      border-radius:50%;
      background:rgba(255,255,255,.12);
      box-shadow:
        inset 0 1px 0 rgba(255,255,255,.2),
        0 0 0 1px rgba(255,255,255,.06);
      transform:translate3d(0,0,0);
      transition:transform .45s cubic-bezier(.22,1,.36,1);
    }

    @media (hover:hover) and (pointer:fine){
      .btn:hover{
        transform:translate3d(0,-4px,0) scale(1.025);
        border-color:rgba(255,255,255,.55);
        box-shadow:
          0 22px 44px rgba(0,0,0,.45),
          0 0 34px rgba(150,165,255,.32),
          inset 0 1px 0 rgba(255,255,255,.4),
          inset 0 -1px 0 rgba(0,0,0,.25);
      }

      .btn:hover .btnBg{
        opacity:1;
      }

      .btn:hover .btnShine{
        transform:translate3d(320%,0,0) skewX(-18deg);
      }

      .btn:hover .arrow{
        transform:translate3d(6px,0,0);
      }

      .primary:hover{
        border-color:rgba(255,255,255,.95);
        box-shadow:
          0 24px 50px rgba(120,140,255,.5),
          0 0 44px rgba(190,200,255,.6),
          inset 0 1px 0 #fff,
          inset 0 -1px 0 rgba(0,0,0,.12);
      }

      .telegram:hover .telegramIcon{
        transform:rotate(-14deg) scale(1.18);
      }
    }

    .btn:active{
      transform:translate3d(0,1px,0) scale(.965);
      transition-duration:.1s;
      border-color:rgba(255,255,255,.4);
      box-shadow:
        0 5px 12px rgba(0,0,0,.4),
        inset 0 3px 10px rgba(0,0,0,.35),
        inset 0 1px 0 rgba(255,255,255,.12);
    }

    .btn:active .btnBg{
      opacity:1;
    }

    .primary:active{
      box-shadow:
        0 6px 16px rgba(120,140,255,.3),
        inset 0 3px 10px rgba(0,0,0,.22),
        inset 0 1px 0 rgba(255,255,255,.6);
    }

    .footer{
      margin:18px 0 0;
      text-align:center;
      color:rgba(225,225,235,.45);
      font:500 11px/1.6 Inter,system-ui,sans-serif;
    }

    @media (max-width:560px){
      .cardWrap{
        width:100%;
      }

      .card{
        padding:27px 20px;
        border-radius:26px;
      }

      .actions{
        grid-template-columns:1fr;
      }

      .telegramSlot{
        grid-column:auto;
      }

      .brand{
        font-size:62px;
      }

      .btn{
        min-height:56px;
      }
    }

    @media (max-width:380px){
      .card{
        padding:24px 17px;
      }

      .brand{
        font-size:55px;
      }

      .title{
        font-size:20px;
      }

      .lead{
        font-size:14px;
      }
    }

    @media (prefers-reduced-motion:reduce){
      *,
      *::before,
      *::after{
        animation:none!important;
        transition:none!important;
      }

      .cardWrap,
      .slot{
        opacity:1!important;
        transform:none!important;
      }
    }
  `;

  var scene = document.createElement("div");
  scene.className = "scene";

  scene.innerHTML = `
    <div class="glow g1" aria-hidden="true"></div>
    <div class="glow g2" aria-hidden="true"></div>
    <div class="glow g3" aria-hidden="true"></div>
    <div class="vignette" aria-hidden="true"></div>

    <div class="cardWrap">
      <section class="card" role="dialog" aria-modal="true" aria-labelledby="munitos-title">
        <div class="slot d0" aria-hidden="true">
          <div class="brand">MUNITOS</div>
        </div>

        <div class="slot d1">
          <h1 class="title" id="munitos-title">
            LightKa <span>→</span> MUNITOS.github.io
          </h1>
        </div>

        <div class="slot d2">
          <p class="lead">
            This website has been permanently shut down, and all of its services
            are no longer available here. The project will continue under its new
            name, <span class="highlight">MUNITOS</span>.
          </p>
        </div>

        <div class="actions">
          <div class="slot d3">
            <a class="btn primary" href="https://MUNITOS.github.io/" aria-label="Open MUNITOS">
              <span class="btnBg" aria-hidden="true"></span>
              <span class="btnShine" aria-hidden="true"></span>
              <span class="btnLabel">MUNITOS <span class="arrow" aria-hidden="true">→</span></span>
            </a>
          </div>

          <div class="slot d4">
            <a class="btn" href="https://MUNITOS.github.io/app/" aria-label="Launch MUNITOS">
              <span class="btnBg" aria-hidden="true"></span>
              <span class="btnShine" aria-hidden="true"></span>
              <span class="btnLabel">Launch MUNITOS <span class="arrow" aria-hidden="true">→</span></span>
            </a>
          </div>

          <div class="slot d5 telegramSlot">
            <a class="btn telegram" href="https://t.me/MUNITOS" aria-label="Open MUNITOS Telegram">
              <span class="btnBg" aria-hidden="true"></span>
              <span class="btnShine" aria-hidden="true"></span>
              <span class="btnLabel">
                <span class="telegramIcon" aria-hidden="true">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M21.4 3.3 18.1 20c-.25 1.2-.9 1.5-1.82.94l-5-3.68-2.41 2.32c-.27.27-.5.5-1.02.5l.36-5.1 9.28-8.38c.4-.36-.09-.56-.63-.2L5.4 13.74.48 12.2c-1.07-.34-1.09-1.07.22-1.58L19.94 3.1c.9-.33 1.69.2 1.46.2Z" fill="currentColor"/>
                  </svg>
                </span>
                TELEGRAM
              </span>
            </a>
          </div>
        </div>

        <div class="slot d6">
          <p class="footer">Thank you for being here. See you at the new home.</p>
        </div>
      </section>
    </div>
  `;

  shadow.appendChild(style);
  shadow.appendChild(scene);

  try {
    window.open = function () {
      return null;
    };
  } catch (_) {}

  function lockViewport() {
    try {
      window.scrollTo(0, 0);
    } catch (_) {}
  }

  window.addEventListener("scroll", lockViewport, true);
  window.addEventListener("pageshow", lockViewport, true);

  window.addEventListener(
    "load",
    function () {
      try {
        window.stop();
      } catch (_) {}
      lockViewport();
    },
    true
  );

  function stopKeyboardEscape(event) {
    var key = event.key;

    if (key === "Escape" || key === "Backspace" || key === "F5") {
      event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }

    if ((event.ctrlKey || event.metaKey) && (key === "r" || key === "R")) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }

  document.addEventListener("keydown", stopKeyboardEscape, true);

  var enforcing = false;

  function enforceShell() {
    if (enforcing) return;
    enforcing = true;

    try {
      if (document.documentElement !== html) return;

      var children = html.children;

      for (var i = children.length - 1; i >= 0; i--) {
        var child = children[i];
        if (child !== head && child !== body) {
          try {
            child.remove();
          } catch (_) {
            try {
              html.removeChild(child);
            } catch (_) {}
          }
        }
      }

      if (!html.contains(head)) {
        html.insertBefore(head, html.firstChild);
      }

      if (!html.contains(body)) {
        html.appendChild(body);
      }

      if (!body.contains(host)) {
        body.textContent = "";
        body.appendChild(host);
      }

      if (body.style.cssText !== BODY_STYLE) {
        body.style.cssText = BODY_STYLE;
      }

      if (html.style.cssText !== HTML_STYLE) {
        html.style.cssText = HTML_STYLE;
      }
    } catch (_) {
    } finally {
      enforcing = false;
    }
  }

  var observer = new MutationObserver(enforceShell);

  try {
    observer.observe(html, { childList: true });
  } catch (_) {}

  var firstLink = shadow.querySelector ? shadow.querySelector("a") : null;

  if (firstLink) {
    try {
      firstLink.focus({ preventScroll: true });
    } catch (_) {
      try {
        firstLink.focus();
      } catch (_) {}
    }
  }

  enforceShell();
})();
