Light Kali

<p align="center">
  <img src="BannerLightKali.png" width="100%" alt="Light Kali Banner">
</p><h1 align="center">🖥️ Light Kali</h1><p align="center">
  <strong>Light Kali — Iran's First Free Cybersecurity Web OS.</strong>
</p><p align="center">
  Lightweight • Fast • Secure-by-Design • Free • Browser Based
</p>---

🇺🇸 English

About

Light Kali — Iran's First Free Cybersecurity Web OS.

Light Kali is a free, lightweight and browser-based cybersecurity environment designed to provide a fast terminal-style workspace directly through the web.

It combines a modern terminal interface with security-oriented tools, package management, browser capabilities, runtime diagnostics and persistent configuration.

The main goal is simple:

«Bring a lightweight cybersecurity environment to the browser.»

Light Kali does not try to become a complete traditional Linux distribution. Instead, it takes advantage of modern browser technologies to provide a portable and fast cybersecurity workspace without requiring a full operating-system installation.

---

🚀 Why Light Kali?

Light Kali is built around speed, portability and simplicity.

You can launch the environment directly from a browser and start working without preparing a complete Linux installation.

Key Advantages

⚡ Lightweight

Designed to keep the environment fast and responsive.

🌐 Browser Based

Runs directly inside a modern web browser.

🆓 Completely Free

Light Kali is provided as a free project and does not require a paid subscription to use the core environment.

📱 Portable

The same web environment can be accessed from supported desktop and mobile browsers.

⌨️ Interactive Terminal

A terminal-oriented interface provides a familiar command-driven experience.

📦 Package Management

Built-in "apt" and "pkg" style commands provide package installation and management inside Light Kali.

🧠 Runtime Intelligence

The environment can inspect browser capabilities, device information and available runtime features.

🛡️ Security-Oriented

Designed around cybersecurity tools, diagnostics and controlled browser capabilities.

💾 Persistent State

Selected configuration and runtime information can remain available between sessions.

---

⚖️ Light Kali vs Kali Linux

Light Kali and Kali Linux are built for different environments.

Light Kali| Kali Linux
🌐 Browser-based| 🐧 Full Linux-based operating system
⚡ Very lightweight| 💽 Larger complete OS environment
🆓 Free| 🆓 Free
🚀 Starts directly from the browser| 💻 Requires Linux, VM, WSL or installation
📱 Works on supported mobile browsers| 🖥️ Primarily desktop/server oriented
⌨️ Web terminal experience| ⌨️ Native Linux terminal
📦 Browser-native package system| 📦 Native Debian package ecosystem
💾 Browser-side persistent state| 💾 Real Linux filesystem
🧠 Browser/runtime diagnostics| 🖥️ Direct OS and hardware access
🔐 Browser security sandbox| 🔐 Native Linux security model

Where Light Kali Wins

Light Kali has a major advantage when the priority is:

Portability
Fast Startup
Low Overhead
Browser Access
Mobile Access
Web-Native Tools
Simple Deployment

You do not always need to boot a complete operating system just to access a cybersecurity workspace.

Open the browser.

Launch Light Kali.

Start working.

---

🧰 Built-in Terminal

Light Kali provides an interactive terminal-style experience.

Basic commands include:

help

clear

about

Package-related commands include:

apt update
apt list
apt inspect <package>
apt install <package>
apt remove <package>
apt reinstall
apt policy

The same package operations can also be accessed through:

pkg update
pkg list
pkg inspect <package>
pkg install <package>
pkg remove <package>
pkg reinstall
pkg policy

«Important: "apt" and "pkg" in Light Kali are commands provided by the Light Kali web environment. They are not the native Debian/Ubuntu APT or Android Termux package managers.»

---

📦 Package Management

Light Kali includes a built-in package management system for the web environment.

You can update package information:

apt update

List available or installed packages:

apt list

Inspect a package:

apt inspect booster

Install a package:

apt install booster

Remove a package:

apt remove booster

Reinstall packages:

apt reinstall

Check package policy:

apt policy

The "pkg" command provides the same style of operations:

pkg update
pkg list
pkg inspect booster
pkg install booster
pkg remove booster
pkg reinstall
pkg policy

---

🛠️ Installation

Light Kali is a web application, so a complete Linux installation is not required to launch the interface.

Clone the repository:

git clone https://github.com/LiGHTKALi/Kali-Light.git

Enter the project directory:

cd Kali-Light

Start a local web server:

python3 -m http.server 8080

Then open:

http://127.0.0.1:8080

Using an HTTP server is recommended instead of opening the HTML file directly with "file://", because some browser capabilities require a proper web context.

---

📱 Termux

Light Kali can also be served from Termux.

Install Git and Python:

pkg update
pkg install git python

Clone the repository:

git clone https://github.com/LiGHTKALi/Kali-Light.git

Enter the directory:

cd Kali-Light

Start the web server:

python -m http.server 8080

Then open:

http://127.0.0.1:8080

This provides a simple way to access the Light Kali environment from an Android device with a supported browser.

---

🌐 HTTPS Sources

Light Kali also supports its own HTTPS-oriented package installation flow.

Example:

apt install https://example.com/package.js

or:

pkg install https://example.com/package.js

External package sources should always be treated carefully.

Do not execute unknown or untrusted JavaScript.

---

🧠 Runtime Intelligence

Light Kali is aware of the browser environment in which it is running.

Depending on browser and device support, it can inspect capabilities such as:

CPU / Logical Cores
Memory Hints
Device Pixel Ratio
GPU / WebGL Information
WebGPU Availability
Web Workers
Service Worker Availability
Network Information
Browser Capabilities
Runtime Performance
DOM Metrics

This allows Light Kali to make better use of the environment available to it.

---

⚙️ Performance & Booster

Light Kali includes runtime-oriented optimization capabilities, with the "booster" package extending performance and diagnostic functionality.

Relevant areas include:

Performance profiling
Benchmarking
Adaptive rendering
Transcript virtualization
Worker management
Resource allocation
GPU diagnostics
Network latency hints
Runtime capability scanning
Experimental browser feature detection
Cache management
Isolation analysis

The objective is not to artificially increase the physical performance of a device or create bandwidth that does not exist.

The objective is to use available browser resources more efficiently and keep the environment responsive.

---

💾 Persistent Configuration

Light Kali can preserve selected information locally in the browser.

Depending on the feature, this may include:

Package state
Package cache
Runtime configuration
User preferences
Application state

This allows the environment to retain useful information between sessions.

---

🎨 User Experience

Light Kali is designed to feel more like a lightweight cyber terminal than a conventional website.

The interface focuses on:

Fast rendering
Responsive layout
Terminal readability
Interactive feedback
Compact controls
Mobile compatibility
Persistent settings

The result is a browser-based environment designed around practical interaction rather than a traditional dashboard.

---

🌐 Browser-Native Technologies

Light Kali takes advantage of capabilities provided by modern browsers, including:

JavaScript
DOM APIs
Web Workers
WebGL
WebGPU
Storage APIs
Network APIs
Performance APIs
Service Worker APIs
Browser Security APIs

These technologies make it possible to build useful cybersecurity-oriented tools directly on top of the web platform.

---

🔐 Security

Light Kali operates within browser security boundaries.

This means the environment does not automatically receive unrestricted access to:

System Files
Kernel
Root Privileges
Raw Hardware
Native Linux Binaries

Some functionality depends on:

Browser
Browser Version
Operating System
Device
HTTPS / Secure Context
Available Hardware
Browser Permissions
Supported APIs

Different browsers and devices may therefore provide different capabilities.

---

🧪 What Can Light Kali Be Used For?

Light Kali can be useful for:

Cybersecurity Learning
Security Research
Defensive Analysis
OSINT Work
Browser Security Experiments
Network Analysis
Web Security Experiments
Runtime Diagnostics
Terminal-Based Tools

It is especially useful when portability and quick access are more important than full operating-system access.

---

🎯 Mission

The mission of Light Kali is to provide a:

Free
Lightweight
Fast
Portable
Browser-Based
Cybersecurity Environment

that can be accessed without requiring a complete operating-system installation for every task.

The philosophy is simple:

«Cybersecurity tooling should not always require a full operating system.»

Modern browsers already provide powerful execution, networking, graphics, storage, workers and security APIs.

Light Kali turns these capabilities into a unified cybersecurity workspace.

---

❤️ Free & Open

Light Kali is a free project.

The goal is to make browser-based cybersecurity tooling more accessible to developers, researchers, students and security enthusiasts.

No paid license is required for the core project.

---

🌍 Community

<p align="center">
  <img src="LightKaliTeam.png" width="100%" alt="Light Kali Team">
</p>We welcome developers, security researchers, students and technology enthusiasts from around the world.

<p align="center">
  Made with ❤️ by the community
</p>👥 Contributors

<p align="center">
  <a href="https://github.com/BLACKWHITE-CYBER">
    <img src="https://github.com/BLACKWHITE-CYBER.png?size=128" width="72" alt="BLACKWHITE-CYBER">
  </a>  <a href="https://github.com/DrAlanK">
    <img src="https://github.com/DrAlanK.png?size=128" width="72" alt="DrAlanK">
  </a>  <a href="https://github.com/WendigosCyber">
    <img src="https://github.com/WendigosCyber.png?size=128" width="72" alt="WendigosCyber">
  </a>  <a href="https://github.com/Nullspire">
    <img src="https://github.com/Nullspire.png?size=128" width="72" alt="Nullspire">
  </a>  <a href="https://github.com/KILLERDUTCH">
    <img src="https://github.com/KILLERDUTCH.png?size=128" width="72" alt="KILLERDUTCH">
  </a>  <a href="https://github.com/kalitn">
    <img src="https://github.com/kalitnt.png?size=128" width="72" alt="kalitnt">
  </a>  <a href="https://github.com/Zyroeima">
    <img src="https://github.com/Zyroeima.png?size=128" width="72" alt="Zyroeima">
  </a>
</p>---

⚠️ Important Notes

Light Kali is a browser-based cybersecurity environment.

It is not a replacement for:

Linux Kernel
Full Native Linux
Native Privileged Applications
Low-Level Operating-System Access

Browser security restrictions still apply.

Always use cybersecurity functionality only on systems, applications and networks that you are authorized to test.

---

🇮🇷 فارسی

درباره Light Kali

Light Kali — اولین وب‌سیستم‌عامل رایگان امنیت سایبری ایران.

Light Kali یک محیط امنیت سایبری رایگان، سبک و مبتنی بر مرورگر است که یک فضای ترمینالی سریع و کاربردی را مستقیماً در اختیار کاربر قرار می‌دهد.

این محیط، رابط ترمینال مدرن را با ابزارهای امنیتی، سیستم مدیریت پکیج، تشخیص قابلیت‌های مرورگر، Runtime Diagnostics و تنظیمات پایدار ترکیب می‌کند.

هدف اصلی ساده است:

«یک محیط امنیت سایبری سبک را مستقیماً به مرورگر بیاوریم.»

Light Kali تلاش نمی‌کند یک توزیع کامل لینوکس را در مرورگر بازسازی کند؛ بلکه از فناوری‌های مدرن Web استفاده می‌کند تا یک محیط امنیت سایبری سریع و قابل حمل بدون نیاز به نصب کامل سیستم‌عامل فراهم کند.

---

🚀 چرا Light Kali؟

Light Kali بر پایه‌ی سرعت، قابلیت حمل و سادگی طراحی شده است.

می‌توانید محیط را مستقیماً داخل مرورگر اجرا کنید و بدون آماده‌سازی یک نصب کامل لینوکس شروع به کار کنید.

مزیت‌های اصلی

⚡ سبک

برای اجرای سریع و پاسخ‌گویی مناسب طراحی شده است.

🌐 مبتنی بر مرورگر

مستقیماً داخل یک مرورگر مدرن اجرا می‌شود.

🆓 کاملاً رایگان

Light Kali یک پروژه‌ی رایگان است و برای استفاده از هسته‌ی اصلی آن نیازی به اشتراک پولی وجود ندارد.

📱 قابل حمل

همان محیط وب روی مرورگرهای پشتیبانی‌شده‌ی دسکتاپ و موبایل قابل اجرا است.

⌨️ ترمینال تعاملی

رابط کاربری ترمینالی تجربه‌ای آشنا و مبتنی بر Command ارائه می‌کند.

📦 مدیریت پکیج

دستورهای داخلی "apt" و "pkg" امکان مدیریت پکیج‌ها را داخل محیط Light Kali فراهم می‌کنند.

🧠 هوشمندی Runtime

محیط می‌تواند قابلیت‌های مرورگر، اطلاعات دستگاه و قابلیت‌های Runtime موجود را بررسی کند.

🛡️ تمرکز امنیتی

طراحی پروژه بر پایه‌ی ابزارهای امنیتی، Diagnostics و قابلیت‌های کنترل‌شده‌ی مرورگر است.

💾 ذخیره‌سازی وضعیت

برخی تنظیمات و اطلاعات Runtime می‌توانند بین Sessionها حفظ شوند.

---

⚖️ Light Kali در برابر Kali Linux

Light Kali و Kali Linux برای محیط‌های متفاوتی طراحی شده‌اند.

Light Kali| Kali Linux
🌐 مبتنی بر مرورگر| 🐧 سیستم‌عامل کامل مبتنی بر Linux
⚡ بسیار سبک| 💽 محیط کامل سیستم‌عامل
🆓 رایگان| 🆓 رایگان
🚀 اجرای مستقیم از مرورگر| 💻 نیازمند Linux، VM، WSL یا نصب
📱 قابل استفاده در مرورگر موبایل| 🖥️ عمدتاً دسکتاپ و سرور
⌨️ ترمینال Web| ⌨️ ترمینال Native Linux
📦 سیستم Package مخصوص محیط Web| 📦 اکوسیستم Debian
💾 ذخیره‌سازی در مرورگر| 💾 فایل‌سیستم واقعی
🧠 تشخیص قابلیت‌های Browser/Runtime| 🖥️ دسترسی مستقیم به سیستم و سخت‌افزار
🔐 Sandbox مرورگر| 🔐 مدل امنیتی Native Linux

جایی که Light Kali برتری دارد

Light Kali زمانی بسیار مناسب است که اولویت شما این موارد باشد:

Portability
Fast Startup
Low Overhead
Browser Access
Mobile Access
Web-Native Tools
Simple Deployment

برای دسترسی به یک محیط امنیت سایبری همیشه لازم نیست سیستم‌عامل کامل را Boot کنید.

مرورگر را باز کنید.

Light Kali را اجرا کنید.

شروع کنید.

---

🧰 ترمینال داخلی

Light Kali یک ترمینال تعاملی ارائه می‌کند.

دستورات پایه:

help

clear

about

دستورات مربوط به Package:

apt update
apt list
apt inspect <package>
apt install <package>
apt remove <package>
apt reinstall
apt policy

همین عملیات از طریق "pkg" نیز قابل اجرا هستند:

pkg update
pkg list
pkg inspect <package>
pkg install <package>
pkg remove <package>
pkg reinstall
pkg policy

«توجه: "apt" و "pkg" داخل Light Kali، دستورات Runtime خود پروژه هستند و APT واقعی Debian/Ubuntu یا Package Manager واقعی Termux نیستند.»

---

📦 مدیریت Package

Light Kali یک سیستم مدیریت Package داخلی برای محیط Web دارد.

به‌روزرسانی اطلاعات:

apt update

نمایش پکیج‌ها:

apt list

بررسی یک پکیج:

apt inspect booster

نصب:

apt install booster

حذف:

apt remove booster

نصب مجدد:

apt reinstall

بررسی Policy:

apt policy

همین عملیات با "pkg" نیز قابل استفاده است:

pkg update
pkg list
pkg inspect booster
pkg install booster
pkg remove booster
pkg reinstall
pkg policy

---

🛠️ نصب

Light Kali یک Web Application است؛ بنابراین برای اجرای رابط آن نیاز به نصب کامل Linux ندارید.

ابتدا Repository را دریافت کنید:

git clone https://github.com/LiGHTKALi/Kali-Light.git

وارد پروژه شوید:

cd Kali-Light

یک Web Server محلی اجرا کنید:

python3 -m http.server 8080

سپس:

http://127.0.0.1:8080

را در مرورگر باز کنید.

استفاده از HTTP Server نسبت به اجرای مستقیم فایل با "file://" پیشنهاد می‌شود، زیرا بعضی قابلیت‌های مرورگر به Web Context مناسب نیاز دارند.

---

📱 Termux

Light Kali را می‌توان از داخل Termux نیز اجرا کرد.

ابتدا Git و Python را نصب کنید:

pkg update
pkg install git python

Repository را Clone کنید:

git clone https://github.com/LiGHTKALi/Kali-Light.git

وارد پوشه شوید:

cd Kali-Light

سرور را اجرا کنید:

python -m http.server 8080

سپس:

http://127.0.0.1:8080

را در مرورگر باز کنید.

---

🌐 منابع HTTPS

Light Kali مسیر نصب پکیج از منابع HTTPS را نیز دارد.

مثال:

apt install https://example.com/package.js

یا:

pkg install https://example.com/package.js

منابع خارجی باید با دقت استفاده شوند.

هرگز JavaScript ناشناس یا غیرقابل اعتماد را اجرا نکنید.

---

🧠 هوشمندی Runtime

Light Kali می‌تواند محیط مرورگری را که داخل آن اجرا شده بررسی کند.

بسته به مرورگر و دستگاه، مواردی مانند زیر قابل بررسی هستند:

CPU / Logical Cores
Memory Hints
Device Pixel Ratio
GPU / WebGL Information
WebGPU Availability
Web Workers
Service Worker Availability
Network Information
Browser Capabilities
Runtime Performance
DOM Metrics

این قابلیت باعث می‌شود Light Kali بتواند استفاده‌ی مناسب‌تری از منابع محیط داشته باشد.

---

⚙️ عملکرد و Booster

Light Kali دارای قابلیت‌های مرتبط با Runtime و Performance است و پکیج "booster" امکانات Performance و Diagnostics را گسترش می‌دهد.

حوزه‌های مرتبط شامل:

Performance profiling
Benchmarking
Adaptive rendering
Transcript virtualization
Worker management
Resource allocation
GPU diagnostics
Network latency hints
Runtime capability scanning
Experimental browser feature detection
Cache management
Isolation analysis

هدف افزایش جادویی قدرت سخت‌افزار یا سرعت اینترنت نیست.

هدف، استفاده‌ی بهینه‌تر از منابع موجود مرورگر و حفظ پاسخ‌گویی محیط است.

---

💾 ذخیره‌سازی

Light Kali می‌تواند بعضی اطلاعات را به‌صورت محلی در مرورگر حفظ کند.

بسته به قابلیت مورد استفاده:

Package state
Package cache
Runtime configuration
User preferences
Application state

می‌توانند در Sessionهای بعدی نیز باقی بمانند.

---

🎨 تجربه کاربری

Light Kali تلاش می‌کند بیشتر شبیه یک Cyber Terminal سبک باشد تا یک Website معمولی.

تمرکز رابط کاربری بر:

Fast rendering
Responsive layout
Terminal readability
Interactive feedback
Compact controls
Mobile compatibility
Persistent settings

قرار دارد.

---

🌐 فناوری‌های Web-Native

Light Kali از قابلیت‌های مرورگرهای مدرن استفاده می‌کند:

JavaScript
DOM APIs
Web Workers
WebGL
WebGPU
Storage APIs
Network APIs
Performance APIs
Service Worker APIs
Browser Security APIs

این قابلیت‌ها ساخت ابزارهای امنیت سایبری مبتنی بر Web را امکان‌پذیر می‌کنند.

---

🔐 امنیت

Light Kali در محدوده‌ی امنیتی مرورگر اجرا می‌شود.

بنابراین به‌صورت خودکار دسترسی نامحدود به موارد زیر ندارد:

System Files
Kernel
Root Privileges
Raw Hardware
Native Linux Binaries

بعضی قابلیت‌ها به موارد زیر وابسته هستند:

Browser
Browser Version
Operating System
Device
HTTPS / Secure Context
Available Hardware
Browser Permissions
Supported APIs

در نتیجه رفتار بعضی امکانات ممکن است در مرورگرها و دستگاه‌های مختلف متفاوت باشد.

---

🧪 Light Kali برای چه کارهایی مناسب است؟

Light Kali می‌تواند برای موارد زیر مفید باشد:

یادگیری امنیت سایبری
تحقیقات امنیتی
تحلیل دفاعی
OSINT
آزمایش‌های امنیتی مرورگر
تحلیل شبکه
آزمایش امنیت Web
Runtime Diagnostics
ابزارهای ترمینالی

خصوصاً زمانی که قابلیت حمل و اجرای سریع از دسترسی کامل سیستم‌عامل مهم‌تر باشد.

---

🎯 هدف پروژه

هدف Light Kali ایجاد یک محیط امنیت سایبری:

رایگان
سبک
سریع
قابل حمل
مبتنی بر مرورگر

است که بدون نیاز به نصب یک سیستم‌عامل کامل برای هر کار قابل استفاده باشد.

فلسفه پروژه ساده است:

«ابزار امنیت سایبری همیشه به یک سیستم‌عامل کامل نیاز ندارد.»

مرورگرهای مدرن در حال حاضر قابلیت‌های قدرتمندی برای اجرا، شبکه، گرافیک، ذخیره‌سازی، Worker و امنیت در اختیار دارند.

Light Kali این قابلیت‌ها را در قالب یک محیط امنیت سایبری یکپارچه ارائه می‌کند.

---

❤️ رایگان و آزاد

Light Kali یک پروژه رایگان است.

هدف آن دسترسی‌پذیرتر کردن ابزارهای امنیت سایبری مبتنی بر Web برای توسعه‌دهندگان، پژوهشگران، دانش‌آموزان و علاقه‌مندان امنیت است.

برای استفاده از هسته‌ی اصلی پروژه نیازی به خرید License یا اشتراک پولی نیست.

---

🌍 Community

<p align="center">
  <img src="LightKaliTeam.png" width="100%" alt="تیم Light Kali">
</p>از توسعه‌دهندگان، پژوهشگران امنیت، دانش‌آموزان، برنامه‌نویسان و علاقه‌مندان فناوری در سراسر جهان برای مشارکت استقبال می‌شود.

<p align="center">
  Made with ❤️ by the community
</p>👥 Contributors

<p align="center">
  <a href="https://github.com/BLACKWHITE-CYBER">
    <img src="https://github.com/BLACKWHITE-CYBER.png?size=128" width="72" alt="BLACKWHITE-CYBER">
  </a>  <a href="https://github.com/DrAlanK">
    <img src="https://github.com/DrAlanK.png?size=128" width="72" alt="DrAlanK">
  </a>  <a href="https://github.com/WendigosCyber">
    <img src="https://github.com/WendigosCyber.png?size=128" width="72" alt="WendigosCyber">
  </a>  <a href="https://github.com/Nullspire">
    <img src="https://github.com/Nullspire.png?size=128" width="72" alt="Nullspire">
  </a>  <a href="https://github.com/KILLERDUTCH">
    <img src="https://github.com/KILLERDUTCH.png?size=128" width="72" alt="KILLERDUTCH">
  </a>  <a href="https://github.com/kalitn">
    <img src="https://github.com/kalitnt.png?size=128" width="72" alt="kalitnt">
  </a>  <a href="https://github.com/Zyroeima">
    <img src="https://github.com/Zyroeima.png?size=128" width="72" alt="Zyroeima">
  </a>
</p>---

⚠️ نکات مهم

Light Kali یک محیط امنیت سایبری مبتنی بر مرورگر است.

این پروژه جایگزین موارد زیر نیست:

Linux Kernel
Full Native Linux
Native Privileged Applications
Low-Level Operating-System Access

محدودیت‌های امنیتی Browser همچنان برقرار هستند.

همیشه قابلیت‌های امنیت سایبری را فقط روی سیستم‌ها، برنامه‌ها و شبکه‌هایی استفاده کنید که اجازه‌ی آزمایش آن‌ها را دارید.

---

<div align="center">🖥️ Light Kali

Iran's First Free Cybersecurity Web OS

Lightweight • Fast • Free • Secure-by-Design

Built for Cybersecurity. Powered by the Web.

</div>
