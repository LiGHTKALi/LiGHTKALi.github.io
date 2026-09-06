(() => {
    "use strict";

    const root = document.documentElement;
    const body = document.body;
    const navShell = document.getElementById("navShell");
    const themeToggle = document.getElementById("themeToggle");
    const mobileToggle = document.getElementById("mobileToggle");
    const mobileMenu = document.getElementById("mobileMenu");
    const langWrapper = document.getElementById("langWrapper");
    const langButton = document.getElementById("langButton");
    const year = document.getElementById("year");
    const themeColor = document.getElementById("themeColor");

    const THEME_KEY = "light-kali-theme";

    let savedTheme = null;

    try {
        savedTheme = localStorage.getItem(THEME_KEY);
    } catch {}

    const systemDark =
        window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: dark)").matches;

    root.dataset.theme =
        savedTheme === "dark" || savedTheme === "light"
            ? savedTheme
            : systemDark
                ? "dark"
                : "light";

    const updateTheme = () => {
        if (!themeColor) return;

        themeColor.setAttribute(
            "content",
            root.dataset.theme === "dark" ? "#050505" : "#f4f4f6"
        );
    };

    updateTheme();

    const setTheme = (theme) => {
        root.dataset.theme = theme;

        try {
            localStorage.setItem(THEME_KEY, theme);
        } catch {}

        updateTheme();
    };

    themeToggle?.addEventListener("click", () => {
        setTheme(root.dataset.theme === "dark" ? "light" : "dark");
    });

    const updateHeader = () => {
        navShell?.classList.toggle("scrolled", window.scrollY > 16);
    };

    updateHeader();

    let scrollTicking = false;

    window.addEventListener(
        "scroll",
        () => {
            if (scrollTicking) return;

            scrollTicking = true;

            requestAnimationFrame(() => {
                updateHeader();
                scrollTicking = false;
            });
        },
        { passive: true }
    );

    const closeMobileMenu = () => {
        if (!mobileMenu) return;

        mobileMenu.hidden = true;
        mobileToggle?.setAttribute("aria-expanded", "false");
        mobileToggle?.setAttribute("aria-label", "Open navigation");
    };

    mobileToggle?.addEventListener("click", () => {
        if (!mobileMenu) return;

        const opening = mobileMenu.hidden;

        mobileMenu.hidden = !opening;
        mobileToggle.setAttribute("aria-expanded", String(opening));
        mobileToggle.setAttribute(
            "aria-label",
            opening ? "Close navigation" : "Open navigation"
        );
    });

    mobileMenu?.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", closeMobileMenu);
    });

    langButton?.addEventListener("click", (event) => {
        event.stopPropagation();

        const open = langWrapper?.classList.toggle("open");

        langButton.setAttribute("aria-expanded", String(Boolean(open)));
    });

    langWrapper?.addEventListener("click", (event) => {
        event.stopPropagation();
    });

    document.addEventListener("click", () => {
        langWrapper?.classList.remove("open");
        langButton?.setAttribute("aria-expanded", "false");
    });

    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;

        langWrapper?.classList.remove("open");
        langButton?.setAttribute("aria-expanded", "false");
        closeMobileMenu();
    });

    window.addEventListener("resize", () => {
        if (window.innerWidth > 900) {
            closeMobileMenu();
        }
    });

    if (year) {
        year.textContent = String(new Date().getFullYear());
    }

    const lazyImages = [
        ...document.querySelectorAll('img[loading="lazy"]')
    ];

    if ("IntersectionObserver" in window) {
        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (!entry.isIntersecting) return;

                    const img = entry.target;

                    if (img.dataset.src) {
                        img.src = img.dataset.src;
                        img.removeAttribute("data-src");
                    }

                    observer.unobserve(img);
                });
            },
            {
                rootMargin: "700px 0px"
            }
        );

        lazyImages.forEach((img) => observer.observe(img));
    } else {
        lazyImages.forEach((img) => {
            if (img.dataset.src) {
                img.src = img.dataset.src;
                img.removeAttribute("data-src");
            }
        });
    }

    const wallpapers = [
        ...document.querySelectorAll(".hero-wallpaper")
    ];

    if (wallpapers.length > 1) {
        let currentIndex = 0;
        let timer = null;

        const activateWallpaper = (nextIndex) => {
            wallpapers.forEach((image, index) => {
                image.classList.toggle("active", index === nextIndex);
            });

            currentIndex = nextIndex;
        };

        const startWallpaperRotation = () => {
            if (timer) {
                clearInterval(timer);
            }

            timer = window.setInterval(() => {
                const nextIndex =
                    (currentIndex + 1) % wallpapers.length;

                activateWallpaper(nextIndex);
            }, 6500);
        };

        wallpapers.slice(1).forEach((image) => {
            if (image.dataset.src) {
                image.src = image.dataset.src;
                image.removeAttribute("data-src");
            }
        });

        startWallpaperRotation();

        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                if (timer) {
                    clearInterval(timer);
                    timer = null;
                }

                return;
            }

            startWallpaperRotation();
        });
    }

    const anchorLinks = document.querySelectorAll('a[href^="#"]');

    anchorLinks.forEach((link) => {
        link.addEventListener("click", (event) => {
            const href = link.getAttribute("href");

            if (!href || href === "#") return;

            const target = document.querySelector(href);

            if (!target) return;

            event.preventDefault();

            const headerOffset =
                parseFloat(
                    getComputedStyle(root)
                        .getPropertyValue("--header-h")
                ) || 76;

            const targetTop =
                target.getBoundingClientRect().top +
                window.scrollY -
                headerOffset -
                14;

            window.scrollTo({
                top: Math.max(0, targetTop),
                behavior: "smooth"
            });

            closeMobileMenu();
        });
    });

    const revealTargets = [
        ...document.querySelectorAll(
            ".feature-card, .platform-card, .package-card, .doc-card, .wallpaper-card, .about-panel, details, .cta-box"
        )
    ];

    revealTargets.forEach((element, index) => {
        element.classList.add("motion-ready");
        element.style.setProperty(
            "--motion-delay",
            `${Math.min(index * 35, 280)}ms`
        );
    });

    if ("IntersectionObserver" in window) {
        const revealObserver = new IntersectionObserver(
            (entries, observer) => {
                entries.forEach((entry) => {
                    if (!entry.isIntersecting) return;

                    entry.target.classList.add("motion-visible");
                    observer.unobserve(entry.target);
                });
            },
            {
                threshold: 0.08,
                rootMargin: "0px 0px -50px 0px"
            }
        );

        revealTargets.forEach((element) =>
            revealObserver.observe(element)
        );
    } else {
        revealTargets.forEach((element) =>
            element.classList.add("motion-visible")
        );
    }

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            root.classList.add("page-ready");
            body.classList.add("page-ready");
        });
    });
})();