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
        window.matchMedia?.("(prefers-color-scheme: dark)").matches === true;

    root.dataset.theme =
        savedTheme === "dark" || savedTheme === "light"
            ? savedTheme
            : systemDark
                ? "dark"
                : "light";

    const updateTheme = () => {
        if (!themeColor) return;

        themeColor.content =
            root.dataset.theme === "dark"
                ? "#050505"
                : "#f4f4f6";
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
        setTheme(
            root.dataset.theme === "dark"
                ? "light"
                : "dark"
        );
    });

    const updateHeader = () => {
        navShell?.classList.toggle(
            "scrolled",
            window.scrollY > 16
        );
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

        mobileToggle?.setAttribute(
            "aria-expanded",
            "false"
        );

        mobileToggle?.setAttribute(
            "aria-label",
            "Open navigation"
        );
    };

    mobileToggle?.addEventListener("click", () => {
        if (!mobileMenu) return;

        const opening = mobileMenu.hidden;

        mobileMenu.hidden = !opening;

        mobileToggle.setAttribute(
            "aria-expanded",
            String(opening)
        );

        mobileToggle.setAttribute(
            "aria-label",
            opening
                ? "Close navigation"
                : "Open navigation"
        );
    });

    mobileMenu?.querySelectorAll("a").forEach((link) => {
        link.addEventListener(
            "click",
            closeMobileMenu
        );
    });

    langButton?.addEventListener("click", (event) => {
        event.stopPropagation();

        const open =
            langWrapper?.classList.toggle("open");

        langButton.setAttribute(
            "aria-expanded",
            String(Boolean(open))
        );
    });

    langWrapper?.addEventListener(
        "click",
        (event) => {
            event.stopPropagation();
        }
    );

    document.addEventListener("click", () => {
        langWrapper?.classList.remove("open");

        langButton?.setAttribute(
            "aria-expanded",
            "false"
        );
    });

    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;

        langWrapper?.classList.remove("open");

        langButton?.setAttribute(
            "aria-expanded",
            "false"
        );

        closeMobileMenu();
    });

    let resizeTimer = null;

    window.addEventListener(
        "resize",
        () => {
            if (resizeTimer) {
                clearTimeout(resizeTimer);
            }

            resizeTimer = setTimeout(() => {
                if (window.innerWidth > 900) {
                    closeMobileMenu();
                }

                resizeTimer = null;
            }, 120);
        },
        { passive: true }
    );

    if (year) {
        year.textContent =
            String(new Date().getFullYear());
    }

    const lazyImages = [
        ...document.querySelectorAll(
            'img[loading="lazy"][data-src]'
        )
    ];

    const loadImage = (img) => {
        if (!img?.dataset?.src) return;

        img.src = img.dataset.src;
        img.removeAttribute("data-src");
    };

    if (
        lazyImages.length &&
        "IntersectionObserver" in window
    ) {
        const imageObserver =
            new IntersectionObserver(
                (entries, observer) => {
                    entries.forEach((entry) => {
                        if (!entry.isIntersecting) return;

                        loadImage(entry.target);
                        observer.unobserve(entry.target);
                    });
                },
                {
                    rootMargin: "700px 0px"
                }
            );

        lazyImages.forEach((img) => {
            imageObserver.observe(img);
        });
    } else {
        lazyImages.forEach(loadImage);
    }

    const wallpapers = [
        ...document.querySelectorAll(
            ".hero-wallpaper"
        )
    ];

    if (wallpapers.length > 1) {
        let currentIndex = 0;
        let timer = null;

        const activateWallpaper = (nextIndex) => {
            wallpapers.forEach((image, index) => {
                image.classList.toggle(
                    "active",
                    index === nextIndex
                );
            });

            currentIndex = nextIndex;
        };

        const startWallpaperRotation = () => {
            if (timer) {
                clearInterval(timer);
            }

            timer = window.setInterval(() => {
                activateWallpaper(
                    (currentIndex + 1) %
                        wallpapers.length
                );
            }, 6500);
        };

        wallpapers.slice(1).forEach(loadImage);

        startWallpaperRotation();

        document.addEventListener(
            "visibilitychange",
            () => {
                if (document.hidden) {
                    if (timer) {
                        clearInterval(timer);
                        timer = null;
                    }

                    return;
                }

                startWallpaperRotation();
            }
        );
    }

    document
        .querySelectorAll('a[href^="#"]')
        .forEach((link) => {
            link.addEventListener("click", (event) => {
                const href =
                    link.getAttribute("href");

                if (!href || href === "#") return;

                const target =
                    document.querySelector(href);

                if (!target) return;

                event.preventDefault();

                const headerOffset =
                    parseFloat(
                        getComputedStyle(root)
                            .getPropertyValue(
                                "--header-h"
                            )
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
            [
                ".feature-card",
                ".platform-card",
                ".package-card",
                ".doc-card",
                ".wallpaper-card",
                ".about-panel",
                "details",
                ".cta-box"
            ].join(",")
        )
    ];

    const reduceMotion =
        window.matchMedia?.(
            "(prefers-reduced-motion: reduce)"
        ).matches === true;

    revealTargets.forEach((element, index) => {
        element.classList.add("motion-ready");

        element.style.setProperty(
            "--motion-delay",
            `${Math.min(index * 45, 360)}ms`
        );

        element.style.setProperty(
            "--motion-duration",
            reduceMotion
                ? "1ms"
                : "900ms"
        );

        element.style.setProperty(
            "--motion-easing",
            "cubic-bezier(0.16, 1, 0.3, 1)"
        );
    });

    if (
        revealTargets.length &&
        "IntersectionObserver" in window
    ) {
        const revealObserver =
            new IntersectionObserver(
                (entries, observer) => {
                    entries.forEach((entry) => {
                        if (!entry.isIntersecting) {
                            return;
                        }

                        const element =
                            entry.target;

                        element.classList.add(
                            "motion-visible"
                        );

                        observer.unobserve(element);
                    });
                },
                {
                    threshold: 0,
                    rootMargin:
                        "120px 0px 120px 0px"
                }
            );

        revealTargets.forEach((element) => {
            revealObserver.observe(element);
        });
    } else {
        revealTargets.forEach((element) => {
            element.classList.add(
                "motion-visible"
            );
        });
    }

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            root.classList.add("page-ready");
            body.classList.add("page-ready");
        });
    });
})();