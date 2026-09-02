(() => {
    "use strict";
    const root = document.documentElement;
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
    try { savedTheme = localStorage.getItem(THEME_KEY) } catch { }
    const systemDark = window.matchMedia && window.matchMedia("(prefers-color-scheme:dark)").matches;
    root.dataset.theme = savedTheme === "dark" || savedTheme === "light" ? savedTheme : (systemDark ? "dark" : "light");
    const updateTheme = () => {
        if (themeColor) themeColor.setAttribute("content", root.dataset.theme === "dark" ? "#050505" : "#f4f4f6");
    };
    updateTheme();
    const setTheme = theme => {
        root.dataset.theme = theme;
        try { localStorage.setItem(THEME_KEY, theme) } catch { }
        updateTheme();
    };
    themeToggle?.addEventListener("click", () => setTheme(root.dataset.theme === "dark" ? "light" : "dark"));
    const updateHeader = () => navShell?.classList.toggle("scrolled", window.scrollY > 16);
    updateHeader();
    window.addEventListener("scroll", updateHeader, { passive: true });
    mobileToggle?.addEventListener("click", () => {
        const opening = mobileMenu.hidden;
        mobileMenu.hidden = !opening;
        mobileToggle.setAttribute("aria-expanded", String(opening));
        mobileToggle.setAttribute("aria-label", opening ? "Close navigation" : "Open navigation");
    });
    mobileMenu?.querySelectorAll("a").forEach(link => link.addEventListener("click", () => {
        mobileMenu.hidden = true;
        mobileToggle?.setAttribute("aria-expanded", "false");
        mobileToggle?.setAttribute("aria-label", "Open navigation");
    }));
    langButton?.addEventListener("click", event => {
        event.stopPropagation();
        const open = langWrapper.classList.toggle("open");
        langButton.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("click", () => {
        langWrapper?.classList.remove("open");
        langButton?.setAttribute("aria-expanded", "false");
    });
    document.addEventListener("keydown", event => {
        if (event.key === "Escape") {
            langWrapper?.classList.remove("open");
            langButton?.setAttribute("aria-expanded", "false");
            mobileMenu.hidden = true;
            mobileToggle?.setAttribute("aria-expanded", "false");
        }
    });
    if (year) year.textContent = String(new Date().getFullYear());
    // Lazy load images
    const lazyImages = [...document.querySelectorAll('img[loading="lazy"]')];
    if ("IntersectionObserver" in window) {
        const observer = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                const img = entry.target;
                if (img.dataset.src) img.src = img.dataset.src;
                observer.unobserve(img);
            });
        }, { rootMargin: "500px 0px" });
        lazyImages.forEach(img => observer.observe(img));
    }
})();