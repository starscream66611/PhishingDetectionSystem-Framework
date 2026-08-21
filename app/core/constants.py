from __future__ import annotations

BRANDS = [
    "paypal",
    "google",
    "facebook",
    "instagram",
    "microsoft",
    "apple",
    "amazon",
    "bank",
    "roblox",
    "fidelity",
]

SAFE_BRAND_DOMAINS = {
    "paypal.com",
    "paypal.me",
    "google.com",
    "facebook.com",
    "instagram.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "roblox.com",
    "fidelity.com",
    "visualstudio.com",
    "github.com",
    "binus.ac.id",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "ru", "cn",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "t.co",
    "goo.gl",
    "rb.gy",
    "is.gd",
    "ow.ly",
}

PUBLIC_HOSTING_DOMAINS = {
    "github.io",
    "hosted.app",
    "herokuapp.com",
    "pages.dev",
    "netlify.app",
    "vercel.app",
}

COMMON_SAFE_PORTS = {80, 443}

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
    "signin",
    "wallet",
    "payment",
    "auth",
    "confirm",
]

SUSPICIOUS_FILE_HINTS = [
    "wget",
    "curl",
    "bin.sh",
    ".sh",
    ".exe",
    ".apk",
    ".arm",
    ".mips",
    ".elf",
    "powershell",
    "cmd.exe",
]