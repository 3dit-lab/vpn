#!/usr/bin/env python3
"""Build the download page from installers already present in the mirror."""
import argparse
import os
import re
import tempfile
from html import escape
from pathlib import Path
from string import Template
from urllib.parse import quote

REPOSITORIES = ("amnezia-vpn/amnezia-client", "Happ-proxy/happ-desktop")


def card(platform, title, description, href, action):
    return (
        f'<article class="download" data-os="{platform}">'
        f'<h3>{escape(title)}</h3><p>{escape(description)}</p>'
        f'<a class="button" aria-label="{escape(title + " · " + action)}" '
        f'href="{escape(href)}">{escape(action)}</a></article>'
    )


def describe(filename):
    name = filename.lower()
    arch = ""
    if any(value in name for value in ("arm64", "aarch64")):
        arch = "ARM64"
    elif any(value in name for value in ("x64", "x86_64", "amd64")):
        arch = "x64"
    elif "universal" in name:
        arch = "Universal"
    for extensions, platform, title, detail in (
        ((".exe", ".msi"), "windows", "Windows", "Установщик"),
        ((".dmg", ".pkg"), "mac", "macOS", "Установщик"),
        ((".apk",), "android", "Android", "Файл APK"),
        ((".deb",), "linux", "Debian / Ubuntu", "Пакет DEB"),
        ((".rpm",), "linux", "Fedora / RHEL", "Пакет RPM"),
        ((".pkg.tar.zst", ".pkg.tar.xz"), "linux", "Arch Linux", "Пакет pacman"),
        ((".appimage",), "linux", "Linux", "AppImage"),
    ):
        if name.endswith(extensions):
            return platform, title, " · ".join(filter(None, (arch, detail)))
    return "other", filename, "Архив"


def mirror_section(directory, title, amnezia):
    rows, older = [], []
    manifest = directory / "SHA256SUMS"
    for entry in manifest.read_text(encoding="utf-8").splitlines():
        # sha256sum uses a space or an asterisk after the separator.
        match = re.fullmatch(r"[a-fA-F0-9]{64} [ *](.+)", entry)
        if not match:
            continue
        filename = match[1]
        if Path(filename).name != filename:
            continue
        size = (directory / filename).stat().st_size
        href = f"{quote(directory.name)}/{quote(filename)}"
        action = f"Скачать · {max(1, round(size / (1024 * 1024)))} МБ"
        platform, label, description = describe(filename)
        if amnezia and platform == "android":
            name = filename.lower()
            if "android11+" in name and "arm64-v8a" in name:
                description = "Android 11 и новее · ARM64 · APK"
            elif "android9-10" in name and "arm64-v8a" in name:
                older.append(card("android-legacy", "Android", "Android 9–10 · ARM64 · APK", href, action))
                continue
            elif "android11+" in name or "android9-10" in name:
                continue
        rows.append((platform, card(platform, label, description, href, action)))

    order = {"windows": 0, "mac": 1, "android": 2, "linux": 4}
    rows.sort(key=lambda row: order.get(row[0], 5))
    cards = [html for _, html in rows]
    if amnezia:
        ios = card("ios", "iPhone / iPad", "DefaultVPN · App Store",
                   "https://apps.apple.com/app/id6744725017", "Открыть App Store")
        cards.insert(sum(order.get(platform, 5) < 3 for platform, _ in rows), ios)
        if not any(platform == "linux" for platform, _ in rows):
            cards.append(card("linux", "Linux", "Amnezia VPN · сайт разработчика",
                              "https://amnezia.org/downloads", "Открыть загрузки"))
    if title == "Happ":
        mobile = [
            card("android", "Android", "Happ · APK от разработчика",
                 "https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk", "Скачать APK"),
            card("ios", "iPhone / iPad", "Happ · доступность зависит от региона App Store",
                 "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215", "Открыть App Store"),
        ]
        mobile_index = sum(order.get(platform, 5) < 4 for platform, _ in rows)
        cards[mobile_index:mobile_index] = mobile

    details = ""
    if older:
        details = ('<details><summary>Amnezia VPN для Android 9–10</summary>'
                   f'<div class="grid">{"".join(older)}</div></details>')
    source = directory / "SOURCE.txt"
    source_text = source.read_text(encoding="utf-8") if source.is_file() else ""
    version = re.search(r"/releases/tag/([^\s]+)", source_text)
    subtitle = ('Для файла из кнопки «Скачать конфиг». <a href="/help#amnezia">Как подключить Amnezia VPN</a>' if amnezia
                else 'Для подписки из личного кабинета. <a href="/help#happ">Как подключить Happ</a>' if title == "Happ" else "")
    section_id = "amnezia" if amnezia else "happ" if title == "Happ" else quote(directory.name)
    version_html = f'<span class="version">{escape(version[1])}</span>' if version else ""
    source_link = f' · <a href="{quote(directory.name)}/SOURCE.txt">Источник файлов</a>' if source.is_file() else ""
    return (
        f'<section id="{section_id}"><h2>{escape(title)} {version_html}</h2>'
        f'<p class="subtitle">{subtitle}</p><div class="grid">{"".join(cards)}</div>{details}'
        f'<p class="sources"><a href="{quote(directory.name)}/SHA256SUMS">Контрольные суммы SHA256</a>'
        f'{source_link}</p></section>'
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("repositories", nargs="*", default=REPOSITORIES)
    parser.add_argument("--output", type=Path, help="Defaults to index.html in the mirror")
    args = parser.parse_args()
    sections = []
    secondary = []
    links = []
    for repo in args.repositories:
        name = repo.split("/")[-1]
        amnezia = name == "amnezia-client"
        is_happ = name == "happ-desktop"
        title = "Amnezia VPN" if amnezia else "Happ" if is_happ else name
        html = mirror_section(args.directory / name, title, amnezia)
        if amnezia:
            sections.append(html)
            links.append('<a href="#amnezia">Amnezia VPN</a>')
        else:
            secondary.append(html)
    links.append('<a href="#wireguard">WireGuard</a>')
    if "happ-desktop" in [repo.split("/")[-1] for repo in args.repositories]:
        links.append('<a href="#happ">Happ</a>')
    template = Template(Path(__file__).with_name("apps.html").read_text(encoding="utf-8"))
    html = template.substitute(nav="".join(links), primary="".join(sections), secondary="".join(secondary))
    output = args.output or args.directory / "index.html"
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(html)
            handle.close()
            temporary.chmod(0o644)
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
