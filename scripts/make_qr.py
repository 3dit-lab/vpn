#!/usr/bin/env python3
"""Единый QR-код на портал выдачи конфигов (один на всех сотрудников).

    python3 scripts/make_qr.py --url https://pm-vpn.3dit.ru/ --out out/qr-portal.png
"""
import argparse
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont

FONTS = ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"]


def font(size):
    for p in FONTS:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://pm-vpn.3dit.ru/")
    ap.add_argument("--out", default="out/qr-portal.png")
    ap.add_argument("--title", default="Доступ к VPN · ООО «Тридит»")
    args = ap.parse_args()

    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=14, border=4)
    q.add_data(args.url)
    q.make(fit=True)
    img = q.make_image(fill_color="black", back_color="white").convert("RGB")
    w, h = img.size
    f, f2 = font(26), font(20)
    if f:  # подпись добавляем только если есть шрифт с кириллицей
        probe = ImageDraw.Draw(img)
        tw = max(probe.textlength(args.title, font=f), probe.textlength(args.url, font=f2))
        cw = max(w, int(tw) + 60)  # холст шире текста, чтобы подпись не обрезалась
        canvas = Image.new("RGB", (cw, h + 90), "white")
        canvas.paste(img, ((cw - w) // 2, 0))
        d = ImageDraw.Draw(canvas)
        d.text((cw // 2, h + 6), args.title, fill="black", font=f, anchor="ma")
        d.text((cw // 2, h + 46), args.url, fill="black", font=f2, anchor="ma")
        img = canvas
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    img.save(args.out)
    print(f"QR для {args.url} сохранён в {args.out}")


if __name__ == "__main__":
    main()
