#!/usr/bin/env bash
# Скачивает последние ОФИЦИАЛЬНЫЕ релизы клиентов Amnezia и Happ с GitHub в каталог раздачи,
# проверяет SHA256 (если GitHub отдаёт digest), пишет SHA256SUMS и обновляет /apps/index.html.
# Файлы не изменяются и не пересобираются. Запускайте вручную, когда хотите обновить приложения:
# автоматическое скачивание без проверки на сервере, раздающем файлы сотрудникам, не настроено намеренно.
#
#   sudo ./scripts/fetch-apps.sh
#   REPOS="amnezia-vpn/amnezia-client другой/репозиторий" sudo ./scripts/fetch-apps.sh
set -euo pipefail

APPS_DIR="${APPS_DIR:-/var/www/vpn/apps}"
REPOS="${REPOS:-amnezia-vpn/amnezia-client Happ-proxy/happ-desktop}"
PATTERN='\.(exe|msi|dmg|pkg|apk|deb|rpm|AppImage|zip|tar\.(gz|zst|xz))$'

for t in curl jq sha256sum; do
  command -v "$t" >/dev/null || { echo "Нужна утилита: $t (apt-get install -y curl jq coreutils)"; exit 1; }
done

# человекочитаемое описание файла: "ОС|пояснение|ключ для подсветки"
describe() {
  local f="${1,,}" arch=""
  case "$f" in *arm64*|*aarch64*) arch="ARM-процессоры (Apple M, Snapdragon)";; *x64*|*x86_64*|*amd64*) arch="обычные ПК и ноутбуки (x64)";; esac
  case "$f" in
    *.exe|*.msi) echo "Windows|${arch:-установщик}|windows";;
    *.dmg|*.pkg) echo "macOS|${arch:-для Mac}|mac";;
    *.apk) echo "Android|файл приложения .apk|android";;
    *.deb) echo "Linux · Debian / Ubuntu|${arch:-пакет .deb}|linux";;
    *.rpm) echo "Linux · Fedora / RHEL|${arch:-пакет .rpm}|linux";;
    *.pkg.tar.*) echo "Linux · Arch|${arch:-пакет pacman}|linux";;
    *.appimage) echo "Linux · любой дистрибутив|${arch:-AppImage}|linux";;
    *) echo "Другое|архив или исходники|other";;
  esac
}

esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

mkdir -p "$APPS_DIR"
sections=""

for repo in $REPOS; do
  name="${repo#*/}"
  echo "== $repo"
  rel="$(curl -fsSL --retry 3 -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$repo/releases/latest")"
  tag="$(jq -r '.tag_name' <<<"$rel")"
  [ -n "$tag" ] && [ "$tag" != "null" ] || { echo "Не удалось получить релиз $repo"; exit 1; }
  dest="$APPS_DIR/$name"
  rm -rf "$dest.new"; mkdir -p "$dest.new"

  count=0
  while IFS=$'\t' read -r fname url digest; do
    [ -n "$fname" ] || continue
    echo "  скачиваю $fname"
    curl -fL --retry 3 -o "$dest.new/$fname" "$url"
    if [[ "$digest" == sha256:* ]]; then
      want="${digest#sha256:}"
      got="$(sha256sum "$dest.new/$fname" | cut -d' ' -f1)"
      if [ "$want" != "$got" ]; then
        echo "ОШИБКА: контрольная сумма $fname не совпала с указанной GitHub" >&2
        rm -rf "$dest.new"; exit 1
      fi
      echo "    SHA256 совпала с данными GitHub"
    else
      echo "    GitHub не отдал digest для проверки, сумма только вычислена"
    fi
    count=$((count+1))
  done < <(jq -r --arg re "$PATTERN" '.assets[] | select(.name|test($re)) | [.name, .browser_download_url, (.digest // "")] | @tsv' <<<"$rel")

  [ "$count" -gt 0 ] || { echo "В релизе $repo $tag нет подходящих файлов"; rm -rf "$dest.new"; exit 1; }

  ( cd "$dest.new" && sha256sum -- * > SHA256SUMS )
  printf 'Источник: https://github.com/%s/releases/tag/%s\nДата загрузки: %s\n' "$repo" "$tag" "$(date -u +%FT%TZ)" > "$dest.new/SOURCE.txt"
  rm -rf "$dest"; mv "$dest.new" "$dest"
  chmod -R a+rX "$dest"

  rows=""
  while read -r sum fn; do
    fn="${fn#\*}"
    size="$(du -h -- "$dest/$fn" | cut -f1)"
    IFS='|' read -r os note key <<<"$(describe "$fn")"
    rows+="<a class=\"item\" data-os=\"$key\" href=\"$name/$(printf '%s' "$fn" | esc)\"><span class=\"os\">$os</span><span class=\"note\">$note</span><span class=\"btn\">Скачать · $size</span><span class=\"fn\">$(printf '%s' "$fn" | esc) · SHA256 ${sum:0:12}…</span></a>"
  done < "$dest/SHA256SUMS"
  case "$name" in
    happ*) title="Happ (запасной вариант, ссылка из личного кабинета)";;
    amnezia*) title="Amnezia VPN (основной вариант, конфиг из личного кабинета)";;
    *) title="$name";;
  esac
  sections+="<h2>$(printf '%s' "$title" | esc) · $(printf '%s' "$tag" | esc)</h2><div class=\"grid\">$rows</div><p class=\"src\"><a href=\"$name/SHA256SUMS\">SHA256SUMS</a> · <a href=\"$name/SOURCE.txt\">источник</a></p>"
done

cat > "$APPS_DIR/index.html" <<HTML
<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>Приложения для VPN</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:860px;margin:0 auto;padding:16px;color:#1c1c1e;background:#fff}
@media(prefers-color-scheme:dark){body{background:#17181a;color:#eee}.item{background:#222426;border-color:#3a3d40}}
h2{margin:28px 0 10px;font-size:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.item{display:flex;flex-direction:column;gap:4px;padding:14px;border:1px solid #d0d3d6;border-radius:12px;text-decoration:none;color:inherit;background:#f7f8f9}
.item .os{font-weight:700;font-size:17px}.item .note{opacity:.75;font-size:14px}
.item .btn{margin-top:8px;padding:10px;border-radius:8px;background:#2b6cb0;color:#fff;text-align:center;font-weight:600}
.item .fn{font-size:11px;opacity:.55;word-break:break-all;margin-top:4px}
.item.me{border:2px solid #2b6cb0;box-shadow:0 0 0 3px #2b6cb033}
.src{font-size:13px;opacity:.7}
</style></head><body>
<h1>Приложения для VPN</h1>
<p>Официальные сборки Amnezia и Happ без изменений. Для проверки целостности сравните SHA256 скачанного файла с файлом SHA256SUMS.</p>
<p>Подходящий вашему устройству вариант выделен рамкой. <b>iPhone / iPad:</b> файл приложения для iOS с этой страницы не раздаётся, приложение ставится из App Store (подробности на вашей личной странице).</p>
$sections
<script>
(function(){var u=navigator.userAgent||"",p=navigator.platform||"",id="";
if(/Android/.test(u))id="android";else if(/Windows/.test(u))id="windows";else if(/iPhone|iPad|iPod/.test(u))id="ios";
else if(/Mac/.test(p)||/Mac/.test(u))id="mac";else if(/Linux|X11/.test(u))id="linux";
document.querySelectorAll('.item[data-os="'+id+'"]').forEach(function(e){e.className+=" me";});})();
</script>
</body></html>
HTML
chmod a+r "$APPS_DIR/index.html"
echo "Готово: $APPS_DIR"
