#!/usr/bin/env bash
# Скачивает последние ОФИЦИАЛЬНЫЕ релизы клиентов Amnezia с GitHub в каталог раздачи,
# проверяет SHA256 (если GitHub отдаёт digest), пишет SHA256SUMS и обновляет /apps/index.html.
# Файлы не изменяются и не пересобираются. Запускайте вручную, когда хотите обновить приложения:
# автоматическое скачивание без проверки на сервере, раздающем файлы сотрудникам, не настроено намеренно.
#
#   sudo ./scripts/fetch-apps.sh
#   REPOS="amnezia-vpn/amnezia-client другой/репозиторий" sudo ./scripts/fetch-apps.sh
set -euo pipefail

APPS_DIR="${APPS_DIR:-/var/www/vpn/apps}"
REPOS="${REPOS:-amnezia-vpn/amnezia-client}"
PATTERN='\.(exe|msi|dmg|pkg|apk|deb|rpm|AppImage|zip|tar\.(gz|zst|xz))$'

for t in curl jq sha256sum; do
  command -v "$t" >/dev/null || { echo "Нужна утилита: $t (apt-get install -y curl jq coreutils)"; exit 1; }
done

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
    rows+="<tr><td><a href=\"$name/$(printf '%s' "$fn" | esc)\">$(printf '%s' "$fn" | esc)</a></td><td>$size</td><td><code>${sum:0:16}…</code></td></tr>"
  done < "$dest/SHA256SUMS"
  sections+="<h2>$(printf '%s' "$name" | esc) $(printf '%s' "$tag" | esc)</h2><table><tr><th>Файл</th><th>Размер</th><th>SHA256</th></tr>$rows</table><p><a href=\"$name/SHA256SUMS\">SHA256SUMS</a> · <a href=\"$name/SOURCE.txt\">источник</a></p>"
done

cat > "$APPS_DIR/index.html" <<HTML
<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>Приложения для VPN</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:16px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #8884;padding:8px;text-align:left}
code{font-size:13px}
</style></head><body>
<h1>Приложения для VPN</h1>
<p>Официальные сборки Amnezia без изменений. Для проверки целостности сравните SHA256 скачанного файла с файлом SHA256SUMS.</p>
<p><b>iPhone / iPad:</b> файл приложения для iOS с этой страницы не раздаётся, приложение ставится из App Store (подробности на вашей личной странице).</p>
$sections
</body></html>
HTML
chmod a+r "$APPS_DIR/index.html"
echo "Готово: $APPS_DIR"
