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

for t in curl jq sha256sum python3; do
  command -v "$t" >/dev/null || { echo "Нужна утилита: $t (apt-get install -y curl jq coreutils python3)"; exit 1; }
done

mkdir -p "$APPS_DIR"

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

done

python3 "$(dirname -- "${BASH_SOURCE[0]}")/render-apps.py" "$APPS_DIR" $REPOS
echo "Готово: $APPS_DIR"
