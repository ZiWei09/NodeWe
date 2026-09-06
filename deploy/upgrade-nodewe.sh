#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--install-root DIR] [--service NAME] RELEASE_DIR\n' "$0" >&2
  printf '       %s [--install-root DIR] [--service NAME] --rollback\n' "$0" >&2
  exit 2
}

install_root=/opt/nodewe
service_name=nodewe-control-plane
release_dir=
rollback=0
while (($#)); do
  case "$1" in
    --install-root)
      [[ $# -ge 2 ]] || usage
      install_root=$2
      shift 2
      ;;
    --service)
      [[ $# -ge 2 ]] || usage
      service_name=$2
      shift 2
      ;;
    --rollback)
      rollback=1
      shift
      ;;
    -*|'') usage ;;
    *)
      [[ -z "$release_dir" ]] || usage
      release_dir=$1
      shift
      ;;
  esac
done

current_link=$install_root/current
previous_link=$install_root/previous
next_link=$install_root/.current.next.$$

atomic_replace() {
  local source=$1
  local target=$2
  # GNU coreutils supports replacing an existing symlink without following
  # it. BSD/macOS mv lacks -T, so use the POSIX rename(2) syscall via the
  # system Perl runtime instead of unlinking the live link first.
  if mv -fT "$source" "$target" 2>/dev/null; then
    return 0
  fi
  command -v perl >/dev/null 2>&1 || {
    printf 'NodeWe upgrade requires mv -T or a Perl runtime for atomic symlink replacement\n' >&2
    exit 1
  }
  perl -e 'rename($ARGV[0], $ARGV[1]) or die "$!\n"' "$source" "$target"
}

if ((rollback)); then
  [[ -L "$previous_link" ]] || {
    printf 'NodeWe rollback unavailable: %s is not a symlink\n' "$previous_link" >&2
    exit 1
  }
  previous_target=$(readlink "$previous_link")
  [[ -d "$previous_target" ]] || {
    printf 'NodeWe rollback target is missing: %s\n' "$previous_target" >&2
    exit 1
  }
  old_target=
  if [[ -L "$current_link" ]]; then
    old_target=$(readlink "$current_link")
  fi
  ln -s "$previous_target" "$next_link"
  atomic_replace "$next_link" "$current_link"
  if [[ -n "$old_target" ]]; then
    ln -s "$old_target" "$previous_link.$$.tmp"
    atomic_replace "$previous_link.$$.tmp" "$previous_link"
  fi
else
  [[ -n "$release_dir" && -d "$release_dir" ]] || usage
  release_dir=$(cd "$release_dir" && pwd)
  [[ -f "$release_dir/SHA256SUMS" ]] || {
    printf 'NodeWe release is missing SHA256SUMS: %s\n' "$release_dir" >&2
    exit 1
  }
  for binary in nodewe node-runtime node-control-plane; do
    [[ -x "$release_dir/$binary" ]] || {
      printf 'NodeWe release is missing executable: %s\n' "$release_dir/$binary" >&2
      exit 1
    }
  done
  (cd "$release_dir" && shasum -a 256 -c SHA256SUMS)
  mkdir -p "$install_root"
  if [[ -L "$current_link" ]]; then
    current_target=$(readlink "$current_link")
    ln -s "$current_target" "$previous_link.$$.tmp"
    atomic_replace "$previous_link.$$.tmp" "$previous_link"
  fi
  ln -s "$release_dir" "$next_link"
  atomic_replace "$next_link" "$current_link"
fi

if [[ "${NODEWE_SKIP_RESTART:-0}" != 1 ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl restart "$service_name"
fi
printf 'NodeWe deployment now points to %s\n' "$(readlink "$current_link")"
