#!/usr/bin/env bash
set -euo pipefail

branch="release"
commit_message="chore: publish rule artifacts"
author_name="github-actions[bot]"
author_email="41898282+github-actions[bot]@users.noreply.github.com"
artifacts_dir=""
repo=""
token=""
remote_url=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts-dir)
      artifacts_dir="$2"
      shift 2
      ;;
    --repo)
      repo="$2"
      shift 2
      ;;
    --token)
      token="$2"
      shift 2
      ;;
    --branch)
      branch="$2"
      shift 2
      ;;
    --remote-url)
      remote_url="$2"
      shift 2
      ;;
    --commit-message)
      commit_message="$2"
      shift 2
      ;;
    --author-name)
      author_name="$2"
      shift 2
      ;;
    --author-email)
      author_email="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$artifacts_dir" ]]; then
  echo "Usage: $0 --artifacts-dir <dir> (--remote-url <url> | --repo <owner/name> --token <token>) [--branch release]" >&2
  exit 1
fi

if [[ -z "$remote_url" ]]; then
  if [[ -z "$repo" || -z "$token" ]]; then
    echo "Either --remote-url or both --repo and --token are required" >&2
    exit 1
  fi
  remote_url="https://x-access-token:${token}@github.com/${repo}.git"
fi

artifacts_dir=$(cd "$artifacts_dir" && pwd)
publish_dir=$(mktemp -d)
current_dir=$(mktemp -d)
probe_dir=$(mktemp -d)

cleanup() {
  rm -rf "$publish_dir" "$current_dir" "$probe_dir"
}
trap cleanup EXIT

shopt -s nullglob
artifact_files=("$artifacts_dir"/*.json "$artifacts_dir"/*.srs)
if [[ ${#artifact_files[@]} -eq 0 ]]; then
  echo "No artifacts found in $artifacts_dir" >&2
  exit 1
fi
cp "${artifact_files[@]}" "$publish_dir/"

if git ls-remote --exit-code --heads "$remote_url" "$branch" >/dev/null 2>&1; then
  git init -q "$probe_dir"
  git -C "$probe_dir" remote add origin "$remote_url"
  git -C "$probe_dir" fetch --depth=1 origin "$branch"
  git -C "$probe_dir" archive FETCH_HEAD | tar -x -C "$current_dir"

  if diff -qr "$publish_dir" "$current_dir" >/dev/null; then
    echo "No release changes to publish"
    exit 0
  fi
fi

git init -q -b "$branch" "$publish_dir"
git -C "$publish_dir" config user.name "$author_name"
git -C "$publish_dir" config user.email "$author_email"
git -C "$publish_dir" add .
git -C "$publish_dir" commit -m "$commit_message"
git -C "$publish_dir" remote add origin "$remote_url"
git -C "$publish_dir" push --force origin HEAD:"$branch"

echo "Published artifacts to $branch"
