#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

STAGE="all"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stage)
      STAGE="${2:-}"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--stage smoke|more|all]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

PYTHON_BIN="${PYTHON_BIN:-python3}"
JUNIT_DIR="${JUNIT_DIR:-}"

run_tier() {
  tier="$1"
  echo "==> Running pytest tier: $tier"
  if [ -n "$JUNIT_DIR" ]; then
    mkdir -p "$JUNIT_DIR"
    "$PYTHON_BIN" -m pytest -m "$tier" --junitxml="$JUNIT_DIR/junit-$tier.xml"
  else
    "$PYTHON_BIN" -m pytest -m "$tier"
  fi
}

case "$STAGE" in
  smoke)
    run_tier smoke
    ;;
  more)
    run_tier unit
    run_tier integration
    run_tier security
    ;;
  all)
    run_tier smoke
    run_tier unit
    run_tier integration
    run_tier security
    ;;
  *)
    echo "Invalid --stage '$STAGE' (expected: smoke, more, all)" >&2
    exit 2
    ;;
esac
