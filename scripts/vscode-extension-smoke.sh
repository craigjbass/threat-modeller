#!/usr/bin/env bash
# Builds and tests the VS Code extension the way the release workflow does.
#
# The extension's own test suite starts a VS Code, loads the extension into
# it, and states the file associations, the setting, the commands and the
# language client. Run it on any machine:
#
#     scripts/vscode-extension-smoke.sh
#
# The suite needs a display. macOS gives one. On Linux the script runs the
# tests under xvfb-run, which the runner installs.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/vscode"

npm ci
npm run compile

if [ "$(uname)" = "Linux" ] && [ -z "${DISPLAY:-}" ]; then
    if command -v xvfb-run > /dev/null 2>&1; then
        xvfb-run -a npm test
    else
        echo "the tests need a display: install xvfb, or set DISPLAY" >&2
        exit 1
    fi
else
    npm test
fi
