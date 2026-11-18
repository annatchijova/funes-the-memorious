#!/bin/sh
set -eu

: "${QNX_CONTRACT_LOG:?QNX_CONTRACT_LOG is required}"
printf '%s\n' "$@" >"$QNX_CONTRACT_LOG"

# The contract harness supplies a target-style -V flag. Strip it before
# delegating to the host compiler; the resulting binary remains host-only.
case "${1-}" in
    -V*) shift
        ;;
esac
exec "${HOST_CC:-cc}" "$@"
