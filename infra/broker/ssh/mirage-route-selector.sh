#!/bin/sh
# Step 8b/8c SSH broker (Appendix H.2): "A backend selector (ForceCommand)
# calls /route before the server channel opens."
#
# Runs as a linuxserver/openssh-server custom-cont-init.d script (executes
# once at container start, before sshd starts) — installs the actual
# ForceCommand target this file's sibling, mirage-route-select, and points
# sshd_config at it.
set -e

# The bastion's onward key lives in a dedicated /mirage-broker-keys mount, NOT
# under /config. Two reasons, both observed: linuxserver's init chowns /config
# recursively and a read-only bind mount inside it makes that fail, and a key
# bind-mounted from the host keeps the HOST's uid — which the container user can
# only read if PUID/PGID are set to match (the compose files and the integration
# fixture both do). Without that match the ForceCommand dies with
# `Load key "...": Permission denied` and the session is refused by the backend.
#
# Verified empirically: an SSH session's ForceCommand runs with a
# sanitized/reset environment, NOT the container's own `docker run -e`
# variables (the symptom: the exec'd onward ssh call failed with "Bad port
# ''" — MIRAGE_EMPLOYEE_SSH_PORT etc. were empty inside the session even
# though `docker exec` into the same container sees them fine). Persisting
# the values this init script CAN see to a file, then having the selector
# source that file explicitly, is what actually works.
cat > /etc/mirage-broker-env.sh <<ENVEOF
MIRAGE_API_URL="${MIRAGE_API_URL}"
MIRAGE_BROKER_CERT_SERIAL="${MIRAGE_BROKER_CERT_SERIAL}"
MIRAGE_BROKER_PROXY_SECRET="${MIRAGE_BROKER_PROXY_SECRET}"
MIRAGE_SANDBOX_SSH_HOST="${MIRAGE_SANDBOX_SSH_HOST}"
MIRAGE_SANDBOX_SSH_PORT="${MIRAGE_SANDBOX_SSH_PORT}"
MIRAGE_EMPLOYEE_SSH_HOST="${MIRAGE_EMPLOYEE_SSH_HOST}"
MIRAGE_EMPLOYEE_SSH_PORT="${MIRAGE_EMPLOYEE_SSH_PORT}"
ENVEOF
chmod 644 /etc/mirage-broker-env.sh

install -Dm755 /dev/stdin /usr/local/bin/mirage-route-select <<'SELECTOR'
#!/bin/sh
# The real backend-selection logic (Appendix H.2): calls /route with a
# real match_key built from THIS connection's own attributes, then execs a
# NEW, bastion-authenticated ssh session to the chosen backend. The
# client's already-authenticated-to-the-bastion channel becomes that new
# session's stdio — "backend selection before the backend channel opens,"
# not a hijack of an established connection to somewhere else (§6.2).
set -e

. /etc/mirage-broker-env.sh

CLIENT_IP="$(printf '%s' "$SSH_CONNECTION" | cut -d' ' -f1)"
MATCH_KEY="SSH|bastion-1|${CLIENT_IP}|${USER}"

RESPONSE="$(curl -sf \
    -H "X-Mirage-Client-Cert-Serial: ${MIRAGE_BROKER_CERT_SERIAL}" \
    -H "X-Mirage-Proxy-Auth: ${MIRAGE_BROKER_PROXY_SECRET}" \
    -G "${MIRAGE_API_URL}/route" \
    --data-urlencode "match_key=${MATCH_KEY}" \
    --data-urlencode "protocol=SSH")" || {
    echo "mirage-route-select: /route unreachable — failing safe to ENDPOINT" >&2
    RESPONSE='{"upstream":"ENDPOINT"}'
}

UPSTREAM="$(printf '%s' "$RESPONSE" | sed -n 's/.*"upstream":"\([A-Z]*\)".*/\1/p')"
[ -n "$UPSTREAM" ] || UPSTREAM="ENDPOINT"

if [ "$UPSTREAM" = "SANDBOX" ]; then
    BACKEND_HOST="${MIRAGE_SANDBOX_SSH_HOST}"
    BACKEND_PORT="${MIRAGE_SANDBOX_SSH_PORT}"
else
    BACKEND_HOST="${MIRAGE_EMPLOYEE_SSH_HOST}"
    BACKEND_PORT="${MIRAGE_EMPLOYEE_SSH_PORT}"
fi

# ForceCommand replaces whatever command the client actually asked for —
# OpenSSH's own mechanism for recovering it is $SSH_ORIGINAL_COMMAND (set
# only when the client requested a specific command; unset for a plain
# interactive session). Forwarding it here is what makes a one-shot
# command (e.g. a provisioning script, or this file's own test suite)
# behave identically through the broker as connecting directly would,
# while a plain interactive client still gets a real interactive shell on
# the selected backend.
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    exec ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -i /mirage-broker-keys/bastion_backend_key -p "$BACKEND_PORT" \
        "employee01@${BACKEND_HOST}" "$SSH_ORIGINAL_COMMAND"
else
    exec ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -i /mirage-broker-keys/bastion_backend_key -p "$BACKEND_PORT" \
        "employee01@${BACKEND_HOST}"
fi
SELECTOR

# Verified empirically: linuxserver/openssh-server's shipped sshd_config
# has `Include /etc/ssh/sshd_config.d/*.conf` commented OUT, so a drop-in
# file there is silently never read (the symptom: ForceCommand appears to
# do nothing — the client's own requested command runs directly on the
# bastion instead of being redirected). Appending straight to the real,
# active config (/config/sshd/sshd_config — confirmed via the running
# sshd's own -f argument) is what actually takes effect.
echo "ForceCommand /usr/local/bin/mirage-route-select" >> /config/sshd/sshd_config

echo "mirage-route-select installed; ForceCommand configured."
