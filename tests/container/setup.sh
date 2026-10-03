#!/bin/sh
# Install the packages a typical VPS has, inside a container. POSIX sh on
# purpose: Alpine images have no bash until this script installs it.
#
# Exits non-zero if the package install failed; the caller still runs the tests
# so the result shows what degrades without those tools, but marks the leg.

[ -r /etc/os-release ] || { echo "no /etc/os-release" >&2; exit 2; }
# shellcheck disable=SC1091
. /etc/os-release

# Trust an extra CA (networks that intercept TLS). Appending to the system
# bundles works on every family without needing update-ca-* tools, which a
# minimal image may not have installed yet.
if [ -r /extra-ca.crt ]; then
    for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
        /etc/ssl/ca-bundle.pem /etc/ca-certificates/extracted/tls-ca-bundle.pem; do
        [ -e "$bundle" ] && cat /extra-ca.crt >>"$bundle"
    done
fi

case "$ID" in
    ubuntu | debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq &&
            apt-get install -y -qq --no-install-recommends \
                openssh-server iproute2 procps hostname jq nftables iptables ufw \
                sudo findutils ca-certificates
        ;;
    fedora | rocky | almalinux | amzn)
        pm=dnf
        command -v dnf >/dev/null 2>&1 || pm=yum
        "$pm" install -y -q \
            openssh-server iproute procps-ng hostname jq nftables iptables-nft \
            sudo findutils
        ;;
    alpine)
        apk add --no-cache \
            bash coreutils findutils grep gawk sed procps iproute2 openssh \
            jq nftables iptables sudo shadow
        ;;
    arch)
        pacman -Sy --noconfirm --needed \
            openssh iproute2 procps-ng inetutils jq nftables iptables-nft sudo findutils
        ;;
    opensuse-leap | opensuse-tumbleweed | sles)
        zypper -n install -y \
            openssh iproute2 procps hostname jq nftables iptables sudo findutils
        rc=$?
        # 106 = "some repositories were skipped" (an unreachable optional repo);
        # the packages we asked for were installed.
        [ "$rc" -eq 106 ] && rc=0
        exit "$rc"
        ;;
    *)
        echo "unknown distro ID=$ID: installing nothing" >&2
        ;;
esac
