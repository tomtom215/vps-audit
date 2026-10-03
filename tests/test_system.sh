#!/usr/bin/env bash
# shellcheck shell=bash
#
# System-detection primitives and the regressions found by running the audit
# on real hosts: service-manager detection, symlink-aware permission reads,
# PATH inspection, local-mount enumeration.

# --- portable_stat -----------------------------------------------------------

# Regression: `stat -c %a` on a symlink reports the link's own mode (777).
# On merged-/usr systems /bin and /sbin are symlinks, so the PATH check
# reported "world-writable directory in PATH: /sbin (777)" on every host.
test_portable_stat_follows_symlinks() {
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/real" && chmod 700 "$d/real"
    ln -s "$d/real" "$d/link"
    detect_tool_versions
    assert_eq 700 "$(portable_stat mode "$d/link")" "mode of the symlink target" || return 1
    rm -rf "$d"
}

test_portable_stat_reports_owner_and_size() {
    local d
    d="$(make_tmp)" || return 1
    printf 'abc' >"$d/f" && chmod 640 "$d/f"
    detect_tool_versions
    assert_eq 640 "$(portable_stat mode "$d/f")" || return 1
    assert_eq 3 "$(portable_stat size "$d/f")" || return 1
    assert_eq "$(id -u)" "$(portable_stat uid "$d/f")" || return 1
    rm -rf "$d"
}

test_portable_stat_missing_file_fails() {
    detect_tool_versions
    portable_stat mode /nonexistent/definitely/not/here >/dev/null && return 1
    return 0
}

# --- PATH security -----------------------------------------------------------

test_path_check_passes_for_symlinked_system_dirs() {
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/usr-bin" && chmod 755 "$d/usr-bin"
    ln -s "$d/usr-bin" "$d/bin"
    detect_tool_versions
    ORIGINAL_PATH="$d/bin"
    PATH="$d/bin:$PATH"
    record_checks
    check_path_security
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
    rm -rf "$d"
}

test_path_check_flags_world_writable_dir() {
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/evil" && chmod 777 "$d/evil"
    detect_tool_versions
    ORIGINAL_PATH="$d/evil:/usr/bin"
    record_checks
    check_path_security
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "$d/evil" || return 1
    rm -rf "$d"
}

test_path_check_flags_current_directory() {
    detect_tool_versions
    ORIGINAL_PATH="/usr/bin::/bin"
    record_checks
    check_path_security
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

# The script prepends system directories to its own PATH. The check must
# inspect the PATH the user invoked it with, not the one it rewrote.
test_path_check_ignores_script_hardening() {
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/evil" && chmod 777 "$d/evil"
    detect_tool_versions
    ORIGINAL_PATH="/usr/bin:/bin"
    PATH="$d/evil:$PATH"
    record_checks
    check_path_security
    assert_eq PASS "$RESULT_STATUS" "only ORIGINAL_PATH is inspected" || return 1
    rm -rf "$d"
}

# --- service manager ---------------------------------------------------------

# Regression: containers and WSL ship a working `systemctl --version` without
# systemd being PID 1. detect_os then chose "systemd", `systemctl list-units`
# failed, and the audit reported "Running 0 services - minimal attack
# surface" as a PASS.
test_detect_os_requires_systemd_to_be_running() {
    local d
    d="$(make_tmp)" || return 1
    SYSTEMD_RUNTIME_DIR="$d/does-not-exist"
    hide_system_commands
    stub systemctl 'return 0'
    detect_os
    assert_ne systemd "${OS_INFO[service_manager]}" "systemctl exists but systemd is not running" || return 1
}

test_detect_os_accepts_running_systemd() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/system"
    SYSTEMD_RUNTIME_DIR="$d/system"
    hide_system_commands
    stub systemctl 'return 0'
    detect_os
    assert_eq systemd "${OS_INFO[service_manager]}" || return 1
}

test_running_services_count_failure_is_not_zero() {
    OS_INFO[service_manager]=systemd
    hide_system_commands
    stub systemctl 'return 1'
    local out rc=0
    out="$(get_running_services_count)" || rc=$?
    assert_ne 0 "$rc" "a failing systemctl must be reported as 'unknown', not 0" || return 1
}

test_running_services_check_warns_when_unknown() {
    OS_INFO[service_manager]=systemd
    hide_system_commands
    stub systemctl 'return 1'
    record_checks
    check_running_services
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
}


# --- local mounts ------------------------------------------------------------

# Regression: `find / -xdev` only scans the root filesystem, so SUID files on a
# separate /home, /var or /opt partition were never examined.
mounts_fixture() {
    cat >"$1" <<'EOF'
/dev/vda1 / ext4 rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
tmpfs /tmp tmpfs rw,relatime 0 0
/dev/vda2 /home xfs rw,relatime 0 0
/dev/vdb1 /var/lib/data btrfs rw,relatime 0 0
/dev/vdb2 /srv ext4 rw,nosuid,relatime 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw,relatime 0 0
10.0.0.5:/export /mnt/nfs nfs4 rw,relatime 0 0
/dev/vdc1 /mnt/usb\040drive ext4 rw,relatime 0 0
EOF
}

test_list_local_mountpoints_default_is_disk_backed_only() {
    local d
    d="$(make_tmp)" || return 1
    mounts_fixture "$d/mounts"
    PROC_MOUNTS="$d/mounts"
    assert_eq "/ /home /var/lib/data /srv /mnt/usb drive " "$(list_local_mountpoints | tr '\n' ' ')" || return 1
    rm -rf "$d"
}

test_list_local_mountpoints_suid_mode() {
    local d
    d="$(make_tmp)" || return 1
    mounts_fixture "$d/mounts"
    PROC_MOUNTS="$d/mounts"
    # nosuid mounts cannot hold effective SUID files; tmpfs without nosuid can.
    assert_eq "/ /tmp /home /var/lib/data /mnt/usb drive " "$(list_local_mountpoints suid | tr '\n' ' ')" || return 1
    rm -rf "$d"
}

# A container's root filesystem is an overlay; it must still be scanned.
test_list_local_mountpoints_always_includes_root() {
    local d
    d="$(make_tmp)" || return 1
    printf 'overlay / overlay rw,relatime 0 0\nproc /proc proc rw 0 0\n' >"$d/mounts"
    PROC_MOUNTS="$d/mounts"
    assert_eq "/ " "$(list_local_mountpoints | tr '\n' ' ')" || return 1
    rm -rf "$d"
}

test_list_local_mountpoints_deduplicates_stacked_mounts() {
    local d
    d="$(make_tmp)" || return 1
    printf '/dev/vda1 / ext4 rw 0 0\n/dev/vda2 /data ext4 rw 0 0\n/dev/vda3 /data ext4 rw 0 0\n' >"$d/mounts"
    PROC_MOUNTS="$d/mounts"
    assert_eq "/ /data " "$(list_local_mountpoints | tr '\n' ' ')" || return 1
    rm -rf "$d"
}

# --- container storage -------------------------------------------------------

test_container_storage_includes_default_roots() {
    hide_system_commands
    load_container_storage_paths
    local joined=" ${CONTAINER_STORAGE_PATHS[*]} "
    assert_contains "$joined" " /var/lib/docker " || return 1
    assert_contains "$joined" " /var/lib/containerd " || return 1
}

# Docker's data root can be moved; the scan must follow it or the moved image
# layers flood the SUID results again.
test_container_storage_follows_custom_docker_root() {
    hide_system_commands
    stub_bin docker 'echo /srv/docker-data'
    load_container_storage_paths
    assert_contains " ${CONTAINER_STORAGE_PATHS[*]} " " /srv/docker-data " || return 1
}

test_find_in_mount_skips_container_storage() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/real" "$d/layers/root/usr/bin"
    : >"$d/real/suid" && chmod 4755 "$d/real/suid"
    : >"$d/layers/root/usr/bin/suid" && chmod 4755 "$d/layers/root/usr/bin/suid"
    hide_system_commands
    stub_bin docker "echo $d/layers"
    local found
    found="$(find_in_mount "$d" -type f -perm -4000 -print)"
    assert_eq "$d/real/suid" "$found" "only the file outside container storage" || return 1
}

# A count of 0 on a booted server is not "minimal attack surface": it means the
# service manager is not reporting (container, unsupported init). Found by the
# distro matrix, where `service --status-all` listed nothing.
test_running_services_zero_is_unknown_not_healthy() {
    get_running_services_count() { echo 0; }
    OS_INFO[service_manager]=sysv
    record_checks
    check_running_services
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_not_contains "$RESULT_MSG" "minimal attack surface" || return 1
}

test_running_services_normal_count_passes() {
    get_running_services_count() { echo 12; }
    record_checks
    check_running_services
    assert_eq PASS "$RESULT_STATUS" || return 1
}
