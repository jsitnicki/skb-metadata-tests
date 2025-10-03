#!/usr/bin/env bash

BPFFS_DIR=
INIT_NETNS=
TEST_NETNS=

set_up_before_script()
{
    BPFFS_DIR=$(mktemp -d -p /sys/fs/bpf bashunit_XXXXXX)
    assert_is_directory $BPFFS_DIR

    $BPFTOOL prog loadall progs.bpf.o $BPFFS_DIR
}

tear_down_after_script()
{
    rm -r $BPFFS_DIR
}

set_up() {
    local old_netns=$(readlink /proc/self/ns/net)

    # Pin current netns
    INIT_NETNS=$(temp_file)
    mount --bind /proc/self/ns/net "$INIT_NETNS"

    # Create and enter test netns
    TEST_NETNS=$(temp_file)
    unshare --net="$TEST_NETNS" ip link set dev lo up
    cd "$TEST_NETNS" # 'cd' is overloaded to call setns(2)

    local new_netns=$(readlink /proc/self/ns/net)
    assert_not_same "$old_netns" "$new_netns"

    sysctl -w net.ipv4.conf.lo.log_martians=1
}

tear_down() {
    local old_netns=$(readlink /proc/self/ns/net)

    # Unpin test netns
    umount "$TEST_NETNS"

    # Return to initial netns and unpin it
    cd "$INIT_NETNS"
    umount "$INIT_NETNS"

    local new_netns=$(readlink /proc/self/ns/net)
    assert_not_same "$old_netns" "$new_netns"
}

clear_trace() {
    local prog="$1"

    $BPFTOOL prog tracelog stdout pinned $prog > /dev/null
    $BPFTOOL prog tracelog stderr pinned $prog 2> /dev/null
}

check_trace() {
    local prog="$1"
    local want_file="$2"
    local have_file=$(mktemp)

    $BPFTOOL prog tracelog stdout pinned $prog > $have_file
    assert_files_equals $want_file $have_file
    xxd -c 40 $have_file

    rm $have_file
}

check_error() {
    assert_exec "$BPFTOOL prog tracelog stderr pinned $1" --stderr ""
}

# Run UDP packet through a TCX ingress program, verify metadata, drop packet
drop_test() {
    local dst_addr="127.0.0.1"
    if [[ "$1" == "-6" ]]; then
        dst_addr="::1"
        shift
    fi

    local tcx_prog="$1"

    set_test_title "$FUNCNAME: $tcx_prog"

    $BPFTOOL net attach xdpgeneric  pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/$tcx_prog dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_dump_meta_1 dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_drop dev lo

    clear_trace $BPFFS_DIR/tcx_dump_meta_1
    echo > "/dev/udp/${dst_addr}/0"
    check_trace $BPFFS_DIR/tcx_dump_meta_1 want_meta.txt

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/$tcx_prog
    check_error $BPFFS_DIR/tcx_dump_meta_1
    check_error $BPFFS_DIR/tcx_drop
}

test_tcx_grow_room_1b() {
    drop_test $FUNCNAME
}

# expands head
test_tcx_grow_room_256b() {
    drop_test $FUNCNAME
}

test_tcx_shrink_room_1b() {
    drop_test $FUNCNAME
}

test_tcx_change_head_1b() {
    drop_test $FUNCNAME
}

test_tcx_change_proto_to_6() {
    drop_test $FUNCNAME
}

test_tcx_change_proto_to_4() {
    drop_test -6 $FUNCNAME
}

# expands head
test_tcx_change_tail() {
    drop_test $FUNCNAME
}

test_tcx_vlan_push_x2() {
    drop_test $FUNCNAME
}

test_tcx_vlan_push_x2_pop() {
    drop_test $FUNCNAME
}

ping_test() {
    local push_prog="$1"
    local pull_prog="$2"

    set_test_title "$FUNCNAME: $push_prog/$pull_prog"

    $BPFTOOL net attach xdpgeneric  pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/$push_prog dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_dump_meta_1 dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/$pull_prog dev lo
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_dump_meta_2 dev lo

    clear_trace $BPFFS_DIR/tcx_dump_meta_1
    clear_trace $BPFFS_DIR/tcx_dump_meta_2

    ping -c 1 -w 1 127.0.0.1
    assert_successful_code

    check_trace $BPFFS_DIR/tcx_dump_meta_1 want_meta_x2.txt
    check_trace $BPFFS_DIR/tcx_dump_meta_2 want_meta_x2.txt

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/$push_prog
    check_error $BPFFS_DIR/tcx_dump_meta_1
    check_error $BPFFS_DIR/$pull_prog
    check_error $BPFFS_DIR/tcx_dump_meta_2
}

test_ping_nop() {
    ping_test tcx_next_1 tcx_next_2
}

test_ping_adjust_room_1b() {
    ping_test test_tcx_grow_room_1b test_tcx_shrink_room_1b
}

test_ping_vlan() {
    ping_test test_tcx_vlan_push_x2 test_tcx_vlan_pop_x2
}

test_ping_change_proto() {
    skip "echo request dropped due to martian destination, why?" && return
    ping_test test_tcx_change_proto_to_6 test_tcx_change_proto_to_4
}
