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

decap_vlan_test() {
    local fill_prog="$BPFFS_DIR/xdp_fill_meta_and_pass"
    local dump1_prog="$1"
    local dump2_prog="$2"
    local push_prog="$3"
    local pull_prog="$4"

    # VLAN setup
    local peer_netns="ns_$(random_str 3)"

    ip netns add $peer_netns
    trap "trap - RETURN; ip netns del $peer_netns" RETURN

    sysctl -q net.ipv6.conf.all.disable_ipv6=1
    ip netns exec $peer_netns sysctl -q net.ipv6.conf.all.disable_ipv6=1

    ip link add name veth0 address 02:00:00:00:00:01 type veth \
       peer name veth1 address 02:00:00:00:00:02 netns $peer_netns

    ethtool -K veth0 rx-vlan-hw-parse off
    ethtool -K veth0 tx-vlan-hw-insert off

    ip netns exec $peer_netns ethtool -K veth1 rx-vlan-hw-parse off
    ip netns exec $peer_netns ethtool -K veth1 tx-vlan-hw-insert off

    ip link set dev veth0 up
    ip link add name vlan0 link veth0 type vlan id 42
    ip addr add 10.0.0.1/24 dev vlan0
    ip link set dev vlan0 up
    ip neigh add 10.0.0.2 lladdr 02:00:00:00:00:02 nud permanent dev vlan0

    ip -n $peer_netns link set dev veth1 up
    ip -n $peer_netns link add name vlan1 link veth1 type vlan id 42
    ip -n $peer_netns addr add 10.0.0.2/24 dev vlan1
    ip -n $peer_netns link set dev vlan1 up
    ip -n $peer_netns neigh add 10.0.0.1 lladdr 02:00:00:00:00:01 nud permanent dev vlan1

    # BPF setup
    $BPFTOOL net attach xdpgeneric  pinned $fill_prog dev veth0
    [[ "$push_prog"  ]] && $BPFTOOL net attach tcx_ingress pinned $push_prog  dev vlan0
    $BPFTOOL net attach tcx_ingress pinned $dump1_prog dev vlan0
    [[ "$pull_prog"  ]] && $BPFTOOL net attach tcx_ingress pinned $pull_prog  dev vlan0
    [[ "$dump2_prog" ]] && $BPFTOOL net attach tcx_ingress pinned $dump2_prog dev vlan0

    clear_trace $fill_prog
    [[ "$push_prog" ]] && clear_trace $push_prog
    clear_trace $dump1_prog
    [[ "$pull_prog" ]] && clear_trace $pull_prog
    [[ "$dump2_prog" ]] && clear_trace $dump2_prog

    # Test
    ip netns exec $peer_netns ping -c 1 -w 1 10.0.0.1
    assert_successful_code

    check_error $fill_prog
    [[ "$push_prog" ]] && check_error $push_prog
    check_error $dump1_prog
    [[ "$pull_prog" ]] && check_error $pull_prog
    [[ "$dump2_prog" ]] && check_error $dump2_prog

    check_trace $dump1_prog want_meta.txt
    [[ "$dump2_prog" ]] && check_trace $dump2_prog want_meta.txt

    return 0 # mask the error from last [[ ]] test
}

test_decap_vlan_dynptr()
{
    set_test_title $FUNCNAME
    decap_vlan_test $BPFFS_DIR/tcx_dump_meta_1
}

test_decap_vlan_pktptr()
{
    set_test_title $FUNCNAME
    decap_vlan_test $BPFFS_DIR/tcx_dump_meta_pktptr
}

test_decap_vlan_adjust_room_1b()
{
    set_test_title $FUNCNAME
    decap_vlan_test \
        $BPFFS_DIR/tcx_dump_meta_1 \
        $BPFFS_DIR/tcx_dump_meta_2 \
        $BPFFS_DIR/test_tcx_grow_room_1b \
        $BPFFS_DIR/test_tcx_shrink_room_1b
}

test_decap_qinq() {
    set_test_title $FUNCNAME

    # VLAN setup
    local peer_netns="ns_$(random_str 3)"

    ip netns add $peer_netns
    trap "trap - RETURN; ip netns del $peer_netns" RETURN

    sysctl -q net.ipv6.conf.all.disable_ipv6=1
    ip netns exec $peer_netns sysctl -q net.ipv6.conf.all.disable_ipv6=1

    ip link add name veth0 address 02:00:00:00:00:01 type veth \
       peer name veth1 address 02:00:00:00:00:02 netns $peer_netns

    ethtool -K veth0 rx-vlan-hw-parse off
    ethtool -K veth0 tx-vlan-hw-insert off
    ethtool -K veth0 rx-vlan-stag-hw-parse off
    ethtool -K veth0 tx-vlan-stag-hw-insert off

    ip netns exec $peer_netns ethtool -K veth1 rx-vlan-hw-parse off
    ip netns exec $peer_netns ethtool -K veth1 tx-vlan-hw-insert off
    ip netns exec $peer_netns ethtool -K veth1 rx-vlan-stag-hw-parse off
    ip netns exec $peer_netns ethtool -K veth1 tx-vlan-stag-hw-insert off

    ip link set dev veth0 up
    ip -n $peer_netns link set dev veth1 up

    ip link add name vlan00 link veth0 type vlan proto 802.1ad id 100
    ip link set dev vlan00 up
    ip link add name vlan0 link vlan00 type vlan proto 802.1q id 200
    ip link set dev vlan0 up

    ip addr add 10.0.0.1/24 dev vlan0
    ip neigh add 10.0.0.2 lladdr 02:00:00:00:00:02 nud permanent dev vlan0

    ip -n $peer_netns link add name vlan11 link veth1 type vlan proto 802.1ad id 100
    ip -n $peer_netns link set dev vlan11 up
    ip -n $peer_netns link add name vlan1 link vlan11 type vlan proto 802.1q id 200
    ip -n $peer_netns link set dev vlan1 up

    ip -n $peer_netns addr add 10.0.0.2/24 dev vlan1
    ip -n $peer_netns neigh add 10.0.0.1 lladdr 02:00:00:00:00:01 nud permanent dev vlan1

    # BPF setup
    $BPFTOOL net attach xdpgeneric  pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev veth0
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_dump_meta_1 dev vlan0

    clear_trace $BPFFS_DIR/xdp_fill_meta_and_pass
    clear_trace $BPFFS_DIR/tcx_dump_meta_1

    # Test
    ip netns exec $peer_netns ping -c 1 -w 1 10.0.0.1
    assert_successful_code

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/tcx_dump_meta_1

    check_trace $BPFFS_DIR/tcx_dump_meta_1 want_meta.txt
}

test_decap_mpls() {
    set_test_title $FUNCNAME

    # veth setup
    local peer_netns="ns_$(random_str 3)"

    ip netns add $peer_netns
    trap "trap - RETURN; ip netns del $peer_netns" RETURN

    sysctl -q net.ipv6.conf.all.disable_ipv6=1
    ip netns exec $peer_netns sysctl -q net.ipv6.conf.all.disable_ipv6=1

    ip link add name veth0 address 02:00:00:00:00:01 type veth \
       peer name veth1 address 02:00:00:00:00:02 netns $peer_netns

    ip link set dev veth0 up
    ip -n $peer_netns link set dev veth1 up
    ip -n $peer_netns link set dev lo up

    ip addr add 10.0.0.1/24 dev veth0
    ip neigh add 10.0.0.2 lladdr 02:00:00:00:00:02 nud permanent dev veth0

    ip -n $peer_netns addr add 10.0.0.2/24 dev veth1
    ip -n $peer_netns neigh add 10.0.0.1 lladdr 02:00:00:00:00:01 nud permanent dev veth1

    # MPLS setup
    sysctl -w net.mpls.platform_labels=65535
    sysctl -w net.mpls.conf.veth0.input=1

    ip netns exec $peer_netns sysctl -w net.mpls.platform_labels=65535
    ip netns exec $peer_netns sysctl -w net.mpls.conf.veth1.input=1

    ip                route change 10.0.0.0/24 encap mpls 100 via 10.0.0.2
    ip -n $peer_netns route change 10.0.0.0/24 encap mpls 100 via 10.0.0.1

    ip                -f mpls route add 100 dev lo
    ip -n $peer_netns -f mpls route add 100 dev lo

    # BPF setup
    $BPFTOOL net attach xdpgeneric  pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev veth0
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_dump_meta_1 dev lo

    clear_trace $BPFFS_DIR/xdp_fill_meta_and_pass
    clear_trace $BPFFS_DIR/tcx_dump_meta_1

    # Test
    ip netns exec $peer_netns ping -c 1 -w 1 10.0.0.1
    assert_successful_code

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/tcx_dump_meta_1

    check_trace $BPFFS_DIR/tcx_dump_meta_1 want_meta.txt
}

test_decap_gre4() {
    set_test_title $FUNCNAME

    # netns setup
    local peer_netns="ns_$(random_str 3)"
    local nsA=
    local nsB="-n ${peer_netns}"
    local inA=
    local inB="ip netns exec ${peer_netns}"

    ip netns add $peer_netns
    trap "trap - RETURN; ip netns del $peer_netns" RETURN

    # Tunnel setup
    $inA sysctl -q net.ipv6.conf.all.disable_ipv6=1
    $inB sysctl -q net.ipv6.conf.all.disable_ipv6=1

    ip link add name veth0 address 02:00:00:00:00:01 type veth \
           peer name veth1 address 02:00:00:00:00:02 netns $peer_netns

    ip $nsA link set dev veth0 up
    ip $nsB link set dev veth1 up

    ip $nsA addr add 192.0.2.1/24 dev veth0
    ip $nsB addr add 192.0.2.2/24 dev veth1

    ip $nsA neigh add 192.0.2.2 lladdr 02:00:00:00:00:02 nud permanent dev veth0
    ip $nsB neigh add 192.0.2.1 lladdr 02:00:00:00:00:01 nud permanent dev veth1

    ip $nsA tunnel add tun0 mode gre local 192.0.2.1 remote 192.0.2.2
    ip $nsB tunnel add tun1 mode gre local 192.0.2.2 remote 192.0.2.1

    ip $nsA link set dev tun0 up
    ip $nsB link set dev tun1 up

    ip $nsA addr add 10.0.0.1/24 dev tun0
    ip $nsB addr add 10.0.0.2/24 dev tun1

    ip $nsA neigh add 10.0.0.2 lladdr 02:00:00:00:00:02 nud permanent dev tun0
    ip $nsB neigh add 10.0.0.1 lladdr 02:00:00:00:00:01 nud permanent dev tun1

    # BPF setup
    $BPFTOOL net attach xdpgeneric  pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev veth0
    $BPFTOOL net attach tcx_ingress pinned $BPFFS_DIR/tcx_dump_meta_1        dev tun0

    clear_trace $BPFFS_DIR/xdp_fill_meta_and_pass
    clear_trace $BPFFS_DIR/tcx_dump_meta_1

    # Test
    $inB ping -c 1 -w 1 10.0.0.1
    assert_successful_code

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/tcx_dump_meta_1

    check_trace $BPFFS_DIR/tcx_dump_meta_1 want_meta.txt
}

test_fwd() {
    set_test_title $FUNCNAME

    sysctl -w -q net.ipv6.conf.all.disable_ipv6=1
    sysctl -w -q net.ipv4.conf.all.forwarding=1

    # netns setup
    local nsA="ns_$(random_str 3)"
    local nsB="ns_$(random_str 3)"
    local inA="ip netns exec ${nsA}"
    local inB="ip netns exec ${nsB}"

    ip netns add ${nsA}
    ip netns add ${nsB}

    trap "trap - RETURN; ip netns del $nsA; ip netns del $nsB" RETURN

    $inA sysctl -w -q net.ipv6.conf.all.disable_ipv6=1
    $inB sysctl -w -q net.ipv6.conf.all.disable_ipv6=1

    $inA ip link set dev lo up
    $inB ip link set dev lo up

    # veth setup

    ip link add name toA address 02:00:00:00:10:01 type veth \
       peer name fromA address 02:00:00:00:10:02 netns ${nsA}

    ip link add name toB address 02:00:00:00:11:01 type veth \
       peer name fromB address 02:00:00:00:11:02 netns ${nsB}

    ip link set dev toA up
    ip link set dev toB up

    $inA ip link set dev fromA up
    $inB ip link set dev fromB up

    ip addr add 10.0.10.1/24 dev toA
    ip addr add 10.0.11.1/24 dev toB

    $inA ip addr add 10.0.10.2/24 dev fromA
    $inB ip addr add 10.0.11.2/24 dev fromB

    ip neigh add 10.0.10.2 lladdr 02:00:00:00:10:02 nud permanent dev toA
    ip neigh add 10.0.11.2 lladdr 02:00:00:00:11:02 nud permanent dev toB

    $inA ip neigh add 10.0.10.1 lladdr 02:00:00:00:10:01 nud permanent dev fromA
    $inB ip neigh add 10.0.11.1 lladdr 02:00:00:00:11:01 nud permanent dev fromB

    # routing setup

    $inA ip route add default via 10.0.10.1
    $inB ip route add default via 10.0.11.1

    # bpf setup
    $BPFTOOL net attach xdpgeneric pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev toA
    $BPFTOOL net attach tcx_egress pinned $BPFFS_DIR/tcx_dump_meta_1_egress dev toB

    # ping test
    clear_trace $BPFFS_DIR/xdp_fill_meta_and_pass
    clear_trace $BPFFS_DIR/tcx_dump_meta_1_egress

    $inA ping -c 1 -w 1 10.0.11.2
    assert_successful_code

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/tcx_dump_meta_1_egress

    check_trace $BPFFS_DIR/tcx_dump_meta_1_egress want_meta.txt
}

test_encap_vlan() {
    set_test_title $FUNCNAME

    sysctl -w -q net.ipv6.conf.all.disable_ipv6=1
    sysctl -w -q net.ipv4.conf.all.forwarding=1

    # netns setup
    local nsA="ns_$(random_str 3)"
    local nsB="ns_$(random_str 3)"
    local inA="ip netns exec ${nsA}"
    local inB="ip netns exec ${nsB}"

    ip netns add ${nsA}
    ip netns add ${nsB}

    trap "trap - RETURN; ip netns del $nsA; ip netns del $nsB" RETURN

    $inA sysctl -w -q net.ipv6.conf.all.disable_ipv6=1
    $inB sysctl -w -q net.ipv6.conf.all.disable_ipv6=1

    $inA ip link set dev lo up
    $inB ip link set dev lo up

    # veth setup

    ip link add name toA address 02:00:00:00:10:01 type veth \
       peer name fromA address 02:00:00:00:10:02 netns ${nsA}

    ip link add name toB address 02:00:00:00:11:01 type veth \
       peer name fromB address 02:00:00:00:11:02 netns ${nsB}

    ip link set dev toA up
    ip link set dev toB up

    $inA ip link set dev fromA up
    $inB ip link set dev fromB up

    ip addr add 10.0.10.1/24 dev toA
    ip addr add 10.0.11.1/24 dev toB

    $inA ip addr add 10.0.10.2/24 dev fromA
    $inB ip addr add 10.0.11.2/24 dev fromB

    ip neigh add 10.0.10.2 lladdr 02:00:00:00:10:02 nud permanent dev toA
    ip neigh add 10.0.11.2 lladdr 02:00:00:00:11:02 nud permanent dev toB

    $inA ip neigh add 10.0.10.1 lladdr 02:00:00:00:10:01 nud permanent dev fromA
    $inB ip neigh add 10.0.11.1 lladdr 02:00:00:00:11:01 nud permanent dev fromB

    # routing setup

    $inA ip route add default via 10.0.10.1
    $inB ip route add default via 10.0.11.1

    # vlan setup

    ethtool -K toB rx-vlan-hw-parse off
    ethtool -K toB tx-vlan-hw-insert off

    ip link add name vlan0 link toB type vlan id 42
    ip addr add 192.0.2.1/24 dev vlan0
    ip link set dev vlan0 up

    $inB ip link add name vlan1 link fromB type vlan id 42
    $inB ip addr add 192.0.2.2/24 dev vlan1
    $inB ip link set dev vlan1 up

         ip neigh add 192.0.2.2 lladdr 02:00:00:00:11:02 nud permanent dev vlan0
    $inB ip neigh add 192.0.2.1 lladdr 02:00:00:00:11:01 nud permanent dev vlan1

    # bpf setup
    $BPFTOOL net attach xdpgeneric pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev toA
    $BPFTOOL net attach tcx_egress pinned $BPFFS_DIR/tcx_dump_meta_1_egress dev toB

    # ping test
    clear_trace $BPFFS_DIR/xdp_fill_meta_and_pass
    clear_trace $BPFFS_DIR/tcx_dump_meta_1_egress

    $inA ping -c 1 -w 1 192.0.2.2
    assert_successful_code

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/tcx_dump_meta_1_egress

    check_trace $BPFFS_DIR/tcx_dump_meta_1_egress want_meta.txt
}

test_encap_qinq() {
    set_test_title $FUNCNAME

    sysctl -w -q net.ipv6.conf.all.disable_ipv6=1
    sysctl -w -q net.ipv4.conf.all.forwarding=1

    # netns setup
    local nsA="ns_$(random_str 3)"
    local nsB="ns_$(random_str 3)"
    local inA="ip netns exec ${nsA}"
    local inB="ip netns exec ${nsB}"

    ip netns add ${nsA}
    ip netns add ${nsB}

    trap "trap - RETURN; ip netns del $nsA; ip netns del $nsB" RETURN

    $inA sysctl -w -q net.ipv6.conf.all.disable_ipv6=1
    $inB sysctl -w -q net.ipv6.conf.all.disable_ipv6=1

    $inA ip link set dev lo up
    $inB ip link set dev lo up

    # veth setup

    ip link add name toA address 02:00:00:00:10:01 type veth \
       peer name fromA address 02:00:00:00:10:02 netns ${nsA}

    ip link add name toB address 02:00:00:00:11:01 type veth \
       peer name fromB address 02:00:00:00:11:02 netns ${nsB}

    ip link set dev toA up
    ip link set dev toB up

    $inA ip link set dev fromA up
    $inB ip link set dev fromB up

    ip addr add 10.0.10.1/24 dev toA
    ip addr add 10.0.11.1/24 dev toB

    $inA ip addr add 10.0.10.2/24 dev fromA
    $inB ip addr add 10.0.11.2/24 dev fromB

    ip neigh add 10.0.10.2 lladdr 02:00:00:00:10:02 nud permanent dev toA
    ip neigh add 10.0.11.2 lladdr 02:00:00:00:11:02 nud permanent dev toB

    $inA ip neigh add 10.0.10.1 lladdr 02:00:00:00:10:01 nud permanent dev fromA
    $inB ip neigh add 10.0.11.1 lladdr 02:00:00:00:11:01 nud permanent dev fromB

    # routing setup

    $inA ip route add default via 10.0.10.1
    $inB ip route add default via 10.0.11.1

    # qinq setup

    ethtool -K toB rx-vlan-hw-parse off
    ethtool -K toB tx-vlan-hw-insert off
    ethtool -K toB rx-vlan-stag-hw-parse off
    ethtool -K toB tx-vlan-stag-hw-insert off

    ip link add name vlan00 link toB type vlan proto 802.1ad id 100
    ip link set dev vlan00 up

    $inB ip link add name vlan11 link fromB type vlan proto 802.1ad id 100
    $inB ip link set dev vlan11 up

    ip link add name vlan0 link vlan00 type vlan id 42
    ip addr add 192.0.2.1/24 dev vlan0
    ip link set dev vlan0 up

    $inB ip link add name vlan1 link vlan11 type vlan id 42
    $inB ip addr add 192.0.2.2/24 dev vlan1
    $inB ip link set dev vlan1 up

         ip neigh add 192.0.2.2 lladdr 02:00:00:00:11:02 nud permanent dev vlan0
    $inB ip neigh add 192.0.2.1 lladdr 02:00:00:00:11:01 nud permanent dev vlan1

    # bpf setup
    $BPFTOOL net attach xdpgeneric pinned $BPFFS_DIR/xdp_fill_meta_and_pass dev toA
    $BPFTOOL net attach tcx_egress pinned $BPFFS_DIR/tcx_dump_meta_1_egress dev toB

    # ping test
    clear_trace $BPFFS_DIR/xdp_fill_meta_and_pass
    clear_trace $BPFFS_DIR/tcx_dump_meta_1_egress

    $inA ping -c 1 -w 1 192.0.2.2
    assert_successful_code

    check_error $BPFFS_DIR/xdp_fill_meta_and_pass
    check_error $BPFFS_DIR/tcx_dump_meta_1_egress

    check_trace $BPFFS_DIR/tcx_dump_meta_1_egress want_meta.txt
}
