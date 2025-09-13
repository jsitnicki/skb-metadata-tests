#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define META_LEN 192

enum {
  BPF_STDOUT = 1,
  BPF_STDERR = 2,
};

#define bpf_print(fmt, ...)	bpf_stream_printk(BPF_STDOUT, fmt, ##__VA_ARGS__)
#define bpf_eprint(fmt, ...)	bpf_stream_printk(BPF_STDERR, fmt, ##__VA_ARGS__)

extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset,
                              void *buffer__opt,
                              __u32 buffer__szk) __weak __ksym;
extern int
bpf_dynptr_from_skb_meta(struct __sk_buff *skb_, __u64 flags,
                         struct bpf_dynptr *ptr__uninit) __weak __ksym;

SEC("xdp")
int xdp_fill_meta_and_pass(struct xdp_md *ctx)
{
	__u8 *meta, *data;
	int ret;

	ret = bpf_xdp_adjust_meta(ctx, -META_LEN);
	if (ret < 0)
		return XDP_ABORTED;

	meta = (typeof(meta))(unsigned long)ctx->data_meta;
	data = (typeof(data))(unsigned long)ctx->data;

	if (meta + META_LEN > data)
		return XDP_ABORTED;

	for (int i = 0; i*16 < META_LEN; i++)
		__builtin_memset(meta + i*16, (i+1)*0x11, 16);

        return XDP_PASS;
}

static int dump_meta(struct __sk_buff *skb) {
        
	struct bpf_dynptr meta;
	__u8 *md;
	int ret;

	ret = bpf_dynptr_from_skb_meta(skb, 0, &meta);
	if (ret)
		return ret;

	md = bpf_dynptr_slice(&meta, 0, NULL, META_LEN);
	if (!md)
                return -ENODATA;

        bpf_print("%pI6\n" "%pI6\n" "%pI6\n" "%pI6\n"
		  "%pI6\n" "%pI6\n" "%pI6\n" "%pI6\n"
		  "%pI6\n" "%pI6\n" "%pI6\n" "%pI6\n",
		  &md[0x00], &md[0x10], &md[0x20], &md[0x30],
		  &md[0x40], &md[0x50], &md[0x60], &md[0x70],
		  &md[0x80], &md[0x90], &md[0xa0], &md[0xb0]);

	return 0;
}

static int tcx_dump_meta(struct __sk_buff *ctx)
{
        int ret;

        ret = dump_meta(ctx);
        if (ret)
                bpf_eprint("error: dump_meta -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_dump_meta_1(struct __sk_buff *ctx)
{
        return tcx_dump_meta(ctx);
}

SEC("tcx/ingress")
int tcx_dump_meta_2(struct __sk_buff *ctx)
{
        return tcx_dump_meta(ctx);
}

SEC("tcx/ingress")
int tcx_drop(struct __sk_buff *ctx [[maybe_unused]])
{
        return TCX_DROP;
}

SEC("tcx/ingress")
int tcx_next_1(struct __sk_buff *ctx [[maybe_unused]])
{
        return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_next_2(struct __sk_buff *ctx [[maybe_unused]])
{
	return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_grow_room_1b(struct __sk_buff *ctx)
{
	int ret;

	ret = bpf_skb_adjust_room(ctx, 1, BPF_ADJ_ROOM_MAC, 0);
	if (ret)
		bpf_eprint("error: bpf_adjust_room -> %d\n", ret);

	return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_grow_room_256b(struct __sk_buff *ctx)
{
        int ret;

        ret = bpf_skb_adjust_room(ctx, 256, BPF_ADJ_ROOM_MAC, 0);
        if (ret)
                bpf_eprint("error: bpf_adjust_room -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_shrink_room_1b(struct __sk_buff *ctx)
{
        int ret;

        ret = bpf_skb_adjust_room(ctx, -1, BPF_ADJ_ROOM_MAC, 0);
        if (ret)
                bpf_eprint("error: bpf_adjust_room -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_change_head_1b(struct __sk_buff *ctx)
{
        int ret;

        ret = bpf_skb_change_head(ctx, 1, 0);
        if (ret)
                bpf_printk("error: bpf_skb_change_head -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_change_proto_to_6(struct __sk_buff *ctx)
{
        int ret;

        ret = bpf_skb_change_proto(ctx, bpf_htons(ETH_P_IPV6), 0);
        if (ret)
                bpf_eprint("error: bpf_skb_change_proto -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_change_proto_to_4(struct __sk_buff *ctx)
{
        int ret;

        ret = bpf_skb_change_proto(ctx, bpf_htons(ETH_P_IP), 0);
        if (ret)
                bpf_eprint("error: bpf_skb_change_proto -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_change_tail(struct __sk_buff *ctx) {
        int ret;

	/* try to trigger pskb_expand_head */
        ret = bpf_skb_change_tail(ctx, ctx->len + 4096, 0);
        if (ret)
                bpf_eprint("error: bpf_skb_change_tail -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_vlan_push_x2(struct __sk_buff *ctx) {
        int ret;

        ret = bpf_skb_vlan_push(ctx, 0, 42);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_push-1 -> %d\n", ret);

        ret = bpf_skb_vlan_push(ctx, 0, 207);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_push-2 -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_vlan_push_x2_pop(struct __sk_buff *ctx) {
        int ret;

        ret = bpf_skb_vlan_push(ctx, 0, 42);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_push-1 -> %d\n", ret);

        ret = bpf_skb_vlan_push(ctx, 0, 207);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_push-2 -> %d\n", ret);

        ret = bpf_skb_vlan_pop(ctx);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_pop-1 -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int test_tcx_vlan_pop_x2(struct __sk_buff *ctx) {
        int ret;

        ret = bpf_skb_vlan_pop(ctx);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_pop-1 -> %d\n", ret);

        ret = bpf_skb_vlan_pop(ctx);
        if (ret)
                bpf_eprint("error: bpf_skb_vlan_pop-2 -> %d\n", ret);

        return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_hello([[maybe_unused]] struct __sk_buff *ctx)
{
        bpf_stream_printk(BPF_STDOUT, "hello stdout\n");
        bpf_stream_printk(BPF_STDERR, "hello stderr\n");

	return TCX_NEXT;
}        

const char _license[] SEC("license") = "GPL";
