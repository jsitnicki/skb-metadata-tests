test *args:
    LD_PRELOAD=./chdir_setns.so ./bashunit {{args}} .

libbpf-headers:
    cd ~/src/linux && make -C tools/lib/bpf/ prefix=$PWD/usr install_headers
