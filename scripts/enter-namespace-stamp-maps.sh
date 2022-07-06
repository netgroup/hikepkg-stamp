#!/bin/bash

read -r -d '' sut_env <<-EOF
	# Everything that is private to the bash process that will be launch
	# mount the bpf filesystem.
	# Note: childs of the launching (parent) bash can access this instance
	# of the bpf filesystem. If you need to get access to the bpf filesystem
	# (where maps are available), you need to use nsenter with -m and -t
	# that points to the pid of the parent process (launching bash).


	cd /opt/eclat-daemon

	# NOT an HIKe eBPF Program
	# mkdir -p /sys/fs/bpf/{progs/rawpass,} || true
	# bpftool prog loadall testbed/raw_pass.o /sys/fs/bpf/progs/rawpass type xdp

	# Attach the (pinned) raw_pass program to netdev enp6s0f1 on the
	# XDP hook.
	bpftool net attach xdpdrv 				\
		pinned /sys/fs/bpf/progs/rawpass/xdp_pass	\
                dev enp6s0f1

	# compile C program to calculate delta time
	cd develop
	gcc t2.c -o t2
	cd ..
    # Python scripts to populate maps
	python components/stamp/python/stamp_xcon_map.py
    python components/stamp/python/stamp_maps.py --prog stamp_mono --l23
EOF

nsenter -t $(ps ax | grep e[c]latd | grep -v '\.eclat'  | awk '{ print $1 }') -m -n -- bash -c "${sut_env}"
