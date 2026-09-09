# hewn-mini capture, 2026-09-09: why the direct path never wins in the lab

One held visit (doctor --hold 20) captured with tcpdump on both NATs'
outward interfaces (nat-a.txt, nat-b.txt) and both houses' inner
interfaces (house-a.txt, house-b.txt), conntrack and nft dumped mid
visit. pcaps decoded to text. Binaries 9ec424a, EIM masquerade both
sides. Full analysis: issue 88.

## The finding

Probes cross both ways, 70 packets each, none answered. External port
mapping, from conntrack:

| house | port the gate saw | port its peer probes left from |
|-------|-------------------|--------------------------------|
| house-a (10.1.0.2) | 54421 | 54421, preserved |
| house-b (10.2.0.2) | 57205 | 15798, reallocated |

The doctor sent house-a to house-b at the gate-reflected 57205;
house-b's probes actually egress from 15798, so each side's probe hits
the other NAT with no matching conntrack tuple and is dropped. Zero
direct probes reach inside either house.

## Conclusion

The punch code is correct (gather, exchange, simultaneous probe of the
gate-reflected address, all present). netns-nat.sh's "EIM" masquerade
does not keep one external port across two destination addresses, which
is what a hole punch needs and which run 1 never tested (it tested two
ports on one address). Plain Linux masquerade is not a faithful
full-cone NAT, so the netns lab cannot judge NAT traversal. That is
WO-1.5's job, on real machines and real routers. The lab remains good
for relay behaviour and the fault matrix.
