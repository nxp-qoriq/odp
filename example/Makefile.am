SUBDIRS = classifier generator ipsec packet time timer l2fwd_simple switch l3fwd reflector lpm-ipfwd traffic_manager
DIST_SUBDIRS = classifier generator ipsec packet time timer l2fwd_simple switch l3fwd reflector lpm-ipfwd traffic_manager
if BUILD_DPAA2
SUBDIRS += kni_demo ipsec_offload
DIST_SUBDIRS += kni_demo ipsec_offload
if !BUILD_LS2080
SUBDIRS += cmdif_demo
DIST_SUBDIRS += cmdif_demo
endif
else
SUBDIRS += ipsec_proto
endif
