SUBDIRS = classifier generator ipsec packet time timer l2fwd_simple switch l3fwd reflector lpm-ipfwd
DIST_SUBDIRS = classifier generator ipsec packet time timer l2fwd_simple switch l3fwd reflector lpm-ipfwd
if BUILD_DPAA2
SUBDIRS += kni_demo ipsec_offload traffic_manager
DIST_SUBDIRS += kni_demo ipsec_offload traffic_manager
if !BUILD_LS2080
SUBDIRS += cmdif_demo traffic_manager
DIST_SUBDIRS += cmdif_demo traffic_manager
endif
else
SUBDIRS += ipsec_proto
endif
