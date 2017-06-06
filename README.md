The ODP project has been established to produce an open-source, cross-platform 
set of application programming interfaces (APIs) for the networking data plane.
This repo provides implementation for ODP monarch release on NXP DPAA2 platforms.
Further details on ODP open-source project refer to www.opendataplane.org.

DPAA2 specific headers and implementation is available in platform/liunx-dpaa2 directory.

For more details about sample applications and their usage please refer to "Linux user space" section 
in QorIQ Layerscaper Software Development Kit documentation.

Supported Platforms:
LS2088ardb
LS1088ardb

Build Steps:

For compiling ODP using the flex-builder following commands needs to be run.

soure setup.env
flex-builder -c linux -a arm64
flex-builder -i mkrfs -a arm64
Run “flex-builder -c apps -a arm64” to generate all apps components. 
If only ODP needs to be compiled run "flex-builder -c odp -m ls2088ardb".
To install odp apps into rootfs:
flex-builder -i merge-component
flex-builder -i compressrfs

For compiling ODP as standalone application please refer to README file in linux-dpaa2 folder.
