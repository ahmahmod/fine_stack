# name of the example application
APPLICATION = sdn_vf

# Default is to build for the "native" target. Allows overriding
BOARD ?= iotlab-m3

# This has to be the absolute path to the RIOT base directory:
RIOTBASE = $(CURDIR)/../../RIOT

USE_FC ?= 1
USE_DUTY ?= 1
USE_RPL ?= 0

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# # Activate ICMPv6 error messages
USEMODULE += gnrc_icmpv6_error

# Specify the mandatory networking module for a IPv6 routing node
USEMODULE += gnrc_ipv6_router_default

ifeq (1, $(USE_RPL))
# Add a routing protocol
  CFLAGS += -DUSE_RPL=1
  USEMODULE += gnrc_rpl
  USEMODULE += auto_init_gnrc_rpl
  USEMODULE += gnrc_rpl_sr
endif
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo

# SUIT update specific stuff
#USEMODULE += nanocoap_sock sock_util
USEMODULE += suit suit_transport_coap
USEMODULE += suit_storage_ram

# Display a progress bar during firmware download
# USEMODULE += progress_bar

# Optional feature to trigger suit update through gpio callback
FEATURES_OPTIONAL += periph_gpio_irq

# Default COAP manifest resource location when fetched through gpio trigger
CFLAGS += -DSUIT_MANIFEST_RESOURCE=\"$(SUIT_COAP_ROOT)/$(SUIT_NOTIFY_MANIFEST)\"

#1 Storage region in RAM with 1K in size
CFLAGS += -DCONFIG_SUIT_STORAGE_RAM_REGIONS=1 -DCONFIG_SUIT_STORAGE_RAM_SIZE=2048

# Include the bpf module
USEMODULE += gnrc_pktbuf_static
USEMODULE += ztimer

# Use duty cycling
ifeq (1, $(USE_DUTY))
  USEMODULE += gnrc_gomach
endif


# CFLAGS += -DCONFIG_GNRC_IPV6_NIB_ARSM=0
# FC configuration
ifeq (1, $(USE_FC))
  CFLAGS += -DUSE_FC=1
  USEPKG += femto-container
  USEMODULE += fc_array
endif

ifeq (1, $(USE_RPL))
  CFLAGS += -DUSE_RPL=1
  ifeq (1,$(MODE))
  F12R_DIRS += $(CURDIR)/sr_dao_recv
  F12R_DIRS += $(CURDIR)/sr_dao_send
  F12R_DIRS += $(CURDIR)/sr_dao_send2
  F12R_DIRS += $(CURDIR)/sr_root
else
  F12R_DIRS += $(CURDIR)/dao_recv
  F12R_DIRS += $(CURDIR)/dao_send
  F12R_DIRS += $(CURDIR)/dao_send2
  F12R_DIRS += $(CURDIR)/root
endif
  F12R_DIRS += $(CURDIR)/dio_recv
  F12R_DIRS += $(CURDIR)/dio_recv2
  F12R_DIRS += $(CURDIR)/ack_dao_recv
  F12R_DIRS += $(CURDIR)/dis_recv
  F12R_DIRS += $(CURDIR)/dio_send
  F12R_DIRS += $(CURDIR)/ack_dao_send
  F12R_DIRS += $(CURDIR)/dis_send
  
  F12R_DIRS += $(CURDIR)/switch_non_storing

ifeq (1,$(MODE))
  F12R_BLOBS += sr_dao_recv/dao_recv.bin
  F12R_BLOBS += sr_dao_send/dao_send.bin
  F12R_BLOBS += sr_dao_send2/dao_send2.bin
  F12R_BLOBS += sr_root/root.bin 
else
  F12R_BLOBS += dao_recv/dao_recv.bin
  F12R_BLOBS += dao_send/dao_send.bin
  F12R_BLOBS += dao_send2/dao_send2.bin
  F12R_BLOBS += root/root.bin 
endif
  F12R_BLOBS += dio_recv/dio_recv.bin
  F12R_BLOBS += dio_recv2/dio_recv2.bin
  F12R_BLOBS += ack_dao_recv/ack_dao_recv.bin
  F12R_BLOBS += dis_recv/dis_recv.bin
  F12R_BLOBS += dio_send/dio_send.bin
  F12R_BLOBS += ack_dao_send/ack_dao_send.bin
  F12R_BLOBS += dis_send/dis_send.bin

  F12R_BLOBS += switch_non_storing/switch_non_normal.bin
endif


# Set the default value for USE_SEQ_NUMBER if not provided
# USE_SEQ_NUMBER is used here to avoid checking the seq_no as we use
# the same slot for updating all FCs
USE_SEQ_NUMBER ?= 0
CFLAGS += -DUSE_SEQ_NUMBER=$(USE_SEQ_NUMBER)

#TEST_ON_CI_WHITELIST += native

# Set the default value for SUIT_VERSION if not provided
SUIT_VERSION ?= 1
CFLAGS += -DSUIT_VERSION=$(SUIT_VERSION)


ifeq ($(BOARD),native)
  USE_ETHOS ?= 0
endif

# Change this to 1 to use ethos
USE_ETHOS ?= 0

ifeq (1,$(USE_ETHOS))
  USEMODULE += stdio_ethos
  USEMODULE += gnrc_uhcpc

  # ethos baudrate can be configured from make command
  ETHOS_BAUDRATE ?= 115200
  CFLAGS += -DETHOS_BAUDRATE=$(ETHOS_BAUDRATE)

  # make sure ethos and uhcpd are built
  TERMDEPS += host-tools

  # For local testing, run
  #
  #     $ cd dist/tools/ethos; sudo ./setup_network.sh riot0 2001:db8::0/64
  #
  #... in another shell and keep it running.
  export TAP ?= riot0
  TERMPROG = $(RIOTTOOLS)/ethos/ethos
  TERMFLAGS = $(TAP) $(PORT)
endif

# Ensure both slot bin files are always generated and linked to avoid compiling
# during the test. This ensures that "BUILD_IN_DOCKER=1 make test"
# can rely on them being present without having to trigger re-compilation.
BUILD_FILES += $(SLOT_RIOT_ELFS:%.elf=%.bin)

# The test needs the linked slot binaries without header in order to be able to
# create final binaries with specific APP_VER values. The CI RasPi test workers
# don't compile themselves and re-create signed images, thus add the required
# files here so they will be submitted along with the test jobs.
TEST_EXTRA_FILES += $(SLOT_RIOT_ELFS) $(SUIT_SEC) $(SUIT_PUB)


# Instead of simulating an Ethernet connection, we can also simulate
# an IEEE 802.15.4 radio using ZEP
USE_ZEP ?= 0

# set the ZEP port for native
ZEP_PORT_BASE ?= 17754
ifeq (1,$(USE_ZEP))
  TERMFLAGS += -z [::1]:$(ZEP_PORT_BASE)
  USEMODULE += socket_zep
endif


# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 0
DEFAULT_CHANNEL=15

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

# allow to use large blocks to utilize large MTUs (802.15.4g, Ethernet, WiFi)
LARGE_BLOCKS ?= 0
ifeq (1, $(LARGE_BLOCKS))
  CFLAGS += -DCONFIG_SUIT_COAP_BLOCKSIZE=COAP_BLOCKSIZE_1024
endif

# # Set GNRC_PKTBUF_SIZE via CFLAGS if not being set via Kconfig.
# ifndef CONFIG_GNRC_PKTBUF_SIZE
#   CFLAGS += -DCONFIG_GNRC_PKTBUF_SIZE=6144
# endif

.PHONY: host-tools

host-tools:
	$(Q)env -u CC -u CFLAGS $(MAKE) -C $(RIOTTOOLS)

include $(RIOTMAKE)/default-radio-settings.inc.mk
