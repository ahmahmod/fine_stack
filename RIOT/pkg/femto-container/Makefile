PKG_NAME    = femto-container
PKG_VERSION = 5cf406863475f869af192f469fa174b1b1ab6343
PKG_URL = https://forge.icube.unistra.fr/ahmad-mahmod-phd/femto-cont.git # anonymized
PKG_LICENSE = apache
PKG_SOURCE_LOCAL = $(RIOTBASE)/../femto-container

include $(RIOTBASE)/pkg/pkg.mk

all:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(PKG_DIR)/Makefile.femto MODULE=$(PKG_NAME)
