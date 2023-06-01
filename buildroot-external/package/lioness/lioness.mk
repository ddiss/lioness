################################################################################
#
# lioness
#
################################################################################

LIONESS_VERSION = 1.0.0
# all local cargo dependencies are vendored under $(LIONESS_PKGDIR)src/vendor
# and referenced in src/.cargo/config.toml
LIONESS_SITE = $(LIONESS_PKGDIR)/src
LIONESS_SITE_METHOD = local
LIONESS_LICENSE = GPL-3.0

define LIONESS_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0755 $(LIONESS_PKGDIR)/S20lioness \
		$(TARGET_DIR)/etc/init.d/S20lioness
endef

$(eval $(cargo-package))
