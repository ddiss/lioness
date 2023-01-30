################################################################################
#
# softfido
#
################################################################################

# current head, untagged but labeled 0.1.0
SOFTFIDO_VERSION = 00eea11fafc5129195a92f25e86d95bda244efad
SOFTFIDO_SITE = $(call github,ellerh,softfido,$(SOFTFIDO_VERSION))
# vendored as a git submodule (cargo vendor must be called beforehand)
#SOFTFIDO_SITE = $(SOFTFIDO_PKGDIR)/mod
#SOFTFIDO_SITE_METHOD = local
SOFTFIDO_LICENSE = GPL-3.0+

$(eval $(cargo-package))
