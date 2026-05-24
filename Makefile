LIBDIR := lib

# All toolchain self-heal logic below applies only to local (non-CI) builds.
# In CI the i-d-template Docker image installs everything globally and there
# is no lib/.venv to manage. We guard the additions accordingly so CI is
# unaffected.
ifneq (true,$(CI))

# --- Parse-time venv health check -----------------------------------------
# If lib/.venv exists but the venv's Python can't `import lxml.etree`, the
# native extensions in the venv don't match the current interpreter (most
# commonly an x86_64 vs arm64 mismatch left over from a previous Python).
# Force-reinstalling xml2rfc alone won't fix this because xml2rfc is pure
# Python and imports lxml from site-packages. The only reliable recovery
# is to delete the venv so venv.mk rebuilds it from scratch.
ifneq (,$(wildcard $(LIBDIR)/.venv/bin/python))
ifeq (broken,$(shell "$(LIBDIR)/.venv/bin/python" -c 'import lxml.etree' >/dev/null 2>&1 || echo broken))
$(info Detected broken venv at $(LIBDIR)/.venv (lxml.etree import failed - likely arch mismatch). Removing for a clean rebuild.)
$(shell rm -rf "$(LIBDIR)/.venv")
endif
endif

# --- Local toolchain bootstrap --------------------------------------------
# Two known local failure modes are fixed by the additions below:
#
# 1. i-d-template (lib/deps.mk) installs kramdown-rfc via Ruby `bundle`. When
#    `bundle` isn't on PATH, deps.mk silently sets NO_RUBY := true, skips the
#    gem install, and the first build then crashes with
#       lib/trace.sh: line 35: kramdown-rfc: command not found
#    `.kramdown-rfc.dep` is a DEPS_FILES marker whose recipe installs
#    kramdown-rfc via `gem install --user-install` and adds the user-gem
#    bin directory to PATH.
#
# 2. If the venv at lib/.venv has pip-installed packages in site-packages
#    but the entry-point scripts in lib/.venv/bin/ are missing (e.g., from
#    a copied/cleaned venv), pip reports "Requirement already satisfied"
#    and never regenerates the scripts. The build then dies with
#       lib/trace.sh: line 35: lib/.venv/bin/xml2rfc: No such file or directory
#    Listing $(LIBDIR)/.venv/bin/xml2rfc in DEPS_FILES, plus the explicit
#    rule below (which overrides venv.mk's wildcard rule for this target)
#    force-reinstalls xml2rfc when the entry script is absent, so pip
#    regenerates it.
#
# DEPS_FILES must be set *before* including main.mk so deps.mk picks it up.
# Note the recursive '=' (not ':='): deps.mk computes $(VENVDIR) as the
# realpath of $(LIBDIR)/.venv, which is the *absolute* path. We must
# defer expansion so our entry matches venv.mk's marker target by name.
DEPS_FILES = .kramdown-rfc.dep $(VENVDIR)/bin/xml2rfc

endif # !CI

include $(LIBDIR)/main.mk

ifneq (true,$(CI))

# Put the user-local gem bin directory on PATH so an already-installed
# kramdown-rfc (or one installed by the rule below) is found by the build.
GEM_USER_BIN := $(shell command -v ruby >/dev/null 2>&1 && \
                  ruby -e 'require "rubygems"; print Gem.user_dir' 2>/dev/null)/bin
ifneq (/bin,$(GEM_USER_BIN))
export PATH := $(GEM_USER_BIN):$(PATH)
endif

.kramdown-rfc.dep:
	@if command -v kramdown-rfc >/dev/null 2>&1; then \
	  echo "kramdown-rfc found: $$(command -v kramdown-rfc)"; \
	else \
	  command -v ruby >/dev/null 2>&1 || { \
	    echo "ERROR: ruby is required but was not found on PATH." 1>&2; \
	    echo "  Install Ruby (e.g. 'sudo port install ruby33') and retry." 1>&2; \
	    exit 1; }; \
	  echo "Installing kramdown-rfc to $(GEM_USER_BIN) ..."; \
	  gem install --user-install --no-document kramdown-rfc \
	    || { echo "ERROR: 'gem install kramdown-rfc' failed." 1>&2; \
	         echo "  Try manually: gem install --user-install kramdown-rfc" 1>&2; \
	         exit 1; }; \
	fi
	@touch $@

# Self-heal for the case where bin/xml2rfc is missing while the package is
# in site-packages (pip would otherwise report "already satisfied" and not
# regenerate the entry script). Arch-mismatch / broken-native-libs cases
# are handled by the parse-time check at the top of this Makefile.
# The target uses $(VENVDIR) (set by deps.mk to the absolute path of
# $(LIBDIR)/.venv) so it matches venv.mk's $(VENV)/$(MARKER) rule by name.
$(VENVDIR)/bin/xml2rfc: $(VENVDIR)/bin/.initialized-with-Makefile.venv
	@if [ ! -x "$(VENVDIR)/bin/python" ]; then \
	  echo "ERROR: $(VENVDIR) is not a valid Python venv." 1>&2; \
	  echo "  Remove $(VENVDIR) and rerun make." 1>&2; \
	  exit 1; \
	fi
	@if [ ! -x "$@" ]; then \
	  echo "Regenerating $@ via 'pip install --force-reinstall --no-deps xml2rfc' ..."; \
	  "$(VENVDIR)/bin/python" -m pip install --no-user --force-reinstall --no-deps xml2rfc; \
	fi
	@test -x $@ || { echo "ERROR: $@ still missing after reinstall." 1>&2; exit 1; }

endif # !CI

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update --init
else
ifneq (,$(wildcard $(ID_TEMPLATE_HOME)))
	ln -s "$(ID_TEMPLATE_HOME)" $(LIBDIR)
else
	git clone -q --depth 10 -b main \
	    https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
endif

export UPLOAD_EMAIL ?= uri@ll.mit.edu

