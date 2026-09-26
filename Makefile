# Builds the native shim that exposes nuvem_p11.p11 to NSS.
#
#   make            build shim/libnuvemp11.so
#   make abi-probe  compile a C probe and diff the CK_FUNCTION_LIST offsets
#   make test       run the Python test suite
#   make icon       regenerate nuvem_p11/icon.png (needs ImageMagick)
#   make clean
#
# The configuration utility is pure Python and needs no build:
#
#   python3 -m serproid --help          (or the `serproid` console script)
#   python3 -m serproid status

PYTHON      ?= python3
PKCS11_INC  ?= $(shell pkg-config --cflags p11-kit-1 2>/dev/null || echo -I/usr/include/p11-kit-1)
PY_CFLAGS   := $(shell $(PYTHON)-config --includes)
PY_LDFLAGS  := $(shell $(PYTHON)-config --ldflags --embed)
# Names tried by the shim when promoting libpython into the global scope (RTLD_GLOBAL);
# a loader that dlopens us with RTLD_LOCAL would otherwise hide CPython's own symbols.
PY_SONAME   := $(shell $(PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('INSTSONAME') or '')")
PY_LIBNAME  := $(shell $(PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LDLIBRARY') or '')")
ROOT        := $(CURDIR)
OUT         := shim/libnuvemp11.so
GENERATED   := shim/generated_functions.h

CFLAGS  ?= -O2 -g -Wall -Wextra -fPIC -D_GNU_SOURCE
CFLAGS  += $(PY_CFLAGS) $(PKCS11_INC) -DNUVEM_P11_PYTHONPATH='"$(ROOT)"' \
           -DNUVEM_P11_PYTHON_SONAME='"$(PY_SONAME)"' -DNUVEM_P11_PYTHON_LIBNAME='"$(PY_LIBNAME)"'

.PHONY: all shim test abi-probe icon clean

# The icon rule sits first for readability; the default goal is still the shim.
.DEFAULT_GOAL := all

# The notification icon (nuvem_p11/icon.png) is a checked-in asset; this regenerates it.
# Same style as the official icon -- rounded square, white monogram -- but a different colour
# and monogram, so the notification says which implementation is asking for the PIN.
ICON_FONT  ?= $(shell fc-match -f '%{file}' 'sans-serif:bold' 2>/dev/null || echo /usr/share/fonts/noto/NotoSans-Bold.ttf)
ICON_COLOR ?= \#0E9F6E

icon:
	magick -size 1024x1024 xc:none -fill '$(ICON_COLOR)' \
	  -draw 'roundrectangle 0,0,1023,1023,177,177' \
	  -font '$(ICON_FONT)' -pointsize 470 -fill white -gravity center \
	  -annotate +21-12 'n11' -strip nuvem_p11/icon.png
	@echo "wrote nuvem_p11/icon.png"

all: $(OUT)

# Single source of truth: the ordering and the names come from the Python table.
$(GENERATED): nuvem_p11/p11/cabi.py
	@$(PYTHON) -c "from nuvem_p11.p11.cabi import FUNCTION_NAMES; \
print('#define NUVEM_P11_FUNCTIONS(X) ' + ' '.join('X(%s)' % n for n in FUNCTION_NAMES))" > $@
	@echo "generated $$(wc -w < $@) words -> $@"

$(OUT): shim/nuvemp11.c $(GENERATED) nuvem_p11/p11/cabi.py
	@mkdir -p shim
	$(CC) $(CFLAGS) -shared -o $@ shim/nuvemp11.c $(PY_LDFLAGS)
	@echo "built $@"

shim: $(OUT)

test: $(OUT)
	$(PYTHON) -m pytest tests/ -q

# Compiles a probe against p11-kit's header and prints every member offset, so the Python
# table can be diffed against the real struct.
abi-probe: .
	@$(PYTHON) tools/emit_abi_probe.py > /tmp/nuvem_p11_abi_probe.c
	$(CC) -o /tmp/nuvem_p11_abi_probe /tmp/nuvem_p11_abi_probe.c $(PKCS11_INC)
	@/tmp/nuvem_p11_abi_probe

clean:
	rm -f $(OUT) $(GENERATED)
