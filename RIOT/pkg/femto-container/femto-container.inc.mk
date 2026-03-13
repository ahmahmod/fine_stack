F12R_SOURCES ?= $(wildcard $(CURDIR)/*.c)
F12R_GENFEMTOC ?= $(RIOTBASE)/build/pkg/femto-container/tools/gen_rbf.py

F12R_BINS = $(F12R_SOURCES:.c=.bin)
F12R_OBJS = $(F12R_SOURCES:.c=.o)

LLC ?= llc
CLANG ?= clang
#INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`

#add -m32 to make pointers of size 32-bit.
EXTRA_CFLAGS ?= -Os -emit-llvm -m32 \
				-fno-optimize-sibling-calls \
#				-target i386-unknown-linux-gnu

							 
F12RINCLUDE =  -I$(RIOTBASE)/build/pkg/femto-container/include \
	       -I$(RIOTBASE)/pkg/femto-container/include \
        	-I$(RIOTBASE)/drivers/include \
	       -I$(RIOTBASE)/core/include \
	       -I$(RIOTBASE)/core/lib/include \
	       -I$(RIOTBASE)/cpu/native/include \
	       -I$(RIOTBASE)/sys/include \
			#

all: $(F12R_BINS)

.PHONY: clean

clean:
	rm -f $(F12R_OBJS) $(F12R_BINS)
	#rm -f $(F12R_OBJS)

#INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
INC_FLAGS = -isystem `$(CLANG) -print-file-name=include`


$(F12R_OBJS): %.o:%.c
	$(CLANG) $(INC_FLAGS) \
	        $(F12RINCLUDE) \
	        -Wno-unused-value -Wno-pointer-sign -g3\
	        -Wno-compare-distinct-pointer-types \
	        -Wno-gnu-variable-sized-type-not-at-end \
	        -Wno-address-of-packed-member -Wno-tautological-compare \
	        -Wno-unknown-warning-option \
	        $(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -mcpu=v2  -filetype=obj -o $@

$(F12R_BINS): %.bin:%.o
	$(Q)$(F12R_GENFEMTOC) generate $< $@