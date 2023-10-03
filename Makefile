MAKEFLAGS += --no-builtin-rules

V ?= $(VERBOSE)
ifeq ($(V),1)
	Q :=
	VECHO := @true
	MAKEMINS :=
else
	Q := @
	VECHO := @echo
	MAKEMINS := -s
endif

CCWARNINGS		:=	-Wall -Wextra -Werror \
						-Wformat-overflow=2 -Wshift-overflow=2 -Wimplicit-fallthrough=5 \
						-Wformat-signedness -Wformat-truncation=2 \
						-Wstringop-overflow=4 -Wunused-const-variable=2 -Walloca \
						-Warray-bounds=2 -Wswitch-bool -Wsizeof-array-argument \
						-Wduplicated-branches -Wduplicated-cond -Wlto-type-mismatch -Wnull-dereference \
						-Wdangling-else -Wdangling-pointer=2 \
						-Wpacked -Wfloat-equal -Winit-self -Wmissing-include-dirs \
						-Wmissing-noreturn -Wbool-compare \
						-Wsuggest-attribute=noreturn -Wsuggest-attribute=format -Wmissing-format-attribute \
						-Wuninitialized -Wtrampolines -Wframe-larger-than=262144 \
						-Wunsafe-loop-optimizations -Wshadow -Wpointer-arith -Wbad-function-cast \
						-Wcast-qual -Wwrite-strings -Wsequence-point -Wlogical-op -Wlogical-not-parentheses \
						-Wredundant-decls -Wvla -Wdisabled-optimization \
						-Wunreachable-code -Wparentheses -Wdiscarded-array-qualifiers \
						-Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -Wmissing-declarations \
						-Wcast-align -Winline -Wmultistatement-macros -Warray-bounds=2 \
						\
						-Wno-error=cast-qual \
						-Wno-error=unsafe-loop-optimizations \
						-Wno-format-zero-length \
						\
						-Wno-packed \
						-Wno-unused-parameter \

CFLAGS			:=	-pipe -Os -g -std=gnu11 -fdiagnostics-color=auto \
						-fno-inline \
						-fno-math-errno -fno-printf-return-value \
						-ftree-vrp \
						-ffunction-sections -fdata-sections

ifeq ($(USE_LTO),1)
CFLAGS 			+=	-flto=8 -flto-compression-level=0 -fuse-linker-plugin -ffat-lto-objects -flto-partition=max
endif

OBJS			:= 	crc16modbus.o
HEADERS			:=	crc16modbus.h

.PRECIOUS:		*.cpp *.c *.h
.PHONY:			all

all:			secollect seanalyse

clean:
				$(VECHO) "CLEAN"
				-$(Q) rm -f $(OBJS) secollect secollect.o seanalyse seanalyse.o 2> /dev/null

secollect:		secollect.o $(OBJS)
				$(VECHO) "LD secollect"
				$(Q) gcc secollect.o $(OBJS) -o $@

seanalyse:		seanalyse.o $(OBJS)
				$(VECHO) "LD seanalyse"
				$(Q) gcc seanalyse.o $(OBJS) -o $@

secollect.o:	secollect.c $(HEADERS)

seanalyse.o:	seanalyse.c $(HEADERS)

%.o:			%.c
				$(VECHO) "CC $<"
				$(Q) gcc $(CCWARNINGS) $(CFLAGS) $(CINC) -c $< -o $@

%.i:			%.c
				$(VECHO) "CC cpp $<"
				$(Q) gcc -E $(CCWARNINGS) $(CFLAGS) $(CINC) -c $< -o $@

%.s:			%.c
				$(VECHO) "CC as $<"
				$(Q) gcc -S $(CCWARNINGS) $(CFLAGS) $(CINC) -c $< -o $@

%:				%.cpp
				$(VECHO) "HOST CPP $<"
				$(Q) $(HOSTCPP) $(HOSTCPPFLAGS) $< -o $@

%.h.gch:		%.h
				$(VECHO) "HOST CPP PCH $<"
