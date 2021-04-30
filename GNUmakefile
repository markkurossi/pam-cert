
SRCS := $(wildcard module/*.c) $(wildcard module/*.h) \
	$(wildcard module/ed25519/*.c) $(wildcard module/ed25519/*.h)
CFLAGS := -Imodule/ed25519 -Wall -Werror -fPIC
LDFLAGS := -shared

all: module/pam_cert.so

module/pam_cert.so: $(filter %.c,$(SRCS))
	cc $(CFLAGS) $(LDFLAGS) -o $@ $+

clean:
	$(RM) module/pam_cert.so
