
SRCS := $(wildcard module/*.c) $(wildcard module/*.h) \
	$(wildcard module/ed25519/*.c) $(wildcard module/ed25519/*.h)
CFLAGS := -Imodule/ed25519 -Wall -Werror -fPIC
LDFLAGS := -shared

all: module/pam_cert.so cmd/pam-test/pam-test

module/pam_cert.so: $(filter %.c,$(SRCS))
	cc $(CFLAGS) $(LDFLAGS) -o $@ $+

cmd/pam-test/pam-test: cmd/pam-test/pam-test.c
	cc -Wall -Werror -o $@ $+ -lpam -lpam_misc

check:
	@echo check

clean:
	$(RM) module/pam_cert.so
	$(RM) cmd/pam-test/pam-test
