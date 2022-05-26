TESTS := demo

CFLAGS = $(TEST_CFLAGS)
LDLIBS = $(TEST_LDLIBS)

all: $(OBJDIR)/$(TESTS)

$(OBJDIR)/$(TESTS): ${TESTS:=.c}
	$(QUIET_CC)$(CC) $(CFLAGS) -c $< -o $@ $(LDLIBS)

.PHONY: clean
clean:
	$(Q)for d in $(TESTS); do \
		[ -f "$(OBJDIR)/$$d" ] && rm "$(OBJDIR)/$$d"; done || true