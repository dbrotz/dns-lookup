CFLAGS := -Wall -Wextra -O2
SOURCE := dns_lookup.c

.PHONY: clean

dns_lookup: $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $(SOURCE)

clean:
	$(RM) dns_lookup
