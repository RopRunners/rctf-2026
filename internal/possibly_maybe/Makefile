CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -g
LDLIBS := -lpthread

all: db_server svm

db_server: db/src/main.c db/src/database.h
	$(CC) $(CFLAGS) -o $@ db/src/main.c $(LDLIBS)

svm: runner/src/main.c runner/src/jit/jit.c runner/src/jit/jit.h db/src/database.h
	$(CC) $(CFLAGS) -o $@ runner/src/main.c runner/src/jit/jit.c $(LDLIBS)

clean:
	rm -f db_server svm db/a.out

.PHONY: all clean
