
CC= gcc
CFLAGS=-g -Wall -DDEBUG_CMAC
INCLUDEDIR= -I .
EXT_SOURCES= TI_aes_128.c aes-cbc-cmac.c

EXT_OBJ=$(EXT_SOURCES:.c=.o)
EXECUTABLE= main


all: $(EXT_SOURCES) $(EXECUTABLE)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDEDIR) -c $< -o $@

$(EXECUTABLE): $(EXT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDEDIR) $(EXT_OBJ) $@.c -o $@

clean:
	rm -f $(EXT_OBJ) $(EXECUTABLE)


