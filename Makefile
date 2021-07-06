TARGET := firehose-from-pcap

.PHONY: all
all: $(TARGET)

$(TARGET): $(TARGET).o
	gcc -g -o $@ $^

%.o: %.c
	gcc -g -Wall -c -o $@ $<

clean:
	rm -f *.o $(TARGET)
