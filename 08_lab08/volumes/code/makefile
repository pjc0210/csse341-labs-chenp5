all: simple_loop.run simple_prompt.run

.PHONY: all clean

simple_loop.run: simple_loop.o
	gcc -o $@ $^

simple_prompt.run: simple_prompt.o
	gcc -o $@ $^

clean:
	rm -rf *.run *.o

