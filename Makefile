all: example

example:
	gcc -o example example.c -ldl -masm=intel
	gcc -o test test.c -Wl,-z,norelro -no-pie

test: example
	./example ./test

clean:
	rm -rf ./example ./test