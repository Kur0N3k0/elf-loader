all: example

example:
	clang -fsanitize=address,fuzzer example.cpp -o fuzzer -g
	gcc -o target target.c -no-pie

test: example
	./fuzzer ./target

clean:
	rm -rf ./fuzzer ./target