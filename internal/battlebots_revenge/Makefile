build:
	gcc -static-pie -Wl,-z,relro -Wl,-z,now src/main.c -o battlebots -O2 -fno-stack-protector

clean:
	rm battlebots
