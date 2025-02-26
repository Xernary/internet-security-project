main:	main.c utils.c
	gcc -o main main.c -no-pie -m32
	pwninit --bin main --libc libc.so.6 --ld ld-linux.so.2
