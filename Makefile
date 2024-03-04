all:
	gcc main.c methods.c events.c -o run -I/opt/homebrew/Cellar/libnet/1.3/include -L/opt/homebrew/Cellar/libnet/1.3/lib -lnet -lpcap