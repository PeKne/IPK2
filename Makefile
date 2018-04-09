$FLAGS = -Wall -Wextra

make: ipk-lookup.c
	gcc $(FLAGS) ipk-lookup.c -o ipk-lookup


clean:
	rm ipk-lookup
