name = input_name_of_prog
CC = gcc

all:
		$(CC) -Wall -o $(name) $(name).c

cli:
		rm -f $(name).o $(name)

clean: cli