NAME	= pcapinfo

CC      = gcc

SRCS	= src/pcapinfo.c \
        src/threadpool.c

OBJS	= $(SRCS:.c=.o)

CFLAGS	= -Wall -Wextra -O2 -I./inc -std=gnu99 -Wno-unused-result

LDFLAGS	= -lpcap -lpthread

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
