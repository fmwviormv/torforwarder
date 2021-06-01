PROG=	torforwarder
SRCS=	torforwarder.c
MAN=
NOMAN=

CFLAGS+= -std=c99 -pedantic -Wall -Wextra -Werror

.include <bsd.prog.mk>
