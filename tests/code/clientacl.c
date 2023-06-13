#include <nbdsrv.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>

bool do_test(char* address, char* netmask) {
	struct addrinfo hints;
	struct addrinfo *res, *tmp;
	char buf[1024];
	int err;

	printf("Doing test for %s, netmask %s\n", address, netmask);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;

	if((err = getaddrinfo(address, NULL, &hints, &res))) {
		fprintf(stderr, "E: %s\n", gai_strerror(err));
		exit(EXIT_FAILURE);
	}
	tmp = res;
	while(res) {
		if((err = getnameinfo((struct sockaddr*)res->ai_addr, res->ai_addrlen, buf,
                                       sizeof (buf), NULL, 0, NI_NUMERICHOST))) {
			fprintf(stderr, "E: %s\n", gai_strerror(err));
			exit(EXIT_FAILURE);
		}

		printf("Found %s\n", buf);

		if(address_matches(netmask, (struct sockaddr*)res->ai_addr, NULL)) {
			printf("Yes!\n");
			freeaddrinfo(tmp);
			return true;
		} else {
			printf("oh noes!\n");
		}
		res = res->ai_next;
	}
	freeaddrinfo(tmp);
	return false;
}

int main(void) {
	if(!do_test("192.168.0.1", "192.168.1.1/23")) {
		return 1;
	}
	if(!do_test("192.168.0.1", "192.168.0.1/24")) {
		return 1;
	}
	if(!do_test("::ffff:192.168.200.1", "192.168.200.1/24")) {
                return 1;
        }
        if(do_test("::ffff:192.168.200.1", "192.168.100.1/24")) {
                return 1;
	}
	if(do_test("192.168.200.1", "192.168.0.0/24")) {
		return 1;
	}
	if(do_test("192.168.200.1", "192.168.0.0/23")) {
		return 1;
	}

	return 0;
}
