#include <windows.h>
#include <stdio.h>

int portnr;
char *filename;

int READ(SOCKET sh, UCHAR *whereto, int howmuch)
{
	int pnt = 0;

#ifdef _DEBUG
	printf("read: %d bytes requested\n", howmuch);
#endif

	while(howmuch > 0)
	{
		int nread = recv(sh, (char *)&whereto[pnt], howmuch, 0);
		if (nread == 0)
			break;
		if (nread == SOCKET_ERROR)
		{
			fprintf(stderr, "Connection dropped. Error: %d\n", WSAGetLastError());
			break;
		}

		pnt += nread;
		howmuch -= nread;
	}

	return pnt;
}

int WRITE(SOCKET sh, UCHAR *wherefrom, int howmuch)
{
	int pnt = 0;

	while(howmuch > 0)
	{
		int nwritten = send(sh, (char *)&wherefrom[pnt], howmuch, 0);
		if (nwritten == 0)
			break;
		if (nwritten == SOCKET_ERROR)
		{
			fprintf(stderr, "Connection dropped. Error: %d\n", WSAGetLastError());
			break;
		}

		pnt += nwritten;
		howmuch -= nwritten;
	}

	return pnt;
}

BOOL getu32(SOCKET sh, ULONG *val)
{
	UCHAR buffer[4];

	if (READ(sh, buffer, 4) != 4)
		return FALSE;

	*val = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + (buffer[3]);

	return TRUE;
}

BOOL putu32(SOCKET sh, ULONG value)
{
	UCHAR buffer[4];

	buffer[0] = (value >> 24) & 255;
	buffer[1] = (value >> 16) & 255;
	buffer[2] = (value >>  8) & 255;
	buffer[3] = (value      ) & 255;

	if (WRITE(sh, buffer, 4) != 4)
		return FALSE;
	else
		return TRUE;
}

DWORD WINAPI draad(LPVOID data)
{
	SOCKET sockh = (SOCKET)data;
	HANDLE fh;
	char neg = 1;

	// open file 'filename'
	fh = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fh == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Error opening file %s: %d\n", filename, GetLastError());
	}

	for(;fh != INVALID_HANDLE_VALUE;)
	{
		UCHAR handle[9];
		ULONG magic, from, len, type, dummy;

		/* negotiating time? */
		if (neg)
		{
				printf("Negotiating...\n");
				if (WRITE(sockh, (unsigned char *)"NBDMAGIC", 8) != 8)
				{
					fprintf(stderr, "Failed to send magic string\n");
					break;
				}

				// some other magic value
				unsigned char magic[8];
				magic[0] = 0x00;
				magic[1] = 0x00;
				magic[2] = 0x42;
				magic[3] = 0x02;
				magic[4] = 0x81;
				magic[5] = 0x86;
				magic[6] = 0x12;
				magic[7] = 0x53;
				if (WRITE(sockh, magic, 8) != 8)
				{
					fprintf(stderr, "Failed to send 2nd magic string\n");
					break;
				}

				// send size of file
				unsigned char exportsize[8];
				DWORD fsize = GetFileSize(fh, NULL);
				if (fsize == 0xFFFFFFFF)
				{
					fprintf(stderr, "Failed to get filesize. Error: %d\n", GetLastError());
					break;
				}
				exportsize[7] = (fsize      ) & 255;
				exportsize[6] = (fsize >>  8) & 255;
				exportsize[5] = (fsize >> 16) & 255;
				exportsize[4] = (fsize >> 24) & 255;
				exportsize[3] = (fsize >> 32) & 255;
				exportsize[2] = (fsize >> 40) & 255;
				exportsize[1] = (fsize >> 48) & 255;
				exportsize[0] = (fsize >> 56) & 255;
#ifdef _DEBUG
				printf("File is %ld bytes\n", fsize);
#endif
				if (WRITE(sockh, exportsize, 8) != 8)
				{
					fprintf(stderr, "Failed to send filesize\n");
					break;
				}
				
				// send a couple of zeros */
				unsigned char buffer[128];
				memset(buffer, 0x00, 128);
				if (WRITE(sockh, buffer, 128) != 128)
				{
					fprintf(stderr, "Failed to send a couple of 0x00s\n");
					break;
				}

				printf("Started!\n");
				neg = 0;
		}

		if (getu32(sockh, &magic) == FALSE ||	// 0x12560953
			getu32(sockh, &type)  == FALSE ||	// 0=read,1=write
			READ(sockh, handle, 8) != 8    ||	// handle
			getu32(sockh, &dummy) == FALSE ||	// ... high word of offset
			getu32(sockh, &from)  == FALSE ||	// offset
			getu32(sockh, &len)   == FALSE)		// length
		{
			fprintf(stderr, "Failed to read from socket\n");
			break;
		}

#ifdef _DEBUG
		handle[8] = 0x00;
		printf("Magic:    %lx\n", magic);
		printf("Offset:   %ld\n", from);
		printf("Len:      %ld\n", len);
		printf("Handle:   %s\n", handle);
		printf("Req.type: %ld (%s)\n\n", type, type?"write":"read");
#endif

		// verify protocol
		if (magic != 0x25609513)
		{
			fprintf(stderr, "Unexpected protocol version! (got: %lx, expected: 0x25609513)\n", magic);
			break;
		}

		// seek to 'from'
		if (SetFilePointer(fh, from, NULL, FILE_BEGIN) == 0xFFFFFFFF)
		{
			fprintf(stderr, "Error seeking in file %s to position %d: %d\n", filename, from, GetLastError());
			break;
		}

		if (type == 1)	// write
		{
			while(len > 0)
			{
				DWORD dummy;
				UCHAR buffer[32768];
				// read from socket
				int nb = recv(sockh, (char *)buffer, min(len, 32768), 0);
				if (nb == 0)
					break;

				// write to file;
				if (WriteFile(fh, buffer, nb, &dummy, NULL) == 0)
				{
					fprintf(stderr, "Failed to write to %s: %d\n", filename, GetLastError());
					break;
				}
				if (dummy != nb)
				{
					fprintf(stderr, "Failed to write to %s: %d (written: %d, requested to write: %d)\n", filename, GetLastError(), dummy, nb);
					break;
				}

				len -= nb;
			}
			if (len)	// connection was closed
			{
				fprintf(stderr, "Connection was dropped while receiving data\n");
				break;
			}

			// send 'ack'
			if (putu32(sockh, 0x67446698) == FALSE ||
				putu32(sockh, 0) == FALSE ||
				WRITE(sockh, handle, 8) != 8)
			{
				fprintf(stderr, "Failed to send through socket\n");
				break;
			}
		}
		else if (type == 0)
		{
			// send 'ack'
			if (putu32(sockh, 0x67446698) == FALSE ||
				putu32(sockh, 0) == FALSE ||
				WRITE(sockh, handle, 8) != 8)
			{
				fprintf(stderr, "Failed to send through socket\n");
				break;
			}

			while(len > 0)
			{
				DWORD dummy;
				UCHAR buffer[32768];
				int nb = min(len, 32768);
				int pnt = 0;

				// read nb to buffer;
				if (ReadFile(fh, buffer, nb, &dummy, NULL) == 0)
				{
					fprintf(stderr, "Failed to read from %s: %d\n", filename, GetLastError());
					break;
				}
				if (dummy != nb)
				{
					fprintf(stderr, "Failed to read from %s: %d\n", filename, GetLastError());
					break;
				}

				// send through socket
				if (WRITE(sockh, buffer, nb) != nb) // connection was closed
				{
					fprintf(stderr, "Connection dropped while sending block\n");
					break;
				}

				len -= nb;
			}
			if (len)	// connection was closed
				break;
		}
		else
		{
			printf("Unexpected commandtype: %d\n", type);
			break;
		}
	}

	// close file
	if (CloseHandle(fh) == 0)
	{
		fprintf(stderr, "Failed to close handle: %d\n", GetLastError());
	}

	closesocket(sockh);

	ExitThread(0);

	return 0;
}
	
int main(int argc, char *argv[])
{
	SOCKET newconnh;
	WSADATA WSAData;

	printf("nbdsrvr v0.1, (C) 2003 by folkert@vanheusden.com\n");

	if (argc != 3)
	{
		fprintf(stderr, "Usage: %s file portnr\n", argv[0]);
		return 1;
	}
	filename = argv[1];
	portnr = atoi(argv[2]);

	// initialize WinSock library
	(void)WSAStartup(0x101, &WSAData); 
 	
	// create listener socket
	newconnh= socket(AF_INET, SOCK_STREAM, 0);
	if (newconnh == INVALID_SOCKET)
		return -1;

	// bind
	struct sockaddr_in      ServerAddr;
	int     ServerAddrLen;
	ServerAddrLen = sizeof(ServerAddr);
	memset((char *)&ServerAddr, '\0', ServerAddrLen);
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	ServerAddr.sin_port = htons(portnr);
	if (bind(newconnh, (struct sockaddr *)&ServerAddr, ServerAddrLen) == -1)
		return -1;

	// listen
	if (listen(newconnh, 5) == -1)
		return -1;

	for(;;)
	{
		SOCKET clienth;
		struct sockaddr_in      clientaddr;
		int     clientaddrlen;

		clientaddrlen = sizeof(clientaddr);

		/* accept a connection */
		clienth = accept(newconnh, (struct sockaddr *)&clientaddr, &clientaddrlen);

		if (clienth != INVALID_SOCKET)
		{
			printf("Connection made with %s\n", inet_ntoa(clientaddr.sin_addr));

			DWORD tid;
			HANDLE th = CreateThread(NULL, 0, draad, (void *)clienth, 0, &tid);
		}
	}

	return 0;
}
