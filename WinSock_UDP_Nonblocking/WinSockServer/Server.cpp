#include <winsock2.h>
#include <stdio.h>

#define no_init_all deprecated
#define SERVER_PORT 15000
#define SERVER_SLEEP_TIME 50
#define ACCESS_BUFFER_SIZE 2048
#define IP_ADDRESS_LEN 16


struct Grupa
{
	int procesi[10];
	int brClanova = 0;
	int brojac = 0;
};
struct Proces
{
	int grupa;
	int port;
};
struct Node
{
	char *data;
	struct Node *next;
};

struct queue
{
	struct Node *top;
	struct Node *bottom;
}*q;

int iResult;
// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();
void Write(char *x, queue *q);
char* Read();
int posalji(queue *q, Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen);
bool Poruka(char* accessBuffer);

int main(int argc,char* argv[])
{
    // Server address
    sockaddr_in serverAddress;
	// Server's socket
    int serverPort = SERVER_PORT;
	// size of sockaddr structure
    int sockAddrLen=sizeof(struct sockaddr);
	// buffer we will use to receive client message
    char accessBuffer[ACCESS_BUFFER_SIZE];
	// variable used to store function return value
//	int iResult;
	char mqueue[1000][1000];
	Grupa grupe[10];
	Proces procesi[10];
	int brClanova = 0;
	int groupNmb = 0;
	queue red[10];
	red[0].bottom = NULL;
	red[0].top = NULL;
	Node *node;
	/*
	j	
i	1 2 3 4
	5 6 7 8
	9 1 1 2
	
	
	*/
    if(InitializeWindowsSockets() == false)
	{
        // we won't log anything since it will be logged
        // by InitializeWindowsSockets() function
        return 1;
    }

    // Initialize serverAddress structure used by bind
    memset((char*)&serverAddress,0,sizeof(serverAddress));
    serverAddress.sin_family = AF_INET; /*set server address protocol family*/
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(serverPort);

    // create a socket
    SOCKET serverSocket = socket(AF_INET,      // IPv4 address famly
								 SOCK_DGRAM,   // datagram supporting socket
								 IPPROTO_UDP); // UDP

	// check if socket creation succeeded
    if (serverSocket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Bind port number and local address to socket
    iResult = bind(serverSocket,(LPSOCKADDR)&serverAddress,sizeof(serverAddress));

    if (iResult == SOCKET_ERROR)
    {
        printf("Socket bind failed with error: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Set socket to nonblocking mode
    unsigned long int nonBlockingMode = 1;
    iResult = ioctlsocket( serverSocket, FIONBIO, &nonBlockingMode );

    if (iResult == SOCKET_ERROR)
    {
        printf("ioctlsocket failed with error: %ld\n", WSAGetLastError());
        return 1;
    }

	printf("Simple UDP server started and waiting clients.\n");

    // Main server loop
    while(1)
    {
        // clientAddress will be populated from recvfrom
        sockaddr_in clientAddress;
		memset(&clientAddress, 0, sizeof(sockaddr_in));

		// set whole buffer to zero
        memset(accessBuffer, 0, ACCESS_BUFFER_SIZE);

        // Initialize select parameters
        FD_SET set;
        timeval timeVal;

        FD_ZERO( &set );
		// Add socket we will wait to read from
        FD_SET( serverSocket, &set );

        // Set timeouts to zero since we want select to return
        // instantaneously
        timeVal.tv_sec = 0;
        timeVal.tv_usec = 0;

        iResult = select( 0 /* ignored */, &set, NULL, NULL, &timeVal );

        // lets check if there was an error during select
        if( iResult == SOCKET_ERROR )
        {
            fprintf(stderr,"select failed with error: %ld\n", WSAGetLastError());
            continue;
        }

        // now, lets check if there are any sockets ready
        if( iResult == 0 )
        {
            // there are no ready sockets, sleep for a while and check again
            Sleep( SERVER_SLEEP_TIME );
            continue;
        }

        iResult = recvfrom(serverSocket,
                           accessBuffer,
                           ACCESS_BUFFER_SIZE,
                           0,
                           (LPSOCKADDR)&clientAddress,
                           &sockAddrLen);
		//printf("%s ACCes buffed\n", accessBuffer);
		
		int i = 0;
		//ovde pravi problem posle slanja poruka!!
        if (iResult == SOCKET_ERROR)
        {
            printf("recvfrom failed with error: %d\n", WSAGetLastError());
            continue;
        }
		
		if (strcmp(accessBuffer, "NEW_GROUP") == 0)
		{
			printf("Nova grupa\n");
			grupe[groupNmb].brClanova++;

			//printf("NOVA GRUPA/n");
			
			int clientPort = ntohs((u_short)clientAddress.sin_port);
			procesi[i].port = clientPort;
			i++;
			procesi[i].grupa = groupNmb;
			int brojac = grupe[groupNmb].brojac;
			grupe[groupNmb].procesi[brojac] = clientPort;
			grupe[groupNmb].brojac++;

			groupNmb++;
			// TODO dodaj novu grupu
		}
		else if (strcmp(accessBuffer, "RETURN_GROUPS") == 0)
		{
			//printf("Return groups\n");
			//printf("Lista");
			char a[10];
			itoa(groupNmb, a, 10);


			iResult = sendto(serverSocket,
				a,
				strlen(a),
				0,
				(LPSOCKADDR)&clientAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(serverSocket);
				WSACleanup();
				return 1;
			}
			/*
			recive koja grupa je izabrana
			*/
		}
		else if (strcmp(accessBuffer, "DQ") == 0)
		{
			int clientPort = ntohs((u_short)clientAddress.sin_port);
			for (int i = 0; i < 1000; i++)
			{
				if (procesi[i].port == clientPort)
				{
					grupe[procesi[i].grupa].brClanova--;
					// izbrisi proces iz liste
					// ako je broj clanva postao nula izbrisi grupu iz niza "grupe"
				}
			}
		}
		//prima poruke
		else if (Poruka(accessBuffer))
		{
			printf("PRIMI I SALJE \n");
			char ipAddress[IP_ADDRESS_LEN];
			// copy client ip to local char[]
			strcpy_s(ipAddress, sizeof(ipAddress), inet_ntoa(clientAddress.sin_addr));

			// convert port number from TCP/IP byte order to
			// little endian byte order
			int clientPort = ntohs((u_short)clientAddress.sin_port);

			printf("Client connected from ip: %s, port: %d, sent: %s.\n", ipAddress, clientPort, accessBuffer);

			//TODO u koji que da upise

			//pisanje u que
			Write(accessBuffer, &red[0]);

			/*clientAddress.sin_port = htons((u_short)grupe->procesi[0]);
			iResult = sendto(serverSocket,
				red->top->data,
				strlen(red->top->data),
				0,
				(LPSOCKADDR)&clientAddress,
				sockAddrLen);*/
			//thread da salje svima
			int dobro;
			dobro = posalji(&red[0], grupe[0], serverSocket, clientAddress, sockAddrLen);
		}
		//ubacuje u izabranu grupu
		else
		{
			char ipAddress[IP_ADDRESS_LEN];
			// copy client ip to local char[]
			strcpy_s(ipAddress, sizeof(ipAddress), inet_ntoa(clientAddress.sin_addr));
			// convert port number from TCP/IP byte order to
			// little endian byte order
			int br = atoi(accessBuffer);
			printf("%d\n", br);

			int clientPort = ntohs((u_short)clientAddress.sin_port);
			grupe[br].brClanova++;
			grupe[br].procesi[grupe[br].brojac] = clientPort;
			grupe[br].brojac++;
			
		}


		// possible server-shutdown logic could be put here
    }

    // if we are here, it means that server is shutting down
	// close socket and unintialize WinSock2 library
    iResult = closesocket(serverSocket);
    if (iResult == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    iResult = WSACleanup();
    if (iResult == SOCKET_ERROR)
    {
        printf("WSACleanup failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    printf("Server successfully shut down.\n");
    return 0;
}

bool Poruka(char* accessBuffer)
{
	int count = 0;
	char p[7] = "Poruka";
	for (int i = 0; i < 6; i++)
	{
		if (accessBuffer[i] == p[i])
			count++;
	}
	//printf("%d COUNT", count);
	if (count == 6)
		return true;
	return false;
}


//posalji svim klijentima u grupi
int posalji(queue *q, Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen)
{
	//int iResult;
	for (int i = 0; i < g.brClanova; i++)
	{
		//linija ispod nece da se izvrsi nekim cudom wtf
		//printf("Na adresu: %i\n", g.procesi[i]);
		clientAddress.sin_port = htons((u_short)g.procesi[0]);
		printf("saljem klijentima: %s\n", q->top->data);
		printf("Na adresu: %i\n", clientAddress.sin_port);
		/*iResult = sendto(serverSocket,
				a,
				strlen(a),
				0,
				(LPSOCKADDR)&clientAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(serverSocket);
				WSACleanup();
				return 1;
			}*/
		iResult = sendto(serverSocket,
			q->top->data,
			strlen(q->top->data),
			0,
			(LPSOCKADDR)&clientAddress,
			sockAddrLen);

		if (iResult == SOCKET_ERROR)
		{
			printf("sendto failed with error: %d\n", WSAGetLastError());
			closesocket(serverSocket);
			WSACleanup();
			return 1;
		}
		printf("Poslao poruku klijentu\n");
	}
}

void Write(char *x, queue *q)
{
	Node *ptr = (Node*)malloc(sizeof(Node));
	if (ptr == NULL)
	{
		printf("GRESKA KOD PTR");
	}
	ptr->data = (char*)malloc(strlen(x) + 1);
	strcpy(ptr->data, x);
	ptr->next = NULL;
	if (q->top == NULL && q->bottom == NULL)
	{
		q->top = q->bottom = ptr;
	}
	else
	{
		q->top->next = ptr;
		q->top = ptr;
	}
}

char* Read()
{
	if (q->bottom == NULL)
	{
		printf("Empty QUEUE!");
		return 0;
	}
	struct Node *ptr = (Node*)malloc(sizeof(struct Node));
	ptr = q->bottom;
	if (q->top == q->bottom)
	{
		q->top = NULL;
	}
	q->bottom = q->bottom->next;
	char *x = ptr->data;
	free(ptr);
	return x;
}


bool InitializeWindowsSockets()
{
    WSADATA wsaData;
	// Initialize windows sockets library for this process
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return false;
    }
	return true;
}
/*



*/