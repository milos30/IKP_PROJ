#include <winsock2.h>
#include <stdio.h>

#define no_init_all deprecated
#define SERVER_PORT 15000
#define SERVER_SLEEP_TIME 50
#define ACCESS_BUFFER_SIZE 2048
#define IP_ADDRESS_LEN 16


typedef struct Grupa
{
	//struct PROCES* klijenti;
	int* klijenti;

	int brClanova = 0;	// koliko grupa ima clanova
	int brojGrupe = 0;	// broj Grupe
	struct queue *q;    // red grupe 
	struct Grupa *next;			//pokazivac za sledeci
}GRUPE;
typedef struct Proces
{
	int grupa;
	int port;
}PROCES;
struct Node
{
	char *data;
	struct Node *next;
};

typedef struct queue
{
	struct Node *top;
	struct Node *bottom;
}QUEUE;

int iResult;
// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();
void Write(char *x, queue *q);
char* Read(queue *q);
int posalji(Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen);
bool Poruka(char* accessBuffer);
void dodaj_grupu_u_listu(GRUPE* grupa, GRUPE** pocetak);
GRUPE *nadji_grupu(int br, GRUPE *pocetak);
int nadji_broj_grupe(int port, GRUPE *niz_grupa_pocetak, int groupnmb);

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
	//
	// 
	//
	Grupa *niz_grupa_pocetak; // mozda nece trebati?
	niz_grupa_pocetak = NULL;
	Proces *procesi;
	int brClanova = 0;
	int groupNmb = 1;
//	queue red[10];
	//red[0].bottom = NULL;
	//red[0].top = NULL;
	//Node *node;
	int brProcesa = 0;
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
			//niz_grupa_pocetak = new Grupa;  // mozda nece trebati?
			GRUPE* nova_grupa = (GRUPE *)malloc(sizeof(GRUPE));
			nova_grupa->brClanova = 1;

			QUEUE* novi_q = (QUEUE*)malloc(sizeof(QUEUE));
			novi_q->bottom = NULL;
			novi_q->top = NULL;
			nova_grupa->q = novi_q;
			nova_grupa->brojGrupe = groupNmb;
			nova_grupa->next = NULL;

			// eventualno ovaj blok koda ispod malo izmeniti za vise klijenata, ne znam glup je c dosta
			int clientPort = ntohs((u_short)clientAddress.sin_port);
			nova_grupa->klijenti = new int;
			int port_klijenta = clientPort;
			nova_grupa->klijenti[0] = port_klijenta;
			
			dodaj_grupu_u_listu(nova_grupa, &niz_grupa_pocetak); //ne zaboravi da obrises grupe na kraju

			//da li isto i za procese uraditi??
			procesi = new Proces;
			PROCES* novi_proces = (PROCES*)malloc(sizeof(PROCES));
			novi_proces->port = clientPort;
			novi_proces->grupa = groupNmb;
			
			
			//*(niz_grupa + (groupNmb-1)*sizeof(GRUPE)) = *nova_grupa;
			*(procesi + brProcesa * sizeof(Proces)) = *novi_proces;
			brProcesa++;

			groupNmb++;
		}
		else if (strcmp(accessBuffer, "RETURN_GROUPS") == 0)
		{
			printf("Return groups\n");

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
			recive koja grupa je izabrana je u poslednjem else..
			*/
		}
		else if (strcmp(accessBuffer, "DQ") == 0)
		{
			int clientPort = ntohs((u_short)clientAddress.sin_port);
			for (int i = 0; i < 1000; i++)
			{
			//	if (procesi[i].port == clientPort)
				{
					//grupe[procesi[i].grupa].brClanova--;
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
			int trenutnaGrupa = -1;
			Grupa* trenutna;
			trenutnaGrupa = nadji_broj_grupe(clientPort, niz_grupa_pocetak, groupNmb-1);
			trenutna = nadji_grupu(trenutnaGrupa, niz_grupa_pocetak);

			/*//TODO u koji que da upise
			for (int i = 0; i < brProcesa; i++)
			{
				if (clientPort == procesi[i].port)
				{
					trenutnaGrupa = procesi[i].grupa;
					break;
				}
				else
					printf("Klijent nije ubacen u grupu\n");
			}*/

			//pisanje u queue
			Write(accessBuffer,trenutna->q);

			
			int dobro;
			dobro = posalji(*trenutna, serverSocket, clientAddress, sockAddrLen);

		}
		//ubacuje u izabranu grupu
		else
		{
			int br = atoi(accessBuffer);	// uzimamo broj grupe
			printf("%d\n", br);

			int clientPort = ntohs((u_short)clientAddress.sin_port);  // uzmemo klijent port
			Grupa *trenutna;

			//for (int i = 0; i <= groupNmb; i++)
			{
				trenutna = nadji_grupu(br, niz_grupa_pocetak);
			}
			
			trenutna->brClanova++;
			//int clientPort = ntohs((u_short)clientAddress.sin_port);


			// ovde ne radi ovo najbolje, problem je sto new int ne napravi novo mesto u redu nego nzm ni ja,
			// c je dosta glup za ove stvari iskreno
			trenutna->klijenti = new int;
			int port_klijenta = clientPort;
			trenutna->klijenti[brClanova - 1] = port_klijenta;
			/*//for nije dobar, unutra tek nista
			for (int i = 1; i <= groupNmb; i++)
			{
				if (niz_grupa->brojGrupe == br)
				{
					niz_grupa[br-1].brClanova++;
					niz_grupa[br-1].klijenti[brClanova-1] = clientPort;

					procesi = new Proces;
					PROCES* novi_proces = (PROCES*)malloc(sizeof(PROCES));
					novi_proces->port = clientPort;
					novi_proces->grupa = br;
					procesi[brProcesa] = *novi_proces;
					brProcesa++;
				}
			}		*/	
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
int posalji(Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen)
{
	int iResult;
	printf("Prije fora\n");
	for (int i = 0; i < g.brClanova; i++)
	{
		clientAddress.sin_port = htons((u_short)g.klijenti[i]);
		
		//printf("saljem klijentima: %s\n", q->top->data);
		printf("Na adresu: %i\n", clientAddress.sin_port);
		printf("Posalje q->bottom %s\n", g.q->bottom->data);
		iResult = sendto(serverSocket,
			g.q->bottom->data,
			strlen(g.q->bottom->data),
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
	Read(g.q);

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
	printf("Sta je upisao %s\n", q->bottom->data);
}

char* Read(queue *q)
{
	if (q->bottom== NULL)
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

void dodaj_grupu_u_listu(GRUPE* grupa, GRUPE** pocetak) 
{
	if (*pocetak == NULL)
	{
		*pocetak = grupa;
		return;
	}

	dodaj_grupu_u_listu(grupa, &((*pocetak)->next));
}

GRUPE *nadji_grupu(int br, GRUPE* pocetak)
{
	Grupa *retval;
	if ((pocetak)->brojGrupe == br)
	{
		retval = pocetak;
		return retval;
	}

	else
	{
		nadji_grupu(br, ((pocetak)->next));
	}
}

int nadji_broj_grupe(int port, GRUPE* pocetak, int groupnmb)
{
	int retval;
	for (int j = 0; j < groupnmb; j++)
	{
		for (int i = 0; i < (pocetak)->brClanova; i++)
		{
			if ((pocetak)->klijenti[i] == port)
			{
				retval = (pocetak)->brojGrupe;
				return retval;
			}
		}
		pocetak = (pocetak)->next;
	}
}