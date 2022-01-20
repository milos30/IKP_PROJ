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
	//int* klijenti;

	int brClanova = 0;	// koliko grupa ima clanova
	int brojGrupe = 0;	// broj Grupe
	struct queue *q;    // red grupe 
	struct Grupa *next;			//pokazivac za sledeci
}GRUPE;
typedef struct Proces
{
	int port;
	int grupa;
	struct Proces *sledeci;
}PROCES;
/*struct Node
{
	char *data;
	struct queue *next;
};*/
typedef struct queue {
	char *data;
	struct queue* next;
} QUEUE;
/*typedef struct queue
{
	struct Node *top;
	struct Node *bottom;
}QUEUE;*/

int iResult;
// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();
void Write(char *x, queue **q);
void Read(queue **q);
int posalji(Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen, int brojKorisnika, PROCES *p);
bool Poruka(char* accessBuffer);
void dodaj_grupu_u_listu(GRUPE* grupa, GRUPE** pocetak);
GRUPE *nadji_grupu(int br, GRUPE *pocetak);
int nadji_broj_grupe(int port, PROCES *lista_procesa_pocetak, int groupnmb);
void dodaj_proces_u_listu(Proces *novi_proces, PROCES **lista_procesa_pocetak);
int obrisi_korisnika(PROCES *lista_procesa_pocetak, int clientPort);
void obrisi_grupu(GRUPE **trenutna, GRUPE *pocetak);
void obrisi_que_grupe(QUEUE **q);

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


	Grupa *niz_grupa_pocetak = NULL; // mozda nece trebati?
	niz_grupa_pocetak = NULL;
	Proces *lista_procesa_pocetak = NULL;
	int brClanova = 0;
	int groupNmb = 1;


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
			novi_q->data = NULL;
			novi_q->next = NULL;
			nova_grupa->q = novi_q;
			nova_grupa->brojGrupe = groupNmb;
			nova_grupa->next = NULL;

			// eventualno ovaj blok koda ispod malo izmeniti za vise klijenata, ne znam glup je c dosta
			int clientPort = ntohs((u_short)clientAddress.sin_port);
			/*nova_grupa->klijenti = new int;
			int port_klijenta = clientPort;
			nova_grupa->klijenti[0] = port_klijenta;*/
			
			dodaj_grupu_u_listu(nova_grupa, &niz_grupa_pocetak); //ne zaboravi da obrises grupe na kraju

			//da li isto i za procese uraditi??
			PROCES* novi_proces = (PROCES*)malloc(sizeof(PROCES));
			novi_proces->port = clientPort;
			novi_proces->sledeci = NULL;
			novi_proces->grupa = groupNmb;
			dodaj_proces_u_listu(novi_proces, &lista_procesa_pocetak);
			
			//*(niz_grupa + (groupNmb-1)*sizeof(GRUPE)) = *nova_grupa;
			brProcesa++; // dali nam ovo sad treba? mislim da ne

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
			int clientPort = ntohs((u_short)clientAddress.sin_port);  // uzmemo klijent port

			Grupa* trenutna;
			int broj_grupe_brisanog_korisnika = 0;
			broj_grupe_brisanog_korisnika = obrisi_korisnika(lista_procesa_pocetak, clientPort);
			trenutna = nadji_grupu(broj_grupe_brisanog_korisnika, niz_grupa_pocetak);
			trenutna->brClanova--;
			if (trenutna->brClanova == 0)
			{
				obrisi_grupu(&trenutna, niz_grupa_pocetak);
			}

			brProcesa--;
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
			trenutnaGrupa = nadji_broj_grupe(clientPort, lista_procesa_pocetak, groupNmb-1);
			trenutna = nadji_grupu(trenutnaGrupa, niz_grupa_pocetak);

			//pisanje u queue
			Write(accessBuffer,&trenutna->q);
			
			int dobro;
			dobro = posalji(*trenutna, serverSocket, clientAddress, sockAddrLen, brProcesa, lista_procesa_pocetak);

		}
		//ubacuje u izabranu grupu
		else
		{
			int br = atoi(accessBuffer);	// uzimamo broj grupe
			printf("%d\n", br);

			int clientPort = ntohs((u_short)clientAddress.sin_port);  // uzmemo klijent port

			Grupa *trenutna;
			trenutna = nadji_grupu(br, niz_grupa_pocetak);		
			trenutna->brClanova++;


			//int clientPort = ntohs((u_short)clientAddress.sin_port);
			PROCES* novi_proces = (PROCES*)malloc(sizeof(PROCES));
			novi_proces->port = clientPort;
			novi_proces->sledeci = NULL;
			novi_proces->grupa = br;
			dodaj_proces_u_listu(novi_proces, &lista_procesa_pocetak);
			brProcesa++;	
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

//(Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen, int brProcesa, PROCES *p)
//posalji svim klijentima u grupi
int posalji(Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen, int brojKorisnika, Proces *p)
{
	Proces *temp = p;
	int iResult;
	//printf("Prije fora\n");
	for (int i = 0; i < brojKorisnika; i++)
	{
		if (!(temp->grupa == g.brojGrupe))
		{
			temp = temp->sledeci;
			continue;
		}

		clientAddress.sin_port = htons((u_short)temp->port);
		
		//printf("saljem klijentima: %s\n", q->top->data);
		printf("Na adresu: %i\n", clientAddress.sin_port);
		printf("Posalje q->bottom %s\n", g.q->data);
		iResult = sendto(serverSocket,
			g.q->data,
			strlen(g.q->data),
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
		temp = temp->sledeci;
	}
	Read(&g.q);

}

void Write(char* val, queue** head) {
	queue* new_node = (queue*)malloc(sizeof(queue));
	if (!new_node) return;

	new_node->data = val;
	new_node->next = *head;

	*head = new_node;
}

void Read(queue** head) {
	queue* current, * prev = NULL;
	//int retval = -1;

	//if (*head == NULL) return -1;

	current = *head;
	while (current->next != NULL) {
		prev = current;
		current = current->next;
	}

	//retval = current->data;
	free(current);

	if (prev)
		prev->next = NULL;
	else
		*head = NULL;

	//return retval;
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

int nadji_broj_grupe(int port, PROCES* lista_procesa_pocetak, int groupnmb)
{
	int retval;
	Proces* temp = lista_procesa_pocetak;
	while (temp != NULL)
	{
		if (temp->port == port)
		{
			retval = temp->grupa;
			return retval;
		}
		temp = temp->sledeci;
		continue;
	}
	return retval;
}

void dodaj_proces_u_listu(Proces* novi_proces, PROCES** lista_procesa_pocetak)
{
	if (*lista_procesa_pocetak == NULL) {
		*lista_procesa_pocetak = novi_proces;
	}
	else {
		Proces* tekuci = *lista_procesa_pocetak;

		while (tekuci->sledeci != NULL) {
			tekuci = tekuci->sledeci;
		}

		tekuci->sledeci = novi_proces;
	}
}

int obrisi_korisnika(PROCES* lista_procesa_pocetak, int clientPort)
{
	Proces* temp, * previous;
	temp = previous = lista_procesa_pocetak;
	int broj_grupe = 0;
	while (1)
	{
		if (temp->port == clientPort)
		{
			broj_grupe = temp->grupa;
			previous->sledeci = temp->sledeci;
			free(temp);
			temp = NULL;
			return broj_grupe;
		}
		else
		{
			previous = temp;
			temp = temp->sledeci;
		}
	}
	//return broj_grupe;
}

void obrisi_grupu(GRUPE** trenutna, GRUPE *pocetak)
{
	obrisi_que_grupe(&(*trenutna)->q);
	GRUPE* temp, * previous;
	temp = previous = pocetak;
	while (1)
	{
		if (temp == *trenutna)
		{
			temp->brClanova = 0;
			temp->brojGrupe = 0;
			previous->next = temp->next;
			temp->next = NULL;
			temp->q = NULL;
			free(temp);
			temp = NULL;
			break;
		}
		else
		{
			previous = temp;
			temp = temp->next;
		}
	}
}

void obrisi_que_grupe(QUEUE** q)
{
	QUEUE *temp;

	while (*q != NULL)
	{
		temp = *q;
		*q = (*q)->next;
		temp->next = NULL;
		free(temp);
	}
}