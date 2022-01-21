#include <winsock2.h>
#include <stdio.h>
#include <Windows.h>
#include <conio.h>
#define no_init_all deprecated
#define SERVER_PORT 15000
#define SERVER_SLEEP_TIME 50
#define ACCESS_BUFFER_SIZE 2048
#define IP_ADDRESS_LEN 16


typedef struct Grupa
{
	int brClanova = 0;			   // koliko grupa ima clanova
	int brojGrupe = 0;		  	  // broj Grupe
	struct queue *q;			 // red grupe 
	struct Grupa *next;			//pokazivac za sledeci
}GRUPE;
typedef struct Proces
{
	int port;
	int grupa;
	struct Proces *sledeci;
}PROCES;
typedef struct queue {
	char *data;
	struct queue* next;
} QUEUE;

typedef struct New_group {
	Grupa** g;
	Proces** p;
	int groupnmb;
	int brprocesa;
	SOCKET serverSocket;
	sockaddr_in clientadres;
};

typedef struct Insert_into_group {
	int br;
	sockaddr_in clientAdress;
	Grupa* g;
	Proces** p;
}INSERT;

typedef struct Get_mess {
	int clientPort;
	Grupa* g;
	PROCES* p;
	int groupnmb;
	char* Accssesbuf;
}GETMESS;

Grupa* trenutna_grupa = (Grupa*)malloc(sizeof(Grupa));

//(Grupa g, SOCKET serverSocket, sockaddr_in clientAddress, int sockAddrLen, int brojKorisnika, Proces *p)
typedef struct Send_mess {
	SOCKET serverSocket;
	sockaddr_in clientadres;
	int sockaddrlen;
	int brojKorisnika;
	Proces* p;
}SENDMESS;

typedef struct Discon {
	int clientPort;
	GRUPE* g;
	Proces** p;
}DC;
int iResult;
CRITICAL_SECTION cs;
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
int obrisi_korisnika(PROCES **lista_procesa_pocetak, int clientPort);
void obrisi_grupu(GRUPE **trenutna, GRUPE *pocetak);
void obrisi_que_grupe(QUEUE **q);
void ocisti_memoriju_grupe(GRUPE** g);
void ocisti_memoriju_procesa(Proces** p);
DWORD WINAPI New_Group(LPVOID lpParam);
DWORD WINAPI Insert_into_group(LPVOID lpParam);
DWORD WINAPI Get_message(LPVOID lpParam);
DWORD WINAPI Send_message(LPVOID lpParam);
DWORD WINAPI Disconnect(LPVOID lpParam);

int main(int argc,char* argv[])
{
	InitializeCriticalSection(&cs);
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

	DWORD dNew_group, dPrimi_poruku, dUbaci_u_izabranu_grupu, dPosalji_poruku, dDiskonekt;
	HANDLE hNew_group, hPrimi_poruku, hUbaci_u_izabranu_grupu, hPosalji_poruku, hDiskonekt;
	bool New, Poslato, Dodato, Primljeno, Diskonektovao;
	New = Poslato = Dodato = Primljeno = Diskonektovao = false;

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
			New = true;
			//ime funkcije treba promeniti i parametre
			New_group* values = (New_group*)malloc(sizeof(New_group));
			values->brprocesa = brProcesa;
			values->g = &niz_grupa_pocetak;
			values->groupnmb = groupNmb;
			values->p = &lista_procesa_pocetak;
			values->serverSocket = serverSocket;
			values->clientadres = clientAddress;
			
			hNew_group = CreateThread(NULL, 0, &New_Group, values, 0, &dNew_group);
			//CloseHandle(hRecive);
			Sleep(500);
			free(values);
			printf("zavrsio nit");
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
			int clientPort = ntohs((u_short)clientAddress.sin_port);  // uzmemo klijent port

			DC* val = (DC*)malloc(sizeof(DC));
			val->clientPort = clientPort;
			val->g = niz_grupa_pocetak;
			val->p = &lista_procesa_pocetak;


			hDiskonekt = CreateThread(NULL, 0, &Disconnect, val, 0, &dDiskonekt);
			Sleep(300);
			Diskonektovao = true;
			free(val);
			brProcesa--;
		}
		//prima poruke
		else if (strcmp(accessBuffer, "SERVER_SHUT_DOWN") == 0)
		{
			break;
		}
		else if (Poruka(accessBuffer))
		{
			printf("PRIMI I SALJE \n");
			char ipAddress[IP_ADDRESS_LEN];
			strcpy_s(ipAddress, sizeof(ipAddress), inet_ntoa(clientAddress.sin_addr));
			int clientPort = ntohs((u_short)clientAddress.sin_port);
			printf("Client connected from ip: %s, port: %d, sent: %s.\n", ipAddress, clientPort, accessBuffer);

			//Grupa* trenutna = NULL;
			GETMESS* values = (GETMESS*)malloc(sizeof(GETMESS));
			values->Accssesbuf = accessBuffer;
			values->clientPort = clientPort;
			values->g = niz_grupa_pocetak;
			values->p = lista_procesa_pocetak;
			values->groupnmb = groupNmb-1;
			Primljeno = true;

			hPrimi_poruku = CreateThread(NULL, 0, &Get_message, values, 0, &dPrimi_poruku);		
			/*int trenutnaGrupa = -1;
			Grupa* trenutna;
			trenutnaGrupa = nadji_broj_grupe(clientPort, lista_procesa_pocetak, groupNmb - 1);
			trenutna = nadji_grupu(trenutnaGrupa, niz_grupa_pocetak);

			//pisanje u queue
			Write(accessBuffer, &trenutna->q);*/
			Sleep(3000);
			free(values);
			
			SENDMESS* val = (SENDMESS*)malloc(sizeof(SENDMESS));
			val->brojKorisnika = brProcesa;
			val->clientadres = clientAddress;
			val->p = lista_procesa_pocetak;
			val->serverSocket = serverSocket;
			val->sockaddrlen = sockAddrLen;
			printf("--------------PRE KREIRANJA THREDA %s\n", trenutna_grupa->q->data);
			hPosalji_poruku = CreateThread(NULL, 0, &Send_message, val, 0, &dPosalji_poruku);
			//printf("--------------POSLE KREIRANJA THREDA %s\n", trenutna_grupa->q->data);
			//int dobro;
			Poslato = true;
			//dobro = posalji(*trenutna_grupa, serverSocket, clientAddress, sockAddrLen, brProcesa, lista_procesa_pocetak);
			Sleep(3000);
			free(val);
		}
		//ubacuje u izabranu grupu
		else
		{
			Dodato = true;
			int br = atoi(accessBuffer);	// uzimamo broj grupe
			printf("%d\n", br);
			INSERT* values = (INSERT*)malloc(sizeof(INSERT));
			values->br = br;
			values->clientAdress = clientAddress;
			values->g = niz_grupa_pocetak;
			values->p = &lista_procesa_pocetak;
			hUbaci_u_izabranu_grupu = CreateThread(NULL, 0, &Insert_into_group, values, 0, &dUbaci_u_izabranu_grupu);
			Sleep(500);
			free(values);
			printf("Nit za dodavanje u grupu");
			brProcesa++;	
		}
		// possible server-shutdown logic could be put here
    }
	if (Poslato)
		CloseHandle(hPosalji_poruku);
	if (Primljeno)
		CloseHandle(hPrimi_poruku);
	if (New)
		CloseHandle(hNew_group);
	if (Dodato)
		CloseHandle(hUbaci_u_izabranu_grupu);
	if (Diskonektovao)
		CloseHandle(hDiskonekt);
	ocisti_memoriju_grupe(&niz_grupa_pocetak);
	ocisti_memoriju_procesa(&lista_procesa_pocetak);
	getch();
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

	//free(trenutna_grupa);
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
	printf("Posalje q->bottom %s\n", trenutna_grupa->q->data);
	printf("%i\n", brojKorisnika);
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
		printf("Posalje q->bottom %s\n", trenutna_grupa->q->data);
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

int obrisi_korisnika(PROCES** lista_procesa_pocetak, int clientPort)
{
	Proces* temp, * previous;
	temp = previous = *lista_procesa_pocetak;
	int broj_grupe = 0;
	while (1)
	{
		if (temp->port == clientPort)
		{
			broj_grupe = temp->grupa;
			previous->sledeci = temp->sledeci;
			if (temp->sledeci != NULL)
			{
				*lista_procesa_pocetak = temp->sledeci;
			}
			//temp = temp->sledeci;
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
	QUEUE* temp;

	while (*q != NULL)
	{
		temp = *q;

		*q = (*q)->next;
			temp->next = NULL;
			free(temp);

	}

/*	if (*q == NULL)
	{
		return;
	}
	obrisi_que_grupe(&(*q)->next);
	free(*q);
	*q = NULL;*/
}

DWORD WINAPI New_Group(LPVOID lpParam)
{
	New_group *values = (New_group*)lpParam;

	GRUPE* nova_grupa = (GRUPE*)malloc(sizeof(GRUPE));
	nova_grupa->brClanova = 1;

	QUEUE* novi_q = (QUEUE*)malloc(sizeof(QUEUE));
	novi_q->data = NULL;
	novi_q->next = NULL;
	nova_grupa->q = novi_q;
	nova_grupa->brojGrupe = values->groupnmb;
	nova_grupa->next = NULL;


	int clientPort = ntohs((u_short)values->clientadres.sin_port);
	EnterCriticalSection(&cs);
	dodaj_grupu_u_listu(nova_grupa, values->g);
	LeaveCriticalSection(&cs);

	PROCES* novi_proces = (PROCES*)malloc(sizeof(PROCES));
	novi_proces->port = clientPort;
	novi_proces->sledeci = NULL;
	novi_proces->grupa = values->groupnmb;
	EnterCriticalSection(&cs);
	dodaj_proces_u_listu(novi_proces, (values->p));
	LeaveCriticalSection(&cs);
	return 0;
}

DWORD WINAPI Insert_into_group(LPVOID lpParam) 
{
	INSERT* values = (INSERT*)lpParam;

	int br = values->br;
	int clientPort = ntohs((u_short)values->clientAdress.sin_port);  // uzmemo klijent port

	Grupa* trenutna;
	trenutna = nadji_grupu(br, values->g);
	trenutna->brClanova++;


	PROCES* novi_proces = (PROCES*)malloc(sizeof(PROCES));
	novi_proces->port = clientPort;
	novi_proces->sledeci = NULL;
	novi_proces->grupa = br;
	EnterCriticalSection(&cs);
	dodaj_proces_u_listu(novi_proces, values->p);
	LeaveCriticalSection(&cs);
	return 0;
}

DWORD WINAPI Get_message(LPVOID lpParam)
{
	GETMESS* values = (GETMESS*)lpParam;
	int trenutnaGrupa = -1;
	EnterCriticalSection(&cs);
	trenutnaGrupa = nadji_broj_grupe(values->clientPort, values->p, values->groupnmb - 1);
	trenutna_grupa = nadji_grupu(trenutnaGrupa, values->g);

	//pisanje u queue
	Write(values->Accssesbuf, &trenutna_grupa->q);
	LeaveCriticalSection(&cs);
	return 0;
}

DWORD WINAPI Send_message(LPVOID lpParam)
{
	SENDMESS* values = (SENDMESS*)lpParam;

	printf("nit za send message %s\n", trenutna_grupa->q->data);
	EnterCriticalSection(&cs);
	int dobro;
	dobro = posalji(*trenutna_grupa, values->serverSocket, values->clientadres, values->sockaddrlen, values->brojKorisnika, values->p);
	LeaveCriticalSection(&cs);
	return 0;
}

void ocisti_memoriju_grupe(GRUPE** g)
{
	if (*g == NULL)
	{
		return;
	}
	//if((*g)->q != NULL)
	//free(((*g)->q));
	ocisti_memoriju_grupe(&(*g)->next);
	free(*g);
	*g = NULL;
}

void ocisti_memoriju_procesa(Proces** p)
{
	if (*p == NULL)
	{
		return;
	}
	ocisti_memoriju_procesa(&(*p)->sledeci);
	free(*p);
	*p = NULL;
}

DWORD WINAPI Disconnect(LPVOID lpParam)
{
	DC* values = (DC*)lpParam;

	Grupa* trenutna;
	int broj_grupe_brisanog_korisnika = 0;
	EnterCriticalSection(&cs);
	broj_grupe_brisanog_korisnika = obrisi_korisnika(values->p, values->clientPort);
	trenutna = nadji_grupu(broj_grupe_brisanog_korisnika, values->g);
	trenutna->brClanova--;
	if (trenutna->brClanova == 0)
	{
		obrisi_grupu(&trenutna, values->g);
	}
	LeaveCriticalSection(&cs);
	return 0;
}