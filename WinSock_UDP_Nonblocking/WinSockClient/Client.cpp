#include <stdio.h>
#include <winsock2.h>
#include <conio.h>
#include <Windows.h>


#define no_init_all deprecated
#define SERVER_PORT 15000
#define OUTGOING_BUFFER_SIZE 1024
// for demonstration purposes we will hard code
// local host ip adderss
#define SERVER_IP_ADDERESS "127.0.0.1"

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();

int iResult2;
sockaddr_in serverAddress, serverAddress2;
int sockAddrLen = sizeof(struct sockaddr);


//prijem nije dobar
DWORD WINAPI Recive(LPVOID lpParam)
{
	char prijem[OUTGOING_BUFFER_SIZE];
	SOCKET clientSocket2 = *(SOCKET*)lpParam;
	while (1)
	{
		FD_SET set;
		timeval timeVal;
		FD_ZERO(&set);
		FD_SET(clientSocket2, &set);
		timeVal.tv_sec = 0;
		timeVal.tv_usec = 0;
		//printf("Usao u Recive tredovani\n");
		iResult2 = select(0 /* ignored */, &set, NULL, NULL, &timeVal);
		memset(prijem, 0, OUTGOING_BUFFER_SIZE);

		//printf("Pre ifa, spavam..\n");
		if (iResult2 == 0)
		{
			// there are no ready sockets, sleep for a while and check again
			Sleep(2000);
			continue;
		}

		iResult2 = recvfrom(clientSocket2,
			prijem,
			OUTGOING_BUFFER_SIZE,
			0,
			(LPSOCKADDR)&serverAddress2,
			&sockAddrLen);

		if (strcmp(prijem, "") != 0)
			printf("Poruka: %s\n", prijem);
		else
			printf("No messages for now\n");

		if (iResult2 == SOCKET_ERROR)
		{
			printf("recvfrom failed with error: %d\n", WSAGetLastError());
			continue;
		}
	}
}



int main(int argc,char* argv[])
{
	DWORD dRecive;
	HANDLE hRecive;

    // Server address
   
    // size of sockaddr structure    
	
	// buffer we will use to store message
    char outgoingBuffer[OUTGOING_BUFFER_SIZE];
    // port used for communication with server
    int serverPort = SERVER_PORT;
	int serverPort2 = 15001;
	// variable used to store function return value
	int iResult;
	char proc_group[OUTGOING_BUFFER_SIZE];
    // Initialize windows sockets for this process
    InitializeWindowsSockets();

    // Initialize serverAddress structure
    memset((char*)&serverAddress,0,sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDERESS);
    serverAddress.sin_port = htons((u_short)serverPort);

	memset((char*)&serverAddress2, 0, sizeof(serverAddress2));
	serverAddress2.sin_family = AF_INET;
	serverAddress2.sin_addr.s_addr = inet_addr(SERVER_IP_ADDERESS);
	serverAddress2.sin_port = htons((u_short)serverPort2);
	// create a socket
	SOCKET clientSocket = socket(AF_INET,      // IPv4 address famly
								SOCK_DGRAM,   // datagram socket
								IPPROTO_UDP); // UDP
	SOCKET clientSocket2 = socket(AF_INET,      // IPv4 address famly
		SOCK_DGRAM,   // datagram socket
		IPPROTO_UDP); // UDP


	iResult2 = bind(clientSocket2, (LPSOCKADDR)&serverAddress2, sizeof(serverAddress2));

    // check if socket creation succeeded
    if (clientSocket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
	if (clientSocket2 == INVALID_SOCKET)
	{
		printf("Creating socket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	unsigned long int nonBlockingMode = 1;
	iResult2 = ioctlsocket(clientSocket2, FIONBIO, &nonBlockingMode);
	
	int iz,group;
	bool work = true;
	//////////////////
		printf("1. Nova grupa\n2. Postojeca grupa\n");
		scanf("%d", &group);
		scanf("");
		if (group == 1)
		{
			strcpy(outgoingBuffer, "NEW_GROUP");

			iResult = sendto(clientSocket,
				outgoingBuffer,
				strlen(outgoingBuffer),
				0,
				(LPSOCKADDR)&serverAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}
			// Broj nove grupe je ovdje u proc_group
		}
		else
		{
			strcpy(outgoingBuffer, "RETURN_GROUPS");

			iResult = sendto(clientSocket,
				outgoingBuffer,
				strlen(outgoingBuffer),
				0,
				(LPSOCKADDR)&serverAddress,
				sockAddrLen);
			// TODO funkcija za primanje poruke od servera za listu postojecih grupa
			iResult = recvfrom(clientSocket,
				proc_group,
				OUTGOING_BUFFER_SIZE,
				0,
				(LPSOCKADDR)&serverAddress,
				&sockAddrLen);


			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}
			int pom = atoi(proc_group);
			
			printf("Postojece grupe su:\n");
			for (int i = 1; i <pom; i++)
			{
				printf("Grupa %d.\n", i);
			}

			
			group = -1;
		while (group <0 || group >=pom)
			{
				printf("Izaberite grupu\n");
				scanf("%d", &group);
			}
			char a[5];
			strcpy(outgoingBuffer,itoa(group,a,10));
			iResult = sendto(clientSocket,
				outgoingBuffer,
				strlen(outgoingBuffer),
				0,
				(LPSOCKADDR)&serverAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}
			
		}

		//dont touch, MAGIC
		clientSocket2 = clientSocket;
		serverAddress2 = serverAddress;



	///////////////////
		char c;

		char prijem[OUTGOING_BUFFER_SIZE];
		hRecive = CreateThread(NULL, 0, &Recive, &clientSocket2, 0, &dRecive);
	while (work)
	{	

		printf("Izaberite:\n1. Diskonektujte se\n2. Posaljite poruku\n3. Ugasi server\n");
		scanf("%d", &iz);
		scanf("%c",&c);
		switch (iz)
		{
		case 1: {

			strcpy(outgoingBuffer, "DQ");
			iResult = sendto(clientSocket,
				outgoingBuffer,
				strlen(outgoingBuffer),
				0,
				(LPSOCKADDR)&serverAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}
			CloseHandle(hRecive);
			/*
			Poruka serveru za diskonektovanje
			*/
			printf("Press any key to exit.\n");
			_getch();

			iResult = closesocket(clientSocket);
			if (iResult == SOCKET_ERROR)
			{
				printf("closesocket failed with error: %d\n", WSAGetLastError());
				return 1;
			}

			iResult = WSACleanup();
			if (iResult == SOCKET_ERROR)
			{
				printf("WSACleanup failed with error: %ld\n", WSAGetLastError());
				return 1;
			}
			work = false;
			break;
		}
		case 2 :
		{
			printf("Enter message for the group queue:\n");
			char slanje[OUTGOING_BUFFER_SIZE];
			char poruka[8] = "Poruka ";
			memset(slanje, 0, OUTGOING_BUFFER_SIZE);
			// Read string from user into outgoing buffer
			gets_s(outgoingBuffer, OUTGOING_BUFFER_SIZE);
			strcat(slanje, poruka);
			strcat(slanje, outgoingBuffer);
			strcpy(outgoingBuffer, slanje);
			iResult = sendto(clientSocket,
				outgoingBuffer,
				strlen(outgoingBuffer),
				0,
				(LPSOCKADDR)&serverAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}
			break;
		}
		case 3: {

			strcpy(outgoingBuffer, "SERVER_SHUT_DOWN");
			iResult = sendto(clientSocket,
				outgoingBuffer,
				strlen(outgoingBuffer),
				0,
				(LPSOCKADDR)&serverAddress,
				sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("sendto failed with error: %d\n", WSAGetLastError());
				closesocket(clientSocket);
				WSACleanup();
				return 1;
			}
			CloseHandle(hRecive);
			/*
			Poruka serveru za diskonektovanje
			*/
			printf("Press any key to exit.\n");
			_getch();

			iResult = closesocket(clientSocket);
			if (iResult == SOCKET_ERROR)
			{
				printf("closesocket failed with error: %d\n", WSAGetLastError());
				return 1;
			}

			iResult = WSACleanup();
			if (iResult == SOCKET_ERROR)
			{
				printf("WSACleanup failed with error: %ld\n", WSAGetLastError());
				return 1;
			}
			work = false;
			break;
		}
		default: printf("INPUT INVALID\n");
			break;
		}
		if (iResult2 == 0)
		{
			// there are no ready sockets, sleep for a while and check again
			Sleep(50);
			continue;
		}
		
	}

    return 0;
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
