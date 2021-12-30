#include <winsock2.h>
#include <stdio.h>
#include <conio.h>

#define SERVER_PORT 15000
#define OUTGOING_BUFFER_SIZE 1024
// for demonstration purposes we will hard code
// local host ip adderss
#define SERVER_IP_ADDERESS "127.0.0.1"

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();

int main(int argc,char* argv[])
{
    // Server address
    sockaddr_in serverAddress;
    // size of sockaddr structure    
	int sockAddrLen = sizeof(struct sockaddr);
	// buffer we will use to store message
    char outgoingBuffer[OUTGOING_BUFFER_SIZE];
    // port used for communication with server
    int serverPort = SERVER_PORT;
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

	// create a socket
    SOCKET clientSocket = socket(AF_INET,      // IPv4 address famly
								 SOCK_DGRAM,   // datagram socket
								 IPPROTO_UDP); // UDP

    // check if socket creation succeeded
    if (clientSocket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
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
			for (int i = 0; i <pom; i++)
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
	///////////////////
		char c;
	while (work)
	{
		printf("Izaberite:\n1. Diskonektujte se\n2. Posaljite poruku\n");
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

			// Read string from user into outgoing buffer
			gets_s(outgoingBuffer, OUTGOING_BUFFER_SIZE);

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
			break;
		}
		default: printf("INPUT INVALID\n");
			break;
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
