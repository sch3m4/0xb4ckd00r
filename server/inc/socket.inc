;#####################
;# PASA UN HOST A IP #
;#####################
proc HostIp Host
     push [Host]
     call gethostbyname
     or eax,0
     je error_hostip
     virtual at eax
     .h hostent
     end virtual
     push esi
     mov esi,[.h.h_addr_list]
     lodsd
     pop esi
     mov eax,[eax]
     push eax
     call inet_ntoa
error_hostip:
     ret
endp

;################################################
;# Conecta a un host, por el puerto determinado #
;#                                              #
;# NO HAY ERROR:                                #
;#   + EAX       = 0                            #
;#   + sock      = Conectado                    #
;################################################
proc Conectar sock,Host,Puerto,sockaddrin
push 0
push 0
push 0
push 0x6;IPPROTO_TCP
push SOCK_STREAM
push AF_INET
call WSASocket
cmp eax,0xffffffff;INVALID_SOCKET
je salir_conectar

mov ebx,[sock]
mov [ebx],eax
lea edi,[sockaddrin]
mov word [edi],AF_INET
push [Puerto]
call htons
cmp eax,-1
je salir_conectar

lea edi,[sockaddrin]
add edi,2
mov word [edi],ax
push [Host]
call inet_addr
cmp eax,0xffffffff;INADDR_NONE
je salir_conectar

lea edi,[sockaddrin]
mov [edi+4],eax
mov ebx,[sock]
mov ebx,[ebx]
push 16
push edi;sockaddr_in
push ebx ;socket
call connect

salir_conectar:
ret
endp

;#############################################
;# CREA UNA CONEXIÓN A UN HOST POR UN PUERTO #
;#                                           #
;# NO HAY ERROR:                             #
;#   + EAX       = 0                         #
;#   + Socket    = Conectado                 #
;#############################################
proc CrearConexion RHost,Puerto,sock,wsa,sckaddrin
pushad

push [wsa]
push 200
call WSAStartup
or eax,0
jne error_conexion

;convertimos a IP
push [RHost]
call HostIp
or eax,0
je error_conexion
push [sckaddrin]
push [Puerto]
push eax
push [sock]
call Conectar
ret

error_conexion:
mov eax,1
ret
endp

;#################################
;## ENVIA UN BUFFER A UN SOCKET ##
;#################################
proc EnviarDatos sock, mBuffer
xor ecx,ecx
mov esi,[mBuffer]
len:
cmp byte [esi],0
je enviar
inc esi
inc ecx
jmp len

enviar:
mov edi,[sock]
sub esi,ecx
push 0
push ecx
push esi
push dword [edi]
call send
ret
endp

;########################################################
;## RECIBE DATOS DEL SOCKET Y LO ALMACENA EN EL BUFFER ##
;########################################################
proc RecibirDatos sock,cadena,len
;borramos el contenido de la cadena
mov edi,[cadena]
xor ecx,ecx
borrar_cadena:
cmp ecx,[len]
je fborrar
mov byte [edi],0
inc edi
inc ecx
jmp borrar_cadena
fborrar:

mov ebx,[sock]
mov ecx,[cadena]
push 0
push [len]
push ecx
push dword [ebx]
call recv

ret
endp