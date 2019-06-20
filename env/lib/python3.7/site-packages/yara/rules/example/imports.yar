include "example/pe.yar"

private rule winsock_wsa
{
	strings:
		$ ="WSASocket"
		$ ="WSASend"
		$ ="WSARecv"
		$ ="WSAConnect"
		$ ="WSAIoctl"
		$ ="WSAConnect"
	condition:
		any of them and is_pe
}

private rule winsock_generic 
{
	strings:
		$ ="socket"
		$ ="send"
		$ ="recv"
		$ ="connect"
		$ ="ioctlsocket"
		$ ="closesocket"
	condition:
		any of them 
}

private rule has_winsock
{
    condition:
        winsock_wsa or winsock_generic and is_pe
}

