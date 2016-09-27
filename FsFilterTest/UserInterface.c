#include "UserInterface.h"

/******Initialize the communication port*********/
NTSTATUS InitServerPort(_In_ PFLT_FILTER Filter, _Deref_out_ PFLT_PORT *ServerPort, _In_ PFLT_CONNECT_NOTIFY ConnectNotifyCallback,
	_In_ PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback, _In_opt_ PFLT_MESSAGE_NOTIFY MessageNotifyCallback)
{
	NTSTATUS status;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);//give the access tothe sd
	if (!NT_SUCCESS(status))
	{
		DbgPrint("build default security descriptor error!\n");
		return status;
	}

	UNICODE_STRING portName = RTL_CONSTANT_STRING(SERVER_PORT_NAME);

	InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

	status = FltCreateCommunicationPort(Filter, ServerPort, &oa, NULL, ConnectNotifyCallback, DisconnectNotifyCallback, MessageNotifyCallback,
		SERVER_MAX_COUNT);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FLT Create port error!\n");
		return status;
	}

	FltFreeSecurityDescriptor(sd);
	return status;

}