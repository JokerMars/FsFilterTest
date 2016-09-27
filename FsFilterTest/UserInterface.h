///
//	this is the interface for communication between user and kernel
///


#pragma once

#ifndef _USER_INTERFACE_H
#define _USER_INTERFACE_H

#include<fltKernel.h>
#include<dontuse.h>
#include<suppress.h>

/***********defined the constant variable********/
//define the name of communication port
#define SERVER_PORT_NAME           L"\\FileEncryptPort"

//max count of link
#define SERVER_MAX_COUNT			1


//define message code: request
#define CODE_OPEN_SYSTEM			0X0001

#define CODE_CLOSE_SYSTEM			0X0002

#define CODE_SEND_STRATEGY			0X0003

#define CODE_SEND_KEY				0X0004

#define CODE_IS_RUNNING				0X0005

//define message code: reply

#define CODE_SUCCESS				0X0006

#define CODE_UNSUCCESS				0X0007

#define CODE_UNKNOWN_CODE			0X0008

#define CODE_RUNNING				0X0009

#define CODE_CLOSED					0X000A

/*
	define the data structure
*/
typedef struct _MESSAGE_DATA
{
	INT32 code;
	INT32 bufferLen;
	CHAR buffOffset[1];
}MESSAGE_DATA, *PMESSAGE_DATA;

typedef struct _MESSAGE_BACK
{
	INT32 code;
}MESSAGE_BACK, *PMESSAGE_BACK;

NTSTATUS InitServerPort(_In_ PFLT_FILTER Filter, _Deref_out_ PFLT_PORT *ServerPort, _In_ PFLT_CONNECT_NOTIFY ConnectNotifyCallback,
	_In_ PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback, _In_opt_ PFLT_MESSAGE_NOTIFY MessageNotifyCallback);

#endif
