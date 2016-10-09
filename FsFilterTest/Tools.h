#pragma once

#ifndef _TOOLS_H
#define _TOOLS_H


#include<fltKernel.h>
#include<dontuse.h>
#include<suppress.h>

#include "FileEncrypt.h"

//get a strategy from string, return the header of a list
PTYPE_KEY_WORD GetStrategyFromString(CHAR *strategyString);

//release a list
VOID FreeStrategy(PTYPE_KEY_WORD head);


//check the file type, see if it's in keyword list.
BOOLEAN IsInKeyWordList(_In_ PTYPE_KEY_WORD keyWord, _In_ PUNICODE_STRING fileName, _Out_ PTYPE_KEY_WORD *out_keyWord);

//check if the process is the confidential process
BOOLEAN IsSecretProcess(PTYPE_KEY_WORD keyWord, CHAR *processName);

INT UnicodeStringIndexOf(UNICODE_STRING *source, UNICODE_STRING *value);


/******Get the Encrypt file info******/
NTSTATUS GetFileEncryptInfoToCtx(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Inout_ PSTREAM_HANDLE_CONTEXT ctx, _In_ PTYPE_KEY_WORD keyWord);

/*******Encrypt file******/
NTSTATUS EncryptFile(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PCHAR key);

NTSTATUS PutEncryptHead(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS FltObjects);

VOID WriteEncryptTrail(PVOID buff, ULONG offset);

/*++
description:
	this is a encrypt function
parametes:
	buff: the input buffer
	outbuff: the output buffer
	offset:  the offset
	len: the length of buffer
	key: encrypt key
return:
	void
--*/
VOID EncryptData(_In_ PVOID buff, _In_ PVOID outbuff, _In_ LONGLONG offset, _In_ ULONG len, PCHAR key);

VOID DecodeData(_In_ PVOID buff, _In_ PVOID outbuff, _In_ LONGLONG offset, _In_ ULONG len, PCHAR key);

/**clear the file cache*/
VOID FileCacheClear(PFILE_OBJECT pFileObject);
VOID cfFileCacheClear(PFILE_OBJECT pFileObject);

/************
	process related
*/
//get the offset of a process
ULONG GetProcessNameOffset(VOID);

//get the process name
PCHAR GetCurrentProcessName(ULONG ProcessNameOffset);


/*deal with the string*/

void wstr2cstr(const wchar_t *pwstr, char *pcstr, size_t len);

void cstr2wstr(const char *pcstr, wchar_t *pwstr, size_t len);

#endif
