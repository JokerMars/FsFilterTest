#include "Tools.h"

#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()


/*++
	the string format like following:
	¡°.txt=nopad.exe,TxtReader.exe,;.cad=*,;.jpg=ImageView.exe,explore.exe,;¡±
--*/
PTYPE_KEY_WORD GetStrategyFromString(CHAR * strategyString)
{
	int len = strlen(strategyString);

	CHAR line_div = ";";
	CHAR mid_div = "=";
	CHAR process_div = ",";

	int lineStart = 0;
	int lineEnd = -1;
	int lineDiv = 0;

	TYPE_KEY_WORD keyword_head;
	keyword_head.next = NULL;

	for (int i = 0; i < len; i++)
	{
		if (strategyString[i] == line_div)
		{
			lineStart = lineEnd + 1;
			lineEnd = i;

			for (lineDiv = lineStart; lineDiv < lineEnd; lineDiv++)
			{
				if (strategyString[lineDiv] != mid_div)
					continue;

				
				PTYPE_KEY_WORD kw = (PTYPE_KEY_WORD)ExAllocatePoolWithTag(NonPagedPool, sizeof(TYPE_KEY_WORD), BUFFER_SWAP_TAG);
				if (kw != NULL)
				{
					kw->next = keyword_head.next;
					keyword_head.next = kw;

					RtlZeroMemory(kw->keyWord, TYPE_KEY_WORD_LEN);

					size_t keyWord_size = lineDiv - lineStart;
					size_t size = keyWord_size < TYPE_KEY_WORD_LEN ? keyWord_size : TYPE_KEY_WORD_LEN;

					RtlCopyMemory(kw->keyWord, &(strategyString[lineStart]), size);
					DbgPrint("find a key word: %s", kw->keyWord);

					//now we find the process
					PROCESS_INFO proc_head;
					proc_head.next = NULL;

					int proc_div_end = lineDiv;
					int proc_div_start = proc_div_end;

					for (int j = lineDiv + 1; j < lineEnd; j++)
					{
						if (strategyString[j] != process_div)continue;
						proc_div_start = proc_div_end + 1;
						proc_div_end = j;

						PPROCESS_INFO pi = (PPROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_INFO), BUFFER_SWAP_TAG);
						if (pi != NULL)
						{
							pi->next = proc_head.next;
							proc_head.next = pi;

							RtlZeroMemory(pi->processName, PROCESS_NAME_LEN);
							size_t procName_size = proc_div_end - proc_div_start;
							size = procName_size < PROCESS_NAME_LEN ? procName_size : PROCESS_NAME_LEN;

							RtlCopyMemory(pi->processName, &(strategyString[proc_div_start]), size);

							DbgPrint("Find a process name: %s", pi->processName);
						}

					}

					kw->processInfo = proc_head.next;

				}
			}

		}
	}

	return keyword_head.next;
}


void FreeProcessInfoList(PPROCESS_INFO head)
{
	PPROCESS_INFO tmp = NULL;
	PPROCESS_INFO next = NULL;

	tmp = head;
	while (tmp != NULL)
	{
		next = tmp->next;
		ExFreePool(tmp);
		tmp = next;
	}
}

VOID FreeStrategy(PTYPE_KEY_WORD head)
{
	PTYPE_KEY_WORD tmp;
	PTYPE_KEY_WORD next;

	tmp = head;
	while (tmp != NULL)
	{
		next = tmp->next;
		FreeProcessInfoList(tmp->processInfo);
		ExFreePool(tmp);
		tmp = next;
	}
}



BOOLEAN IsInKeyWordList(PTYPE_KEY_WORD keyWord, PUNICODE_STRING fileName, PTYPE_KEY_WORD * out_keyWord)
{
	if (keyWord == NULL || fileName == NULL)
		return FALSE;

	*out_keyWord = NULL;

	UNICODE_STRING un_filename;
	RtlUpcaseUnicodeString(&un_filename, fileName, TRUE);

	DbgPrint("file name is %wZ", &un_filename);

	UNICODE_STRING un_kw;
	WCHAR buff[TYPE_KEY_WORD_LEN];
	un_kw.Buffer = buff;
	un_kw.Length = 0;
	un_kw.MaximumLength = TYPE_KEY_WORD_LEN * 2;

	BOOLEAN isBreak = FALSE;
	BOOLEAN res = FALSE;

	while (keyWord != NULL&&isBreak == FALSE)
	{
		size_t len = strlen(keyWord->keyWord);
		cstr2wstr(keyWord->keyWord, buff, len);

		un_kw.Length = len * 2;

		RtlUpcaseUnicodeString(&un_kw, &un_kw, FALSE);
		DbgPrint("key word is %wZ", &un_kw);

		INT index = UnicodeStringIndexOf(&un_filename, &un_kw);

		if (index != -1)
		{
			res = TRUE;
			isBreak = TRUE;
			*out_keyWord = keyWord;
			break;
		}
		keyWord = keyWord->next;
	}

	RtlFreeUnicodeString(&un_filename);
	return res;
}



BOOLEAN IsSecretProcess(PTYPE_KEY_WORD keyWord, CHAR * processName)
{
	if (keyWord == NULL || processName == NULL)
		return FALSE;

	PPROCESS_INFO info = keyWord->processInfo;
	while (info != NULL)
	{
		DbgPrint("process name is %s\n", processName);
		DbgPrint("secret process name is %s\n", info->processName);

		if (strncmp(info->processName, "*", strlen("*")) == 0)
		{
			return TRUE;
		}

		if (strncmp(processName, info->processName, strlen(processName)) == 0)
			return TRUE;
		info = info->next;
	}

	return FALSE;
}



INT UnicodeStringIndexOf(UNICODE_STRING * source, UNICODE_STRING * value)
{
	if ((source->Length) < (value->Length))
	{
		return -1;
	}

	int i, j;
	int source_len = source->Length / 2;//unicode 2 bytes represent a character
	int value_len = value->Length / 2;
	int len = source_len - value_len + 1;

	DbgPrint("source is %wZ and value is %wZ\n", source, value);
	DbgPrint("source_len is %d and value_len is %d and len is %d\n", source_len, value_len, len);
	for (i = 0; i < len; i++)
	{
		BOOLEAN flag = TRUE;
		for (j = 0; j < value_len; j++)
		{
			WCHAR c1 = source->Buffer[i + j];
			WCHAR c2 = value->Buffer[j];
			if (c1 != c2)
			{
				flag = FALSE;
				break;
			}
		}
		if (flag)
			return i;
	}
	return -1;
}




NTSTATUS GetFileEncryptInfoToCtx(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS FltObjects, PSTREAM_HANDLE_CONTEXT ctx, PTYPE_KEY_WORD keyWord)
{
	NTSTATUS status;
	ctx->isEncrypted = IS_NOT_ENCRYPTED;//file is not encrypted
	ctx->isEncryptFile = IS_NOT_ENCRYPT_FILE;//file is not one of encrypted file types
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	//check the IRQL
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//check if it's a directory
	BOOLEAN isDir;
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);
	if (NT_SUCCESS(status))
	{
		if (isDir)
		{
			DbgPrint("it's a directory!\n");
			return status;
		}
		else
		{
			//get the file name
			status = FltGetFileNameInformation(data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
			if (NT_SUCCESS(status))
			{
				FltParseFileNameInformation(nameInfo);

				//check if it's a need encrypted file type
				BOOLEAN is_encrypt_file = IsInKeyWordList(keyWord, &(nameInfo->Name), &(ctx->keyWord));
				if (is_encrypt_file)
				{
					DbgPrint("file name is %wZ", &(nameInfo->Name));
					DbgPrint("is a encrypt file type");
					ctx->isEncryptFile = IS_ENCRYPT_FILE;

					//check if this file has been encrypted, see the encrypt trail
					ENCRYPT_TRAIL trail;
					ULONG readLen = 0;
					//get the file information
					FILE_STANDARD_INFORMATION fileInfo;
					
					status = FltQueryInformationFile(FltObjects->Instance, data->Iopb->TargetFileObject, &fileInfo,
						sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);

					if (NT_SUCCESS(status))
					{
						//get the file length
						LONGLONG offset = fileInfo.EndOfFile.QuadPart - ENCRYPT_MARK_LEN;
						if (offset < 0)
						{
							ctx->isEncrypted = IS_NOT_ENCRYPTED;
							DbgPrint("file has not been encrypted!\n");
						}
						else//read the tail mark
						{
							LARGE_INTEGER readPos;
							readPos.QuadPart = offset;

							status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &(readPos), ENCRYPT_MARK_LEN, (PVOID)trail.mark,
								FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, &readLen, NULL, NULL);
							if (NT_SUCCESS(status))
							{
								DbgPrint("file trail is %s", trail.mark);
								DbgPrint("entry string is %s", ENCRYPT_MARK_STRING);
								//compare the mark with tail
								if (strncmp(trail.mark, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING)) == 0)
								{
									DbgPrint("file %wZ has been encrypted!\n", &(nameInfo->Name));
									ctx->isEncrypted = IS_ENCRYPTED;
								}
							}
							else
							{
								DbgPrint("FltReadFile error!\n");
							}

						}

					}
				}
				else
				{
					DbgPrint("Not a filter file type\n");
				}
			}
			else
			{
				DbgPrint("can not read a file name");
			}
		}
	}
	else
	{
		DbgPrint("FltIsDirectory error");
	}

	if (nameInfo != NULL)
	{
		FltReleaseFileNameInformation(&nameInfo);
	}
	return status;
}




#pragma LOCKEDCODE
NTSTATUS EncryptFile(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS FltObjects, PCHAR key)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fileInfo;
	ULONG len = 0;

	//check the irql
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//Get file information
	status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &fileInfo, sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation, &len);
	if (NT_SUCCESS(status))
	{
		LONGLONG fileLen = fileInfo.EndOfFile.QuadPart;
		ULONG buffLen = 1024 * 1024;
		ULONG writeLen;
		ULONG readLen;
		LARGE_INTEGER offset;
		offset.QuadPart = 0;

		//malloc a memory
		PVOID buff = ExAllocatePoolWithTag(NonPagedPool, buffLen, BUFFER_SWAP_TAG);
		if (buff == NULL)
		{
			DbgPrint("No enough memory\n");
			return STATUS_UNSUCCESSFUL;
		}

		PMDL newMdl = IoAllocateMdl(buff, buffLen, FALSE, FALSE, NULL);
		if (newMdl != NULL)
		{
			MmBuildMdlForNonPagedPool(newMdl);
		}

		RtlZeroMemory(buff, buffLen);

		//encrypt file
		LONGLONG hadWrite = 0;//make a record of the length of had write
		while (hadWrite < fileLen)
		{
			//read file
			status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &offset, buffLen, buff,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, &readLen, NULL, NULL);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("read file error when encrypt");
				ExFreePool(buff);
				if (newMdl != NULL)
				{
					IoFreeMdl(newMdl);
				}

				return status;
			}

			//encrypt the buffer
			EncryptData(buff, buff, offset.QuadPart, readLen, key);

			//write in disk
			status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &offset, readLen, buff, 0,
				&writeLen, NULL, NULL);

			if (readLen != writeLen)
			{
				DbgPrint("read len not equal to write len");
			}

			if (!NT_SUCCESS(status))
			{
				DbgPrint("FltWriteFile error when encrypt a file");
				ExFreePool(buff);
				if (newMdl != 0)
				{
					IoFreeMdl(newMdl);
				}
				return status;
			}
			offset.QuadPart += readLen;//offset has changed
			hadWrite += writeLen;
		}

		//add the mark tail
		offset = fileInfo.EndOfFile;
		RtlZeroMemory(buff, buffLen);
		RtlCopyMemory(buff, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

		DbgPrint("buff is %s", buff);
		status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &offset, ENCRYPT_MARK_LEN,
			buff, 0, &writeLen, NULL, NULL);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("write encrypt mark error");
			ExFreePool(buff);
			if (newMdl != NULL)
				IoFreeMdl(newMdl);
			return status;
		}

		ExFreePool(buff);
		if (newMdl != NULL)
			IoFreeMdl(newMdl);
		return status;
	}

	return status;
}




NTSTATUS PutEncryptHead(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS FltObjects)
{
	NTSTATUS status;
	ULONG buffLen = ENCRYPT_FILE_CONTENT_OFFSET;//the length of mark

	//malloc a memory
	PVOID buff = ExAllocatePoolWithTag(NonPagedPool, buffLen, BUFFER_SWAP_TAG);
	if (buff == NULL)
	{
		DbgPrint("No enough memory");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(buff, buffLen);

	RtlCopyMemory(buff, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

	LARGE_INTEGER offset;
	offset.QuadPart = 0;

	status = FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &offset, buffLen, buff, 0,
		NULL, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("write encrypt mark error");
	}
	ExFreePool(buff);

	return status;
}




VOID WriteEncryptTrail(PVOID buff, ULONG offset)
{
	ENCRYPT_TRAIL trail;
	RtlZeroMemory(trail.mark, ENCRYPT_MARK_LEN);
	RtlCopyMemory(trail.mark, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

	PCHAR pos = (PCHAR)buff;
	RtlCopyMemory((PVOID)(&(pos[offset])), trail.mark, ENCRYPT_MARK_LEN);
}


/*encrypt or decrypt using RC4 Algorithm*/
void swap(unsigned char *a, unsigned char *b)
{
	unsigned char tmp;
	tmp = *a;
	*a = *b;
	*b = tmp;
}


void re_S(unsigned char *S)
{
	unsigned int i;
	for (i = 0; i < 256; i++)
	{
		S[i] = (unsigned char)i;
	}
}


void re_T(char *T, char *key)
{
	int i;
	int keyLen;
	keyLen = strlen(key);
	for (i = 0; i < 256; i++)
	{
		T[i] = key[i%keyLen];
	}
}

void re_Sbox(unsigned char *S, char *T)
{
	int i, j = 0;
	for (i = 0; i < 256; i++)
	{
		j = (j + S[i] + T[i]) % 256;
		swap(&S[i], &S[j]);
	}
}


void re_RC4(unsigned char *S, char *key)
{
	char T[256] = { 0 };
	re_S(S);
	re_T(T, key);
	re_Sbox(S, T);
}

void RC4(char *inBuf, char *outBuf, LONGLONG offset, ULONG bufLen, char *key)
{
	unsigned char S[256] = { 0 };
	unsigned char readbuf[1];

	int i, j, t;
	LONGLONG z;
	re_RC4(S, key);

	i = j = 0;
	z = 0;
	while (z < offset)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(&S[i], &S[j]);
		z++;
	}
	z = 0;
	while (z < bufLen)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(&S[i], &S[j]);
		t = (S[i] + (S[j] % 256)) % 256;
		readbuf[0] = inBuf[z];
		readbuf[0] = readbuf[0] ^ S[t];
		outBuf[z] = readbuf[0];
		z++;
	}
}

void XOR(char *buf, char *output, int len, char *key)
{
	int keylen = strlen(key);
	char c = 0;
	for (int i = 0; i < keylen; i++)
	{
		c = c^key[i];
	}

	for (int i = 0; i < len; i++)
	{
		output[i] = buf[i] ^ c;
	}
}





VOID EncryptData(PVOID buff, PVOID outbuff, LONGLONG offset, ULONG len, PCHAR key)
{
	char *indata = (char *)buff;
	char *outdata = (char *)outbuff;

	RC4(indata, outdata, offset, len, key);
}

VOID DecodeData(PVOID buff, PVOID outbuff, LONGLONG offset, ULONG len, PCHAR key)
{
	char *indata = (char *)buff;
	char *outdata = (char *)outbuff;

	RC4(indata, outdata, offset, len, key);
}




#pragma LOCKEDCODE
VOID FileCacheClear(PFILE_OBJECT pFileObject)
{
	PFSRTL_COMMON_FCB_HEADER pFcb;
	LARGE_INTEGER interval;
	BOOLEAN bNeedReleaseResource = FALSE;
	BOOLEAN bNeedReleasePagingIoResource = FALSE;
	KIRQL irql;

	pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
	if (pFcb == NULL)
		return;
	irql = KeGetCurrentIrql();
	if (irql >= DISPATCH_LEVEL)
	{
		return;
	}

	interval.QuadPart = -1 * (LONGLONG)50;
	while (TRUE)
	{
		BOOLEAN bBreak = TRUE;
		BOOLEAN bLockedResource = FALSE;
		BOOLEAN bLockedPagingIoResource = FALSE;
		bNeedReleaseResource = FALSE;
		bNeedReleasePagingIoResource = FALSE;

		if (pFcb->PagingIoResource)
		{
			bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);
		}
		if (pFcb->Resource)
		{
			bLockedResource = TRUE;
			if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
			{
				bNeedReleaseResource = TRUE;
				if (bLockedPagingIoResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bNeedReleaseResource = FALSE;
						bLockedResource = FALSE;
					}
				}
				else
				{
					ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE);
				}
			}

			if (bLockedPagingIoResource == FALSE)
			{
				if (pFcb->PagingIoResource)
				{
					bLockedPagingIoResource = TRUE;
					bNeedReleasePagingIoResource = TRUE;
					if (bLockedResource)
					{
						if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
						{
							bBreak = FALSE;
							bLockedPagingIoResource = FALSE;
							bNeedReleasePagingIoResource = FALSE;
						}
					}
					else
					{
						ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE);
					}
				}
			}

			if (bBreak)
				break;

			if (bNeedReleasePagingIoResource)
				ExReleaseResourceLite(pFcb->PagingIoResource);

			if (bNeedReleaseResource)
				ExReleaseResourceLite(pFcb->Resource);

			if (irql == PASSIVE_LEVEL)
			{
				KeDelayExecutionThread(KernelMode, FALSE, &interval);
			}
			else
			{
				KEVENT waitEvent;
				KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
				KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &interval);
			}
		}

		if (pFileObject->SectionObjectPointer)
		{
			IO_STATUS_BLOCK ioStatus;
			CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
			if (pFileObject->SectionObjectPointer->ImageSectionObject)
			{
				MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForWrite);
			}
			CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
		}

		if (bNeedReleasePagingIoResource)
			ExReleaseResourceLite(pFcb->PagingIoResource);
		if (bNeedReleaseResource)
			ExReleaseResourceLite(pFcb->Resource);
	}
}


//stay calm, stay cool
#pragma LOCKEDCODE
VOID cfFileCacheClear(PFILE_OBJECT pFileObject)
{
	PFSRTL_COMMON_FCB_HEADER pFcb;
	LARGE_INTEGER interval;
	BOOLEAN bNeedReleaseResource = FALSE;
	BOOLEAN bNeedReleasePagingIoRelease = FALSE;
	KIRQL irql;

	pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
	if (pFcb == NULL)
		return;

	irql = KeGetCurrentIrql();
	if (irql >= DISPATCH_LEVEL)
		return;

	interval.QuadPart = -1 * (LONGLONG)50;

	while (TRUE)
	{
		BOOLEAN bBreak = TRUE;
		BOOLEAN bLockedResource = FALSE;
		BOOLEAN bLockedPagingIoResource = FALSE;

		bNeedReleaseResource = FALSE;
		bNeedReleasePagingIoRelease = FALSE;

		//get lock in fcb
		if (pFcb->PagingIoResource)
			bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);

		//anyway get the lock
		if (pFcb->Resource)
		{
			bLockedResource = TRUE;
			if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
			{
				bNeedReleaseResource = TRUE;
				if (bLockedPagingIoResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bNeedReleaseResource = FALSE;
						bLockedResource = FALSE;
					}
				}
				else
					ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE);
			}
		}

		if (bLockedPagingIoResource == FALSE)
		{
			if (pFcb->PagingIoResource)
			{
				bLockedPagingIoResource = TRUE;
				bNeedReleasePagingIoRelease = TRUE;
				if (bLockedResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bLockedPagingIoResource = FALSE;
						bNeedReleasePagingIoRelease = FALSE;
					}
				}
				else
					ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE);
			}
		}

		if (bBreak)
			break;

		if (bNeedReleasePagingIoRelease)
			ExReleaseResourceLite(pFcb->PagingIoResource);

		if (bNeedReleaseResource)
			ExReleaseResourceLite(pFcb->Resource);

		if (irql == PASSIVE_LEVEL)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &interval);
		}
		else
		{
			KEVENT waitEvent;
			KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
			KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &interval);
		}
	}

	if (pFileObject->SectionObjectPointer)
	{
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
		
		if (NT_SUCCESS(ioStatus.Status))
		{
			KdPrint(("CcFlushCache OK\n"));
		}
		else
		{
			DbgPrint("CcFlushCache Failed\n");
		}

		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			if (MmFlushImageSection(pFileObject->SectionObjectPointer->ImageSectionObject, MmFlushForWrite) == TRUE)
			{
				DbgPrint("MmFlushImageSection OK");
			}
			else
				DbgPrint("MmFlushImageSection Failed");
		}


		if (CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, TRUE) == TRUE)
		{
			DbgPrint("CcPurgeCacheSection OK");
		}
		else
			DbgPrint("CcPurgeCacheSection Failed");

		KEVENT otherWaitEvent;
		LARGE_INTEGER otherInterval;
		otherInterval.QuadPart = 0;
		KeInitializeEvent(&otherWaitEvent, NotificationEvent, FALSE);
		CcUninitializeCacheMap(pFileObject, &otherInterval, (PCACHE_UNINITIALIZE_EVENT)&otherWaitEvent);
		KeWaitForSingleObject(&otherWaitEvent, Executive, KernelMode, FALSE, &otherInterval);
	}

	if (bNeedReleasePagingIoRelease)
		ExReleaseResourceLite(pFcb->PagingIoResource);
	if (bNeedReleaseResource)
		ExReleaseResourceLite(pFcb->Resource);
}

/*++
	
	In an effort to remain version-independent, rather than using a hard
	coded into the KPEB (Kernel Process Enviroment Block), we scan the KPEB looking for the name, which
	should match the GUI process

--*/

ULONG GetProcessNameOffset()
{
	PEPROCESS curproc;
	int i;
	curproc = PsGetCurrentProcess();

	//scan for 12 KB, hopping the KPEB never grows that big!

	for (i = 0; i < 3 * PAGE_SIZE; i++)
	{
		if (!strncmp("System", (PCHAR)curproc + i, strlen("System")))
			return i;
	}

	return 0;
}


//next vesion, the style of  define name will be Camel. All will be Camel
PCHAR GetCurrentProcessName(ULONG ProcessNameOffset)
{
	PEPROCESS curproc;
	char *nameptr;

	//we only try and get the name if we can locate the name offset
	if (ProcessNameOffset)
	{
		curproc = PsGetCurrentProcess();
		nameptr = (PCHAR)curproc + ProcessNameOffset;
	}
	else
		nameptr = NULL;
	return nameptr;
}


//this function need reconsidering...
void wstr2cstr(const wchar_t * pwstr, char * pcstr, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{

	}
}

void cstr2wstr(const char * pcstr, wchar_t * pwstr, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		pwstr[i] = (WCHAR)pcstr[i];
	}
}



