/*++

Module Name:

    FsFilterTest.c

Abstract:

    This is the main module of the FsFilterTest miniFilter driver.
	Test version for file transparent encrypt. It's just a scratch not the final
	version

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "FileEncrypt.h"
#include "Tools.h"
#include "UserInterface.h"

#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


//global variable
NPAGED_LOOKASIDE_LIST Pre2PostContextList;

ULONG ProcessNameOffset = 0;

//header of  a list
PTYPE_KEY_WORD key_word_header;

BOOLEAN IS_SYSTEM_OPEN = FALSE;

CHAR key[KEY_MAX_LEN] = { 0 };

//communication port
PFLT_PORT serverPort = NULL;

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))





/*++
	communication callback function
--*/
NTSTATUS MyConnectionCallback(_In_ PFLT_PORT ClientProt, _In_ PVOID ServerPortCookie, _In_ PVOID ConnectionContext,
	_In_ ULONG SizeOfContext, _Out_ PVOID *ConnectionPortCookie);

VOID MyDisconnectCallback(_In_ PVOID ConnectionCookie);

NTSTATUS MyMessageCallback(_In_ PVOID PortCookie, _In_opt_ PVOID InputBuffer, _In_ ULONG InputBufferLength,
	_Out_opt_ PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);






/*************************************************************************
    Prototypes
*************************************************************************/


VOID CleanupVolumeContext(_In_ PFLT_CONTEXT context, _In_ FLT_CONTEXT_TYPE ContextType);

VOID CleanupStreamHandleContext(_In_ PFLT_CONTEXT context, _In_ FLT_CONTEXT_TYPE ContextType);


//create
FLT_PREOP_CALLBACK_STATUS MyPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MyPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);


//-----Read
FLT_PREOP_CALLBACK_STATUS MyPreRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MyPostRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS SwapPostReadBuffersWhenSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);


//write
FLT_PREOP_CALLBACK_STATUS MyPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MyPostWrite(_Inout_ PFLT_CALLBACK_DATA Data,_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);


//close
FLT_PREOP_CALLBACK_STATUS MyPreClose(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MyPostClose(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

//query information
FLT_PREOP_CALLBACK_STATUS MyPreQueryInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MyPostQueryInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

//set information
FLT_PREOP_CALLBACK_STATUS MyPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MyPostSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);




EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsFilterTestInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );



NTSTATUS
FsFilterTestUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FsFilterTestInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilterTestUnload)
#pragma alloc_text(PAGE, FsFilterTestInstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilterTestInstanceSetup)

#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      MyPreCreate,
      MyPostCreate},

    { IRP_MJ_READ,
      0,
      MyPreRead,
      MyPostRead },

    { IRP_MJ_WRITE,
      0,
      MyPreWrite,
      MyPostWrite },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      MyPreQueryInformation,
      MyPostQueryInformation },

    { IRP_MJ_SET_INFORMATION,
      0,
      MyPreSetInformation,
      MyPostSetInformation },


    { IRP_MJ_CLEANUP,
      0,
      MyPreClose,
      MyPostClose },

 

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//


CONST FLT_CONTEXT_REGISTRATION ContextNotifications[]={
	{FLT_VOLUME_CONTEXT,
	0,
	CleanupVolumeContext,
	sizeof(VOLUME_CONTEXT),
	CONTEXT_TAG
	},

	{FLT_STREAMHANDLE_CONTEXT,
	0,
	CleanupStreamHandleContext,
	sizeof(STREAM_HANDLE_CONTEXT),
	STREAM_HANDLE_CONTEXT_TAG
	},
	{FLT_CONTEXT_END}
};






CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    ContextNotifications,                               //  Context
    Callbacks,                          //  Operation callbacks

    FsFilterTestUnload,                           //  MiniFilterUnload

    FsFilterTestInstanceSetup,                    //  InstanceSetup
    FsFilterTestInstanceQueryTeardown,            //  InstanceQueryTeardown
    NULL,										//  InstanceTeardownStart
    NULL,										//  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsFilterTestInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTest!FsFilterTestInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FsFilterTestInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTest!FsFilterTestInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}





/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTest!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //
	CHAR StrategyString[] = ".txt=notepad.exe,;";
	key_word_header = GetStrategyFromString(StrategyString);

	IS_SYSTEM_OPEN = TRUE;
	CHAR testKey[] = "123";
	RtlCopyMemory(key, testKey, strlen(testKey));

	ProcessNameOffset = GetProcessNameOffset();

	ExInitializeNPagedLookasideList(&Pre2PostContextList,
		NULL,
		NULL,
		0,
		sizeof(PRE_2_POST_CONTEXT),
		PRE_2_POST_TAG,
		0);

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) 
		{
			ExDeleteNPagedLookasideList(&Pre2PostContextList);
            FltUnregisterFilter( gFilterHandle );
        }

		//register the communicate port
		status = InitServerPort(gFilterHandle, &serverPort, MyConnectionCallback, MyDisconnectCallback, MyMessageCallback);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("ServerPort initialize failed\n");
			ExDeleteNPagedLookasideList(&Pre2PostContextList);
			FltUnregisterFilter(gFilterHandle);
		}

    }

    return status;
}

NTSTATUS
FsFilterTestUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterTest!FsFilterTestUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

	ExDeleteNPagedLookasideList(&Pre2PostContextList);
	FreeStrategy(key_word_header);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

/*++
				-----Create------
--*/

FLT_PREOP_CALLBACK_STATUS
MyPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	return retValue;
}


#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS 
MyPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	PSTREAM_HANDLE_CONTEXT ctx = NULL;
	NTSTATUS status;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
		return retValue;

	__try
	{
		//initialize the temp context
		STREAM_HANDLE_CONTEXT tmpCtx;
		tmpCtx.isEncryptFile = IS_NOT_ENCRYPT_FILE;
		tmpCtx.isEncrypted = IS_NOT_ENCRYPTED;
		tmpCtx.keyWord = NULL;

		//get the file information
		status = GetFileEncryptInfoToCtx(Data, FltObjects, &tmpCtx, key_word_header);

		if (!NT_SUCCESS(status))
		{
			return retValue;
		}

		if (tmpCtx.isEncryptFile != IS_ENCRYPT_FILE)
			return retValue;

		//clear the file cache
		cfFileCacheClear(FltObjects->FileObject);

		if (!IS_SYSTEM_OPEN)
			return retValue;

		status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&ctx);
		if (!NT_SUCCESS(status))
		{
			//create stream context
			status = FltAllocateContext(FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT,
				sizeof(STREAM_HANDLE_CONTEXT), NonPagedPool, (PFLT_CONTEXT *)(&ctx));

			if (!NT_SUCCESS(status))
				return retValue;

			PFLT_CONTEXT oldCtx;
			status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, &oldCtx);
			if (oldCtx != NULL)
			{
				ctx = (PSTREAM_HANDLE_CONTEXT)oldCtx;
			}

			if (!NT_SUCCESS(status))
				return retValue;
		}

		ctx->isEncrypted = tmpCtx.isEncrypted;
		ctx->isEncryptFile = tmpCtx.isEncryptFile;
		ctx->keyWord = tmpCtx.keyWord;

		if (ctx->isEncrypted == IS_NOT_ENCRYPTED)
		{
			PCHAR procName = GetCurrentProcessName(ProcessNameOffset);

			if (IsSecretProcess(ctx->keyWord, procName))
			{
				status = EncryptFile(Data, FltObjects, key);
				if (NT_SUCCESS(status))
				{
					ctx->isEncrypted = IS_ENCRYPTED;
					DbgPrint("Encrypt a file succeed while Create\n");

				}
				else
				{
					DbgPrint("Encrypt a file fail while Create\n");
				}
			}
		}

		status = FltQueryInformationFile(FltObjects->Instance, Data->Iopb->TargetFileObject,
			&(ctx->fileInfo), sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);

		cfFileCacheClear(FltObjects->FileObject);


	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("A exception happened while post create \n");
		if (ctx != NULL)
		{
			FltReleaseContext(ctx);
		}
	}

	return retValue;
}



/*++
		----------Read------------
--*/

FLT_PREOP_CALLBACK_STATUS
MyPreRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	NTSTATUS status;

	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;
	ULONG readLen = iopb->Parameters.Read.Length;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
		return retValue;

	__try
	{
		if (IS_SYSTEM_OPEN == FALSE)
			return retValue;

		//acquire the stream context
		PSTREAM_HANDLE_CONTEXT ctx;

		status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&ctx);

		if (!NT_SUCCESS(status))
			return retValue;

		BOOLEAN canDecode = FALSE;

		if (ctx->isEncrypted == IS_ENCRYPTED)
		{
			PCHAR procName = GetCurrentProcessName(ProcessNameOffset);

			if (IsSecretProcess(ctx->keyWord, procName))
			{
				p2pCtx = (PPRE_2_POST_CONTEXT)ExAllocateFromNPagedLookasideList(&Pre2PostContextList);
				if (p2pCtx == NULL)
				{
					//goto leave;//release the resource
					if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
					{
						if (newBuf != NULL)
						{
							ExFreePool(newBuf);
						}

						if (newMdl != NULL)
						{
							IoFreeMdl(newMdl);
						}

						if (p2pCtx != NULL)
						{
							ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
						}
					}
				}

				*CompletionContext = p2pCtx;

				PFILE_STANDARD_INFORMATION fileInfo = &(ctx->fileInfo);

				LONGLONG offset = (fileInfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) - (iopb->Parameters.Read.ByteOffset.QuadPart);

				if (offset < 0)
				{
					DbgPrint("End of File\n");
					iopb->Parameters.Read.ByteOffset.QuadPart = fileInfo->EndOfFile.QuadPart + 1;
					return FLT_PREOP_SUCCESS_NO_CALLBACK;
				}

				offset = (fileInfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) -
					(iopb->Parameters.Read.ByteOffset.QuadPart + iopb->Parameters.Read.Length - 1);

				if (offset < 0)
				{
					DbgPrint("reset read file length\n");
					iopb->Parameters.Read.Length = (fileInfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) -
						(iopb->Parameters.Read.ByteOffset.QuadPart) + 1;

					FltSetCallbackDataDirty(Data);
					readLen = iopb->Parameters.Read.Length;
				}

				p2pCtx->IS_DECONGD = FALSE;

				if (iopb->IrpFlags&(IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE))
				{
					canDecode = TRUE;
				}

				retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
			else
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
		else
		{
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		if (canDecode)
		{
			DbgPrint("read file canDecode\n");
			if (readLen == 0)
			{
				//goto leave;
				if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
				{
					if (newBuf != NULL)
					{
						ExFreePool(newBuf);
					}

					if (newMdl != NULL)
					{
						IoFreeMdl(newMdl);
					}

					if (p2pCtx != NULL)
					{
						ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
					}
				}
			}

			newBuf = ExAllocatePoolWithTag(NonPagedPool, readLen, BUFFER_SWAP_TAG);
			if (newBuf == NULL)
			{
				//goto leave;
				if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
				{
					if (newBuf != NULL)
					{
						ExFreePool(newBuf);
					}

					if (newMdl != NULL)
					{
						IoFreeMdl(newMdl);
					}

					if (p2pCtx != NULL)
					{
						ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
					}
				}
			}

			if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
			{
				newMdl = IoAllocateMdl(newBuf, readLen, FALSE, FALSE, NULL);
				if (newMdl == NULL)
				{
					//goto leave;
					if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
					{
						if (newBuf != NULL)
						{
							ExFreePool(newBuf);
						}

						if (newMdl != NULL)
						{
							IoFreeMdl(newMdl);
						}

						if (p2pCtx != NULL)
						{
							ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
						}
					}
				}

				MmBuildMdlForNonPagedPool(newMdl);
			}

			iopb->Parameters.Read.ReadBuffer = newBuf;
			iopb->Parameters.Read.MdlAddress = newMdl;
			FltSetCallbackDataDirty(Data);

			//store the new buffer to context
			p2pCtx->SwappedBuffer = newBuf;

			p2pCtx->IS_DECONGD = TRUE;
			retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

		}
		else
		{
			DbgPrint("read file Cannot decode\n");
			retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

			PVOID origBuf = NULL;
			FltLockUserBuffer(Data);

			if (iopb->Parameters.Read.MdlAddress != NULL)
			{
				DbgPrint("Get buffer from MDL\n");
				origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);

				if (origBuf == NULL)
				{
					DbgPrint("Memory is error in my  read\n");
					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
					return FLT_PREOP_COMPLETE;
				}
			}
			else
			{
				origBuf = iopb->Parameters.Read.ReadBuffer;


				if (origBuf != NULL)
				{
					status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &(iopb->Parameters.Read.ByteOffset),
						iopb->Parameters.Read.Length, origBuf, FLTFL_IO_OPERATION_NON_CACHED, &(Data->IoStatus.Information), NULL, NULL);
					Data->IoStatus.Status = status;

					DbgPrint("my read complete\n");
					DecodeData(origBuf, origBuf, iopb->Parameters.Read.ByteOffset.QuadPart, Data->IoStatus.Information, key);
					return FLT_PREOP_COMPLETE;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Pre Read error\n");
	}

	return retValue;

}


#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS 
MyPostRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	PVOID origBuf;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	NTSTATUS status;
	PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;
	BOOLEAN cleanupAllocateBuffer = TRUE;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	//decrypt the file
	__try
	{

		PSTREAM_HANDLE_CONTEXT ctx;
		
		status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&ctx);

		if (!NT_SUCCESS(status))
			return retValue;

		DbgPrint("Post Read\n");

		if (p2pCtx == NULL)
		{
			goto leave;
		}

		if (p2pCtx->IS_DECONGD)
		{
			DbgPrint("My Post Read\n");

			DecodeData(p2pCtx->SwappedBuffer, p2pCtx->SwappedBuffer,
				iopb->Parameters.Read.ByteOffset.QuadPart, Data->IoStatus.Information, key);

			if (iopb->Parameters.Read.MdlAddress != NULL)
			{
				DbgPrint("Get Buffer from MDL\n");
				origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);

				if (origBuf == NULL)
				{
					origBuf = iopb->Parameters.Read.ReadBuffer;
				}
			}
			else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
			{
				origBuf = iopb->Parameters.Read.ReadBuffer;
			}
			else
			{
				if (FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, SwapPostReadBuffersWhenSafe, &retValue))
				{
					cleanupAllocateBuffer = FALSE;
				}
				else
				{
					Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
					Data->IoStatus.Information = 0;
				}

				goto leave;
			}

			if (origBuf != NULL)
			{
				RtlCopyMemory(origBuf, p2pCtx->SwappedBuffer, Data->IoStatus.Information);
				FltSetCallbackDataDirty(Data);
			}

			PFILE_STANDARD_INFORMATION fileinfo = &(ctx->fileInfo);

			LONGLONG offset;
			offset = (fileinfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) - (iopb->Parameters.Read.ByteOffset.QuadPart +
				iopb->Parameters.Read.Length - 1);

			if (offset < 0)
			{
				Data->IoStatus.Information = (fileinfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) - 
					(iopb->Parameters.Read.ByteOffset.QuadPart) + 1;
			}

		leave:
			if (cleanupAllocateBuffer)
			{
				ExFreePool(p2pCtx->SwappedBuffer);
				ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
			}
		}
		else
		{
			PFILE_STANDARD_INFORMATION fileinfo = &(ctx->fileInfo);
			LONGLONG offset;
			offset = (fileinfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) - (iopb->Parameters.Read.ByteOffset.QuadPart +
				iopb->Parameters.Read.Length - 1);

			if (offset < 0)
			{
				Data->IoStatus.Information = (fileinfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) -
					(iopb->Parameters.Read.ByteOffset.QuadPart) + 1;

			}

			FltSetCallbackDataDirty(Data);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Exception happened in Post Read!\n");
	}
	return FLT_POSTOP_FINISHED_PROCESSING;

}


#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS
SwapPostReadBuffersWhenSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;
	PVOID origBuf;
	NTSTATUS status;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	if (KeGetCurretnIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	if (p2pCtx->IS_DECONGD)
	{
		status = FltLockUserBuffer(Data);

		if (!NT_SUCCESS(status))
		{
			Data->IoStatus.Status = status;
			Data->IoStatus.Information = 0;
		}
		else
		{
			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);

			if (origBuf == NULL)
			{
				if (iopb->Parameters.Read.ReadBuffer != NULL)
				{
					RtlCopyMemory(iopb->Parameters.Read.ReadBuffer, p2pCtx->SwappedBuffer, Data->IoStatus.Information);
				}
				else
				{
					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
				}
			}
			else
			{
				RtlCopyMemory(origBuf, p2pCtx->SwappedBuffer, Data->IoStatus.Information);
			}

		}
	}


	PSTREAM_HANDLE_CONTEXT ctx;
	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&ctx);

	PFILE_STANDARD_INFORMATION fileinfo = &(ctx->fileInfo);

	LONGLONG offset;
	offset = (iopb->Parameters.Read.ByteOffset.QuadPart + iopb->Parameters.Read.Length - 1) -
		(fileinfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN);
	if (offset > 0)
	{
		Data->IoStatus.Information = (fileinfo->EndOfFile.QuadPart - ENCRYPT_MARK_LEN) - (iopb->Parameters.Read.ByteOffset.QuadPart) + 1;
	}

	FltSetCallbackDataDirty(Data);

	ExFreePool(p2pCtx->SwappedBuffer);
	ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);

	return FLT_POSTOP_FINISHED_PROCESSING;
	
}



#pragma LOCKEDCODE
FLT_PREOP_CALLBACK_STATUS
MyPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PVOID newMdl = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;
	PVOID origBuf;
	NTSTATUS status;
	ULONG writeLen;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	__try
	{
		if (IS_SYSTEM_OPEN == FALSE)
		{
			return retValue;
		}

		PSTREAM_HANDLE_CONTEXT ctx;

		status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&ctx);

		if (!NT_SUCCESS(status))
		{
			return retValue;
		}

		BOOLEAN canEncrypt = FALSE;
		BOOLEAN noCache = FALSE;

		if (ctx->isEncrypted == IS_NOT_ENCRYPTED&&ctx->isEncryptFile == IS_ENCRYPT_FILE)
		{
			PCHAR procName = GetCurrentProcessName(ProcessNameOffset);

			if (IsSecretProcess(ctx->keyWord, procName))
			{
				DbgPrint("IS A SECRET PROCESS in pre Write\n");
				DbgPrint("Process Name is %s.\n", procName);

				canEncrypt = TRUE;
				writeLen = iopb->Parameters.Write.Length;
				if (iopb->IrpFlags&(IRP_NOCACHE))
				{
					noCache = TRUE;
					writeLen += ENCRYPT_MARK_LEN;
				}
				else
				{
					noCache = FALSE;

					return retValue;
				}
			}
		}

		if (canEncrypt)
		{
			if (iopb->Parameters.Write.MdlAddress != NULL)
			{
				origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress, NormalPagePriority);

				if (origBuf == NULL)
				{
					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
					DbgPrint("get Mdl err");
					
					if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
					{
						if (newBuf != NULL)
							ExFreePool(newBuf);
						if (newMdl != NULL)
							IoFreeMdl(newMdl);
						if (p2pCtx != NULL)
						{
							ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
						}
					}
					return retValue;
				}
			}
			else
			{
				origBuf = iopb->Parameters.Write.WriteBuffer;
			}

			if (origBuf == NULL)
			{
				DbgPrint("cann't get orig buf in pre write");

				if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
				{
					if (newBuf != NULL)
						ExFreePool(newBuf);
					if (newMdl != NULL)
						IoFreeMdl(newMdl);
					if (p2pCtx != NULL)
					{
						ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
					}
				}
				return retValue;
			}

			newBuf = ExAllocatePoolWithTag(NonPagedPool, writeLen, BUFFER_SWAP_TAG);
			if (newBuf == NULL)
			{
				DbgPrint("Can't get new buf in pre write.");

				if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
				{
					if (newBuf != NULL)
						ExFreePool(newBuf);
					if (newMdl != NULL)
						IoFreeMdl(newMdl);
					if (p2pCtx != NULL)
					{
						ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
					}
				}

				return retValue;
			}

			if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
			{
				newMdl = IoAllocateMdl(newBuf, writeLen, FALSE, FALSE, NULL);
				if (newMdl == NULL)
				{
					DbgPrint("can not get mdl in pre write");

					if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
					{
						if (newBuf != NULL)
							ExFreePool(newBuf);
						if (newMdl != NULL)
							IoFreeMdl(newMdl);
						if (p2pCtx != NULL)
						{
							ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
						}
					}
					return retValue;
				}
				MmBuildMdlForNonPagedPool(newMdl);
			}

			RtlCopyMemory(newBuf, origBuf, iopb->Parameters.Write.Length);

			EncryptData(newBuf, newBuf, iopb->Parameters.Write.ByteOffset.QuadPart, iopb->Parameters.Write.Length, key);

			if (noCache)
			{
				WriteEncryptTrail(newBuf, iopb->Parameters.Write.Length);
			}

			p2pCtx = (PPRE_2_POST_CONTEXT)ExAllocateFromNPagedLookasideList(&Pre2PostContextList);

			if (p2pCtx == NULL)
			{
				DbgPrint("p2p get err");

				if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
				{
					if (newBuf != NULL)
						ExFreePool(newBuf);
					if (newMdl != NULL)
						IoFreeMdl(newMdl);
					if (p2pCtx != NULL)
					{
						ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
					}
				}
				return retValue;
			}

			iopb->Parameters.Write.WriteBuffer = newBuf;
			iopb->Parameters.Write.MdlAddress = newMdl;
			if (noCache)
			{
				iopb->Parameters.Write.Length += ENCRYPT_MARK_LEN;
			}

			FltSetCallbackDataDirty(Data);
			ctx->isEncrypted = IS_ENCRYPTED;

			p2pCtx->SwappedBuffer = newBuf;
			*CompletionContext = p2pCtx;

			retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

		}


	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("exception happened in MyPreWrite");
	}
	return retValue;
}

#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS 
MyPostWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	ExFreePool(p2pCtx->SwappedBuffer);
	ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);

	Data->IoStatus.Information = Data->Iopb->Parameters.Write.Length;

	FltSetCallbackDataDirty(Data);
	return FLT_POSTOP_FINISHED_PROCESSING;
}



FLT_PREOP_CALLBACK_STATUS
MyPreClose(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	UNREFERENCED_PARAMETER(CompletionContext);

	cfFileCacheClear(FltObjects->FileObject);

	return retValue;
}


#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS 
MyPostClose(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	return retValue;
}



#pragma LOCKEDCODE
FLT_PREOP_CALLBACK_STATUS 
MyPreQueryInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	return retValue;
}


#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS 
MyPostQueryInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	STREAM_HANDLE_CONTEXT ctx;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	__try
	{
		if (!IS_SYSTEM_OPEN)
		{
			return retValue;
		}

		NTSTATUS status = GetFileEncryptInfoToCtx(Data, FltObjects, &ctx, key_word_header);

		if (NT_SUCCESS(status))
		{
			if (ctx.isEncrypted = IS_ENCRYPTED)
			{
				PCHAR procName = GetCurrentProcessName(ProcessNameOffset);

				if (!IsSecretProcess(ctx.keyWord, procName))
				{
					return retValue;
				}

				PVOID buff = iopb->Parameters.QueryFileInformation.InfoBuffer;

				switch (iopb->Parameters.QueryFileInformation.FileInformationClass)
				{

				case FileStandardInformation:
				{
					DbgPrint("Query File Standard Information");
					PFILE_STANDARD_INFORMATION info = (PFILE_STANDARD_INFORMATION)buff;
					info->AllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					info->EndOfFile.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileAllInformation:
				{
					DbgPrint("Query File All Information");
					PFILE_ALL_INFORMATION info = (PFILE_ALL_INFORMATION)buff;
					if (Data->IoStatus.Information >= sizeof(FILE_BASIC_INFORMATION) + sizeof(FILE_STANDARD_INFORMATION))
					{
						info->StandardInformation.AllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
						info->StandardInformation.EndOfFile.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;

						if (Data->IoStatus.Information >=
							sizeof(FILE_BASIC_INFORMATION) +
							sizeof(FILE_STANDARD_INFORMATION) +
							sizeof(FILE_EA_INFORMATION) +
							sizeof(FILE_ACCESS_INFORMATION) +
							sizeof(FILE_POSITION_INFORMATION))
						{
							info->PositionInformation.CurrentByteOffset.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
						}
					}

					break;
				}

				case FileAllocationInformation:
				{
					DbgPrint("Query File Allocation Information");
					PFILE_ALLOCATION_INFORMATION info = (PFILE_ALLOCATION_INFORMATION)buff;
					info->AllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileValidDataLengthInformation:
				{
					DbgPrint("Query Valid Data Length Information");
					PFILE_VALID_DATA_LENGTH_INFORMATION info = (PFILE_VALID_DATA_LENGTH_INFORMATION)buff;
					info->ValidDataLength.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileEndOfFileInformation:
				{
					DbgPrint("Query File End of File Information");
					PFILE_END_OF_FILE_INFORMATION info = (PFILE_END_OF_FILE_INFORMATION)buff;
					info->EndOfFile.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FilePositionInformation:
				{
					PFILE_POSITION_INFORMATION info = (PFILE_POSITION_INFORMATION)buff;
					info->CurrentByteOffset.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileStreamInformation:
				{
					PFILE_STREAM_INFORMATION info = (PFILE_STREAM_INFORMATION)buff;
					info->StreamAllocationSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					info->StreamSize.QuadPart -= ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				default:
				{
					DbgPrint("Default");
					DbgPrint("Query File information class is %d", iopb->Parameters.QueryFileInformation.FileInformationClass);
					break;
				}
				}

				FltSetCallbackDataDirty(Data);
			}
		}
		else
		{
			DbgPrint("Get file info fail in post info");
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("err happen in  post info");
	}
	return retValue;
}



//set information
#pragma LOCKEDCODE
FLT_PREOP_CALLBACK_STATUS
MyPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;//return value, success then call post
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	STREAM_HANDLE_CONTEXT ctx;
	//If the interupt request level is too high, then return
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}

	__try
	{
		if (!IS_SYSTEM_OPEN)
		{
			return retValue;
		}

		NTSTATUS status = GetFileEncryptInfoToCtx(Data, FltObjects, &ctx, key_word_header);

		if (NT_SUCCESS(status))
		{
			//the file is encrypted
			if (ctx.isEncrypted == IS_ENCRYPTED)
			{
				//Get Current process name which is visiting the file
				PCHAR procName = GetCurrentProcessName(ProcessNameOffset);

				if (!IsSecretProcess(ctx.keyWord, procName))
				{
					return retValue;
				}

				//modify the information of file, cuz the ENCRYPT_MARK_LEN
				PVOID buff = iopb->Parameters.SetFileInformation.InfoBuffer;

				switch (iopb->Parameters.SetFileInformation.FileInformationClass)
				{

				case FileStandardInformation:
				{
					DbgPrint("Set File Standard Information");
					PFILE_STANDARD_INFORMATION info = (PFILE_STANDARD_INFORMATION)buff;
					info->AllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					info->EndOfFile.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileAllInformation:
				{
					DbgPrint("Set File All Information");
					PFILE_ALL_INFORMATION info = (PFILE_ALL_INFORMATION)buff;
					if (Data->IoStatus.Information >=
						sizeof(FILE_BASIC_INFORMATION) +
						sizeof(FILE_STANDARD_INFORMATION))
					{
						info->StandardInformation.AllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
						info->StandardInformation.EndOfFile.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;

						if (Data->IoStatus.Information >=
							sizeof(FILE_BASIC_INFORMATION) +
							sizeof(FILE_STANDARD_INFORMATION) +
							sizeof(FILE_EA_INFORMATION) +
							sizeof(FILE_ACCESS_INFORMATION) +
							sizeof(FILE_POSITION_INFORMATION))
						{
							info->PositionInformation.CurrentByteOffset.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
						}
					}
					break;
				}

				case FileAllocationInformation:
				{
					DbgPrint("Set File Allocation Information");
					PFILE_ALLOCATION_INFORMATION info = (PFILE_ALLOCATION_INFORMATION)buff;
					info->AllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileValidDataLengthInformation:
				{
					DbgPrint("set file valid data length information");
					PFILE_VALID_DATA_LENGTH_INFORMATION info = (PFILE_VALID_DATA_LENGTH_INFORMATION)buff;
					info->ValidDataLength.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileEndOfFileInformation:
				{
					DbgPrint("set file end of file information");
					PFILE_END_OF_FILE_INFORMATION info = (PFILE_END_OF_FILE_INFORMATION)buff;
					info->EndOfFile.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FilePositionInformation:
				{
					DbgPrint("set file position information");
					PFILE_POSITION_INFORMATION info = (PFILE_POSITION_INFORMATION)buff;
					info->CurrentByteOffset.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				case FileStreamInformation:
				{
					DbgPrint("set file stream information");
					PFILE_STREAM_INFORMATION info = (PFILE_STREAM_INFORMATION)buff;
					info->StreamAllocationSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					info->StreamSize.QuadPart += ENCRYPT_FILE_CONTENT_OFFSET;
					break;
				}

				default:
				{
					DbgPrint("Default");
					break;
				}
				
				
				}


			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Error happened in pre set info");
	}

	return retValue;
}


#pragma LOCKEDCODE
FLT_POSTOP_CALLBACK_STATUS 
MyPostSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retValue;
	}
	return retValue;
}



#pragma LOCKEDCODE
VOID CleanupVolumeContext(_In_ PFLT_CONTEXT context, _In_ FLT_CONTEXT_TYPE ContextType)
{
	PVOLUME_CONTEXT ctx = (PFLT_CONTEXT)context;
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return;
	}

	UNREFERENCED_PARAMETER(ContextType);
	if (ctx->Name.Buffer != NULL)
	{
		ExFreePool(ctx->Name.Buffer);
		ctx->Name.Buffer = NULL;
	}
	
}


#pragma LOCKEDCODE
VOID CleanupStreamHandleContext(_In_ PFLT_CONTEXT context, _In_ FLT_CONTEXT_TYPE ContextType)
{
	PSTREAM_HANDLE_CONTEXT ctx = (PSTREAM_HANDLE_CONTEXT)context;

	UNREFERENCED_PARAMETER(ContextType);
	
}


NTSTATUS MyConnectionCallback(_In_ PFLT_PORT ClientProt, _In_ PVOID ServerPortCookie, _In_ PVOID ConnectionContext,
	_In_ ULONG SizeOfContext, _Out_ PVOID *ConnectionPortCookie)
{
	return STATUS_SUCCESS;
}

VOID MyDisconnectCallback(_In_ PVOID ConnectionCookie)
{
	return;
}

NTSTATUS MyMessageCallback(_In_ PVOID PortCookie, _In_opt_ PVOID InputBuffer, _In_ ULONG InputBufferLength,
	_Out_opt_ PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength)
{
	if (InputBufferLength < sizeof(MESSAGE_DATA) || OutputBufferLength < sizeof(MESSAGE_BACK))
	{
		DbgPrint("UnSuccess");
		return STATUS_UNSUCCESSFUL;
	}

	PMESSAGE_DATA msg = (PMESSAGE_DATA)InputBuffer;
	PMESSAGE_BACK back = (PMESSAGE_BACK)OutputBuffer;

	*ReturnOutputBufferLength = sizeof(PMESSAGE_BACK);

	switch (msg->code)
	{

	case CODE_OPEN_SYSTEM:
	{
		IS_SYSTEM_OPEN = TRUE;
		back->code = CODE_SUCCESS;
		DbgPrint("System open");
		break;
	}

	case CODE_CLOSE_SYSTEM:
	{
		IS_SYSTEM_OPEN = FALSE;
		back->code = CODE_SUCCESS;
		DbgPrint("System close");
		break;
	}

	case CODE_IS_RUNNING:
	{
		if (IS_SYSTEM_OPEN)
		{
			back->code = CODE_RUNNING;
		}
		else
			back->code = CODE_CLOSED;
		break;
	}

	case CODE_SEND_STRATEGY:
	{
		DbgPrint("send strategy");
		CHAR *str = msg->buffOffset;
		
		IS_SYSTEM_OPEN = FALSE;
		if (key_word_header != NULL)
		{
			FreeStrategy(key_word_header);
		}

		key_word_header = GetStrategyFromString(str);

		back->code = CODE_SUCCESS;
		DbgPrint("strategy is %s", str);
		break;
	}

	case CODE_SEND_KEY:
	{
		DbgPrint("send key");
		CHAR *str = msg->buffOffset;
		size_t len = strlen(str);

		len = len < KEY_MAX_LEN - 1 ? len : KEY_MAX_LEN - 1;

		IS_SYSTEM_OPEN = FALSE;

		RtlZeroMemory(key, KEY_MAX_LEN);
		RtlCopyMemory(key, str, len);
		DbgPrint("new key is %s", str);

		back->code = CODE_SUCCESS;
		break;

	}

	default:
	{
		DbgPrint("Unsuccess");
		back->code = CODE_UNKNOWN_CODE;
		break;
	}


	}

	return STATUS_SUCCESS
}
