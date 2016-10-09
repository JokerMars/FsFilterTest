#pragma once

#ifndef _FILE_ENCRYPT_H
#define _FILE_ENCRYPT_H

#include<fltKernel.h>
#include<dontuse.h>
#include<suppress.h>


/*******Pool Tags********/
#define BUFFER_SWAP_TAG   "bdBS"
#define CONTEXT_TAG		  "xcBS"
#define NAME_TAG		  "mnBS"
#define PRE_2_POST_TAG	  "ppBS"
#define STREAM_HANDLE_CONTEXT_TAG		"shBS"

/*******Local Structure*********/

/*******Encrypt strategy structures*****/

//process info list
#define PROCESS_NAME_LEN		32
typedef struct _PROCESS_INFO
{
	CHAR processName[PROCESS_NAME_LEN];
	struct _PROCESS_INFO *next;
}PROCESS_INFO, *PPROCESS_INFO;


//define the structure of file type keyword list
#define TYPE_KEY_WORD_LEN		32 
typedef struct _TYPE_KEY_WORD
{
	CHAR keyWord[TYPE_KEY_WORD_LEN];//FILE TYPE
	PPROCESS_INFO processInfo;// the matched processes
	struct _TYPE_KEY_WORD *next;
}TYPE_KEY_WORD, *PTYPE_KEY_WORD;

///
///this is a volume context, one of these are attached to each volume we monitor.
///this is used to get a "DOS" name for debug display.
///
typedef struct _VOLUME_CONTEXT
{
	UNICODE_STRING Name;
	ULONG SectorSize;
}VOLUME_CONTEXT, *PVOLUME_CONTEXT;

#define MIN_SECTOR_SIZE 0X200  //512 bytes

//
//this is a context structure that is used to pass state from our pre_operation callback
//to our post_operation callback
//
typedef struct _PRE_2_POST_CONTEXT
{
	BOOLEAN IS_DECONGD;
	PVOID SwappedBuffer;

}PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;




#define IS_ENCRYPT_FILE			0X01//the file type is in strategy
#define IS_NOT_ENCRYPT_FILE		0X00


#define IS_ENCRYPTED			0X01//the file has been encrypted
#define IS_NOT_ENCRYPTED		0X00

//define the stream context
typedef struct _STREAM_HANDLE_CONTEXT
{
	FILE_STANDARD_INFORMATION fileInfo;
	PTYPE_KEY_WORD keyWord;//file type and the matched process
	INT isEncryptFile;     //if it's the encrypt file type
	INT isEncrypted;		//if file has been encrypted

}STREAM_HANDLE_CONTEXT, *PSTREAM_HANDLE_CONTEXT;

//define the mark of encrypt file
#define ENCRYPT_MARK_STRING "*****this file has been encrypted*****"

//the length of mark
#define ENCRYPT_MARK_LEN  128

//the offset of encrypted file content
#define ENCRYPT_FILE_CONTENT_OFFSET 128


//the encrypt file trail
typedef struct _ENCRYPT_TRAIL
{
	CHAR mark[ENCRYPT_MARK_LEN];
}ENCRYPT_TRAIL, *PENCRYPT_TRAIL;


//define the max len of a key
#define KEY_MAX_LEN		32







#endif