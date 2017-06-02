/*
Copyright 2015 refractionPOINT

Licensed under the Apache License, Version 2.0 ( the "License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <rpal/rpal_stringbuffer.h>

#define RPAL_FILE_ID    10

typedef struct
{
    rBlob blob;

} _rString;

RPRIVATE RCHAR g_b64A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
RPRIVATE RWCHAR g_b64W[] = _WCH( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" );
#define _B64_LEN(len) (((4 * (len) / 3) + 3) & ~3)

rString
    rpal_stringbuffer_new
    (
        RU32 initialSize,
        RU32 growBy
    )
{
    _rString* pStr = NULL;

    pStr = rpal_memory_alloc( sizeof( _rString ) );

    if( rpal_memory_isValid( pStr ) )
    {
        pStr->blob = rpal_blob_create( initialSize, growBy );

        if( NULL == pStr->blob )
        {
            rpal_memory_free( pStr );
            pStr = NULL;
        }
    }

    return (rString)pStr;
}

RVOID
    rpal_stringbuffer_free
    (
        rString pStringBuffer
    )
{
    if( rpal_memory_isValid( pStringBuffer ) )
    {
        rpal_blob_free( ((_rString*)pStringBuffer)->blob );
        rpal_memory_free( pStringBuffer );
    }
}

RVOID
    rpal_stringbuffer_freeWrapper
    (
        rString pStringBuffer
    )
{
    if( rpal_memory_isValid( pStringBuffer ) )
    {
        rpal_blob_freeWrapperOnly( ( (_rString*)pStringBuffer )->blob );
        rpal_memory_free( pStringBuffer );
    }
}

RBOOL
    rpal_stringbuffer_add
    (
        rString pStringBuffer,
        RPNCHAR pString
    )
{
    RBOOL isSuccess = FALSE;

    _rString* pStr = (_rString*)pStringBuffer;

    if( rpal_memory_isValid( pStringBuffer ) )
    {
        isSuccess = rpal_blob_add( pStr->blob, pString, rpal_string_strlen( pString ) * sizeof( RNCHAR ) );
    }

    return isSuccess;
}

RBOOL
    rpal_stringbuffer_addA
    (
        rString pStringBuffer,
        RPCHAR pString
    )
{
    RBOOL isSuccess = FALSE;

    _rString* pStr = (_rString*)pStringBuffer;

    if( rpal_memory_isValid( pStringBuffer ) )
    {
        isSuccess = rpal_blob_add( pStr->blob, pString, rpal_string_strlenA( pString ) * sizeof( RCHAR ) );
    }

    return isSuccess;
}

RBOOL
    rpal_stringbuffer_addW
    (
        rString pStringBuffer,
        RPWCHAR pString
    )
{
    RBOOL isSuccess = FALSE;

    _rString* pStr = (_rString*)pStringBuffer;

    if( rpal_memory_isValid( pStringBuffer ) )
    {
        isSuccess = rpal_blob_add( pStr->blob, pString, rpal_string_strlenW( pString ) * sizeof( RWCHAR ) );
    }

    return isSuccess;
}

// This does NOT include NULL termination since the stringbuffer methods take care of it
RPRIVATE
RBOOL
    _base64EncodeA
    (
        RPU8 buffer,
        RU32 bufferSize,
        RPCHAR outStr
    )
{
    RBOOL isSuccess = FALSE;

    RU32 i = 0;
    RPCHAR tmpChar = outStr;
    RPU8 tmpIn = buffer;
    RS32 tmpByte1 = 0;
    RS32 tmpByte2 = 0;
    RS32 tmpByte3 = 0;

    if( NULL != buffer &&
        0 != bufferSize &&
        NULL != outStr )
    {
        if( 2 < bufferSize )
        {
            for( i = 0; i < bufferSize - 2; i += 3 )
            {
                tmpByte1 = *tmpIn++;
                tmpByte2 = *tmpIn++;
                tmpByte3 = *tmpIn++;

                *tmpChar++ = g_b64A[ ( tmpByte1 >> 2 ) & 0x3F ];
                *tmpChar++ = g_b64A[ ( ( ( tmpByte1 & 3 ) << 4 ) + ( tmpByte2 >> 4 ) ) & 0x3F ];
                *tmpChar++ = g_b64A[ ( ( ( tmpByte2 & 15 ) << 2 ) + ( tmpByte3 >> 6 ) ) & 0x3F ];
                *tmpChar++ = g_b64A[ tmpByte3 & 0x3F ];
            }
        }

        if( bufferSize > i )
        {
            tmpByte1 = *tmpIn++;
            if( bufferSize > i + 1 )
            {
                tmpByte2 = *tmpIn++;
            }
            else
            {
                tmpByte2 = 0;
            }

            *tmpChar++ = g_b64A[ ( tmpByte1 >> 2 ) & 0x3F ];
            *tmpChar++ = g_b64A[ ( ( ( tmpByte1 & 3 ) << 4 ) + ( tmpByte2 >> 4 ) ) & 0x3F ];

            if( bufferSize > i + 1 )
            {
                *tmpChar++ = g_b64A[ ( ( tmpByte2 & 15 ) << 2 ) & 0x3F ];
            }
            else
            {
                *tmpChar++ = '=';
            }

            *tmpChar++ = '=';
        }

        isSuccess = TRUE;
    }

    return isSuccess;
}

// This does NOT include NULL termination since the stringbuffer methods take care of it
RPRIVATE
RBOOL
    _base64EncodeW
    (
        RPU8 buffer,
        RU32 bufferSize,
        RPWCHAR outStr
    )
{
    RBOOL isSuccess = FALSE;

    RU32 i = 0;
    RPWCHAR tmpChar = outStr;
    RPU8 tmpIn = buffer;
    RS32 tmpByte1 = 0;
    RS32 tmpByte2 = 0;
    RS32 tmpByte3 = 0;

    if( NULL != buffer &&
        0 != bufferSize &&
        NULL != outStr )
    {
        if( 2 < bufferSize )
        {
            for( i = 0; i < bufferSize - 2; i += 3 )
            {
                tmpByte1 = *tmpIn++;
                tmpByte2 = *tmpIn++;
                tmpByte3 = *tmpIn++;

                *tmpChar++ = g_b64W[ ( tmpByte1 >> 2 ) & 0x3F ];
                *tmpChar++ = g_b64W[ ( ( ( tmpByte1 & 3 ) << 4 ) + ( tmpByte2 >> 4 ) ) & 0x3F ];
                *tmpChar++ = g_b64W[ ( ( ( tmpByte2 & 15 ) << 2 ) + ( tmpByte3 >> 6 ) ) & 0x3F ];
                *tmpChar++ = g_b64W[ tmpByte3 & 0x3F ];
            }
        }

        if( bufferSize > i )
        {
            tmpByte1 = *tmpIn++;
            if( bufferSize > i + 1 )
            {
                tmpByte2 = *tmpIn++;
            }
            else
            {
                tmpByte2 = 0;
            }

            *tmpChar++ = g_b64W[ ( tmpByte1 >> 2 ) & 0x3F ];
            *tmpChar++ = g_b64W[ ( ( ( tmpByte1 & 3 ) << 4 ) + ( tmpByte2 >> 4 ) ) & 0x3F ];

            if( bufferSize > i + 1 )
            {
                *tmpChar++ = g_b64W[ ( ( tmpByte2 & 15 ) << 2 ) & 0x3F ];
            }
            else
            {
                *tmpChar++ = '=';
            }
        }

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    rpal_stringbuffer_addB64A
    (
        rString pStringBuffer,
        RPU8 pBuffer,
        RU32 bufferSize
    )
{
    RBOOL isSuccess = FALSE;
    _rString* pStr = (_rString*)pStringBuffer;
    RU32 encodedLen = 0;
    RPCHAR pChar = NULL;

    if( NULL != pStringBuffer &&
        NULL != pBuffer &&
        0 != bufferSize )
    {
        encodedLen = _B64_LEN( bufferSize );

        // Add enough data for the b64 to the blob.
        if( rpal_blob_add( pStr->blob, NULL, encodedLen * sizeof( RCHAR ) ) &&
            NULL != ( pChar = rpal_blob_getBuffer( pStr->blob ) ) )
        {
            pChar = (RPCHAR)( ( (RPU8)pChar + rpal_blob_getSize( pStr->blob ) ) - ( encodedLen * sizeof( RCHAR ) ) );

            if( _base64EncodeA( pBuffer, bufferSize, pChar ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}

RBOOL
    rpal_stringbuffer_addB64W
    (
        rString pStringBuffer,
        RPU8 pBuffer,
        RU32 bufferSize
    )
{
    RBOOL isSuccess = FALSE;
    _rString* pStr = (_rString*)pStringBuffer;
    RU32 encodedLen = 0;
    RPWCHAR pChar = NULL;

    if( NULL != pStringBuffer &&
        NULL != pBuffer &&
        0 != bufferSize )
    {
        encodedLen = _B64_LEN( bufferSize );

        // Add enough data for the b64 to the blob.
        if( rpal_blob_add( pStr->blob, NULL, encodedLen * sizeof( RWCHAR ) ) &&
            NULL != ( pChar = rpal_blob_getBuffer( pStr->blob ) ) )
        {
            pChar = (RPWCHAR)( ( (RPU8)pChar + rpal_blob_getSize( pStr->blob ) ) - ( encodedLen * sizeof( RWCHAR ) ) );

            if( _base64EncodeW( pBuffer, bufferSize, pChar ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}
RPNCHAR
    rpal_stringbuffer_getString
    (
        rString pStringBuffer
    )
{
    RPNCHAR ret = NULL;

    _rString* pStr = (_rString*)pStringBuffer;
    
    if( rpal_memory_isValid( pStringBuffer ) )
    {
        ret = (RPNCHAR)rpal_blob_getBuffer( (rBlob)( pStr->blob ) );
    }

    return ret;
}

RPCHAR
    rpal_stringbuffer_getStringA
    (
        rString pStringBuffer
    )
{
    return (RPCHAR)rpal_stringbuffer_getString( pStringBuffer );
}

RPWCHAR
    rpal_stringbuffer_getStringW
    (
        rString pStringBuffer
    )
{
    return (RPWCHAR)rpal_stringbuffer_getString( pStringBuffer );
}


RBOOL
    rpal_stringbuffer_reset
    (
        rString pStringBuffer
    )
{
    RBOOL isSuccess = FALSE;
    _rString* pStr = (_rString*)pStringBuffer;

    if( rpal_memory_isValid( pStringBuffer ) )
    {
        isSuccess = rpal_blob_reset( pStr->blob );
    }

    return isSuccess;
}