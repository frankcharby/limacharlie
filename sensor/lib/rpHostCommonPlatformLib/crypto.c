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

#include "crypto.h"

#include <cryptoLib/cryptoLib.h>

#include "deployments.h"

RPRIVATE RU8 dev_c2_public_key[] = {"-----BEGIN CERTIFICATE-----\n\
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\n\
-----END CERTIFICATE-----\n"};


RPRIVATE RU8 dev_root_public_key[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe2, 0x0d, 0x17,
    0x5e, 0x09, 0xdf, 0xe3, 0x1a, 0x98, 0xbe, 0x00, 0x2b, 0x56, 0x3d, 0xce,
    0x2d, 0xc9, 0x2b, 0x05, 0xaf, 0x11, 0x7d, 0xaf, 0xfd, 0x8f, 0x4f, 0x19,
    0x4d, 0x10, 0x29, 0xfd, 0xa4, 0x23, 0x30, 0x5a, 0x2e, 0x68, 0x97, 0xa8,
    0x33, 0xef, 0x54, 0x8f, 0xb3, 0xe8, 0x8b, 0xca, 0x0d, 0xc8, 0xa7, 0x5a,
    0xc8, 0x6b, 0xdc, 0xe2, 0xbe, 0x40, 0x35, 0x9c, 0xb0, 0xbd, 0xf5, 0xd8,
    0xdc, 0xe9, 0xe6, 0x78, 0x37, 0x80, 0xe7, 0x04, 0x86, 0x9c, 0x1c, 0xf0,
    0xdc, 0xe9, 0x22, 0x2c, 0x7d, 0xbd, 0x06, 0xbf, 0xa9, 0x6b, 0xd6, 0xc3,
    0x89, 0x67, 0x74, 0x1d, 0xae, 0xa2, 0xd6, 0x57, 0x57, 0xfe, 0xe5, 0xf5,
    0xb7, 0x22, 0x0b, 0xf2, 0x27, 0x0e, 0xf7, 0x59, 0xaf, 0xa5, 0x7b, 0xf1,
    0x3a, 0x9c, 0xa2, 0xbf, 0x2a, 0x8e, 0xcd, 0x2e, 0x2c, 0x3f, 0xa1, 0x79,
    0x4e, 0xeb, 0xd1, 0xb2, 0xbb, 0xad, 0xa1, 0xfd, 0x32, 0xc5, 0x76, 0x24,
    0x9c, 0x00, 0x38, 0x32, 0x83, 0xd8, 0x5a, 0x69, 0xe6, 0x92, 0x2c, 0xb8,
    0x0c, 0x77, 0x9c, 0x77, 0x05, 0x2a, 0x6b, 0x35, 0xd7, 0x76, 0x93, 0x4e,
    0x77, 0x75, 0x97, 0x27, 0x8c, 0xa5, 0xa6, 0xb0, 0x61, 0xd4, 0xed, 0x53,
    0xc3, 0x31, 0x89, 0x8b, 0xc5, 0xe8, 0x35, 0x6e, 0x43, 0x1a, 0x45, 0x57,
    0xd4, 0x14, 0x27, 0xe6, 0xad, 0x83, 0xbc, 0xaf, 0xf5, 0x9e, 0xbb, 0x8b,
    0xbf, 0xee, 0xc2, 0x0c, 0xe3, 0xc5, 0xb9, 0x75, 0x03, 0x10, 0x4f, 0x53,
    0x2b, 0xd3, 0xe8, 0x6b, 0xf7, 0x96, 0x3f, 0x5b, 0x35, 0x38, 0x06, 0x4e,
    0x92, 0xb4, 0x2b, 0xfc, 0x69, 0xcf, 0xdb, 0xcc, 0xc5, 0x66, 0x41, 0xa7,
    0xad, 0xb8, 0x77, 0x3b, 0x8a, 0xf4, 0xc3, 0xf0, 0xa2, 0x7b, 0x76, 0xb9,
    0xfd, 0xf1, 0xc5, 0xed, 0x7e, 0xe5, 0xf9, 0x5f, 0x7c, 0x4d, 0x3c, 0xbe,
    0x95, 0x02, 0x03, 0x01, 0x00, 0x01
};

static RPU8 prod_c2_public_key = NULL;
static RPU8 prod_root_public_key = NULL;


RVOID
    setC2PublicKey
    (
        RPU8 key
    )
{
    prod_c2_public_key = key;
}

RVOID
    setRootPublicKey
    (
        RPU8 key
    )
{
    prod_root_public_key = key;
}

RVOID
    freeKeys
    (

    )
{
    if( NULL != prod_c2_public_key )
    {
        rpal_memory_free( prod_c2_public_key );
    }

    if( NULL != prod_root_public_key )
    {
        rpal_memory_free( prod_root_public_key );
    }
}


RPU8
    getC2PublicKey
    (

    )
{
    RPU8 pubKey = NULL;

    if( NULL != prod_c2_public_key )
    {
        pubKey = prod_c2_public_key;
    }
    else
    {
        pubKey = dev_c2_public_key;
    }

    return pubKey;
}



RPU8
    getRootPublicKey
    (

    )
{
    RPU8 pubKey = NULL;

    if( NULL != prod_root_public_key )
    {
        pubKey = prod_root_public_key;
    }
    else
    {
        pubKey = dev_root_public_key;
    }

    return pubKey;
}



RBOOL
    verifyC2Signature
    (
        RPU8 buffer,
        RU32 bufferSize,
        RU8 signature[ CRYPTOLIB_SIGNATURE_SIZE ]
    )
{
    RBOOL isValid = FALSE;

    RPU8 pubKey = NULL;

    if( NULL != buffer &&
        0 != bufferSize &&
        NULL != signature )
    {
        pubKey = getC2PublicKey();

        if( NULL != pubKey )
        {
            if( CryptoLib_verify( buffer, bufferSize, pubKey, signature ) )
            {
                isValid = TRUE;
            }
        }
    }

    return isValid;
}
