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
MIIGFzCCA/+gAwIBAgIJAI11dqTnl/4SMA0GCSqGSIb3DQEBCwUAMIGhMQswCQYD\n\
VQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxGDAW\n\
BgNVBAoMD3JlZnJhY3Rpb25QT0lOVDEUMBIGA1UECwwLTGltYUNoYXJsaWUxEjAQ\n\
BgNVBAMMCXJwX2MyX2RldjEpMCcGCSqGSIb3DQEJARYabWF4aW1lQHJlZnJhY3Rp\n\
b25wb2ludC5jb20wHhcNMTcwMzE2MDAxODQ3WhcNMTcwNDE1MDAxODQ3WjCBoTEL\n\
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3\n\
MRgwFgYDVQQKDA9yZWZyYWN0aW9uUE9JTlQxFDASBgNVBAsMC0xpbWFDaGFybGll\n\
MRIwEAYDVQQDDAlycF9jMl9kZXYxKTAnBgkqhkiG9w0BCQEWGm1heGltZUByZWZy\n\
YWN0aW9ucG9pbnQuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\n\
2x4QbFJmUt/xTmOaFToHTnayq3eBuE2HWA8O73YuUaeUFEUAJdjbQdnl2wxmf4Vv\n\
XVYvB+11fvyaoU0mhcNtNjyrLzE/ftG1054E/ktvxCiSd5uhfEm6OWhMxFdsI2ZD\n\
itaDVLXhJXhkWJigwyZwYPpxeGvlI9bZEhWlowLzyiBmL8DsHS+ac6nn2H3Mkty1\n\
H4ol4WzgT7lXk2mVMf++koJJqfkepS0K72f/lEdM5uu0WrA9u9xZH3Z4yBw0aE0i\n\
4bgncwVf+nSaLsaBLeRrB6DnnrTkC3q1BARhnjW8qGmtvUbgnPB3X7vnKO3WEaqZ\n\
hJXk4rA2/AP45oDm3+qIDxnzwkVIimqpTUDUbD/TXAFVjbMeXLu76kGXgNrJ4eXa\n\
oFTjgXUIpZyPj9/P7DAlbW25H9Gd7fXC9ASdy4/Iv9mPQNrMq+ZwTGi2qDpJbY70\n\
AF9DTyLks226OCSwLNVmSxnHhOge55RVSYOiMFOjcrBVfgbJvYodJ3G4Ixl1W9AN\n\
bDs1g9xSUVzD7OhmRDlKJbSovjvdy/859UI9erW6hQPZiXQ4nwa4yrC61cQo+yQw\n\
Xwxo5UFysdNc1ljn6w9kK4jRogPSHJOFxXkdi6WlTTPLQFe8EeXbFy7KAq1hAYoT\n\
r9qYVMKj0FOXqhzlY8hmrqbgdDbpbhIIIcdRBXMOPYcCAwEAAaNQME4wHQYDVR0O\n\
BBYEFOPTA/V9oAdXaDlxLiVBSbHsVVl7MB8GA1UdIwQYMBaAFOPTA/V9oAdXaDlx\n\
LiVBSbHsVVl7MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBADYHOUPT\n\
VdHGkeKaUrYjsxS6AiD92VThZZhvqoYljVV5EQvV3pl4q6OThz8rIzGcvQqFWYwE\n\
zSNSH1vodUhB9wiHsniYRMDfSwpl6YKI7OAM3jzLTykJ2ucMIXPvtGk7LAWE+dFD\n\
CGmPXFBBfaZueq8VoM+5tbOktXzn+7tkoFU0j9sAn//TvQl+IvwrDaeFz4qyhI0k\n\
NThzY9mZmz5OfbGhCFIurV0NOm7mlMvgYSjQtr99LkkuFdm7mzLWMnJAoTEoukZp\n\
9xldlvbNgGpYZ41FSoqk8q+GgDhmErCKubbhTfLlsHU9WGhX935DmLNzKH1ZtH8u\n\
ko6g6u/Zj9iuNh3p87XM10TpyCi/w3jEGVGU0FfxNUOqI9EWRSUDNQjXdEd1DGx7\n\
8xP/U10flR23zQGiiT1YN9yYbHj9GQpb3FMFFs+OIy1NPaY32KkM4icMfIuCW4UM\n\
+uPfOgbICb7kl84T1GucUC+7B9La9n4GXDnLGJusDsnybIop0RJf62ruN+p/QrCF\n\
mahU0aXrBJ71ydzleJBQwbiHMcpc27LPZ0cub2GSpJMWo0PbB0+0VytqIaergLwz\n\
4C4ILO3iYJSBzDjmTMHD1QY2q7MoizvQHs1ubVNnXRyNig/dfKhnxzRaJwj5lbML\n\
prpkbX8rMUWw4JwyzNEEG15ozDNvQ1yLw6Nk\n\
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
