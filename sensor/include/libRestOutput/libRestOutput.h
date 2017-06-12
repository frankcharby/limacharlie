/*
Copyright 2017 Google, Inc

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

#ifndef LIB_REST_OUTPUT_H
#define LIB_REST_OUTPUT_H

#include <rpal/rpal.h>

typedef RPVOID restOutputContext;

restOutputContext
    restOutput_newContext
    (
        RPCHAR destUrl,     // MUST be of format: my.domain.name[:port[/page]]
        RPCHAR apiKeyHeader
    );

RVOID
    restOutput_freeContext
    (
        restOutputContext pContext
    );

RBOOL
    restOutput_send
    (
        restOutputContext pContext,
        RPCHAR payload,
        RU32* pStatusCode,
        RU32 timeout
    );


#endif
