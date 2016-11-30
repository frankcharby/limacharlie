# Copyright 2015 refractionPOINT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from beach.actor import Actor
import traceback
import hashlib
import time
import ipaddress
import uuid
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class EnrollmentManager( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.db.start()

        self.handle( 'enroll', self.enroll )

    def deinit( self ):
        pass

    def enroll( self, msg ):
        req = msg.data

        aid = AgentId( req[ 'aid' ] )
        extIp = req[ 'public_ip' ]
        intIp = req[ 'internal_ip' ]
        hostName = req[ 'host_name' ]

        aid.sensor_id = uuid.uuid4()

        self.db.execute( 'INSERT INTO sensor_states ( sid, oid, iid, plat, arch, enroll ) VALUES ( %s, %s, %s, %s, %s, dateOf( now() ) )', 
                         ( aid.sensor_id, aid.org_id, aid.ins_id, aid.platform, aid.architecture ) )

        return ( True, { 'aid' : aid } )