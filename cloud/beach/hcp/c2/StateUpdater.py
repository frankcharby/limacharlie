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
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class StateUpdater( Actor ):
    def init( self, parameters, resources ):
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )

        self.recordLive = self.db.prepare( 'UPDATE sensor_states SET alive = dateOf(now()), ext_ip = ?, int_ip = ?, hostname = ?, oid = ?, iid = ?, plat = ?, arch = ? WHERE sid = ?' )
        self.recordHostName = self.db.prepare( 'INSERT INTO sensor_hostnames ( hostname, sid ) VALUES ( ?, ? ) USING TTL %s' % ( 60 * 60 * 24 * 30 ) )
        self.recordDead = self.db.prepare( 'UPDATE sensor_states SET dead = dateOf(now()) WHERE sid = ?' )

        self.db.start()

        self.handle( 'live', self.setLive )
        self.handle( 'dead', self.setDead )

    def deinit( self ):
        pass

    def setLive( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        extIp = msg.data[ 'ext_ip' ]
        intIp = msg.data[ 'int_ip' ]
        hostName = msg.data[ 'hostname' ]

        self.db.execute_async( self.recordLive.bind( ( extIp, intIp, hostName, aid.org_id, aid.ins_id, aid.platform, aid.architecture, aid.sensor_id ) ) )
        self.db.execute_async( self.recordHostName.bind( ( hostName.upper(), aid.sensor_id ) ) )
        return ( True, )

    def setDead( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        self.db.execute_async( self.recordDead.bind( ( aid.sensor_id, ) ) )
        return ( True, )
