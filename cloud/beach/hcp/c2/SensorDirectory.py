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

class SensorDirectory( Actor ):
    def init( self, parameters, resources ):

        self.directory = {}
        
        self.handle( 'live', self.setLive )
        self.handle( 'dead', self.setDead )
        self.handle( 'transfered', self.addTransfered )
        self.handle( 'get_endpoint', self.getEndpoint )

    def deinit( self ):
        pass

    def setLive( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        endpoint = msg.data[ 'endpoint' ]
        self.directory[ aid.sensor_id ] = ( endpoint, 0 )
        return ( True, )

    def setDead( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        del( self.directory[ aid.sensor_id ] )
        return ( True, )

    def addTransfered( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        newBytes = msg.data[ 'bytes_transfered' ]
        curEndpoint, curBytes = self.directory.get( aid.sensor_id, ( None, 0 ) )
        self.directory[ aid.sensor_id ] = ( curEndpoint, curBytes + newBytes )
        self.log( '%s transfered %d new bytes.' % ( aid.sensor_id, newBytes ) )
        return ( True, )

    def getEndpoint( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        endpoint, transfered = self.directory.get( aid.sensor_id, ( None, 0 ) )
        return ( True, { 'aid' : aid.sensor_id, 'endpoint' : endpoint, 'transfered' : transfered } )