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

from sets import Set
from beach.actor import Actor
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )
exeFromPath = Actor.importLib( '../utils/hcp_helpers', 'exeFromPath' )
ObjectTypes = Actor.importLib( '../utils/ObjectsDb', 'ObjectTypes' )
ObjectNormalForm = Actor.importLib( '../utils/ObjectsDb', 'ObjectNormalForm' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
CassDb = Actor.importLib( '../utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( '../utils/hcp_databases', 'CassPool' )

class AsynchronousRelationBuilder( Actor ):
    def init( self, parameters, resources ):
    	self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )
    	# This is a mapping indicating the parent type and 
    	# function generating the object value for each child type.
    	self.mapping = { 'notifcation.NEW_PROCESS' : ( 'notification.NEW_PROCESS', 
    												   lambda x: exeFromPath( _x_( x, '?/base.FILE_PATH' ) ) ) }
        self.handle( 'analyze', self.analyze )
        self.schedule( 60, self.compile )
        
    def deinit( self ):
        pass

    def compile( self ):
    	pass

    def analyze( self, msg ):
        routing, event, mtd = msg.data

        childType = routing[ 'event_type' ]
        if childType in self.mapping:
        	parentType = self.mapping[ childType ][ 0 ]
        	
        	eid = routing[ 'event_id' ]
        	aid = AgentId( routing[ 'agentid' ] ).sensor_id
        	ts = _x_( event, 'base.TIMESTAMP' )

        	childValue = self.mapping[ childType ][ 1 ]( event )
        	cK = ObjectKey( childValue, childType )

        	# code to ingest objects should not be here, it should be split off
        	# the analytics modeling actor into a new standalone actor

        return ( True, )


