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
from sets import Set
ObjectTypes = Actor.importLib( '../utils/ObjectsDb', 'ObjectTypes' )
HostObjects = Actor.importLib( '../utils/ObjectsDb', 'HostObjects' )
BEAdmin = Actor.importLib( '../admin_lib', 'BEAdmin' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
chunks = Actor.importLib( '../utils/hcp_helpers', 'chunks' )

class StatsComputer( Actor ):
    def init( self, parameters, resources ):
        HostObjects.setDatabase( parameters[ 'scale_db' ] )
        self.be = BEAdmin( self._beach_config_path, None )

        self.lastStats = {}

        self.schedule( 3600, self.computeRelation, 
                       parentType = ObjectTypes.PROCESS_NAME, 
                       childType = ObjectTypes.FILE_PATH,
                       absoluteParentCoverage = 50 )

        self.handle( 'get_stats', self.getStats )

    def deinit( self ):
        pass

    def getStats( self, msg ):
        parentType = msg.data[ 'parent_type' ]
        childType = msg.data[ 'child_type' ]
        isReversed = bool( msg.data[ 'is_reversed' ] )

        return ( True, self.lastStats.get( ( parentType, childType, isReversed ), {} ) )

    def _tallyLocStats( self, locs, withPlatform = True ):
        tally = {}
        for oid, aid, ts in locs:
            if withPlatform:
                agent = AgentId( aid )
                tally.setdefault( agent.platform, {} ).setdefault( oid, 0 )
                tally[ agent.platform ][ oid ] += 1
            else:
                tally.setdefault( oid, 0 )
                tally[ oid ] += 1
        return tally

    def computeRelation( self, parentType, childType, 
                         parentCoverage = 0.98, 
                         within = ( 60 * 60 * 24 * 30 ), 
                         maxFalsePositives = 10,
                         isReversed = False, absoluteParentCoverage = None ):
        whitelisted = {}
        platforms = {}

        # Count the number of hosts per platform
        agents = [ AgentId( x ) for x in self.be.hcp_getAgentStates().data[ 'agents' ].keys() ]
        for agent in agents:
            platforms.setdefault( agent.platform, 0 )
            platforms[ agent.platform ] += 1
        del agents

        # Find the number of locations per process object
        locs = self._tallyLocStats( HostObjects.ofTypes( ( parentType, ) ).locs( within = within ) )

        # Remove all process objects that were not on X% of hosts of that platform
        highCertaintyObjects = {}
        for platform, locs in locs.iteritems():
            curPlatform = platforms[ platform ]
            for oid, n in locs.iteritems():
                # If the object is in at least X% of hosts of that platform consider it
                if( ( absoluteParentCoverage is None or n  >= absoluteParentCoverage ) and 
                    ( float( n ) / curPlatform ) >= parentCoverage ):
                    highCertaintyObjects.setdefault( platform, {} )[ oid ] = n
        del locs
        del platforms

        # For each of those ubiquitious processes, find all the relationships (parent and child)
        for platform, objects in highCertaintyObjects.iteritems():
            for oid in objects.iterkeys():
                # If we are reversed (meaning we center the stats around the child) we flip it around
                def _genRelations():
                    if isReversed:
                        return HostObjects( oid ).childrenRelations( types = childType )
                    else:
                        return HostObjects( oid ).childrenRelations( types = childType )

                highCertaintyRelations = {}
                nFPs = 0
                nRel = 0
                for rel in _genRelations():
                    relStats = self._tallyLocStats( HostObjects( rel ).locs(), withPlatform = False )
                    for rid, count in relStats.iteritems():
                        if parentCoverage < ( float( count ) / highCertaintyObjects[ platform ][ oid ] ):
                            highCertaintyRelations[ rid ] = count
                        else:
                            nFPs += count
                        nRel += 1
                    if ( nFPs <= maxFalsePositives and 
                       ( float( len( highCertaintyRelations ) ) / nRel ) >= parentCoverage ):
                        whitelisted[ oid ] = highCertaintyRelations.keys()
        self.lastStats[ ( parentType, childType, isReversed ) ] = whitelisted