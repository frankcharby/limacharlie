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
import hashlib
from sets import Set
import time
StateMachine = Actor.importLib( 'analytics/StateAnalysis', 'StateMachine' )
StateEvent = Actor.importLib( 'analytics/StateAnalysis', 'StateEvent' )
CreateOnAccess = Actor.importLib( 'utils/hcp_helpers', 'CreateOnAccess' )

def GenerateDetectReport( nthReport, agentid, msgIds, cat, detect, summary = '', priority = None ):
    if type( msgIds ) is not tuple and type( msgIds ) is not list:
        msgIds = ( msgIds, )
    if type( agentid ) is tuple or type( agentid ) is list:
        agentid = ' / '.join( agentid )
    reportId = hashlib.sha256( '%s%d%s' % ( cat, nthReport, str( msgIds ) ) ).hexdigest()
    return { 'source' : agentid, 
             'msg_ids' : msgIds, 
             'cat' : cat, 
             'detect' : detect, 
             'detect_id' : reportId, 
             'summary' : summary,
             'priority' : priority }

class Detects( object ):
    def __init__( self ):
        self._detects = []
    def add( self, priority, summary, detectInfo, taskings = None ):
        self._detects.append( ( priority, summary, detectInfo, taskings ) )
    def __len__( self ):
        return len( self._detects )
    def __iter__( self ):
        return self._detects.__iter__()

class StatelessActor ( Actor ):
    def init( self, parameters, resources ):
        if not hasattr( self, 'process' ):
            raise Exception( 'Stateless Actor has no "process" function' )
        self._reporting = self.getActorHandle( resources.get( 'report', 'analytics/reporting' ) )
        self._tasking = CreateOnAccess( self.getActorHandle, 
                                        resources.get( 'autotasking', 'analytics/autotasking' ), 
                                        mode = 'affinity' )
        self._cat = type( self ).__name__
        self._cat = self._cat[ self._cat.rfind( '.' ) + 1 : ]
        self._detects = CreateOnAccess( self.getActorHandleGroup, 
                                        resources.get( 'detects', 'analytics/detects/%s' ) % self._cat )
        self.handle( 'process', self._process )

    def task( self, dest, cmdsAndArgs, expiry = None, inv_id = None ):
        '''Send a task manually to a sensor

        :param dest: sensor to task
        :param cmdAndArgs: tuple of arguments (like the CLI) of the task
        :param expiry: number of seconds before the task is not valid anymore
        :param inv_id: investigation id to associate the tasking and reply to
        '''

        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._tasking.shoot( 'task', data, key = dest )
        self.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )

    def _process( self, msg ):
        newDetects = Detects()
        self.process( newDetects, msg )

        if 0 != len( newDetects ):
            self.log( "reporting detects generated" )
            i = 0
            routing, event, mtd = msg.data
            for priority, summary, detect, taskings in newDetects:
                report = GenerateDetectReport( i,
                                               routing[ 'aid' ],
                                               ( routing[ 'event_id' ], ),
                                               self._cat,
                                               detect,
                                               summary,
                                               priority )
                self._reporting.shoot( 'detect', report )
                self._detects.shoot( 'detect', report )
                if taskings is not None and 0 != len( taskings ):
                    self.task( routing[ 'aid' ], taskings, expiry = ( 60 * 60 ), inv_id = report[ 'detect_id' ] )
                i += 1
        return ( True, )

class StatefulActor ( Actor ):
    def init( self, parameters, resources ):
        self._compiled_machines = {}
        self._machine_activity = {}
        self._machine_ttl = parameters.get( 'machine_ttl', ( 60 * 60 * 24 * 30 ) )
        if not hasattr( self, 'initMachines' ):
            raise Exception( 'Stateful Actor has no "initMachines" function' )

        self._machines = []
        self.initMachines( parameters )

        self._detectsEndpoint = resources.get( 'detects', 'analytics/detects/%s' )

        if not hasattr( self, 'shardingKey' ):
            raise Exception( 'Stateful Actor has no associated shardingKey (or None)' )

        self._reporting = CreateOnAccess( self.getActorHandle, 
                                          resources.get( 'report', 'analytics/reporting' ) )
        self._tasking = CreateOnAccess( self.getActorHandle, 
                                        resources.get( 'autotasking', 'analytics/autotasking' ), 
                                        mode = 'affinity' )
        self._detects = {}
        self.handle( 'process', self._process )

        self.schedule( 60 * 60, self._garbageCollectOldMachines )

    def addStateMachineDescriptor( self, desc ):
        self._machines.append( StateMachine( desc ) )

    def _garbageCollectOldMachines( self ):
        for shard in self._compiled_machines.keys():
            for machine in self._compiled_machines[ shard ]:
                if self._machine_activity[ machine ] < time.time() - self._machine_ttl:
                    del( self._machine_activity[ machine ] )
                    self._compiled_machines[ shard ].remove( machine )

    def task( self, dest, cmdsAndArgs, expiry = None, inv_id = None ):
        '''Send a task manually to a sensor

        :param dest: sensor to task
        :param cmdAndArgs: tuple of arguments (like the CLI) of the task
        :param expiry: number of seconds before the task is not valid anymore
        :param inv_id: investigation id to associate the tasking and reply to
        '''

        if type( cmdsAndArgs[ 0 ] ) not in ( tuple, list ):
            cmdsAndArgs = ( cmdsAndArgs, )
        data = { 'dest' : dest, 'tasks' : cmdsAndArgs }

        if expiry is not None:
            data[ 'expiry' ] = expiry
        if inv_id is not None:
            data[ 'inv_id' ] = inv_id

        self._tasking.shoot( 'task', data, key = dest )
        self.log( "sent for tasking: %s" % ( str(cmdsAndArgs), ) )

    def _process( self, msg ):
        routing, event, mtd = msg.data

        newEvent = StateEvent( routing, event, mtd )

        shard = None
        if self.shardingKey is not None:
            shard = routing.get( self.shardingKey, None )

        currentShard = self._compiled_machines.setdefault( shard, [] )

        # First we update currently running machines
        i = 0
        for machine in currentShard:
            self._machine_activity[ machine ] = time.time()
            #self.log( "MACHINE: %s %d" % ( machine._descriptor.detectName, machine._currentState ) )
            reportPriority, reportSummary, reportType, reportContent, isStayAlive = machine.update( newEvent )
            #self.log( "TO MACHINE: %s %d" % ( machine._descriptor.detectName, machine._currentState ) )
            if reportType is not None and reportContent is not None:
                if hasattr( self, 'processDetect' ):
                    reportContent = self.processDetect( reportContent )
                report = GenerateDetectReport( i,
                                               tuple( Set( [ e.routing[ 'aid' ] for e in reportContent ] ) ),
                                               tuple( Set( [ e.routing[ 'event_id' ] for e in reportContent ] ) ),
                                               reportType,
                                               [ x.event for x in reportContent ],
                                               reportSummary,
                                               reportPriority )
                self._reporting.shoot( 'detect', report )
                self._detects.setdefault( reportType,
                                          self.getActorHandle( self._detectsEndpoint % reportType ) ).broadcast( 'detect', report )
            if not isStayAlive:
                del( self._machine_activity[ machine ] )
                currentShard.remove( machine )
            i += 1

        # Next we prime new machines
        for machine in self._machines:
            newMachine = machine.prime( newEvent )
            if newMachine is not None:
                #self.log( "MACHINE PRIMED: %s %d" % ( newMachine._descriptor.detectName, newMachine._currentState ) )
                currentShard.append( newMachine )
                self._machine_activity[ newMachine ] = time.time()

        # Clean up unused shards
        if 0 == len( currentShard ):
            del( self._compiled_machines[ shard ] )

        return ( True, )