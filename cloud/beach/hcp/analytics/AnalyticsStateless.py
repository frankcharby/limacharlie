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
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )

class AnalyticsStateless( Actor ):
    def init( self, parameters, resources ):
        self.handleCache = {}
        self.modulesCommon = {}
        self.modulesWindows = {}
        self.modulesOsx = {}
        self.modulesLinux = {}
        self.specific = resources[ 'specific' ]
        self.allConsumer = self.getActorHandleGroup( resources[ 'all' ],
                                                     timeout = 30,
                                                     nRetries = 3 )
        self.outputs = self.getActorHandleGroup( resources[ 'output' ] )

        self.handle( 'analyze', self.analyze )

    def deinit( self ):
        pass

    def analyze( self, msg ):
        routing, event, mtd = msg.data

        etype = routing[ 'event_type' ]
        agent = AgentId( routing[ 'aid' ] )

        if etype not in self.modulesCommon:
            self.modulesCommon[ etype ] = self.getActorHandleGroup( self.specific % ( 'common', etype ),
                                                                    timeout = 30,
                                                                    nRetries = 3 )
        self.modulesCommon[ etype ].shoot( 'process', msg.data )

        if agent.isWindows():
            if etype not in self.modulesWindows:
                self.modulesWindows[ etype ] = self.getActorHandleGroup( self.specific % ( 'windows', etype ),
                                                                         timeout = 30,
                                                                         nRetries = 3 )
            self.modulesWindows[ etype ].shoot( 'process', msg.data )
        elif agent.isMacOSX():
            if etype not in self.modulesOsx:
                self.modulesOsx[ etype ] = self.getActorHandleGroup( self.specific % ( 'osx', etype ),
                                                                     timeout = 30,
                                                                     nRetries = 3 )
            self.modulesOsx[ etype ].shoot( 'process', msg.data )
        elif agent.isLinux():
            if etype not in self.modulesLinux:
                self.modulesLinux[ etype ] = self.getActorHandleGroup( self.specific % ( 'linux', etype ),
                                                                       timeout = 30,
                                                                       nRetries = 3 )
            self.modulesLinux[ etype ].shoot( 'process', msg.data )

        self.allConsumer.shoot( 'process', msg.data )
        self.outputs.shoot( 'log', msg.data )

        return ( True, )