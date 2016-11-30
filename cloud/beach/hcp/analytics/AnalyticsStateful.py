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

class AnalyticsStateful( Actor ):
    def init( self, parameters, resources ):
        self.handleCache = {}
        self.statefulCommon = self.getActorHandleGroup( resources[ 'modules' ] % 'common',
                                                        mode = 'affinity',
                                                        timeout = 30,
                                                        nRetries = 3 )
        self.statefulWindows = self.getActorHandleGroup( resources[ 'modules' ] % 'windows',
                                                         mode = 'affinity',
                                                         timeout = 30,
                                                         nRetries = 3 )
        self.statefulOsx = self.getActorHandleGroup( resources[ 'modules' ] % 'osx',
                                                     mode = 'affinity',
                                                     timeout = 30,
                                                     nRetries = 3 )
        self.statefulLinux = self.getActorHandleGroup( resources[ 'modules' ] % 'linux',
                                                       mode = 'affinity',
                                                       timeout = 30,
                                                       nRetries = 3 )
        self.handle( 'analyze', self.analyze )

    def deinit( self ):
        pass

    def analyze( self, msg ):
        routing, event, mtd = msg.data

        self.statefulCommon.shoot( 'process', msg.data, key = routing[ 'aid' ] )

        agent = AgentId( routing[ 'aid' ] )
        if agent.isWindows():
            self.statefulWindows.shoot( 'process', msg.data, key = routing[ 'aid' ] )
        elif agent.isMacOSX():
            self.statefulOsx.shoot( 'process', msg.data, key = routing[ 'aid' ] )
        elif agent.isLinux():
            self.statefulLinux.shoot( 'process', msg.data, key = routing[ 'aid' ] )

        return ( True, )