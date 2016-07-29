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
ObjectTypes = Actor.importLib( '../../utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( '../../Detects', 'StatelessActor' )

class YaraDetects ( StatelessActor ):
    def init( self, parameters, resources ):
        super( YaraDetects, self ).init( parameters, resources )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        # No validation for now, straight detect
        detects.add( 90,
        			 'yara signature hit',
        			 event,
        			 None )
