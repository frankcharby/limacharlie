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
import time
from functools import wraps
import re
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )

def apiAiRequest( f ):
    @wraps( f )
    def wrapped( self, msg ):
        action = msg.data.get( 'result', {} ).get( 'action' )
        params = msg.data.get( 'result', {} ).get( 'parameters', {} )
        ctx = msg.data.get( 'result', {} ).get( 'contexts', [] )
        speech, displayText = f( self, action, params, ctx )
        return ( True,
                 { "speech" : speech, 
                   "displayText" : displayText, 
                   "source" : "lc-assistant" } )
    return wrapped

class AssistantEndpoint( Actor ):
    def init( self, parameters, resources ):
        self.Model = self.getActorHandle( resources[ 'modeling' ], timeout = 15, nRetries = 0 )

        self.process_re = re.compile( r'.*\.exe$', re.IGNORECASE )
        self.module_re = re.compile( r'.*\.dll$', re.IGNORECASE )

        self.handle( 'count_sensors', self.count_sensors )
        self.handle( 'object_stat', self.object_stat )

    def deinit( self ):
        pass

    def getCleanParam( self, params, name ):
        ctxName = 'ctx_%s' % name
        res = params.get( name, '' )
        if '' == res:
            res = params.get( ctxName, '' )

        if '' == res:
            res = None
        return res


    @apiAiRequest
    def count_sensors( self, action, params, ctx ):
        resp = self.Model.request( 'list_sensors', {} )
        if resp.isSuccess:
            sensors = resp.data.keys()
            platform = params.get( 'platform', None )
            platform = platform if ( platform is not None and platform != '' and platform != 'all' ) else None
            if platform is not None:
                if platform == 'osx':
                    sensors = [ x for x in sensors if AgentId( x ).isMacOSX() ]
                elif platform == 'windows':
                    sensors = [ x for x in sensors if AgentId( x ).isWindows() ]
                elif platform == 'linux':
                    sensors = [ x for x in sensors if AgentId( x ).isLinux() ]
                else:
                    platform = ''
            return ( "%s%s sensors are currently online." % ( len( sensors ), '' if ( platform is None ) else ( ' ' + platform ) ),
                     "%s%s are currently online." % ( len( sensors ), '' if ( platform is None ) else ( ' ' + platform ) ) )
        else:
            return( "Couldn't get sensor list.",
                    "Couldn't get sensor list." )

    @apiAiRequest
    def object_stat( self, action, params, ctx ):
        sensor = self.getCleanParam( params, 'sensor_id' )
        sensor = AgentId( sensor ) if sensor is not None else None
        obj_name = self.getCleanParam( params, 'object_name' )
        obj_type = self.getCleanParam( params, 'object_type' )
        rel_dir = self.getCleanParam( params, 'relation_dir' )
        relation_type = self.getCleanParam( params, 'relation_type' )
        
        #self.log( "PARAMS: %s" % str( params ) )
        #self.log( "CTX: %s" % str( ctx ) )

        if obj_name is None: return ( 'What\'s the object name?', 'What\'s the object name?' )

        # API.ai will remove . from tokens, so we'll do our best.
        obj_name = obj_name.replace( '  ', '.' )

        #self.log( "RAW: %s / %s" % ( obj_name, obj_type ) )

        if obj_type is None:
            if self.process_re.match( obj_name ):
                obj_type = 'PROCESS_NAME'
            elif self.module_re.match( obj_name ):
                obj_type = 'MODULE_NAME'
            else:
                return ( 'What\'s the object type?', 'What\'s the object type?' )

        #self.log( "QUERY: %s" % str( { 'obj_name' : obj_name,
        #                               'obj_type' : obj_type } ) )

        resp = self.Model.request( 'get_obj_view', { 'host' : sensor.sensor_id if sensor is not None else None,
                                                     'obj_name' : obj_name,
                                                     'obj_type' : obj_type } )

        if not resp.isSuccess:
            return ( 'Error finding object information.', 'Error finding object information.' )

        if rel_dir is None and relation_type is None:
            return ( '%s has been seen on %s hosts, has %s parents and %s children objects.' % ( obj_name,
                                                                                                 len( resp.data[ 'locs' ] ),
                                                                                                 len( resp.data[ 'children' ] ),
                                                                                                 len( resp.data[ 'parents' ] ) ), 
                     '%s has been seen on %s hosts, has %s parents and %s children objects.' % ( obj_name,
                                                                                                 len( resp.data[ 'locs' ] ),
                                                                                                 len( resp.data[ 'children' ] ),
                                                                                                 len( resp.data[ 'parents' ] ) ) )

        #self.log( "INFO: %s" % str( resp.data ) )

        if 0 != len( resp.data ):
            parents = resp.data[ 'parents' ] if ( rel_dir is None or rel_dir == 'all' or rel_dir == 'parent' ) else []
            children = resp.data[ 'children' ] if ( rel_dir is None or rel_dir == 'all' or rel_dir == 'child' ) else []
        else:
            return ( 'Could not find object information.', 'Could not find object information.' )

        if relation_type is not None:
            parents = [ x for x in parents if x[ 2 ] == relation_type ]
            children  = [ x for x in children if x[ 2 ] == relation_type ]

        out = '%s has ' % ( obj_name, )
        out_rel = []
        if rel_dir is None or rel_dir == 'all' or rel_dir == 'parent':
            out_type = ( ' of type %s' % ( relation_type, ) ) if relation_type is not None else ''
            out_rel.append( '%s parents%s' % ( len( parents ), out_type ) )
        if rel_dir is None or rel_dir == 'all' or rel_dir == 'child':
            out_type = ( ' of type %s' % ( relation_type, ) ) if relation_type is not None else ''
            out_rel.append( '%s children%s' % ( len( children ), out_type ) )
        out += ' and '.join( out_rel )

        return ( out, out )
