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
from sets import Set
BEAdmin = Actor.importLib( '../admin_lib', 'BEAdmin' )
Host = Actor.importLib( '../utils/ObjectsDb', 'Host' )
HostObjects = Actor.importLib( '../utils/ObjectsDb', 'HostObjects' )
FluxEvent = Actor.importLib( '../utils/ObjectsDb', 'FluxEvent' )
ObjectTypes = Actor.importLib( '../utils/ObjectsDb', 'ObjectTypes' )
Atoms = Actor.importLib( '../utils/ObjectsDb', 'Atoms' )
ObjectKey = Actor.importLib( '../utils/ObjectsDb', 'ObjectKey' )
RelationNameFromId = Actor.importLib( '../utils/ObjectsDb', 'RelationNameFromId' )
Reporting = Actor.importLib( '../utils/ObjectsDb', 'Reporting' )
KeyValueStore = Actor.importLib( '../utils/ObjectsDb', 'KeyValueStore' )
AgentId = Actor.importLib( '../utils/hcp_helpers', 'AgentId' )
_xm_ = Actor.importLib( '../utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( '../utils/hcp_helpers', '_x_' )

class ModelView( Actor ):
    def init( self, parameters, resources ):
        self.admin = BEAdmin( self._beach_config_path, None )
        Host.setDatabase( self.admin, parameters[ 'scale_db' ] )
        HostObjects.setDatabase( parameters[ 'scale_db' ] )
        Reporting.setDatabase( parameters[ 'scale_db' ] )
        KeyValueStore.setDatabase( parameters[ 'scale_db' ] )
        Atoms.setDatabase( parameters[ 'scale_db' ] )
        self.handle( 'get_timeline', self.get_timeline )
        self.handle( 'get_sensor_info', self.get_sensor_info )
        self.handle( 'get_obj_list', self.get_obj_list )
        self.handle( 'get_obj_view', self.get_obj_view )
        self.handle( 'get_lastevents', self.get_lastevents )
        self.handle( 'get_event', self.get_event )
        self.handle( 'list_sensors', self.list_sensors )
        self.handle( 'get_detects', self.get_detects )
        self.handle( 'get_detect', self.get_detect )
        self.handle( 'get_host_changes', self.get_host_changes )
        self.handle( 'set_kv', self.set_kv )
        self.handle( 'get_kv', self.get_kv )
        self.handle( 'get_obj_loc', self.get_obj_loc )
        self.handle( 'get_file_in_event', self.get_file_in_event )
        self.handle( 'get_atoms_from_root', self.get_atoms_from_root )
        self.handle( 'get_backend_config', self.get_backend_config )
        self.handle( 'get_installer', self.get_installer )

    def deinit( self ):
        Host.closeDatabase()
        HostObjects.closeDatabase()
        Reporting.closeDatabase()

    def get_sensor_info( self, msg ):
        info = {}
        host = None

        aid = msg.data[ 'id_or_host' ]
        try:
            _ = AgentId( aid )
        except:
            aid = None

        if aid is not None:
            host = Host( aid )
        else:
            hosts = Host.getHostsMatching( hostname = msg.data[ 'id_or_host' ] )
            if 0 != len( hosts ):
                host = hosts[ 0 ]
        if host is not None:
            info[ 'id' ] = host.aid
            info[ 'is_online' ] = host.isOnline()
            info[ 'hostname' ] = host.getHostName()
            info[ 'lastseen' ] = host.lastSeen()

        return ( True, info )


    def get_timeline( self, msg ):
        host = Host( msg.data[ 'id' ] )
        maxSize = msg.data.get( 'max_size', 0 )

        events = host.getEvents( before = msg.data.get( 'before', None ),
                                 after = msg.data.get( 'after', None ),
                                 limit = msg.data.get( 'limit', None ),
                                 ofTypes = msg.data.get( 'types', None ),
                                 isIncludeContent = msg.data.get( 'is_include_content', False ) )

        events = [ ( x[ 0 ], x[ 1 ], x[ 2 ], FluxEvent.decode( x[ 3 ] ) if ( 4 <= len( x ) and
                                                                             ( 0 == maxSize or
                                                                               len( x[ 3 ] ) <= maxSize ) )
                                                                        else None ) for x in events ]

        return ( True, { 'events' : events } )

    def get_obj_list( self, msg ):

        oname = msg.data.get( 'name', None )
        otype = msg.data.get( 'type', None )
        host = msg.data.get( 'host', None )

        if oname is not None:
            objects = HostObjects.named( oname ).info()
        elif host is not None:
            objects = HostObjects.onHosts( host, otype ).info()
        elif otype is not None:
            objects = HostObjects.ofTypes( otype ).info()

        objects = [ ( x[ 0 ], x[ 1 ], ObjectTypes.rev[ x[ 2 ] ] ) for x in objects ]

        return ( True, { 'objects' : objects } )

    def get_obj_view( self, msg ):
        info = {}
        info[ 'host' ] = msg.data.get( 'host', None )
        try:
            if 'id' not in msg.data:
                msg.data[ 'id' ] = ObjectKey( msg.data[ 'obj_name' ], ObjectTypes.forward[ msg.data[ 'obj_type' ] ] )
            _ = next( HostObjects( msg.data[ 'id' ] ).info() )
        except:
            return ( True, {} )
        info[ 'id' ] = _[ 0 ]
        info[ 'oname' ] = _[ 1 ]
        info[ 'otype' ] = ObjectTypes.rev[ _[ 2 ] ]
        info[ 'olocs' ] = [ ( x[ 1 ], x[ 2 ] ) for x in HostObjects( _[ 0 ] ).locs() ]

        info[ 'parents' ] = [ ( x[ 0 ], x[ 1 ], ObjectTypes.rev[ x[ 2 ] ], ObjectKey( RelationNameFromId( x[ 0 ], _[ 0 ] ), ObjectTypes.RELATION ) ) for x in HostObjects( info[ 'id' ] ).parents().info() ]
        info[ 'children' ] = [ ( x[ 0 ], x[ 1 ], ObjectTypes.rev[ x[ 2 ] ], ObjectKey( RelationNameFromId( _[ 0 ], x[ 0 ] ), ObjectTypes.RELATION ) ) for x in HostObjects( info[ 'id' ] ).children().info() ]

        locs = {}
        for o in HostObjects( [ x[ 0 ] for x in ( info[ 'parents' ] + info[ 'children' ] ) ] ).locs():
            if o[ 0 ] not in locs:
                locs[ o[ 0 ] ] = 0
            locs[ o[ 0 ] ] += 1

        info[ 'locs' ] = locs

        relToId = {}
        tmplocs = {}
        for child in [ x[ 0 ] for x in info[ 'children' ] ]:
            relToId[ ObjectKey( RelationNameFromId( info[ 'id' ], child ), ObjectTypes.RELATION ) ] = child

        onHost = {}
        for o in HostObjects( relToId.keys() ).locs():
            if relToId[ o[ 0 ] ] not in tmplocs:
                tmplocs[ relToId[ o[ 0 ] ] ] = 0
            tmplocs[ relToId[ o[ 0 ] ] ] += 1
            if o[ 1 ] == info[ 'host' ]:
                onHost[ o[ 0 ] ] = 1

        if 0 != len( onHost ):
            for k in tmplocs.keys():
                if k not in onHost:
                    info[ 'children' ].remove( relToId[ k ] )
                    del( tmplocs[ k ] )

        info[ 'rlocs' ] = tmplocs
        relToId = {}
        tmplocs = {}

        for parent in [ x[ 0 ] for x in info[ 'parents' ] ]:
            relToId[ ObjectKey( RelationNameFromId( parent, info[ 'id' ] ), ObjectTypes.RELATION ) ] = parent

        onHost = {}
        for o in HostObjects( relToId.keys() ).locs():
            if relToId[ o[ 0 ] ] not in tmplocs:
                tmplocs[ relToId[ o[ 0 ] ] ] = 0
            tmplocs[ relToId[ o[ 0 ] ] ] += 1
            if o[ 1 ] == info[ 'host' ]:
                onHost[ o[ 0 ] ] = 1

        if 0 != len( onHost ):
            for k in tmplocs.keys():
                if k not in onHost:
                    info[ 'parents' ].remove( relToId[ k ] )
                    del( tmplocs[ k ] )

        info[ 'rlocs' ].update( tmplocs )

        return ( True, info )

    def get_lastevents( self, msg ):
        host = Host( msg.data[ 'id' ] )

        events = [ ( x[ 'name' ], x[ 'id' ] ) for x in host.lastEvents() ]

        return ( True, { 'events' : events } )

    def get_event( self, msg ):
        event = Host.getSpecificEvent( msg.data[ 'id' ] )

        if event is not None:
            event = ( event[ 0 ], FluxEvent.decode( event[ 2 ] ) )
            return ( True, { 'event' : event } )
        else:
            return ( False, 'event not found' )

    def list_sensors( self, msg ):
        sensors = self.admin.hcp_getAgentStates()

        if sensors.isSuccess and 'agents' in sensors.data:
            return ( True, sensors.data[ 'agents' ] )
        else:
            return ( False, sensors.error )

    def get_detects( self, msg ):
        reports = Reporting.getDetects( before = msg.data.get( 'before', None ),
                                        after = msg.data.get( 'after', None ),
                                        limit = msg.data.get( 'limit', None ) )

        reports = [ ( x[ 0 ], x[ 1 ], x[ 2 ], x[ 3 ], x[ 4 ], FluxEvent.decode( x[ 5 ] ) ) for x in reports ]

        return ( True, { 'reports' : reports } )

    def get_detect( self, msg ):
        detect = Reporting.getDetects( id = msg.data[ 'id' ] )
        isWithEvents = msg.data.get( 'with_events', False )
        isWithInv = msg.data.get( 'with_inv', False )

        detect = ( detect[ 0 ],
                   detect[ 1 ],
                   detect[ 2 ],
                   detect[ 3 ],
                   detect[ 4 ],
                   FluxEvent.decode( detect[ 5 ] ),
                   detect[ 6 ] )

        if isWithEvents:
            events = Reporting.getRelatedEvents( detect[ 1 ].upper(), isIncludeContent = True )
            detect = ( detect[ 0 ],
                       detect[ 1 ],
                       detect[ 2 ],
                       detect[ 3 ],
                       detect[ 4 ],
                       detect[ 5 ],
                       detect[ 6 ],
                       [ ( x[ 0 ], x[ 1 ], FluxEvent.decode( x[ 2 ] ), x[ 3 ], x[ 4 ] ) for x in events ] )

        ret = { 'detect' : detect }

        if isWithInv:
            inv = Reporting.getInvestigations( id = detect[ 1 ] )
            for i in inv.itervalues():
                for d in i[ 'data' ]:
                    d[ 'data' ] = FluxEvent.decode( d[ 'data' ] )
                for t in i[ 'tasks' ]:
                    t[ 'data' ] = FluxEvent.decode( t[ 'data' ] )
            ret[ 'inv' ] = inv

        return ( True, ret )

    def get_host_changes( self, msg ):
        changes = {}
        timeWindow = msg.data.get( 'time_window', ( 60 * 60 * 24 * 7 ) )
        eTypes = ( ( 'notification.OS_SERVICES_REP', '?/base.SVCS/base.SVC_NAME' ),
                   ( 'notification.OS_DRIVERS_REP', '?/base.SVCS/base.SVC_NAME' ),
                   ( 'notification.OS_AUTORUNS_REP', '?/base.AUTORUNS/base.FILE_PATH' ) )

        host = Host( msg.data[ 'id' ] )
        for eType in eTypes:
            events = host.getEvents( after = ( int( time.time() ) - timeWindow ),
                                     ofTypes = ( eType[ 0 ], ),
                                     isIncludeContent = True )
            previous = None
            for event in events:
                if previous is None:
                    previous = Set( _xm_( FluxEvent.decode( event[ 3 ] ), eType[ 1 ] ) )
                eContent = FluxEvent.decode( event[ 3 ] )
                current = Set( _xm_( eContent, eType[ 1 ] ) )
                eTime = _x_( eContent, '?/base.TIMESTAMP' )
                eId = event[ 2 ]
                for e in current:
                    if e not in previous:
                        changes.setdefault( eType[ 0 ], { '+' : {}, '-' : {} } )[ '+' ][ e ] = ( eId, eTime )
                for e in previous:
                    if e not in current:
                        changes.setdefault( eType[ 0 ], { '+' : {}, '-' : {} } )[ '-' ][ e ] = ( eId, eTime )
                previous = current

        return ( True, { 'changes' : changes } )

    def set_kv( self, msg ):
        cat = msg.data[ 'cat' ]
        k = msg.data[ 'k' ]
        v = msg.data[ 'v' ]
        ttl = msg.data.get( 'ttl', ( 60 * 60 * 24 * 30 ) )
        KeyValueStore.setKey( cat, k, v, ttl )
        return ( True, )

    def get_kv( self, msg ):
        cat = msg.data[ 'cat' ]
        k = msg.data[ 'k' ]
        res = KeyValueStore.getKey( cat, k )
        if res is None:
            return ( False, )
        else:
            return ( True, { 'v' : res[ 0 ], 'created' : res[ 1 ] } )

    def get_obj_loc( self, msg ):

        objects = msg.data[ 'objects' ]
        if type( objects ) is not tuple and type( objects ) is not list:
            objects = [ objects ]

        objects = [ ObjectKey( o[ 0 ], ObjectTypes.forward[ o[ 1 ] ] ) for o in objects ]

        locs = [ _ for _ in HostObjects( objects ).locs() ]

        return ( True, locs )

    def get_file_in_event( self, msg ):
        event = Host.getSpecificEvent( msg.data[ 'id' ] )

        if event is not None:
            event = ( event[ 0 ], FluxEvent.decode( event[ 2 ] ) )

            filePath = None
            fileData = _x_( event, '*/base.FILE_CONTENT' )
            if fileData is not None:
                filePath = _x_( event, '*/base.FILE_PATH' )

            return ( True, { 'data' : fileData, 'path' : filePath } )
        else:
            return ( True, {} )

    def get_atoms_from_root( self, msg ):
        tmp_atoms = msg.data[ 'id' ]
        depth = msg.data.get( 'depth', 5 )
        atoms = []
        
        # Get the root by itself
        atoms.extend( Atoms( tmp_atoms ).fillEventIds().events() )
        
        # Then start getting children
        while 0 != depth:
            depth -= 1
            tmp_atoms = [ _ for _ in Atoms( tmp_atoms ).children() ]
            if 0 == len( tmp_atoms ):
                break
            atoms.extend( Atoms( tmp_atoms ).events() )

        return ( True, atoms )

    def get_backend_config( self, msg ):
        info = {}

        info[ 'hcp_installers' ] = self.admin.hcp_getInstallers().data
        info[ 'hcp_taskings' ] = self.admin.hcp_getTaskings().data
        info[ 'hcp_modules' ] = self.admin.hcp_getModules().data
        info[ 'hbs_profiles' ] = self.admin.hbs_getProfiles().data

        return ( True, info )

    def get_installer( self, msg ):
        oid = msg.data[ 'oid' ]
        iid = msg.data[ 'iid' ]
        hash = msg.data[ 'hash' ]
        data = self.admin.hcp_getInstallers( oid = oid, iid = iid, withContent = True ).data

        return ( True, data )