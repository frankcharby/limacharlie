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
import uuid
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
HbsCollectorId = Actor.importLib( 'utils/hcp_helpers', 'HbsCollectorId' )
CassDb = Actor.importLib( 'utils/hcp_databases', 'CassDb' )
CassPool = Actor.importLib( 'utils/hcp_databases', 'CassPool' )
HcpOperations = Actor.importLib( 'utils/hcp_helpers', 'HcpOperations' )
HcpModuleId = Actor.importLib( 'utils/hcp_helpers', 'HcpModuleId' )

def audited( f ):
    def wrapped( self, *args, **kwargs ):
        self.auditor.shoot( 'audit', { 'data' : args[ 0 ].data, 'cmd' : args[ 0 ].req } )
        r = f( self, *args, **kwargs )
        return r
    return wrapped

class AdminEndpoint( Actor ):
    def init( self, parameters, resources ):
        self.symbols = self.importLib( '../Symbols', 'Symbols' )()
        self._db = CassDb( parameters[ 'db' ], 'hcp_analytics', consistencyOne = True )
        self.db = CassPool( self._db,
                            rate_limit_per_sec = parameters[ 'rate_limit_per_sec' ],
                            maxConcurrent = parameters[ 'max_concurrent' ],
                            blockOnQueueSize = parameters[ 'block_on_queue_size' ] )
        self.db.start()
        self.handle( 'ping', self.ping )
        self.handle( 'hcp.get_agent_states', self.cmd_hcp_getAgentStates )
        self.handle( 'hcp.get_taskings', self.cmd_hcp_getTaskings )
        self.handle( 'hcp.add_tasking', self.cmd_hcp_addTasking )
        self.handle( 'hcp.remove_tasking', self.cmd_hcp_delTasking )
        self.handle( 'hcp.get_modules', self.cmd_hcp_getModules )
        self.handle( 'hcp.add_module', self.cmd_hcp_addModule )
        self.handle( 'hcp.remove_module', self.cmd_hcp_delModule )
        self.handle( 'hcp.get_installers', self.cmd_hcp_getInstallers )
        self.handle( 'hcp.add_installer', self.cmd_hcp_addInstaller )
        self.handle( 'hcp.remove_installer', self.cmd_hcp_delInstaller )
        self.handle( 'hbs.set_profile', self.cmd_hbs_addProfile )
        self.handle( 'hbs.get_profiles', self.cmd_hbs_getProfiles )
        self.handle( 'hbs.del_profile', self.cmd_hbs_delProfile )
        self.handle( 'hbs.task_agent', self.cmd_hbs_taskAgent )

        self.auditor = self.getActorHandle( resources[ 'auditing' ], timeout = 5, nRetries = 3 )
        self.enrollments = self.getActorHandle( resources[ 'enrollments' ], timeout = 5, nRetries = 3 )
        self.moduleTasking = self.getActorHandle( resources[ 'module_tasking' ], timeout = 5, nRetries = 3 )
        self.hbsProfiles = self.getActorHandle( resources[ 'hbs_profiles' ], timeout = 5, nRetries = 3 )
        self.taskingProxy = self.getActorHandle( resources[ 'tasking_proxy' ], timeout = 60, nRetries = 3 )
        self.persistentTasks = self.getActorHandle( resources[ 'persistent_tasks' ], timeout = 5, nRetries = 3 )

    def deinit( self ):
        pass

    def ping( self, msg ):
        return ( True, { 'pong' : time.time() } )

    @audited
    def cmd_hcp_getAgentStates( self, msg ):
        request = msg.data
        hostName = request.get( 'hostname', None )
        aids = []
        if 'aid' in request and request[ 'aid' ] is not None:
            aids.append( AgentId( request[ 'aid' ] ) )
        elif hostName is not None:
            found = self.db.getOne( 'SELECT sid FROM sensor_hostnames WHERE hostname = %s', ( hostName.upper().strip(), ) )
            if found is not None:
                aids.append( AgentId( found[ 0 ] ) )
        else:
            aids = None

        data = { 'agents' : {} }

        if aids is None:
            for row in self.db.execute( 'SELECT oid, iid, sid, plat, arch, enroll, alive, dead, hostname, ext_ip, int_ip FROM sensor_states' ):
                tmpAid = AgentId( ( row[ 0 ], row[ 1 ], row[ 2 ], row[ 3 ], row[ 4 ] ) )
                tmpData = {}
                tmpData[ 'aid' ] = str( tmpAid )
                tmpData[ 'last_external_ip' ] = row[ 9 ]
                tmpData[ 'last_internal_ip' ] = row[ 10 ]
                tmpData[ 'last_hostname' ] = row[ 8 ]
                tmpData[ 'enrollment_date' ] = str( row[ 5 ] )
                tmpData[ 'last_connect_date' ] = str( row[ 6 ] )
                tmpData[ 'last_disconnect_date' ] = str( row[ 7 ] )
                data[ 'agents' ][ tmpAid.sensor_id ] = tmpData
        elif 0 != len( aids ):
            for aid in aids:
                filt = aid.asWhere()
                if 0 == len( filt[ 0 ] ):
                    q =  'SELECT oid, iid, sid, plat, arch, enroll, alive, dead, hostname, ext_ip, int_ip FROM sensor_states%s'
                else:
                    q = 'SELECT oid, iid, sid, plat, arch, enroll, alive, dead, hostname, ext_ip, int_ip FROM sensor_states WHERE %s'
                for row in self.db.execute( q % filt[ 0 ], filt[ 1 ] ):
                    tmpAid = AgentId( ( row[ 0 ], row[ 1 ], row[ 2 ], row[ 3 ], row[ 4 ] ) )
                    tmpData = {}
                    tmpData[ 'aid' ] = str( tmpAid )
                    tmpData[ 'last_external_ip' ] = row[ 9 ]
                    tmpData[ 'last_internal_ip' ] = row[ 10 ]
                    tmpData[ 'last_hostname' ] = row[ 8 ]
                    tmpData[ 'enrollment_date' ] = str( row[ 5 ] )
                    tmpData[ 'last_connect_date' ] = str( row[ 6 ] )
                    tmpData[ 'last_disconnect_date' ] = str( row[ 7 ] )
                    data[ 'agents' ][ tmpAid.sensor_id ] = tmpData
        return ( True, data )

    @audited
    def cmd_hcp_getTaskings( self, msg ):
        data = {}
        data[ 'taskings' ] = []
        for row in self.db.execute( 'SELECT aid, mid, mhash FROM hcp_module_tasking' ):
            data[ 'taskings' ].append( { 'mask' : AgentId( row[ 0 ] ),
                                         'module_id' : row[ 1 ],
                                         'hash' : row[ 2 ] } )
        return ( True, data )

    @audited
    def cmd_hcp_addTasking( self, msg ):
        request = msg.data
        mask = AgentId( request[ 'mask' ] )
        moduleid = int( request[ 'module_id' ] )
        h = str( request[ 'hash' ] )
        self.db.execute( 'INSERT INTO hcp_module_tasking ( aid, mid, mhash ) VALUES ( %s, %s, %s )',
                         ( mask.asString(), moduleid, h ) )

        self.delay( 5, self.moduleTasking.broadcast, 'reload', {} )

        return ( True, )

    @audited
    def cmd_hcp_delTasking( self, msg ):
        request = msg.data
        mask = AgentId( request[ 'mask' ] )
        moduleid = int( request[ 'module_id' ] )
        h = str( request[ 'hash' ] )
        self.db.execute( 'DELETE FROM hcp_module_tasking WHERE aid = %s AND mid = %s AND mhash = %s',
                         ( mask.asString(), moduleid, h ) )

        self.delay( 5, self.moduleTasking.broadcast, 'reload', {} )
        
        return ( True, )

    @audited
    def cmd_hcp_getModules( self, msg ):
        modules = []
        data = { 'modules' : modules }
        for row in self.db.execute( 'SELECT mid, mhash, description FROM hcp_modules' ):
            modules.append( { 'module_id' : row[ 0 ],
                              'hash' : row[ 1 ],
                              'description' : row[ 2 ] } )

        return ( True, data )

    @audited
    def cmd_hcp_addModule( self, msg ):
        request = msg.data
        moduleid = int( request[ 'module_id' ] )
        h = str( request[ 'hash' ] )
        b = request[ 'bin' ]
        sig = request[ 'signature' ]
        description = ''
        if 'description' in request:
            description = request[ 'description' ]
        self.db.execute( 'INSERT INTO hcp_modules ( mid, mhash, mdat, msig, description ) VALUES ( %s, %s, %s, %s, %s )',
                         ( moduleid, h, bytearray( b ), bytearray( sig ), description ) )

        data = {}
        data[ 'hash' ] = h
        data[ 'module_id' ] = moduleid
        data[ 'description' ] = description

        return ( True, data )

    @audited
    def cmd_hcp_delModule( self, msg ):
        request = msg.data
        moduleid = int( request[ 'module_id' ] )
        h = str( request[ 'hash' ] )

        self.db.execute( 'DELETE FROM hcp_modules WHERE mid = %s AND mhash = %s',
                         ( moduleid, h ) )

        return ( True, )

    @audited
    def cmd_hcp_getInstallers( self, msg ):
        installers = []
        data = { 'installers' : installers }

        withContent = msg.data.get( 'with_content', False )
        oid = msg.data.get( 'oid', None )
        iid = msg.data.get( 'iid', None )

        filters = []
        filterValues = []
        if oid is not None:
            filters.append( 'oid = %s' )
            filterValues.append( uuid.UUID( oid ) )
            if iid is not None:
                filters.append( 'iid = %s' )
                filterValues.append( uuid.UUID( iid ) )

        filters = ' AND '.join( filters )
        if 0 != len( filters ):
            filters = ' WHERE ' + filters

        for row in self.db.execute( 'SELECT oid, iid, ihash, description, created, data FROM hcp_installers%s' % filters, filterValues ):
            installers.append( { 'oid' : row[ 0 ],
                                 'iid' : row[ 1 ],
                                 'hash' : row[ 2 ],
                                 'description' : row[ 3 ],
                                 'created' : row[ 4 ],
                                 'data' : row[ 5 ] if withContent else None } )

        return ( True, data )

    @audited
    def cmd_hcp_addInstaller( self, msg ):
        oid = uuid.UUID( msg.data[ 'oid' ] )
        iid = uuid.UUID( msg.data[ 'iid' ] )
        description = msg.data[ 'description' ]
        installer = msg.data[ 'installer' ]
        installerHash = hashlib.sha256( installer ).hexdigest()

        self.db.execute( 'INSERT INTO hcp_installers ( oid, iid, ihash, description, data, created ) VALUES ( %s, %s, %s, %s, %s, dateOf( now() ) )',
                         ( oid, iid, installerHash, description, bytearray( installer ) ) )

        self.delay( 5, self.enrollments.broadcast, 'reload', {} )

        return ( True, { 'oid' : oid, 'iid' : iid, 'description' : description, 'hash' : installerHash } )

    @audited
    def cmd_hcp_delInstaller( self, msg ):
        oid = uuid.UUID( msg.data[ 'oid' ] )
        iid = uuid.UUID( msg.data[ 'iid' ] )
        installerHash = msg.data[ 'hash' ]

        self.db.execute( 'DELETE FROM hcp_installers WHERE oid = %s AND iid = %s AND ihash = %s',
                         ( oid, iid, installerHash ) )

        self.delay( 5, self.enrollments.broadcast, 'reload', {} )

        return ( True, )


    @audited
    def cmd_hbs_getProfiles( self, msg ):
        data = { 'profiles' : [] }
        for row in self.db.execute( 'SELECT aid, oprofile FROM hbs_profiles' ):
            data[ 'profiles' ].append( { 'mask' : AgentId( row[ 0 ] ),
                                         'original_configs' : row[ 1 ] } )

        return ( True, data )

    @audited
    def cmd_hbs_addProfile( self, msg ):
        request = msg.data
        mask = AgentId( request[ 'mask' ] ).asString()
        c = request[ 'module_configs' ]
        isValidConfig = False
        profileError = ''
        oc = c
        configHash = None

        if c is not None and '' != c:
            r = rpcm( isDebug = True )
            rpcm_environment = { '_' : self.symbols,
                                 'rList' : rList,
                                 'rSequence' : rSequence,
                                 'HbsCollectorId' : HbsCollectorId }
            try:
                profile = eval( c.replace( '\n', '' ), rpcm_environment )
            except:
                profile = None
                profileError = traceback.format_exc()

            if profile is not None:
                if type( profile ) is rList:
                    profile = r.serialise( profile )

                    if profile is not None:
                        isValidConfig = True
                        c = profile
                        configHash = hashlib.sha256( profile ).hexdigest()
                    else:
                        profileError = 'config could not be serialised'
                else:
                    profileError = 'config did not evaluate as an rList: %s' % type( profile )

        else:
            isValidConfig = True

        if isValidConfig:
            self.db.execute( 'INSERT INTO hbs_profiles ( aid, cprofile, oprofile, hprofile ) VALUES ( %s, %s, %s, %s )',
                             ( mask, bytearray( c ), oc, configHash ) )
            response = ( True, )
        else:
            response = ( False, profileError )

        self.delay( 5, self.hbsProfiles.broadcast, 'reload', {} )

        return response

    @audited
    def cmd_hbs_delProfile( self, msg ):
        request = msg.data
        mask = AgentId( request[ 'mask' ] ).asString()

        self.db.execute( 'DELETE FROM hbs_profiles WHERE aid = %s',
                         ( mask, ) )

        self.delay( 5, self.hbsProfiles.broadcast, 'reload', {} )

        return ( True, )

    @audited
    def cmd_hbs_taskAgent( self, msg ):
        request = msg.data
        expiry = request.get( 'expiry', None )
        if expiry is None:
            expiry = 0
        agent = AgentId( request[ 'aid' ] ).sensor_id
        task = rpcm( isDebug = self.log, 
                     isDetailedDeserialize = True, 
                     isHumanReadable = False ).quickDeserialise( request[ 'task' ],
                                                                 isList = False )

        wrapper = rSequence().addList( self.symbols.hbs.CLOUD_NOTIFICATIONS, 
                                       rList().addSequence( self.symbols.hbs.CLOUD_NOTIFICATION,
                                                            task ) ).serialise( isDebug = self.log,
                                                                                isHumanReadable = False  )

        resp = self.taskingProxy.request( 'task', { 'sid' : agent, 
                                                    'messages' : ( wrapper, ), 
                                                    'module_id' : HcpModuleId.HBS } )

        if resp.isSuccess:
            return ( True, )
        else:
            return ( False, resp.error )
            if int( expiry ) > 0:
                self.db.execute( 'INSERT INTO hbs_queue ( aid, task ) VALUES ( %s, %s ) USING TTL %s',
                                 ( agent, bytearray( task ), expiry ) )
                self.delay( 1, self.persistentTasks.broadcast, 'add', { 'aid' : agent } )
                return ( True, { 'delayed' : True } )
            return ( False, resp.error )
