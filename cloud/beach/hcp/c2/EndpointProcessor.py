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
import gevent
from gevent.lock import Semaphore
from gevent.server import StreamServer
import os
import sys
import struct
import M2Crypto
import zlib
import uuid
import hashlib
import random
import traceback
import time
rpcm = Actor.importLib( 'utils/rpcm', 'rpcm' )
rList = Actor.importLib( 'utils/rpcm', 'rList' )
rSequence = Actor.importLib( 'utils/rpcm', 'rSequence' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )
HcpModuleId = Actor.importLib( 'utils/hcp_helpers', 'HcpModuleId' )
Symbols = Actor.importLib( 'Symbols', 'Symbols' )()
HcpOperations = Actor.importLib( 'utils/hcp_helpers', 'HcpOperations' )

rsa_2048_min_size = 0x100
aes_256_iv_size = 0x10
aes_256_block_size = 0x10
aes_256_key_size = 0x20
rsa_header_size = 0x100 + 0x10 # rsa_2048_min_size + aes_256_iv_size
rsa_signature_size = 0x100

class DisconnectException( Exception ):
    pass

class _ClientContext( object ):
    def __init__( self, parent, socket ):
        self.parent = parent
        self.s = socket
        self.aid = None
        self.lock = Semaphore( 1 )
        self.sKey = None
        self.sIv = None
        self.sendAes = None
        self.recvAes = None
        self.r = rpcm( isHumanReadable = True, isDebug = self.parent.log )
        self.r.loadSymbols( Symbols.lookups )

    def setKey( self, sKey, sIv ):
        self.sKey = sKey
        self.sIv = sIv
        # We disable padding and do it manually on our own
        # to bypass the problem with the API. With padding ON
        # the last call to .update actually withholds the last
        # block until the call to final is made (to apply padding)
        # but when .final is called the cipher is destroyed.
        # In our case we want to keep the cipher alive during the
        # entire session, but we can't wait indefinitely for the
        # next message to come along to "release" the previous block.
        self.sendAes = M2Crypto.EVP.Cipher( alg = 'aes_256_cbc',
                                            key = self.sKey, 
                                            iv = self.sIv, 
                                            salt = False, 
                                            key_as_bytes = False, 
                                            padding = False,
                                            op = 1 ) # 0 == ENC
        self.recvAes = M2Crypto.EVP.Cipher( alg = 'aes_256_cbc',
                                            key = self.sKey, 
                                            iv = self.sIv, 
                                            salt = False, 
                                            key_as_bytes = False, 
                                            padding = False,
                                            op = 0 ) # 0 == DEC

    def setAid( self, aid ):
        self.aid = aid

    def getAid( self ):
        return self.aid

    def close( self ):
        with self.lock:
            self.s.close()

    def recvData( self, size, timeout = None ):
        data = None
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            data = ''
            while size > len( data ):
                tmp = self.s.recv( size - len( data ) )
                if not tmp:
                    raise DisconnectException( 'disconnect while receiving' )
                    break
                data += tmp
        except:
            raise
        finally:
            timeout.cancel()
        return data

    def sendData( self, data, timeout = None ):
        timeout = gevent.Timeout( timeout )
        timeout.start()
        try:
            with self.lock:
                self.s.sendall( data )
        except:
            raise DisconnectException( 'disconnect while sending' )
        finally:
            timeout.cancel()

    def _pad( self, buffer ):
        nPad = aes_256_block_size - ( len( buffer ) % aes_256_block_size )
        if nPad == 0:
            nPad = aes_256_block_size
        return buffer + ( struct.pack( 'B', nPad ) * nPad )

    def _unpad( self, buffer ):
        nPad = struct.unpack( 'B', buffer[ -1 : ] )[ 0 ]
        if nPad <= aes_256_block_size and buffer.endswith( buffer[ -1 : ] * nPad ):
            buffer = buffer[ : 0 - nPad ]
        else:
            raise Exception( 'invalid payload padding' )
        return buffer

    def recvFrame( self, timeout = None ):
        frameSize = struct.unpack( '>I', self.recvData( 4, timeout = timeout ) )[ 0 ]
        if (1024 * 1024 * 50) < frameSize:
            raise Exception( "frame size too large: %s" % frameSize )
        frame = self.recvData( frameSize, timeout = timeout )
        frame = self._unpad( self.recvAes.update( frame ) + self.recvAes.update( '' ) )
        #frame += self.recvAes.final()
        frame = zlib.decompress( frame )
        moduleId = struct.unpack( 'B', frame[ : 1 ] )[ 0 ]
        frame = frame[ 1 : ]
        self.r.setBuffer( frame )
        messages = self.r.deserialise( isList = True )
        return ( moduleId, messages, frameSize + 4 )

    def sendFrame( self, moduleId, messages, timeout = None ):
        msgList = rList()
        for msg in messages:
            msgList.addSequence( Symbols.base.MESSAGE, msg )
        hcpData = struct.pack( 'B', moduleId ) + self.r.serialise( msgList )
        data = struct.pack( '>I', len( hcpData ) )
        data += zlib.compress( hcpData )
        data = self.sendAes.update( self._pad( data ) )
        #data += self.sendAes.final()
        #self.parent.log( 'sending frame of size %d' % len( data ) )
        self.sendData( struct.pack( '>I', len( data ) ) + data, timeout = timeout )

class EndpointProcessor( Actor ):
    def init( self, parameters, resources ):
        self.handlerPortStart = parameters.get( 'handler_port_start', 10000 )
        self.handlerPortEnd = parameters.get( 'handler_port_end', 20000 )
        self.bindAddress = parameters.get( 'handler_address', ' 0.0.0.0' )
        self.privateKey = M2Crypto.RSA.load_key_string( parameters[ '_priv_key' ] )
        self.deploymentToken = parameters.get( 'deployment_token', None )
        self.enrollmentKey = parameters.get( 'enrollment_key', 'DEFAULT_HCP_ENROLLMENT_TOKEN' )

        self.r = rpcm( isHumanReadable = True )
        self.r.loadSymbols( Symbols.lookups )

        self.analyticsIntake = self.getActorHandle( resources[ 'analytics' ] )
        self.enrollmentManager = self.getActorHandle( resources[ 'enrollments' ] )
        self.stateChanges = self.getActorHandleGroup( resources[ 'states' ] )
        self.moduleManager = self.getActorHandle( resources[ 'module_tasking' ] )
        self.hbsProfileManager = self.getActorHandle( resources[ 'hbs_profiles' ] )
        self.handle( 'task', self.taskClient )

        self.server = None
        self.serverPort = random.randint( self.handlerPortStart, self.handlerPortEnd )
        self.currentClients = {}
        self.moduleHandlers = { HcpModuleId.HCP : self.handlerHcp,
                                HcpModuleId.HBS : self.handlerHbs }

        self.processedCounter = 0

        self.startServer()

    def deinit( self ):
        if self.server is not None:
            self.server.close()

    def startServer( self ):
        if self.server is not None:
            self.server.close()
        while True:
            try:
                self.server = StreamServer( ( self.bindAddress, self.serverPort ), self.handleNewClient )
                self.server.start()
                self.log( 'Starting server on port %s' % self.serverPort )
                break
            except:
                self.serverPort = random.randint( self.handlerPortStart, self.handlerPortEnd )

    #==========================================================================
    # Client Handling
    #==========================================================================
    def handleNewClient( self, socket, address ):
        aid = None
        tmpBytesReceived = 0
        try:
            self.log( 'New connection from %s:%s' % address )
            c = _ClientContext( self, socket )
            handshake = c.recvData( rsa_2048_min_size + aes_256_iv_size, timeout = 30.0 )
            
            self.log( 'Handshake received' )
            sKey = handshake[ : rsa_2048_min_size ]
            iv = handshake[ rsa_2048_min_size : ]
            c.setKey( self.privateKey.private_decrypt( sKey, M2Crypto.RSA.pkcs1_padding ), iv )
            c.sendFrame( HcpModuleId.HCP,
                         ( rSequence().addBuffer( Symbols.base.BINARY, 
                                                  handshake ), ) )
            del( handshake )
            self.log( 'Handshake valid, getting headers' )

            moduleId, headers, _ = c.recvFrame( timeout = 30.0 )
            if HcpModuleId.HCP != moduleId:
                raise DisconnectException( 'Headers not from expected module' )
            if headers is None:
                raise DisconnectException( 'Error deserializing headers' )
            headers = headers[ 0 ]
            self.log( 'Headers decoded, validating connection' )

            hostName = headers.get( 'base.HOST_NAME', None )
            internalIp = headers.get( 'base.IP_ADDRESS', None )
            externalIp = address[ 0 ]
            aid = AgentId( headers[ 'base.HCP_ID' ] )
            if aid.org_id is None or aid.ins_id is None or aid.platform is None or aid.architecture is None:
                aidInfo = str( aid )
                if 0 == len( aidInfo ):
                    aidInfo = str( headers )
                raise DisconnectException( 'Invalid sensor id: %s' % aidInfo )
            enrollmentToken = headers.get( 'hcp.ENROLLMENT_TOKEN', None )
            if aid.sensor_id is None:
                self.log( 'Sensor requires enrollment' )
                resp = self.enrollmentManager.request( 'enroll', { 'aid' : aid.asString(),
                                                                   'public_ip' : externalIp,
                                                                   'internal_ip' : internalIp,
                                                                   'host_name' : hostName },
                                                       timeout = 30 )
                if not resp.isSuccess or 'aid' not in resp.data or resp.data[ 'aid' ] is None:
                    raise DisconnectException( 'Sensor could not be enrolled, come back later' )
                aid = AgentId( resp.data[ 'aid' ] )
                enrollmentToken = hashlib.md5( '%s/%s' % ( aid.asString(), 
                                                           self.enrollmentKey ) ).digest()
                self.log( 'Sending sensor enrollment to %s' % aid.asString() )
                c.sendFrame( HcpModuleId.HCP,
                             ( rSequence().addInt8( Symbols.base.OPERATION, 
                                                    HcpOperations.SET_HCP_ID )
                                          .addSequence( Symbols.base.HCP_ID, 
                                                        aid.toJson() )
                                          .addBuffer( Symbols.hcp.ENROLLMENT_TOKEN, 
                                                      enrollmentToken ), ) )
            else:
                expectedEnrollmentToken = hashlib.md5( '%s/%s' % ( aid.asString(), 
                                                                   self.enrollmentKey ) ).digest()
                if enrollmentToken != expectedEnrollmentToken:
                    raise DisconnectException( 'Enrollment token invalid' )
            self.log( 'Valid client connection' )

            # Eventually sync the clocks at recurring intervals
            c.sendFrame( HcpModuleId.HCP, ( self.timeSyncMessage(), ) )

            c.setAid( aid )
            self.currentClients[ aid.sensor_id ] = c
            self.stateChanges.shoot( 'live', { 'aid' : aid.asString(), 
                                               'endpoint' : self.name,
                                               'ext_ip' : externalIp,
                                               'int_ip' : internalIp,
                                               'hostname' : hostName } )

            self.log( 'Client %s registered, beginning to receive data' % aid.asString() )
            frameIndex = 0
            while True:
                moduleId, messages, nRawBytes = c.recvFrame( timeout = 60 * 60 )
                tmpBytesReceived += nRawBytes
                if 100 == frameIndex:
                    self.stateChanges.shoot( 'transfered', { 'aid' : aid.asString(), 
                                             'bytes_transfered' : tmpBytesReceived } )
                    tmpBytesReceived = 0
                    frameIndex = 0
                else:
                    frameIndex += 1
                handler = self.moduleHandlers.get( moduleId, None )
                
                if handler is None:
                    self.log( 'Received data for unknown module' )
                else:
                    handler( c, messages )

        except Exception as e:
            if type( e ) is not DisconnectException:
                self.log( 'Exception while processing: %s' % str( e ) )
                #self.log( traceback.format_exc() )
                raise
            else:
                self.log( 'Disconnecting: %s' % str( e ) )
        finally:
            if aid is not None:
                if aid.sensor_id in self.currentClients:
                    del( self.currentClients[ aid.sensor_id ] )
                    self.stateChanges.shoot( 'transfered', { 'aid' : aid.asString(), 
                                             'bytes_transfered' : tmpBytesReceived } )
                    self.stateChanges.shoot( 'dead', { 'aid' : aid.asString(), 
                                                       'endpoint' : self.name } )
                self.log( 'Connection terminated: %s' % aid.asString() )
            else:
                self.log( 'Connection terminated: %s:%s' % address )

    def handlerHcp( self, c, messages ):
        for message in messages:
            if 'hcp.MODULES' in message:
                moduleUpdateResp = self.moduleManager.request( 'sync', { 'mods' : message[ 'hcp.MODULES' ],
                                                                         'aid' : c.getAid() } )
                if moduleUpdateResp.isSuccess:
                    changes = moduleUpdateResp.data[ 'changes' ]
                    tasks = []
                    for mod in changes[ 'unload' ]:
                        tasks.append( rSequence().addInt8( Symbols.base.OPERATION,
                                                           HcpOperations.UNLOAD_MODULE )
                                                 .addInt8( Symbols.hcp.MODULE_ID,
                                                           mod ) )
                    for mod in changes[ 'load' ]:
                        tasks.append( rSequence().addInt8( Symbols.base.OPERATION,
                                                           HcpOperations.LOAD_MODULE )
                                                 .addInt8( Symbols.hcp.MODULE_ID,
                                                           mod[ 0 ] )
                                                 .addBuffer( Symbols.base.BINARY,
                                                             mod[ 2 ] )
                                                 .addBuffer( Symbols.base.SIGNATURE,
                                                             mod[ 3 ] ) )

                    c.sendFrame( HcpModuleId.HCP, tasks )
                    self.log( 'load %d modules, unload %d modules' % ( len( changes[ 'load' ] ),
                                                                       len( changes[ 'unload' ] ) ) )
                else:
                    self.log( "could not provide module sync: %s" % moduleUpdateResp.error )

    def handlerHbs( self, c, messages ):
        for i in range( len( messages ) ):
            self.processedCounter += 1

            if 0 == ( self.processedCounter % 50 ):
                self.log( 'EP_IN %s' % self.processedCounter )

        for message in messages:
            # We treat sync messages slightly differently since they need to be actioned
            # more directly.
            if 'notification.SYNC' in message:
                self.log( "sync received from %s" % c.getAid() )
                profileHash = message[ 'notification.SYNC' ].get( 'base.HASH', None )
                profileUpdateResp = self.hbsProfileManager.request( 'sync', { 'hprofile' : profileHash,
                                                                              'aid' : c.getAid() } )
                if profileUpdateResp.isSuccess and 'changes' in profileUpdateResp.data:
                    profile = profileUpdateResp.data[ 'changes' ].get( 'profile', None )
                    if profile is not None:
                        r = rpcm( isHumanReadable = False, isDebug = self.log, isDetailedDeserialize = True )
                        r.setBuffer( profile [ 0 ] )
                        realProfile = r.deserialise( isList = True )
                        if realProfile is not None:
                            syncProfile = rSequence().addSequence( Symbols.notification.SYNC,
                                                                   rSequence().addBuffer( Symbols.base.HASH,
                                                                                          profile[ 1 ].decode( 'hex' ) )
                                                                              .addList( Symbols.hbs.CONFIGURATIONS,
                                                                                        realProfile ) )
                            c.sendFrame( HcpModuleId.HBS, ( syncProfile, ) )
                            self.log( "sync profile sent to %s" % c.getAid() )
                            
            # Transmit the message to the analytics cloud.
            routing = { 'agentid' : c.getAid(),
                        'moduleid' : HcpModuleId.HBS,
                        'event_type' : message.keys()[ 0 ],
                        'event_id' : hashlib.sha256( str( uuid.uuid4() ) ).hexdigest() }
            invId = message.values()[ 0 ].get( 'hbs.INVESTIGATION_ID', None )
            if invId is not None:
                routing[ 'investigation_id' ] = invId
            self.analyticsIntake.shoot( 'analyze', ( ( routing, message ), ) )

    def timeSyncMessage( self ):
        return ( rSequence().addInt8( Symbols.base.OPERATION,
                                      HcpOperations.SET_GLOBAL_TIME )
                            .addTimestamp( Symbols.base.TIMESTAMP,
                                           int( time.time() ) ) )

    def taskClient( self, msg ):
        aid = AgentId( msg.data[ 'aid' ] )
        messages = msg.data[ 'messages' ]
        moduleId = msg.data[ 'module_id' ]
        c = self.currentClients.get( aid.sensor_id, None )
        if c is not None:
            outMessages = []
            r = rpcm( isHumanReadable = False, isDebug = self.log, isDetailedDeserialize = True )
            for message in messages:
                r.setBuffer( message )
                outMessages.append( r.deserialise( isList = False ) )
            c.sendFrame( moduleId, outMessages, timeout = 60 * 10 )
            return ( True, )
        else:
            return ( False, )
