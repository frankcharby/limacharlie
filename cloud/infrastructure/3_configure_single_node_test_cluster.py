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

import os
import sys
import hashlib
import argparse
import uuid

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )
originalDir = os.getcwd()
os.chdir( root )
binaryPath = os.path.join( root, 'prebuilt_binaries' )
hcpRootKey = os.path.join( root, 'keys', 'root.priv.der' )
hcpConfig = None
hbsConfig = None
oid = None
iid = None
isDownload = True

parser = argparse.ArgumentParser()
parser.add_argument( '--nodownload',
                     action = 'store_false',
                     required = False,
                     default = True,
                     help = 'set to prevent the latest binaries from being downloaded, use current binaries instead.',
                     dest = 'isDownload' )
parser.add_argument( '-b', '--binaries',
                     type = str ,
                     required = False,
                     help = 'Specify a directory containing all prebuilt and configured binaries you want to task.',
                     dest = 'binaries' )
parser.add_argument( '-hcp', 
                     type = str,
                     required = False,
                     help = 'Specify an HCP sensor config file to apply to the binaries.',
                     dest = 'hcp' )
parser.add_argument( '-hbs', 
                     type = str,
                     required = False,
                     help = 'Specify an HBS sensor config file to apply to the binaries.',
                     dest = 'hbs' )
parser.add_argument( '-k', '--rootkey',
                     type = str,
                     required = False,
                     help = 'Path to the HCP root private key to sign modules with.',
                     dest = 'key' )
parser.add_argument( '-o', '--oid', 
                     type = uuid.UUID,
                     required = False,
                     default = uuid.UUID( '00000000-0000-0000-0000-000000000001' ),
                     help = 'the org id used for everything',
                     dest = 'oid' )
parser.add_argument( '-i', '--iid', 
                     type = uuid.UUID,
                     required = False,
                     default = uuid.UUID( '00000000-0000-0000-0000-000000000001' ),
                     help = 'the installer id used for everything',
                     dest = 'iid' )
arguments = parser.parse_args()

if arguments.binaries is not None:
    binaryPath = os.path.abspath( arguments.binaries )
    print( 'Setting binaries path: %s' % binaryPath )

if arguments.key is not None:
    hcpRootKey = os.path.abspath( arguments.key )
    print( 'Using HCP root key: %s' % hcpRootKey )

if arguments.hcp is not None:
    hcpConfig = os.path.abspath( arguments.hcp )
    print( 'Using HCP config: %s' % hcpConfig )

if arguments.hbs is not None:
    hbsConfig = os.path.abspath( arguments.hbs )
    print( 'Using HBS config: %s' % hbsConfig )

if arguments.oid is not None:
    oid = arguments.oid
    print( 'Using org id: %s' % oid )

if arguments.iid is not None:
    iid = arguments.iid
    print( 'Using installer id: %s' % iid )

isDownload = arguments.isDownload

cwd = os.path.curdir

def printStep( step, *ret ):
    msg = '''
===============
Step: %s
Return Values: %s
===============

''' % ( step, str( ret ) )
    print( msg )
    if any( ret ):
        print( 'Stopping execution since this step failed.' )
        sys.exit(-1)

def execInBackend( script ):

    script = 'login %s\n%s' % ( os.path.join( root,
                                              'cloud',
                                              'beach',
                                              'sample_cli.conf' ),
                                script )

    with open( '_tmp_script', 'w' ) as f:
        f.write( script )

    ret = os.system( 'python %s --script _tmp_script' % ( os.path.join( root,
                                                                        'cloud',
                                                                        'beach',
                                                                        'hcp',
                                                                        'admin_cli.py' ), ) )
    os.unlink( '_tmp_script' )
    return ret

if isDownload:
    printStep( 'Downloading prebuilt release sensor binaries.',
               os.chdir( binaryPath ),
               os.system( os.path.join( binaryPath, 'download_binaries.sh' ) ),
               os.chdir( cwd ) )

binaries = os.listdir( binaryPath )
for binary in binaries:
    if binary.startswith( 'hcp_' ) and not binary.endswith( '.sig' ):
        if hcpConfig is not None:
            printStep( 'Setting HCP to config: %s' % hcpConfig,
                       os.system( 'python %s %s %s %s' % ( os.path.join( root, 'sensor', 'scripts', 'set_sensor_config.py' ),
                                                           hcpConfig,
                                                           os.path.join( binaryPath, binary ),
                                                           iid ) ) )
        printStep( 'Uploading installer: %s.' % binary,
                   execInBackend( '''hcp_addInstaller -o %s -i %s -d %s -f %s''' % ( oid, 
                                                                                     iid,
                                                                                     binary,
                                                                                     os.path.join( binaryPath, binary ) ) ) )

    if hbsConfig is not None:
        if binary.startswith( 'hbs_' ) and not binary.endswith( '.sig' ):
            printStep( 'Setting HBS to config: %s' % hbsConfig,
                       os.system( 'python %s %s %s' % ( os.path.join( root, 'sensor', 'scripts', 'set_sensor_config.py' ),
                                                        hbsConfig,
                                                        os.path.join( binaryPath, binary ) ) ) )

    if ( binary.startswith( 'hbs_' ) or binary.startswith( 'kernel_' ) ) and not binary.endswith( '.sig' ):
        printStep( 'Signing binary: %s' % binary,
            os.system( 'python %s -k %s -f %s -o %s' % ( os.path.join( root, 'tools', 'signing.py' ),
                                                         hcpRootKey,
                                                         os.path.join( binaryPath, binary ),
                                                         os.path.join( binaryPath, binary + '.sig' ) ) ) )

        if 'release' in binary or 'debug' in binary:
            targetAgent = '0.0.0.%s.%s'
            if 'x64' in binary:
                arch = 2
            elif 'x86' in binary:
                arch = 1
            if 'win' in binary:
                plat = 0x10000000
            elif 'osx' in binary:
                plat = 0x30000000
            elif 'ubuntu' in binary:
                plat = 0x20000000

            targetAgent = targetAgent % ( hex( plat )[ 2: ],
                                          hex( arch )[ 2: ] )

            with open( os.path.join( binaryPath, binary ) ) as f:
                h = hashlib.sha256( f.read() ).hexdigest()

            if binary.startswith( 'hbs_' ):
                if 'release' in binary:
                    printStep( 'Tasking HBS %s to all relevant sensors.' % binary,
                        execInBackend( '''hcp_addModule -i 2 -d %s -b %s -s %s
                                          hcp_addTasking -m %s -i 2 -s %s''' % ( binary,
                                                                                 os.path.join( binaryPath, binary ),
                                                                                 os.path.join( binaryPath, binary + '.sig' ),
                                                                                 targetAgent,
                                                                                 h ) ) )
                else:
                    printStep( 'Loading debug HBS %s but not tasking it.' % binary,
                    execInBackend( '''hcp_addModule -i 2 -d %s -b %s -s %s''' % ( binary,
                                                                                  os.path.join( binaryPath, binary ),
                                                                                  os.path.join( binaryPath, binary + '.sig' ) ) ) )
            elif binary.startswith( 'kernel_' ) and 'release' in binary:
                printStep( 'Tasking KERNEL %s to all relevant sensors.' % binary,
                           execInBackend( '''hcp_addModule -i 5 -d %s -b %s -s %s
                                             hcp_addTasking -m %s -i 5 -s %s''' % ( binary,
                                                                                    os.path.join( binaryPath, binary ),
                                                                                    os.path.join( binaryPath, binary + '.sig' ),
                                                                                    targetAgent,
                                                                                    h ) ) )

printStep( 'Setting HBS profile.',
           execInBackend( '''hbs_addProfile -m 0.0.0.0.0 -f %s''' % ( os.path.join( root,
                                                                                    'cloud',
                                                                                    'beach',
                                                                                    'production_hbs.profile' ) ) ) )

os.chdir( originalDir )