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
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

import os
import traceback
import StringIO
import base64
import urllib2
import yara

class YaraUpdater ( StatelessActor ):
    def init( self, parameters, resources ):
        super( YaraUpdater, self ).init( parameters, resources )
        self.rulesDir = parameters.get( 'rules_dir', None )
        if self.rulesDir is not None:
            self.rulesDir = os.path.abspath( self.rulesDir )
        self.lastRules = {}
        self.dirRefreshFrequency = parameters.get( 'dir_refresh_frequency', 60 )
        self.remoteRefreshFrequency = parameters.get( 'remote_refresh_frequency', ( 60 * 60 * 24 ) )
        self.remoteRules = parameters.get( 'remote_rules', {} )
        self.windowsRulesFile = '/tmp/_yara_windows'
        self.osxRulesFile = '/tmp/_yara_osx'
        self.linuxRulesFile = '/tmp/_yara_linux'

        if not os.path.exists( self.rulesDir ):
            for plat in ( 'common', 'windows', 'osx', 'linux' ):
                os.makedirs( os.path.join( self.rulesDir, plat ), 0700 )

        self.schedule( self.dirRefreshFrequency, self.refreshDirRules )
        self.schedule( self.remoteRefreshFrequency, self.refreshRemoteRules )


    # Will need a refactor eventually to support platforms with different endianness.
    def loadRulesInDir( self, rootRule, toFile ):
        rules = yara.compile( rootRule )
        if rules:
            rules.save( toFile )
            self.log( 'loaded rules: %s' % ( rootRule, ) )


    def refreshDirRules( self ):
        if self.rulesDir is None: return

        isNewWindowsRules = False
        isNewOsxRules = False
        isNewLinuxRules = False

        for rootDir in ( os.path.join( self.rulesDir, 'common' ),
                         os.path.join( self.rulesDir, 'windows' ),
                         os.path.join( self.rulesDir, 'osx' ),
                         os.path.join( self.rulesDir, 'linux' ) ):
            indexFile = os.path.join( rootDir, '_all.yar' )
            if os.path.isfile( indexFile ):
                modTime = os.stat( indexFile ).st_mtime
                if rootDir not in self.lastRules or self.lastRules[ rootDir ] != modTime:
                    self.lastRules[ rootDir ] = modTime
                    if 'common' in rootDir or 'windows' in rootDir:
                        isNewWindowsRules = True
                    if 'common' in rootDir or 'osx' in rootDir:
                        isNewOsxRules = True
                    if 'common' in rootDir or 'linux' in rootDir:
                        isNewLinuxRules = True

        if isNewWindowsRules:
            self.loadRulesInDir( os.path.join( self.rulesDir, 'windows.yar' ), self.windowsRulesFile )
        if isNewOsxRules:
            self.loadRulesInDir( os.path.join( self.rulesDir, 'osx.yar' ), self.osxRulesFile )
        if isNewLinuxRules:
            self.loadRulesInDir( os.path.join( self.rulesDir, 'linux.yar' ), self.linuxRulesFile )

        # Right now we refresh globally, but we will have the per-platform flags
        # to do a more intelligent refresh in the future.
        if isNewWindowsRules or isNewOsxRules or isNewLinuxRules:
            self.log( 'new Yara rules detected, refreshing' )

    def refreshRemoteRules( self ):
        for name, remote in self.remoteRules.iteritems():
            try:
                with open( os.path.join( self.rulesDir, name ), 'w' ) as f:
                    f.write( urllib2.urlopen( remote ).read() )
                self.log( 'refreshed remote rules: %s bytes' % os.path.getsize( os.path.join( self.rulesDir, name ) ) )
            except:
                self.logCritical( 'failed to fetch remote rule %s %s' % ( remote, traceback.format_exc() ) )


    def process( self, detects, msg ):
        if self.rulesDir is None: return []

        routing, event, mtd = msg.data

        source = AgentId( routing[ 'aid' ] )
        rules = None

        if source.isWindows():
            rules = self.windowsRulesFile
        elif source.isMacOSX():
            rules = self.osxRulesFile
        elif source.isLinux():
            rules = self.linuxRulesFile

        if rules is not None:
            self.task( routing[ 'aid' ],
                       ( 'yara_update', rules ),
                       expiry = 60 )
