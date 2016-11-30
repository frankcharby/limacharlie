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

from gevent import monkey
monkey.patch_all()

import os
import sys

from beach.beach_api import Beach
from hcp_helpers import AgentId
from hcp_helpers import timeToTs
from hcp_helpers import _x_
from hcp_helpers import _xm_
from hcp_helpers import InvestigationNature
from hcp_helpers import InvestigationConclusion
from EventInterpreter import EventInterpreter

import traceback
import web
import datetime
import time
import json
import base64
import uuid
from functools import wraps
import markdown
import markdown.extensions.tables

from hcp_helpers import _x_
from hcp_helpers import _xm_
from hcp_helpers import timeToTs
from hcp_helpers import normalAtom


###############################################################################
# CUSTOM EXCEPTIONS
###############################################################################


###############################################################################
# REFERENCE ELEMENTS
###############################################################################


###############################################################################
# CORE HELPER FUNCTIONS
###############################################################################
def msTsToTime( ts ):
    return datetime.datetime.fromtimestamp( float( ts ) / 1000 ).strftime( '%Y-%m-%d %H:%M:%S.%f' )

def sanitizeJson( o, summarized = False ):
    if type( o ) is dict:
        for k, v in o.iteritems():
            o[ k ] = sanitizeJson( v, summarized = summarized )
    elif type( o ) is list or type( o ) is tuple:
        o = [ sanitizeJson( x, summarized = summarized ) for x in o ]
    elif type( o ) is uuid.UUID:
        o = str( o )
    else:
        try:
            if ( type(o) is str or type(o) is unicode ) and "\x00" in o: raise Exception()
            json.dumps( o )
        except:
            o = base64.b64encode( o )
        if summarized is not False and len( str( o ) ) > summarized:
            o = str( o[ : summarized ] ) + '...'

    return o

def downloadFileName( name ):
    web.header( 'Content-Disposition', 'attachment;filename="%s"' % name )

def doMarkdown( content ):
    return markdown.markdown( content, extensions = [ 'markdown.extensions.tables' ] )

###############################################################################
# PAGE DECORATORS
###############################################################################
def jsonApi( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/json' )
        r = f( *args, **kwargs )
        try:
            return json.dumps( sanitizeJson( r ) )
        except:
            return json.dumps( { 'error' : str( r ),
                                 'exception' : traceback.format_exc() } )
    return wrapped

def fileDownload( f ):
    ''' Decorator to basic exception handling on function. '''
    @wraps( f )
    def wrapped( *args, **kwargs ):
        web.header( 'Content-Type', 'application/octet-stream' )
        return f( *args, **kwargs )
    return wrapped

###############################################################################
# PAGES
###############################################################################
class Index:
    def GET( self ):
        return render.index()

class Dashboard:
    def GET( self ):

        sensors = model.request( 'list_sensors', {} )

        if not sensors.isSuccess:
            return render.error( str( sensors ) )

        return render.dashboard( sensors = sanitizeJson( sensors.data ) )

class Sensor:
    def GET( self ):
        params = web.input( sensor_id = None, before = None, after = None, max_size = '4096', per_page = '10' )

        if params.sensor_id is None:
            return render.error( 'sensor_id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )

        if not info.isSuccess:
            return render.error( str( info ) )

        if 0 == len( info.data ):
            return render.error( 'Sensor not found' )

        before = None
        after = None

        if '' != params.before:
            before = params.before
        if '' != params.after:
            after = params.after

        return render.sensor( AgentId( info.data[ 'id' ] ), before, after, params.max_size, params.per_page )

class SensorState:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_sensor_info', { 'id_or_host' : params.sensor_id } )
        live_status = sensordir.request( 'get_endpoint', { 'aid' : params.sensor_id } )
        if not live_status.isSuccess:
            live_status = False
            transfered = 0
        else:
            transfered = live_status.data.get( 'transfered', 0 )
            live_status = True if live_status.data.get( 'endpoint', None ) is not None else False

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable: %s' % str( info ) )

        if 0 == len( info.data ):
            raise web.HTTPError( '204 No Content: sensor not found' )

        info.data[ 'live_status' ] = live_status
        info.data[ 'transfered' ] = transfered

        return info.data

class Timeline:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None, after = None, before = None, max_size = '4096', rich = 'false', max_time = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        if params.after is None or '' == params.after:
            raise web.HTTPError( '400 Bad Request: need start time' )

        start_time = int( params.after )
        max_size = int( params.max_size )
        max_time = 60 * 60 * 4
        if params.max_time is not None and '' != params.max_time:
            max_time = int( params.max_time )
        end_time = None
        if params.before is not None and '' != params.before:
            end_time = int( params.before )
        rich = True if params.rich == 'true' else False

        if 0 != start_time:
            effective_end_time = int( time.time() )
            if end_time is not None:
                effective_end_time = end_time
            if max_time < ( effective_end_time - start_time ):
                raise web.HTTPError( '400 Bad Request: maximum time lapse: %d - %d > %d' % ( effective_end_time, start_time, max_time ) )

        if 0 == start_time:
            start_time = int( time.time() ) - 5

        req = { 'id' : params.sensor_id,
                'is_include_content' : True,
                'after' : start_time }

        if not rich:
            req[ 'max_size' ] = max_size

        if end_time is not None:
            req[ 'before' ] = end_time

        info = model.request( 'get_timeline', req )

        if not info.isSuccess:
            return render.error( str( info ) )

        if 0 == int( params.after ):
            info.data[ 'new_start' ] = start_time

        if rich:
            originalEvents = info.data.get( 'events', [] )
            info.data[ 'events' ] = []
            for event in originalEvents:
                thisAtom = event[ 3 ].values()[ 0 ].get( 'hbs.THIS_ATOM', None )
                richEvent = None
                if hasattr( eventRender, event[ 1 ] ):
                    try:
                        richEvent = str( getattr( eventRender, event[ 1 ] )( sanitizeJson( event[ 3 ] ) ) )
                    except:
                        richEvent = None
                if richEvent is None:
                    richEvent = str( eventRender.default( sanitizeJson( event[ 3 ], summarized = 1024 ) ) )

                info.data[ 'events' ].append( ( event[ 0 ],
                                                event[ 1 ],
                                                event[ 2 ],
                                                richEvent,
                                                thisAtom ) )
        return info.data

class ObjSearch:
    def GET( self ):
        params = web.input( objname = None )

        if params.objname is None:
            return render.error( 'Must specify an object name' )

        objects = model.request( 'get_obj_list', { 'name' : params.objname } )

        if not objects.isSuccess:
            return render.error( str( objects ) )

        return render.objlist( sanitizeJson( objects.data[ 'objects' ] ), None )

class ObjViewer:
    def GET( self ):
        params = web.input( sensor_id = None, id = None )

        if params.id is None:
            return render.error( 'need to supply an object id' )

        req = { 'id' : params.id }

        if params.sensor_id is not None:
            req[ 'host' ] = params.sensor_id

        info = model.request( 'get_obj_view', req )

        if not info.isSuccess:
            return render.error( str( info ) )

        return render.obj( sanitizeJson( info.data ), params.sensor_id )

class LastEvents:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_lastevents', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        return info.data.get( 'events', [] )

class EventView:
    def GET( self ):
        params = web.input( id = None, summarized = 1024 )

        if params.id is None:
            return render.error( 'need to supply an event id' )

        info = model.request( 'get_event', { 'id' : params.id } )

        if not info.isSuccess:
            return render.error( str( info ) )

        event = info.data.get( 'event', {} )

        thisAtom = event[ 1 ].values()[ 0 ].get( 'hbs.THIS_ATOM', None )

        return render.event( sanitizeJson( event, summarized = params.summarized ), thisAtom )

class HostObjects:
    def GET( self ):
        params = web.input( sensor_id = None, otype = None )

        if params.sensor_id is None:
            return render.error( 'need to supply a sensor id' )

        req = { 'host' : params.sensor_id }

        if params.otype is not None:
            req[ 'type' ] = params.otype

        objects = model.request( 'get_obj_list', req )

        return render.objlist( sanitizeJson( objects.data[ 'objects' ] ), params.sensor_id )

class JsonDetects:
    @jsonApi
    def GET( self ):
        params = web.input( before = None, after = None )

        if params.after is None or '' == params.after:
            raise web.HTTPError( '400 Bad Request: start time required' )

        start_time = None
        if params.after is not None:
            start_time = int( params.after )

        if start_time is None or 0 == start_time:
            start_time = int( time.time() ) - 5

        search = {}

        if start_time is not None:
            search [ 'after' ] = start_time

        if params.before is not None:
            search[ 'before' ] = int( params.before )

        detects = model.request( 'get_detects', search )

        if not detects.isSuccess:
            return render.error( str( detects ) )
        else:
            return detects.data

class ViewDetects:
    def GET( self ):
        params = web.input( before = None, after = None )

        before = None
        after = None

        if params.before is not None and '' != params.before:
            before = params.before
        if params.after is not None and '' != params.after:
            after = params.after

        return render.detects( before, after )

class ViewDetect:
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            return render.error( 'need to supply a detect id' )

        info = model.request( 'get_detect', { 'id' : params.id, 'with_events' : True, 'with_inv' : True } )

        if not info.isSuccess:
            return render.error( str( info ) )

        return render.detect( sanitizeJson( info.data.get( 'detect', [] ) ), sanitizeJson( info.data.get( 'inv', {} ) ) )

class HostChanges:
    @jsonApi
    def GET( self ):
        params = web.input( sensor_id = None )

        if params.sensor_id is None:
            raise web.HTTPError( '400 Bad Request: sensor id required' )

        info = model.request( 'get_host_changes', { 'id' : params.sensor_id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        return info.data.get( 'changes', {} )

class DownloadFileInEvent:
    @fileDownload
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            raise web.HTTPError( '400 Bad Request: event id required' )

        info = model.request( 'get_file_in_event', { 'id' : params.id } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        if 'path' not in info.data or 'data' not in info.data:
            return render.error( 'no file path or content found in event' )

        downloadFileName( '%s__%s' % ( params.id, ( info.data[ 'path' ].replace( '/', '_' )
                                                                       .replace( '\\', '_' )
                                                                       .replace( '.', '_' ) ) ) )

        return info.data[ 'data' ]


class Explorer:
    @jsonApi
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            raise web.HTTPError( '400 Bad Request: id required' )

        effectiveId = normalAtom( params.id )

        info = model.request( 'get_atoms_from_root', { 'id' : effectiveId } )

        if not info.isSuccess:
            raise web.HTTPError( '503 Service Unavailable : %s' % str( info ) )

        # Make sure the root is present
        info.data = list( info.data )
        isFound = False
        for atom in info.data:
            if effectiveId == normalAtom( atom.values()[0]['hbs.THIS_ATOM'] ):
                isFound = True
                break
        info.data = map( lambda x: { 'data' : x, 'key' : EventInterpreter( x ).shortKey() }, info.data )
        if not isFound:
            info.data.append( { 'data' : { 'UNKNOWN' : { 'hbs.THIS_ATOM' : effectiveId } },
                                'key' : 'UNKNOWN' } )

        # Summarize the events

        return info.data


class ExplorerView:
    def GET( self ):
        params = web.input( id = None )

        if params.id is None:
            return render.error( 'requires an initial id' )

        return renderFullPage.explorer( id = params.id )

class Backend:
    def GET( self ):
        params = web.input()

        info = model.request( 'get_backend_config' )

        if not info.isSuccess:
            return render.error( 'failed to get config: %s' % info.error )

        return render.backend( info.data )


class Capabilities:
    def POST( self ):
        params = web.input( urlToAdd = None, nameToRem = None, nameToAdd = None, argsToAdd = None )

        cap = {}

        if params.urlToAdd is not None and params.nameToAdd is not None:
            capabilities.request( 'load', { 'url' : params.urlToAdd,
                                            'user_defined_name' : params.nameToAdd,
                                            'args' : params.argsToAdd } )
        elif params.nameToRem is not None:
            capabilities.request( 'unload', { 'user_defined_name' : params.nameToRem } )

        return self.GET()

    def GET( self ):
        params = web.input()

        cap = {}

        capReq = capabilities.request( 'list', {} )
        if capReq.isSuccess:
            cap.update( capReq.data[ 'loadedDetections' ] )
            cap.update( capReq.data[ 'loadedPatrols' ] )

        return render.capabilities( capabilities = cap )

###############################################################################
# BOILER PLATE
###############################################################################
os.chdir( os.path.dirname( os.path.abspath( __file__ ) ) )

urls = ( r'/', 'Index',
         r'/dashboard', 'Dashboard',
         r'/sensor', 'Sensor',
         r'/search', 'Search',
         r'/sensor_state', 'SensorState',
         r'/timeline', 'Timeline',
         r'/explorer', 'Explorer',
         r'/explorer_view', 'ExplorerView',
         r'/objsearch', 'ObjSearch',
         r'/obj', 'ObjViewer',
         r'/lastevents', 'LastEvents',
         r'/event', 'EventView',
         r'/hostobjects', 'HostObjects',
         r'/detects_data', 'JsonDetects',
         r'/detects', 'ViewDetects',
         r'/detect', 'ViewDetect',
         r'/hostchanges', 'HostChanges',
         r'/downloadfileinevent', 'DownloadFileInEvent',
         r'/backend', 'Backend',
         r'/capabilities', 'Capabilities' )

web.config.debug = False
app = web.application( urls, globals() )

render = web.template.render( 'templates', base = 'base', globals = { 'json' : json,
                                                                      'msTsToTime' : msTsToTime,
                                                                      '_x_' : _x_,
                                                                      '_xm_' : _xm_,
                                                                      'AgentId' : AgentId,
                                                                      'hex' : hex,
                                                                      'sanitize' : sanitizeJson,
                                                                      'EventInterpreter' : EventInterpreter,
                                                                      'md' : doMarkdown,
                                                                      'sorted' : sorted,
                                                                      'InvestigationNature' : InvestigationNature,
                                                                      'InvestigationConclusion' : InvestigationConclusion } )

renderFullPage = web.template.render( 'templates', base = 'base_full', globals = { 'json' : json,
                                                                                   'msTsToTime' : msTsToTime,
                                                                                   '_x_' : _x_,
                                                                                   '_xm_' : _xm_,
                                                                                   'AgentId' : AgentId,
                                                                                   'hex' : hex,
                                                                                   'sanitize' : sanitizeJson,
                                                                                   'EventInterpreter' : EventInterpreter,
                                                                                   'md' : doMarkdown,
                                                                                   'sorted' : sorted,
                                                                                   'InvestigationNature' : InvestigationNature,
                                                                                   'InvestigationConclusion' : InvestigationConclusion } )
eventRender = web.template.render( 'templates/custom_events', globals = { 'json' : json,
                                                                          'msTsToTime' : msTsToTime,
                                                                          '_x_' : _x_,
                                                                          '_xm_' : _xm_,
                                                                          'AgentId' : AgentId,
                                                                          'hex' : hex,
                                                                          'sanitize' : sanitizeJson,
                                                                          'EventInterpreter' : EventInterpreter,
                                                                          'sorted' : sorted } )

if len( sys.argv ) < 2:
    print( "Usage: python app.py beach_config [listen_port]" )
    sys.exit()

beach = Beach( sys.argv[ 1 ], realm = 'hcp' )
del( sys.argv[ 1 ] )
model = beach.getActorHandle( 'models', nRetries = 3, timeout = 30, ident = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' )
capabilities = beach.getActorHandle( 'analytics/capabilitymanager', nRetries = 3, timeout = 60, ident = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' )
sensordir = beach.getActorHandle( 'c2/sensordir', nRetries = 3, timeout = 30, ident = 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' )

app.run()