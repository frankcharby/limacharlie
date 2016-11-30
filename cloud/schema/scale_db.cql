CREATE KEYSPACE "hcp_analytics" WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 3 };

use hcp_analytics;

CREATE TABLE sensor_states(
  sid uuid,
  oid uuid,
  iid uuid,
  plat int,
  arch int,
  enroll timestamp,
  alive timestamp,
  dead timestamp,
  ext_ip varchar,
  int_ip varchar,
  hostname varchar,
  PRIMARY KEY( sid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE sensor_hostnames(
  hostname varchar,
  sid uuid,
  PRIMARY KEY( hostname, sid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hcp_modules(
  mid int,
  mhash varchar,
  mdat blob,
  msig blob,
  description varchar,
  PRIMARY KEY( mid, mhash )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hcp_module_tasking(
  aid varchar,
  mid int,
  mhash varchar,
  PRIMARY KEY( aid, mid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hbs_profiles(
  aid varchar,
  cprofile blob,
  oprofile varchar,
  hprofile varchar,
  PRIMARY KEY( aid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hbs_queue(
  sid uuid,
  task blob,
  PRIMARY KEY( sid, task )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE events(
  eventid uuid,
  event varchar,
  sid uuid,
  PRIMARY KEY( eventid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE timeline(
  sid uuid,
  ts timeuuid,
  eventtype varchar,
  eventid uuid,
  PRIMARY KEY( sid, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE timeline_by_type(
  sid uuid,
  ts timeuuid,
  eventtype varchar,
  eventid uuid,
  PRIMARY KEY( sid, eventtype, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE obj_man
(
  id varchar,

  obj varchar,
  otype int,

  PRIMARY KEY( id )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE obj_name
(
  obj varchar,
  id varchar,
  PRIMARY KEY( obj, id )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE loc
(
  id varchar,
  sid uuid,

  otype int,
  last timestamp,

  PRIMARY KEY( sid, otype, id )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE loc_by_id
(
  id varchar,
  sid uuid,
  last timestamp,
  PRIMARY KEY( id, sid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE loc_by_type
(
  d256 int,
  otype int,
  id varchar,
  sid uuid,
  PRIMARY KEY( d256, otype, id, sid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE rel_man_parent
(
  parentkey varchar,
  ctype int,
  cid varchar,
  PRIMARY KEY( parentkey, ctype, cid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;


CREATE TABLE rel_man_child
(
  childkey varchar,
  ptype int,
  pid varchar,
  PRIMARY KEY( childkey, ptype, pid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;


CREATE TABLE recentlyActive
(
  sid uuid,
  last timestamp,
  PRIMARY KEY( sid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE last_events
(
  sid uuid,
  type varchar,
  id uuid,
  PRIMARY KEY( sid, type )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE ref_loc
(
  id varchar,
  plat int,
  nloc int,

  PRIMARY KEY( id, plat )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE detects
(
  did varchar,
  gen timestamp,
  source varchar,
  dtype varchar,
  events varchar,
  detect varchar,
  why varchar,

  PRIMARY KEY( did )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE detect_timeline
(
  d int,
  ts timeuuid,
  did varchar,

  PRIMARY KEY( d, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE keyvalue
(
  k varchar,
  c varchar,
  cts timestamp,
  v varchar,

  PRIMARY KEY( k, c )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE atoms_children
(
  atomid uuid,
  child uuid,
  eid uuid,
  PRIMARY KEY( atomid, child )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE atoms_lookup
(
  atomid uuid,
  eid uuid,
  PRIMARY KEY( atomid, eid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE investigation_data
(
  invid varchar,
  ts timeuuid,
  eid uuid,
  etype varchar,
  PRIMARY KEY( invid, ts )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE investigation
(
  invid varchar,
  hunter varchar,
  gen timestamp,
  closed timestamp,
  nature int,
  conclusion int,
  why varchar,

  PRIMARY KEY( invid, hunter )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE inv_data
(
  invid varchar,
  hunter varchar,
  gen timeuuid,
  why varchar,
  data blob,

  PRIMARY KEY( invid, hunter, gen )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE inv_task
(
  invid varchar,
  hunter varchar,
  gen timeuuid,
  why varchar,
  dest varchar,
  data blob,
  sent int,

  PRIMARY KEY( invid, hunter, gen )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
