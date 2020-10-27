!set variable_substitution=true;
!set friendly=false;
!set timing=false;
!set quiet=true

-- Get stage definitions and store them into a table

insert into stage_pipes_streams_tasks
WITH T AS (
select
SCHEMANAME||'.'||STAGENAME as stagename,
CASE
WHEN parent_property = 'STAGE_LOCATION' THEN LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'["','\''),'"]','\''),' ')
WHEN parent_property = 'STAGE_INTEGRATION' THEN LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'[','\''),']','\''),' ')
WHEN parent_property = 'STAGE_COPY_OPTIONS' THEN 'COPY_OPTIONS = ('||LISTAGG(property||'='||REPLACE(REPLACE(PROPERTY_VALUE,'[',' '),']',' '),', ')||')'
WHEN parent_property = 'STAGE_FILE_FORMAT'  THEN 'FILE_FORMAT = ('|| LISTAGG(property||'='||REPLACE(REPLACE((CASE
                                                                                                            WHEN PROPERTY_VALUE = 'true' THEN PROPERTY_VALUE
                                                                                                            WHEN PROPERTY_VALUE = 'false' THEN PROPERTY_VALUE
                                                                                                            WHEN PROPERTY_VALUE = '0' THEN PROPERTY_VALUE
                                                                                                            WHEN PROPERTY_VALUE = '1' THEN PROPERTY_VALUE
                                                                                                            ELSE concat('\'',PROPERTY_VALUE,'\'') END)
                                                                                                            ,'[',' '),']',' '),', ')||')'
ELSE ' '
END as options
from stage_properties
where PROPERTY_VALUE is not null and PROPERTY_VALUE != ''
group by SCHEMANAME,STAGENAME,stagename,parent_property
order by schemaname,stagename)
select 2,'CREATE STAGE '||STAGENAME||' '||LISTAGG(OPTIONS,' ')||';' from T
group by STAGENAME;

!set quiet=false
!set friendly=false;
!set timing=false;


-- Get the SQL statements of stages , streams and pipes.

select def from stage_pipes_streams_tasks order by ordr;

-- This query will take the grants backup

select 'GRANT '||PRIVILEGE||' ON '||GRANTED_ON||' '||REPLACE(strtok(NAME,'.',1),'_OLD')||'.'||strtok(NAME,'.',2)||'.'||strtok(NAME,'.',3)||' TO '||GRANTEE_NAME||';'
from dbgrants
where granted_on not in ('ACCOUNT') and GRANTEE_NAME not in ('ACCOUNTADMIN','SECURITYADMIN')
and name not like 'SNOWFLAKE_SAMPLE_DATA%' and name like '%&{DBNAME}%';