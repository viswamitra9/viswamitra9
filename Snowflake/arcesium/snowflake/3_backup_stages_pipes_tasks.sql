!set variable_substitution=true;

!set friendly=false;
!set timing=false;
!set quiet=true


CREATE OR REPLACE PROCEDURE gather_streams_tasks_pipes(dbname STRING)
RETURNS VARCHAR
LANGUAGE JAVASCRIPT
COMMENT = 'Captures the pipes, streams and tasks'
EXECUTE AS CALLER
AS
$$
var result = "SUCCESS";
try
{
snowflake.execute({sqlText: "create or replace table stage_properties (schemaname varchar, stagename varchar, parent_property varchar, property varchar, property_type varchar, property_value varchar, property_default varchar );"});
snowflake.execute({sqlText: "create or replace table stage_pipes_streams_tasks(ordr int,def varchar);"});
var pipe_cursor = snowflake.createStatement({sqlText: "select PIPE_SCHEMA||'.'||PIPE_NAME as pipe_name from information_schema.pipes where pipe_catalog=?",binds:[DBNAME]}).execute();
while(pipe_cursor.next())
{
    var pipe_name = pipe_cursor.getColumnValue(1)
    var pipes_def = snowflake.createStatement({sqlText: "select get_ddl('pipe', :1);",binds:[pipe_name]}).execute();
    pipes_def.next()
    snowflake.createStatement({sqlText: "insert into stage_pipes_streams_tasks values (5, :1 );",binds:[pipes_def.getColumnValue(1)]}).execute();
}
var show_task = snowflake.createStatement({sqlText: "show tasks in database;"}).execute();
var task_cursor = snowflake.createStatement({sqlText: "select * from table(result_scan(last_query_id()));"}).execute();
while(task_cursor.next())
{
    var task_name = task_cursor.getColumnValue(5) + '.' + task_cursor.getColumnValue(2)
    var task_def = snowflake.createStatement({sqlText: "select get_ddl('task', :1);",binds:[task_name]}).execute();
    task_def.next()
    snowflake.createStatement({sqlText: "insert into stage_pipes_streams_tasks values (4, :1 );",binds:[task_def.getColumnValue(1)]}).execute();
}
var show_stream = snowflake.createStatement({sqlText: "show streams in database;"}).execute();
var stream_cursor = snowflake.createStatement({sqlText: "select * from table(result_scan(last_query_id()));"}).execute();
while(stream_cursor.next())
{
    var stream_name = stream_cursor.getColumnValue(4) + '.' + stream_cursor.getColumnValue(2)
    var stream_def  = snowflake.createStatement({sqlText: "select get_ddl('stream', :1);",binds:[stream_name]}).execute();
    stream_def.next()
    snowflake.createStatement({sqlText: "insert into stage_pipes_streams_tasks values (3, :1 );",binds:[stream_def.getColumnValue(1)]}).execute();
}
var show_fformat = snowflake.createStatement({sqlText: "show file formats in database;"}).execute();
var fformat_cursor = snowflake.createStatement({sqlText: "select * from table(result_scan(last_query_id()));"}).execute();
while(fformat_cursor.next())
{
    var fformat_name = fformat_cursor.getColumnValue(4) + '.' + fformat_cursor.getColumnValue(2)
    var fformat_def  = snowflake.createStatement({sqlText: "select get_ddl('file_format', :1);",binds:[fformat_name]}).execute();
    fformat_def.next()
    snowflake.createStatement({sqlText: "insert into stage_pipes_streams_tasks values (1, :1 );",binds:[fformat_def.getColumnValue(1)]}).execute();
}
var stage_cursor = snowflake.createStatement({sqlText: "select STAGE_SCHEMA,STAGE_NAME from information_schema.stages where stage_catalog=?",binds:[DBNAME]}).execute();
while(stage_cursor.next())
{
    var stage_query = 'desc stage '+stage_cursor.getColumnValue(1)+'.'+stage_cursor.getColumnValue(2)+';'
    var stage_def   =  snowflake.execute({sqlText: stage_query})
    stage_def.next()
    var dbstage_tbl_sql = 'insert into stage_properties select \'' + stage_cursor.getColumnValue(1) + '\',\'' + stage_cursor.getColumnValue(2) + '\',* from table(result_scan(last_query_id()));';
    snowflake.execute( {sqlText: dbstage_tbl_sql} );
}
}
catch (err)
{
result = "FAILED: Code: " + err.code + "\n State: " + err.state;result += "\n Message: " + err.message;
result += "\nStack Trace:\n" + err.stackTraceTxt;
}
return result;
$$;

!set quiet=false
!set friendly=false;
!set timing=false;
!set output_format=plain

CALL gather_streams_tasks_pipes('&{DBNAME}');
