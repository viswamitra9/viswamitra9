!set variable_substitution=true;
!set friendly=false;
!set timing=false;
!set quiet=true

CREATE OR REPLACE PROCEDURE REPLICATE_DATABASE(DBNAME STRING,ACCOUNTNAME STRING)
RETURNS VARCHAR
LANGUAGE JAVASCRIPT
COMMENT = 'return the status of the replication'
EXECUTE AS CALLER
AS
$$
var result = 'SUCCESS';
try
{
snowflake.execute( {sqlText: "show replication accounts;"});
snowflake.createStatement({sqlText: "create or replace temporary table refresh_accounts(snowflake_region,created_on,account_name,description) as select * from table(result_scan(last_query_id()));"}).execute();
var region_cursor = snowflake.createStatement({sqlText: "select snowflake_region from refresh_accounts where account_name=:1",binds:[ACCOUNTNAME]}).execute();
region_cursor.next()
var accname = region_cursor.getColumnValue(1) + '.' + ACCOUNTNAME + '.' + DBNAME
var create_replica_sql = "create database IF NOT EXISTS "+DBNAME+"_new as replica of "+accname
snowflake.execute( {sqlText: create_replica_sql});
var refresh_sql = "alter database "+DBNAME+"_new refresh"
snowflake.execute( {sqlText: refresh_sql});
var exists_db_sql = "select count(*) from information_schema.databases where DATABASE_NAME='"+DBNAME+"_OLD'"
var db_exists_cur = snowflake.createStatement({sqlText: exists_db_sql}).execute();
db_exists_cur.next()
if(db_exists_cur.getColumnValue(1) !=1 )
{
var rename_db_sql = "alter database IF EXISTS "+DBNAME+" rename to "+DBNAME+"_old";
snowflake.execute( {sqlText: rename_db_sql});
}
var create_clone_sql = "create database IF NOT EXISTS "+DBNAME+" clone "+DBNAME+"_new";
snowflake.execute( {sqlText: create_clone_sql});
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
!set output_format=plain
!set timing=false;

CALL REPLICATE_DATABASE('&{DBNAME}','&{ACCOUNTNAME}')
