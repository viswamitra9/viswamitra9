!set variable_substitution=true;
!set friendly=false;
!set timing=false;
!set quiet=true


CREATE OR REPLACE PROCEDURE CHECK_ENABLE_REPLICATION(DBNAME STRING,ACCOUNTNAME STRING)
RETURNS VARCHAR
LANGUAGE JAVASCRIPT
COMMENT = 'return the status of the replication'
EXECUTE AS CALLER
AS
$$
var result = 'SUCCESS';
var s_region;
try
{
snowflake.execute( {sqlText: "show replication accounts;"});
snowflake.createStatement({sqlText: "create or replace temporary table refresh_accounts(snowflake_region,created_on,account_name,description) as select * from table(result_scan(last_query_id()));"}).execute();
var ref_cursor = snowflake.createStatement({sqlText: "select count(*) as result from refresh_accounts where account_name=:1",binds:[ACCOUNTNAME]}).execute();
ref_cursor.next()
if (ref_cursor.getColumnValue(1) == 1)
{
var region_cursor = snowflake.createStatement({sqlText: "select snowflake_region from refresh_accounts where account_name=:1",binds:[ACCOUNTNAME]}).execute();
region_cursor.next()
var accname = region_cursor.getColumnValue(1) + '.' + ACCOUNTNAME
var enable_replication_sql = "alter database "+DBNAME+ " enable replication to accounts "+accname
snowflake.createStatement({sqlText: enable_replication_sql}).execute();
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

CALL CHECK_ENABLE_REPLICATION('&{DBNAME}','&{ACCOUNTNAME}')
