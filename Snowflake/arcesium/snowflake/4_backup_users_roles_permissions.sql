!set variable_substitution=true;
!set friendly=false;
!set timing=false;
!set quiet=true

CREATE OR REPLACE PROCEDURE SNAPSHOT_USERS_ROLES_GRANTS()
RETURNS VARCHAR
LANGUAGE JAVASCRIPT
COMMENT = 'Captures the user , roles and privilages'
EXECUTE AS CALLER
AS
$$
var result = "SUCCESS";
try
{
// backup users
snowflake.execute( {sqlText: "show users;"} );
var dbusers_tbl_sql = 'create or replace table dbusers as select *  from table(result_scan(last_query_id()));';
snowflake.execute( {sqlText: dbusers_tbl_sql} );
// backup roles
snowflake.execute( {sqlText: "show roles;"} );
var dbroles_tbl_sql = 'create or replace table DBROLES as select * from table(result_scan(last_query_id()));';
snowflake.execute( {sqlText: dbroles_tbl_sql} );
// create grants table
var dbgrants_tbl_sql = 'CREATE OR replace TABLE dbgrants(created_on timestamp_ltz,privilege varchar,granted_on varchar,NAME varchar,granted_to varchar,grantee_name varchar,grant_option varchar,granted_by varchar);'
snowflake.execute( {sqlText: dbgrants_tbl_sql} );
function role_grants()
{
var obj_rs = snowflake.execute({sqlText: 'SELECT "name" as NAME FROM DBROLES;'});
while(obj_rs.next())
{
snowflake.execute({sqlText: 'show grants to role "' + obj_rs.getColumnValue(1) + '" ;' });
snowflake.execute({sqlText:'insert into dbgrants select * from table(result_scan(last_query_id()));'});
snowflake.execute({sqlText: 'show grants on role "' + obj_rs.getColumnValue(1) + '" ;' });
snowflake.execute({sqlText:'insert into dbgrants select * from table(result_scan(last_query_id()));'});
}
}
function user_grants()
{
var obj_rs = snowflake.execute({sqlText: 'SELECT "name" as NAME FROM DBUSERS;'});
while(obj_rs.next())
{
snowflake.execute({sqlText: 'show grants to user "' + obj_rs.getColumnValue(1) + '" ;' });
snowflake.execute( {sqlText:'insert into dbgrants select *,null,null,null from table(result_scan(last_query_id()));'});
snowflake.execute({sqlText: 'show grants on user "' + obj_rs.getColumnValue(1) + '" ;' });
snowflake.execute({sqlText:'insert into dbgrants select * from table(result_scan(last_query_id()));'});
}
}
role_grants();
user_grants();
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

CALL SNAPSHOT_USERS_ROLES_GRANTS()