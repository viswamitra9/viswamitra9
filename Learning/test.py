import json
# global variables
connections_list={}
connections_list['connections']={}
connections = {}
datasource_file = 'C:\\Users\\srini\\AppData\\Roaming\\DBeaverData\\workspace6\\General\\.dbeaver\\data-sources-arcesium-new.json'

fileHandle = open('C:\\Users\\srini\\pgpass.conf','r')
for line in fileHandle:
    fields = line.split(':')
    host = fields[0]
    username = fields[3]
    # hold the list of connections
    temp = {}
    connections[host]=temp
    temp['provider'] = 'postgresql'
    temp['driver'] = 'postgres-jdbc'
    temp['name']=host
    temp['save-password']='true'
    temp['show-system-objects']='true'
    temp['read-only']='false'
    temp['configuration']={}
    temp['configuration']['host']=host
    temp['configuration']['port'] = '5432'
    temp['configuration']['user'] = username
    temp['configuration']['database'] = 'audit_archive'
    temp['configuration']['url']='jdbc:postgresql://{}:5432/audit_archive'.format(host)
    temp['configuration']['home']='PostgreSQL Binarie'
    temp['configuration']['auth-model']='postgres_pgpass'
connections_list['connections']=connections
# write to configuration file
fileHandle.close()
with open(datasource_file, 'w') as json_file:
    json.dump(connections_list, json_file)
print(connections_list)