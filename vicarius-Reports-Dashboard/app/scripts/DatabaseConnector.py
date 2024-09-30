#Author: Joaldir Rani, Juan Osorio, Jordan Hamblen

import psycopg2
import pandas as pd
import datetime
import sqlalchemy as sa
import urllib
import urllib.parse 
import numpy as np
from psycopg2 import sql
import json

def add_column_to_table(cur, table, columnName):
    for col in columnName:
        #print(f"Check/Adding {col} column to {table} ")
        cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col};")

def removeConstraints(cur, table):
    cur.execute(f"ALTER TABLE {table} DROP CONSTRAINT {table}_pkey;")

def addConstraints(cur, table, columnName):
    cur.execute(f"ALTER TABLE {table} ADD PRIMARY KEY ({columnName});")

def drop_view(cur, view):
    print(f"Dropping view {view}")
    cur.execute(f"DROP VIEW IF EXISTS {view};") 

def drop_table(cur, table):
    print(f"Dropping table {table}")
    cur.execute(f"DROP TABLE IF EXISTS {table};")

def create_table_views(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "incidente" deve ser verificada/criada
    }
    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    #Create Endpoints_Groups_View
    Endpoint_Groups_View = """
        DROP VIEW IF EXISTS endpoint_groups_view;
        CREATE VIEW endpoint_groups_view AS
        SELECT 
            endpoint_id,
            endpoint_hash,
            groupname
        FROM endpointgroups

        UNION ALL

        SELECT 
            endpoint_id,
            endpoint_hash,
            'All Assets'::text AS groupname
        FROM endpoints;
    """
    cur.execute(Endpoint_Groups_View)
    print("The view 'Endpoint_Groups_view' was successfully created")

    #Create Incident_View
    incident_view_query = """
        CREATE OR REPLACE VIEW incident_view AS
        SELECT 
            *, 
            to_timestamp(created_at_milli / 1000.0) AS created_at,
            to_timestamp(updated_at_milli / 1000.0) AS updated_at,
            CASE
                WHEN vulnerability_v3_base_score <= 3.9 THEN 'Low'
                WHEN vulnerability_v3_base_score > 3.9 AND vulnerability_v3_base_score <= 6.9 THEN 'Medium'
                WHEN vulnerability_v3_base_score > 6.9 AND vulnerability_v3_base_score <= 8.9 THEN 'High'
                ELSE 'Critical'
            END AS sensitivity_level_name
        FROM 
            incident;

    """
    mitigation_time_query = """
        CREATE OR REPLACE VIEW mitigation_time_view AS 
        SELECT
            endpoint_id,
            endpoint_hash,
            cve,
            cvss,
            event_type AS detected_event_type,
            event_type AS mitigated_event_type,
            threat_level_id,
            vulnerability_v3_exploitability_level,
            vulnerability_v3_base_score,
            patch_id,
            vulnerability_summary,
            created_at_milli AS mitigated_at_milli,
            mitigated_event_detected_at,
            (incident.created_at_milli - incident.mitigated_event_detected_at) / 1000 / 60 / 60 AS mitigation_time_hours
        FROM
            incident
        WHERE
            event_type = 'MitigatedVulnerability' and mitigated_event_detected_at > 0;
    """
    mitigation_performance_view = """
        CREATE OR REPLACE VIEW mitigation_performance_view AS
        SELECT
            endpoint_id,
            endpoint_hash,
            asset,
            cve,
            CASE WHEN cvss <> 'Error' THEN cvss ELSE NULL END AS severity,
            product AS product_name,
            event_type,
            patch_id,
            to_timestamp(created_at_milli / 1000) AS created_at,
            to_timestamp(updated_at_milli / 1000) AS updated_at
        FROM
            incident
        WHERE
            event_type = 'MitigatedVulnerability'

        UNION ALL

        SELECT
            endpoint_id,
            endpoint_hash,
            asset,
            cve,
            sensitivity_level_name AS severity,
            product_name,
            'DetectedActive' AS event_type,  -- Assuming all rows in activevulnerabilities are active events
            patchid AS patch_id,
            created_at,  -- Assuming create_at is already in datetime format
            updated_at   -- Assuming update_at is already in datetime format
        FROM
            activevulnerabilities;
    """
    mitigation_detected_active_view = """
        CREATE OR REPLACE VIEW mitigation_detection_active AS
        SELECT
            endpoint_id,
            endpoint_hash,
            asset,
            cve,
            CASE WHEN cvss <> 'Error' THEN cvss ELSE NULL END AS severity,
            product AS product_name,
            event_type,
            patch_id,
            to_timestamp(created_at_milli / 1000) AS created_at,
            to_timestamp(updated_at_milli / 1000) AS updated_at
        FROM
            incident
        WHERE
            event_type IN ('MitigatedVulnerability', 'DetectedVulnerability')

        UNION ALL        

        SELECT
            endpoint_id,
            endpoint_hash,
            asset,
            cve,
            sensitivity_level_name AS severity,
            product_name,
            'DetectedActive' AS event_type,  -- Assuming all rows in activevulnerabilities are active events
            patchid AS patch_id,
            created_at,  -- Assuming create_at is already in datetime format
            updated_at   -- Assuming update_at is already in datetime format
        FROM
            activevulnerabilities;
    """
    incidents_group_view = """
        CREATE OR REPLACE VIEW incidents_group_view AS
        Select
            incident.endpoint_id,
            incident.endpoint_hash,
            incident.asset,
            endpointgroups.groupname,
            incident.cve,
            incident.cvss,
            incident.event_type,
            incident.publisher,
            incident.product,
            incident.threat_level_id,
            incident.vulnerability_v3_exploitability_level,
            incident.vulnerability_v3_base_score,
            incident.patch_id,
            incident.vulnerability_summary,
            incident.created_at_milli,
            incident.updated_at_milli,
            incident.create_at_nano,
            incident.h_created_at,
            incident.h_updated_at
        FROM
            incident
        JOIN
            endpointgroups ON incident.endpoint_hash = endpointgroups.endpoint_hash;
    """
    cur.execute(incident_view_query)
    cur.execute(mitigation_time_query)
    cur.execute(mitigation_performance_view)
    cur.execute(incidents_group_view)
    cur.execute(mitigation_detected_active_view)

def repair_table_incidents(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()
    table = "incident"
    columnName = [
        "endpoint_hash text",
        "mitigated_event_detected_at text"
    ]

    add_column_to_table(cur,table,columnName)
    #add_column_to_table(cur,table,columnName1)

    views = ["incident_view", "mitigation_time_view", "mitigation_performance_view", "incidents_group_view"]

    for view in views:
        drop_view(cur, view)
    

    cur.close()
    conn.close()

def repair_table_tasks(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()
    table = "tasks"
    columnName = [
        'endpoint_hash TEXT',
        'patch_name TEXT',
        'patch_file_name TEXT',
        'patch_package_file_name TEXT',
        'patch_release_date BIGINT'     
    ]
    removeConstraints(cur, table)
    addConstraints(cur, table, "updateatnano")
    add_column_to_table(cur,table,columnName)
    
    cur.close()
    conn.close()
    
def repair_table_scriptActivity(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()
    table = "scriptactivity"
    columnName = [
        'reports TEXT'   
    ]
    add_column_to_table(cur,table,columnName)
    
    cur.close()
    conn.close()

def check_create_database(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': 'postgres'  # Banco de dados padrão para conexão inicial
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se o banco de dados "colla" existe
    cur.execute("SELECT 1 FROM pg_database WHERE datname='" + database + "'")
    exists = cur.fetchone()

    if not exists:
        # Criar o banco de dados se não existir
        cur.execute("CREATE DATABASE " + database)
        print("New database " + database + " is created")
    else:
        print("The database " + database + " exist, skipping creation...")

    # Fechar conexão
    cur.close()
    conn.close()

def check_create_table_endpoints(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "endpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpoints')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "endpoints" se não existir
        create_table_query = """
        CREATE TABLE endpoints (
            endpoint_id INTEGER,
            endpoint_name TEXT,
            endpoint_hash TEXT,
            alive BOOLEAN,
            operating_system_name TEXT,
            agent_version TEXT,
            substatus TEXT,
            connectedbyProxy TEXT,
            tokenGenTime TIMESTAMP,
            deployed BIGINT,
            last_connected BIGINT,
            deploymentDate TIMESTAMP,
            LastContactDate TIMESTAMP
        );
        """
        #,
        #    PRIMARY KEY (endpoint_id,tokenGenTime) 
        cur.execute(create_table_query)
        print("The table 'endpoints' was successfully created")


    else:
        print("The table 'endpoints' already exists")



    # Verificar se The table "endpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpoints_status')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "endpoints" se não existir
        create_table_query = """
        CREATE TABLE endpoints_status (
            endpoint_id INTEGER,
            endpoint_name TEXT,
            endpoint_hash TEXT,
            alive BOOLEAN,
            connectedbyProxy TEXT,
            LastContactDate TIMESTAMP,
            runtime TIMESTAMP,
            PRIMARY KEY (endpoint_id,runtime) 
        );
        """
        cur.execute(create_table_query)
        print("The table 'endpoints_status' was successfully created")


    else:
        print("The table 'endpoints_status' already exists")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpointsold(data_string, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()

    try:
        data_lines = data_string.split("\n")
        for line in data_lines:
            try:
                if line.strip():
                    # Split the line into values
                    raw_values = line.split(',')
                    processed_values = [value.strip("'") for value in raw_values]
                    sqlquery = """
                    INSERT INTO endpoints
                    (endpoint_id, endpoint_name, endpoint_hash, alive, operating_system_name, agent_version, substatus, connectedbyProxy, tokenGenTime, deployed, last_connected, deploymentDate, LastContactDate)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    cur.execute(sqlquery, tuple(processed_values ))
            except Exception as e:
                print(f"Error inserting record {line} into table 'endpoints': {e}") 
        ct = datetime.datetime.now()
        print(str(ct) + "The data was inserted into the table 'endpoints' with great success!")
    except psycopg2.Error as e:
        print(str(ct) + "An error occurred when inserting data into the table 'endpoints':", e)

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpoints(json_data, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    print("inserting to endpoints")
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()
    try:
        sql = """
        INSERT INTO endpoints 
        (endpoint_id, endpoint_name, endpoint_hash, alive, operating_system_name, agent_version, substatus, connectedbyProxy, tokenGenTime, deployed, last_connected, deploymentDate, LastContactDate) 
        VALUES (%(endpointId)s, %(endpointName)s, %(endpointHash)s, %(alive)s, %(operatingSystemName)s, %(agentVersion)s, %(substatus)s, %(connectedbyProxy)s, %(tokenGenTime)s, %(deployment_date)s, %(last_connected)s, %(deploymentDate)s, %(LastContact)s)
        """

        for record in json_data:
            #print(json.dumps(record))
            #print(sql)
            cur.execute(sql, record)

        print(str(ct) + f"Records inserted into the table 'endpoints' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'endpoints':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def load_endpoints_LEID(host,port,user,password,database):

    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    # Construct the query
    query = """
        SELECT endpoint_id FROM endpoints 
        ORDER BY endpoint_id DESC
        LIMIT 1;
    """
    cur.execute(query)
    result = cur.fetchone()

    # Return just the endpoint_id (extract the first item from the tuple)
    if result:
        endpoint_id = result[0]
        #print(endpoint_id)
        return endpoint_id
    else:
        print("No result found.")
        return None

def clean_table_endpoints(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "activevulnerabilities" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "activevulnerabilities" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpoints')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "activevulnerabilities"
        cur.execute("DELETE FROM endpoints;")
        print("The table  'endpoints' was dropped with great success")
    else:
        print("The table 'endpoints'  does not exist")

    # Fechar conexão
    cur.close()
    conn.close()

def load_endpoints_to_df(host, port, user, password, database):
    table = "endpoints"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        sql = (f"select * from {table}")
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        #df['create_at_nano'] = df['create_at_nano'].astype(np.int64)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def insert_into_table_endpointsStatusold(data_string, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()

    try:
        data_lines = data_string.split("\n")
        for line in data_lines:
            try:
                if line.strip():
                    # Split the line into values
                    raw_values = line.split(',')
                    processed_values = [value.strip("'") for value in raw_values]
                    sqlquery = """
                    INSERT INTO endpoints_status
                    (endpoint_id, endpoint_name, endpoint_hash, alive, connectedbyProxy, LastContactDate, runtime)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """
                    cur.execute(sqlquery, tuple(processed_values ))
            except Exception as e:
                print(f"Error inserting record {line} into table 'endpoints_Status': {e}") 
        ct = datetime.datetime.now()
        print(str(ct) + "The data was inserted into the table 'endpoints_status' with great success!")
    except psycopg2.Error as e:
        print(str(ct) + "An error occurred when inserting data into the table 'endpoints_status:", e)

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpointsStatus(json_data, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()

    try:
        sql = """
        INSERT INTO endpoints_status 
        (endpoint_id, endpoint_name, endpoint_hash, alive, connectedbyProxy, LastContactDate, runtime) 
        VALUES (%(endpointId)s, %(endpointName)s, %(endpointHash)s, %(alive)s, %(connectedbyProxy)s, %(LastContact)s, %(runtime)s)
        """

        for record in json_data:
            #print(json.dumps(record))
            #print(sql)
            cur.execute(sql, record)

        print(str(ct) + f"Records inserted into the table 'endpoints_status' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'endpoints_status':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

def check_create_table_endpointsAttribute(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "endpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointattributes')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "endpoints" se não existir
        create_table_query = """
        CREATE TABLE endpointattributes (
            endpoint_id INTEGER,
            endpoint_name TEXT,
            endpoint_hash TEXT,
            attribute_name TEXT,
            attribute_value TEXT,
            PRIMARY KEY (endpoint_id,attribute_name,attribute_value) 
        );
        """
        cur.execute(create_table_query)
        print("The table 'endpointattributes' was successfully created")


    else:
        print("The table 'endpointattributes' already exists")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpointsAttribute(json_data, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()

    try:
        sql = """
        INSERT INTO endpointattributes (endpoint_id, endpoint_name, endpoint_hash, attribute_name, attribute_value) VALUES (%(endpointId)s, %(endpointName)s, %(endpointHash)s, %(attrib)s, %(value)s) 
        """
        inserted_records = 0
        for record in json_data:
            #print(record)
            try:
                cur.execute(sql, record)

                inserted_records += 1

            except psycopg2.Error as e:
                print(str(ct) + "An error occurred while inserting data into the table 'endpointattributes':()", e)
                # Printing the last executed query can help in debugging
                print(cur.mogrify(sql, record))
        print(str(ct) + f" - {inserted_records}  'endpointattributes' inserted successfull at {str(ct)}")
    except Exception as e:
        print(str(ct) + "An error occurred while inserting data into the table 'endpointattributes':()", e)

    # Fechar conexão
    cur.close()
    conn.close()

def clean_table_endpointsAttribute(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "activevulnerabilities" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "activevulnerabilities" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointattributes')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "activevulnerabilities"
        cur.execute("DELETE FROM endpointattributes;")
        print("The table  'endpointattributes' was dropped with great success")
    else:
        print("The table 'endpointattributes'  does not exist")

    # Fechar conexão
    cur.close()
    conn.close()

def check_create_table_endpointsImpactFactors(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "endpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointsimpactriskfactors')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "endpoints" se não existir
        create_table_query = """
        CREATE TABLE endpointsimpactriskfactors (
            endpoint_id INTEGER,
            endpoint_name TEXT,
            risk_factor_term TEXT,
            risk_factor_score TEXT,
            PRIMARY KEY (endpoint_id,risk_factor_term) 
        );
        """
        cur.execute(create_table_query)
        print("The table 'endpointsimpactriskfactors' was successfully created")


    else:
        print("The table 'endpointsimpactriskfactors' already exists")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpointsImpactFactors(json_data, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()

    try:
        sql = """
        INSERT INTO endpointsimpactriskfactors (endpoint_id, endpoint_name, risk_factor_term, risk_factor_score) VALUES (%(endpointId)s, %(endpointName)s, %(riskFactorTerm)s, %(riskFactorScore)s) 
        """
        inserted_records = 0
        for record in json_data:
            #print(record)
            try:
                cur.execute(sql, record)

                inserted_records += 1

            except psycopg2.Error as e:
                print(str(ct) + "An error occurred while inserting data into the table 'endpointsimpactriskfactors':()", e)
                # Printing the last executed query can help in debugging
                print(cur.mogrify(sql, record))
        print(str(ct) + f" - {inserted_records}  'endpointsimpactriskfactors' inserted successfull at {str(ct)}")
    except Exception as e:
        print(str(ct) + "An error occurred while inserting data into the table 'endpointsimpactriskfactors':()", e)

    # Fechar conexão
    cur.close()
    conn.close()

def clean_table_endpointsImpactFactors(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "activevulnerabilities" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "activevulnerabilities" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointsimpactriskfactors')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "activevulnerabilities"
        cur.execute("DELETE FROM endpointsimpactriskfactors;")
        print("The table  'endpointsimpactriskfactors' was dropped with great success")
    else:
        print("The table 'endpointsimpactriskfactors'  does not exist")

    # Fechar conexão
    cur.close()
    conn.close()

def check_create_table_endpointsExploitabilityRiskFactors(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "endpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointsexploitabilityriskfactors')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "endpoints" se não existir
        create_table_query = """
        CREATE TABLE endpointsexploitabilityriskfactors (
            endpoint_id INTEGER,
            endpoint_name TEXT,
            risk_factor_term TEXT,
            risk_factor_definition TEXT,
            PRIMARY KEY (endpoint_id,risk_factor_term) 
        );
        """
        cur.execute(create_table_query)
        print("The table 'endpointsexploitabilityriskfactors' was successfully created")


    else:
        print("The table 'endpointsexploitabilityriskfactors' already exists")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpointsExploitabilityRiskFactors(json_data, host, port, user, password, database):
    #print (data_string)
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "endpoints" está localizada
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    cur = conn.cursor()

    try:
        sql = """
        INSERT INTO endpointsexploitabilityriskfactors (endpoint_id, endpoint_name, risk_factor_term, risk_factor_definition) VALUES (%(endpointId)s, %(endpointName)s, %(riskFactorTerm)s, %(riskFactorDescription)s) 
        """
        inserted_records = 0
        for record in json_data:
            #print(record)
            try:
                cur.execute(sql, record)

                inserted_records += 1

            except psycopg2.Error as e:
                print(str(ct) + "An error occurred while inserting data into the table 'endpointsexploitabilityriskfactors':()", e)
                # Printing the last executed query can help in debugging
                print(cur.mogrify(sql, record))
        print(str(ct) + f" - {inserted_records}  'endpointsexploitabilityriskfactors' inserted successfull at {str(ct)}")
    except Exception as e:
        print(str(ct) + "An error occurred while inserting data into the table 'endpointsexploitabilityriskfactors':()", e)

    # Fechar conexão
    cur.close()
    conn.close()

def clean_table_endpointsExploitabilityRiskFactors(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "activevulnerabilities" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "activevulnerabilities" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointsexploitabilityriskfactors')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "activevulnerabilities"
        cur.execute("DELETE FROM endpointsexploitabilityriskfactors;")
        print("The table  'endpointsexploitabilityriskfactors' was dropped with great success")
    else:
        print("The table 'endpointsexploitabilityriskfactors'  does not exist")

    # Fechar conexão
    cur.close()
    conn.close()

def check_create_table_groupendpoints(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Criar The table "groupendpoints" se não existir
    create_table_query = """
    CREATE TABLE IF NOT EXISTS groupendpoints (
        groupname TEXT,
        hostname TEXT,
        endpoint_id BIGINT,
        endpoint_hash TEXT
    );
    """
    #,
    #      PRIMARY KEY (groupname, hostname, endpoint_id, endpoint_hash)
    cur.execute(create_table_query)
    print("The table 'groupendpoints' was created or already exists")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_groupendpoints(data_string, host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" está localizada
    }
    ct = datetime.datetime.now()
    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    try:
        data_lines = data_string.split("\n")
        for line in data_lines:
            if line.strip():
                groupname, assets, assetsids, assethashs = line.split(',')
                assets_list = assets.split('|')
                assetsids_list = assetsids.split('|')
                assethashs_list = assethashs.split('|')

                for asset, asset_id, asset_hash in zip(assets_list, assetsids_list, assethashs_list):
                    query = f"INSERT INTO groupendpoints (groupname, hostname, endpoint_id, endpoint_hash) VALUES (%s, %s, %s, %s);"
                    values = (groupname, asset, asset_id, asset_hash)
                    cur.execute(query, values)

        print(str(ct) + "The data was inserted to table 'groupendpoints' with success")
    except psycopg2.Error as e:
        print(str(ct) + "An error ocurred when inserting data to the table 'groupendpoints':", e)

    # Fechar conexão
    cur.close()
    conn.close()

def clean_table_groupendpoints(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "groupendpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groupendpoints')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "groupendpoints"
        cur.execute("DELETE FROM groupendpoints;")
        #cur.execute("DROP TABLE groupendpoints;")
        print("The table  'groupendpoints' was dropped with great success")
    else:
        print("The table  'groupendpoints'  does not exist")

    #add column to groupendpoints
    table="groupendpoints"
    column = [
        "endpoint_hash text"
    ]
    #column="endpoint_hash"
    add_column_to_table(cur,table,column)
    #cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} TEXT;")
    # Fechar conexão
    cur.close()
    conn.close()

def check_create_table_incident(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "incidente" deve ser verificada/criada
    }
    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "incidente" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'incident')")
    exists = cur.fetchone()[0]

    # TABLES:
    create_table_query = """
    CREATE TABLE incident (
        endpoint_id INTEGER,
        endpoint_hash TEXT,
        asset TEXT,
        cve TEXT,
        cvss TEXT,
        event_type TEXT,
        publisher TEXT,
        product TEXT,
        threat_level_id INTEGER,
        vulnerability_v3_exploitability_level INTEGER,
        vulnerability_v3_base_score FLOAT,
        patch_id INTEGER,
        vulnerability_summary TEXT,
        created_at_milli NUMERIC,
        updated_at_milli NUMERIC,
        create_at_nano NUMERIC,
        h_created_at TIMESTAMP,
        h_updated_at TIMESTAMP,
        mitigated_event_detected_at NUMERIC,
        PRIMARY KEY (create_at_nano)
    )
    """

    if not exists:
        try:
            cur.execute(create_table_query)

            print("The table 'incident' and views associated were created!")
        except Exception as e:
            print (e)
    
    else:
        print("The table  'incident' exist!")

      
    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_incident(json_data, host, port, user, password, database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()
    table = "incident"
    columnNmae = [
        "endpoint_hash text"
    ]
    add_column_to_table(cur,table,columnNmae)
    # Insert data into the "incident" table
    try:
        sql = """
        INSERT INTO incident (endpoint_id, endpoint_hash, asset, cve, cvss, event_type, publisher, product, threat_level_id,vulnerability_v3_exploitability_level, vulnerability_v3_base_score, patch_id, vulnerability_summary, created_at_milli, updated_at_milli, create_at_nano, h_created_at, h_updated_at, mitigated_event_detected_at) VALUES (%(assetId)s, %(assetHash)s, %(asset)s, %(cve)s, %(cvss)s, %(eventType)s, %(publisher)s, %(product)s, 
        %(threatLevelId)s, %(vulnerabilityV3ExploitabilityLevel)s, %(vulnerabilityV3BaseScore)s, %(patchId)s, %(vulnerabilitySummary)s, %(created_at_milli)s, %(updated_at_milli)s, %(create_at_nano)s, %(created_at)s, %(updated_at)s, %(mitigated_event_detected_at)s) 
        """
        inserted_records = 0
        for record in json_data:
            #print(record)
            try:
                cur.execute(sql, record)

                inserted_records += 1

            except psycopg2.Error as e:
                print(str(ct) + "An error occurred while inserting data into the table 'incident':()", e)
                # Printing the last executed query can help in debugging
                print(cur.mogrify(sql, record))
        print(str(ct) + f" - {inserted_records}  'incidents' inserted successfull at {str(ct)}")
        #print("Incidents Inserted")
    except Exception as e:
        print(str(ct) + "An error occurred while inserting data into the table 'incident':()", e)

    # Close connection
    cur.close()
    conn.close()

def load_task_to_df(host, port, user, password, database, maxDate):
    table = "tasks"
    column = "updateatnano"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        sql = (f"select {column} from {table} where {table}.{column} <= {maxDate} Order BY {column} DESC LIMIT 1")
        #print(sql)
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        df['updateatnano'] = df['updateatnano'].astype(np.int64)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def load_tasks_waiting_to_dfold(two_weeks_ago, host, port, user, password, database):
    table = "tasks"
    column = "hcreateat"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        #sql = (f"select * from {table} where {table}.{column} > {two_weeks_ago} and action_status = 'Waiting'")
        sql = (f"Select distinct automation_id from {table} where {column} > '{two_weeks_ago}' and action_status = 'Waiting';")
        print(sql)
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        print(df)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def load_tasks_waiting_to_dfpyscop(two_weeks_ago, host, port, user, password, database):
    table = "tasks"
    column = "hcreateat"
    
    # Create connection
    try:
        connection = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        cursor = connection.cursor()

        # SQL query using parameterized input to avoid SQL injection
        query = sql.SQL("""
            SELECT DISTINCT automation_id 
            FROM {table} 
            WHERE {column} > %s AND action_status = 'Waiting';
        """).format(
            table=sql.Identifier(table),
            column=sql.Identifier(column)
        )

        # Load data into pandas DataFrame
        df = pd.read_sql_query(query.as_string(connection), con=connection, params=[two_weeks_ago])
        
        print(df)
        return df
    
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None
    
    finally:
        if connection:
            cursor.close()
            connection.close()

def load_tasks_waiting_to_df(two_weeks_ago, host, port, user, password, database):
    table = "tasks"
    column = "hcreateat"
    
    # Create connection string
    enpassword = urllib.parse.quote_plus(password)
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    
    # Load table into DataFrame
    try:
        sql = f"""
        SELECT DISTINCT automation_id 
        FROM {table} 
        WHERE {column} > %(two_weeks_ago)s AND action_status = 'Waiting';
        """
        
        # Using parameterized query to avoid SQL injection risks
        params = {'two_weeks_ago': two_weeks_ago}
        df = pd.read_sql_query(sql, con=engine, params=params)
        
        print(df)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def drop_tasks_waiting_to_dfold(two_weeks_ago, host, port, user, password, database):
    table = "tasks"
    column = "hcreateat"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        #sql = (f"select * from {table} where {table}.{column} > {two_weeks_ago} and action_status = 'Waiting'")
        #sql = (f"Select distinct automation_id from {table} where {table}.{column} > {two_weeks_ago} and action_status = 'Waiting';")
        sql = (f"Delete from {table} where {column} > '{two_weeks_ago}' and action_status = 'Waiting';")
        #print(sql)
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        print(df)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def drop_tasks_waiting_to_dfpsycop(two_weeks_ago, host, port, user, password, database):
    table = "tasks"
    column = "hcreateat"
    
    # Create connection
    try:
        connection = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        cursor = connection.cursor()

        # SQL query using parameterized input to avoid SQL injection
        query = sql.SQL("""
            DELETE FROM {table} 
            WHERE {column} > %s AND action_status = 'Waiting';
        """).format(
            table=sql.Identifier(table),
            column=sql.Identifier(column)
        )

        # Execute the DELETE statement
        cursor.execute(query, [two_weeks_ago])
        connection.commit()  # Commit the changes to the database

        print("Records deleted successfully.")
    
    except Exception as e:
        print(f"Error executing DELETE from {table}: {e}")
        return None
    
    finally:
        if connection:
            cursor.close()
            connection.close()

def drop_tasks_waiting_to_df(two_weeks_ago, host, port, user, password, database, aID):
    table = "tasks"
    column = "hcreateat"
    
    # URL encode the password
    enpassword = urllib.parse.quote_plus(password)
    
    # Create connection string using SQLAlchemy
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    
    # Ensure numpy types are cast to native Python types
    aID = int(aID) if isinstance(aID, np.integer) else aID
    
    # Execute DELETE query
    try:
        sql = f"""
        DELETE FROM {table} 
        WHERE {column} > :two_weeks_ago AND automation_id = :aID;
        """
        
        # Using parameterized query to avoid SQL injection risks
        with engine.begin() as connection:
            connection.execute(sa.text(sql), {'two_weeks_ago': two_weeks_ago, 'aID': aID})
        
        print("Records deleted successfully.")
    
    except Exception as e:
        print(f"Error executing DELETE from {table}: {e}")
        return None
 
def load_last_task(host, port, user, password, database):
    table = "tasks"
    column = "updateatnano"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    conn = psycopg2.connect(**db_params)
    with conn.cursor() as cur:
        # Construct the query using psycopg2's SQL template language for safety
        query = sql.SQL("""
            SELECT updateatnano FROM tasks
            ORDER BY tasks.updateatnano DESC
            LIMIT 1;
        """)
    cur.execute(query)
    result = cur.fetchone()
    print(result)
    return result
    
def load_incident_to_df(host, port, user, password, database, maxDate):
    table = "incident"
    column = "create_at_nano"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        sql = (f"select {column} from {table} where {table}.{column} <= {maxDate} Order BY {column} DESC LIMIT 1")
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        df['create_at_nano'] = df['create_at_nano'].astype(np.int64)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def check_create_table_activevulnerabilities(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "activevulnerabilities" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "activevulnerabilities" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'activevulnerabilities')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "activevulnerabilities" se não existir
        create_table_query = """
        CREATE TABLE activevulnerabilities (
            endpoint_id INTEGER, 
            asset TEXT,
            endpoint_hash TEXT,
            product_name TEXT,
            product_raw_entry_name TEXT,
            sensitivity_level_name TEXT,
            cve TEXT,
            vulid INTEGER,
            patchid INTEGER,
            patch_name TEXT,
            patch_release_date TEXT,
            patch_release_timestamp TIMESTAMP,
            created_at TIMESTAMP(6),
            updated_at TIMESTAMP(6),
            link TEXT,
            vulnerability_summary TEXT,
            vulnerability_v3_base_score FLOAT,
            vulnerability_v3_exploitability_level FLOAT,
            typecve TEXT,
            version TEXT,
            subversion TEXT   
            )
        """
        #,
        #    PRIMARY KEY (endpoint_hash,product_name,cve,version)  
        cur.execute(create_table_query)
               
        print("The table 'activevulnerabilities' was created successfully!")
    else:
        #cur.execute("DROP TABLE activevulnerabilities;")
        #cur.execute("DELETE FROM activevulnerabilities;") 
        print("The table 'activevulnerabilities' exists!")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_activevulnerabilities(json_data, host, port, user, password, database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    # Insert data into the "activevulnerabilities" table
    duplicates = []
    
    sql = """
    INSERT INTO activevulnerabilities (endpoint_id, asset, endpoint_hash, product_name, product_raw_entry_name, sensitivity_level_name, cve, vulid, patchid, patch_name, patch_release_date, patch_release_timestamp, created_at, updated_at, link, vulnerability_summary, vulnerability_v3_base_score, vulnerability_v3_exploitability_level, typecve, version, subversion) 
    VALUES (%(endpointId)s, %(asset)s, %(endpointHash)s, %(productName)s, %(productRawEntryName)s, 
    %(sensitivityLevelName)s, %(cve)s, %(vulid)s, %(patchid)s, %(patchName)s, %(patchReleaseDate)s, %(patchReleaseDateTimeStamp)s,
    %(createAt)s, %(updateAt)s, %(link)s, %(vulnerabilitySummary)s, %(vulnerabilityV3BaseScore)s, 
    %(vulnerabilityV3ExploitabilityLevel)s, %(typecve)s, %(version)s, %(subversion)s)
    """

    for record in json_data:
        #print (record)
        try:
            cur.execute(sql, record)
            
        except psycopg2.Error as e:
            if "duplicate key value violates unique constraint" in str(e):
                duplicates.append(record)
            else:
                print (sql, record)
                print(str(ct) + "An error occurred while inserting data into the table 'activevulnerabilities':", e)
                # Printing the last executed query can help in debugging
                print(cur.mogrify(sql, record))
    print(f"{len (json_data)} records inserted into'activevulnerabilities' successfully!" + str(ct))
    

    # Close connection
    print("Duplicate values not inserted: " + str(len(duplicates)))
    cur.close()
    conn.close()

def clean_table_activevulnerabilities(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "activevulnerabilities" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "activevulnerabilities" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'activevulnerabilities')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "activevulnerabilities"
        cur.execute("DELETE FROM activevulnerabilities;")
        print("The table 'activevulnerabilities' was dropped with success")
    else:
        print("The table 'activevulnerabilities'  does not exist")

    # Fechar conexão
    cur.close()
    conn.close()

def check_create_table_tasks(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'tasks')")
    exists = cur.fetchone()[0]

    if not exists:
        create_table_query = """
        CREATE TABLE tasks (
            id Serial,
            endpoint_id INTEGER,
            task_id INTEGER,
            automation_id INTEGER,
            automation_name TEXT,
            endpoint_hash TEXT,
            asset TEXT,
            task_type TEXT,
            publisher_name TEXT,
            path_or_product TEXT,
            path_or_product_desc TEXT,
            patch_name TEXT,
            patch_file_name TEXT,
            patch_package_file_name TEXT,
            patch_release_date Bigint,
            action_status TEXT,
            message_status TEXT,
            username TEXT,
            team TEXT,
            run_sequence TEXT,
            asset_status Text,
            createatnano BIGINT,
            updateatnano BIGINT,
            hcreateat TIMESTAMP,
            hupdateat TIMESTAMP,
            created_at BIGINT,
            updated_at BIGINT,
            PRIMARY Key (updateatnano)
        );
        """
        cur.execute(create_table_query)
        print("The table 'tasks' was created successfully!")
    else:
        repair_table_tasks(host, port, user, password, database)
        print("The table 'tasks' already exists!")

    cur.close()
    conn.close()

def insert_into_table_tasksold(json_data, host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()
    table = "tasks"
    columnName = [
        'endpoint_hash TEXT',
        'patch_name TEXT',
        'patch_file_name TEXT',
        'patch_package_file_name TEXT',
        'patch_release_date BIGINT'     
    ]
    add_column_to_table(cur,table,columnName)

    try:
        sqlquery = """
        INSERT INTO tasks (endpoint_id, task_id, automation_id, automation_name, endpoint_hash, asset, task_type, publisher_name, path_or_product, path_or_product_desc, patch_name, patch_file_name, patch_package_file_name, patch_release_date, action_status, message_status, username, team, run_sequence, asset_status, createatnano, updateatnano, hcreateat, hupdateat, created_at, updated_at)
        VALUES (%(endpointId)s, %(taskid)s, %(automationId)s, %(automationName)s, %(assetHash)s, %(asset)s, %(taskType)s, %(publisherName)s, %(pathproduct)s, %(pathproductdesc)s, %(patchName)s, %(patchFileName)s, %(patchPackageFileName)s, %(patchReleaseDate)s, %(actionStatus)s, %(messageStatus)s, %(username)s, %(orgTeam)s, %(runSequence)s, %(assetStatus)s, %(createAtNano)s, %(updateAtNano)s, %(hcreateAt)s, %(hupdateAt)s, %(createAt)s, %(updateAt)s)        """
        for record in json_data:
            #print(record['assetHash'])
            #print(record)
            #print(sqlquery)
            cur.execute(sqlquery, record)
            
        print(str(ct) + "The data was inserted into the table 'tasks' with great success!")

    except psycopg2.Error as e:
        #print(ct)
        print(str(ct) + "An error occurred when inserting data into the table 'tasks':", e)


    cur.close()
    conn.close()

def insert_into_table_tasks(json_data, host, port, user, password, database):
    # DB connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    
    try:
        # Connect to PostgreSQL using a context manager
        with psycopg2.connect(**db_params) as conn:
            # Disable autocommit for transaction management
            conn.autocommit = False
            
            # Create cursor within the connection context
            with conn.cursor() as cur:
                table = "tasks"
                
                # Columns to add dynamically if not already present
                columnName = [
                    'endpoint_hash TEXT',
                    'patch_name TEXT',
                    'patch_file_name TEXT',
                    'patch_package_file_name TEXT',
                    'patch_release_date BIGINT'
                ]
                
                # Dynamically add columns (assuming add_column_to_table handles this safely)
                add_column_to_table(cur, table, columnName)

                # Define the SQL query with parameterized placeholders
                sql_query = """
                    INSERT INTO tasks (
                        endpoint_id, task_id, automation_id, automation_name, 
                        endpoint_hash, asset, task_type, publisher_name, 
                        path_or_product, path_or_product_desc, patch_name, 
                        patch_file_name, patch_package_file_name, patch_release_date, 
                        action_status, message_status, username, team, run_sequence, 
                        asset_status, createatnano, updateatnano, hcreateat, 
                        hupdateat, created_at, updated_at
                    ) 
                    VALUES (
                        %(endpointId)s, %(taskid)s, %(automationId)s, %(automationName)s, 
                        %(assetHash)s, %(asset)s, %(taskType)s, %(publisherName)s, 
                        %(pathproduct)s, %(pathproductdesc)s, %(patchName)s, 
                        %(patchFileName)s, %(patchPackageFileName)s, %(patchReleaseDate)s, 
                        %(actionStatus)s, %(messageStatus)s, %(username)s, %(orgTeam)s, 
                        %(runSequence)s, %(assetStatus)s, %(createAtNano)s, %(updateAtNano)s, 
                        %(hcreateAt)s, %(hupdateAt)s, %(createAt)s, %(updateAt)s
                    )
                """
                
                # Insert records using executemany for batch processing
                cur.executemany(sql_query, json_data)
                
                # Commit the transaction
                conn.commit()
                
                print(f"{ct} The data was inserted into the 'tasks' table successfully!")
    
    except psycopg2.Error as e:
        # Rollback the transaction if an error occurs
        if conn:
            conn.rollback()
        print(f"{ct} An error occurred when inserting data into the 'tasks' table: {e}")
    except Exception as e:
        print(f"{ct} General error: {e}")

def update_table_tasks(json_data, host, port, user, password, database):
    # DB connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    
    try:
        # Connect to PostgreSQL using a context manager
        with psycopg2.connect(**db_params) as conn:
            # Disable autocommit for transaction management
            conn.autocommit = False
            
            # Create cursor within the connection context
            with conn.cursor() as cur:
                table = "tasks"
                
                # Define the SQL UPDATE query with parameterized placeholders
                sql_query = """
                    UPDATE tasks
                    SET
                        automation_name = %(automationName)s,
                        endpoint_hash = %(assetHash)s,
                        asset = %(asset)s,
                        task_type = %(taskType)s,
                        publisher_name = %(publisherName)s,
                        path_or_product = %(pathproduct)s,
                        path_or_product_desc = %(pathproductdesc)s,
                        patch_name = %(patchName)s,
                        patch_file_name = %(patchFileName)s,
                        patch_package_file_name = %(patchPackageFileName)s,
                        patch_release_date = %(patchReleaseDate)s,
                        action_status = %(actionStatus)s,
                        message_status = %(messageStatus)s,
                        username = %(username)s,
                        team = %(orgTeam)s,
                        run_sequence = %(runSequence)s,
                        asset_status = %(assetStatus)s,
                        updateatnano = %(updateAtNano)s,
                        hupdateat = %(hupdateAt)s,
                        updated_at = %(updateAt)s
                    WHERE createatnano = %(createAtNano)s
                """
                
                # Update records using executemany for batch processing
                cur.executemany(sql_query, json_data)
                
                # Commit the transaction
                conn.commit()
                
                print(f"{ct} The data was updated in the 'tasks' table successfully!")
    
    except psycopg2.Error as e:
        # Rollback the transaction if an error occurs
        if conn:
            conn.rollback()
        print(f"{ct} An error occurred when updating data in the 'tasks' table: {e}")
    except Exception as e:
        print(f"{ct} General error: {e}")

def clean_table_tasks(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'tasks')")
    exists = cur.fetchone()[0]

    if exists:
        cur.execute("DELETE FROM tasks;")
        print("The table 'tasks' was dropped with great success")
    else:
        print("The table 'tasks'  does not exist")
    table = "tasks"
    columnName = [
        'endpoint_hash TEXT',
        'patch_name TEXT',
        'patch_file_name TEXT',
        'patch_package_file_name TEXT',
        'patch_release_date BIGINT'     
    ]
    add_column_to_table(cur,table,columnName)

    cur.close()
    conn.close()

def check_create_table_assetspatchs(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'assetspatchs')")
    exists = cur.fetchone()[0]

    if not exists:
        create_table_query = """
        CREATE TABLE assetspatchs (
            asset_id SERIAL PRIMARY KEY,
            endpoint_hash TEXT,
            asset TEXT,
            so TEXT,
            patch_name TEXT,
            patchid NUMERIC,
            severity_level TEXT,
            severity_name TEXT,
            description TEXT,
            patch_release_date TIMESTAMP,
            patch_id BIGINT
        );
        """
        cur.execute(create_table_query)
        print("The table 'assetspatchs' was created successfully!")
    else:
        print("The table 'assetspatchs' already exists!")

    cur.close()
    conn.close()

def insert_into_table_assetspatchs(json_data, host, port, user, password, database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    # Insert data into the "assetspatchs" table
    try:
        sql = """
        INSERT INTO assetspatchs 
        (endpoint_hash, asset, patch_name, patchid, severity_level, severity_name, description, patch_release_date, patch_id) 
        VALUES (%(endpointHash)s, %(endpointName)s, %(PatchName)s, %(patchId)s, %(sensitivityLevelRanks)s, %(sensitivityLevelNames)s, %(patchDescriptions)s, %(patchreleasedate)s, %(externalReferenceSourceIds)s)
        """
        nullSQL = """
        INSERT INTO assetspatchs 
        (endpoint_hash, asset, patch_name, patchid, severity_level, severity_name, description, patch_release_date, patch_id) 
        VALUES (%(endpointHash)s, %(endpointName)s, %(PatchName)s, %(patchId)s, %(sensitivityLevelRanks)s, %(sensitivityLevelNames)s, %(patchDescriptions)s, (NULL), %(externalReferenceSourceIds)s)
        """
        for record in json_data:
            if record['patchreleasedate'] is None:
                print("NULL PATCH RELASE DATE INSERTED")
                cur.execute(nullSQL, record)
            else:
                cur.execute(sql, record)

        print(str(ct) + f"Records inserted into the table 'assetspatchs' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'assetspatchs':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def clean_table_assetspatchs(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'assetspatchs')")
    exists = cur.fetchone()[0]

    if exists:
        cur.execute("DELETE FROM assetspatchs;")
        print(str(ct) + "The table 'assetspatchs' was dropped with great success")
    else:
        print(str(ct) + "The table 'assetspatchs'  does not exist")
    table = "assetspatchs"
    columnName = [
        "endpoint_hash Text"
    ]
    add_column_to_table(cur,table,columnName)
    cur.close()
    conn.close()

def check_create_table_apps(host,port,user,password,database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'apps')")
    exists = cur.fetchone()[0]

    if not exists:
        create_table_query = """
        CREATE TABLE apps (
            appIndex SERIAL PRIMARY KEY,
            appName TEXT,
            ProductID TEXT,
            publisherHash TEXT,
            riskLevel TEXT,
            riskScore NUMERIC,
            vulRiskFactor TEXT,
            predictedAttackSurface TEXT,
            patch TEXT,
            vulExploit TEXT,
            ProductUpdatedAt TIMESTAMP
        );
        """
        cur.execute(create_table_query)
        print("The table 'apps' was created successfully!")
    else:
        print("The table 'apps' already exists!")
    cur.close()
    conn.close()

def insert_into_table_apps(json_data,host,port,user,password,database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    # Insert data into the "assetspatchs" table
    try:
        sql = """
        INSERT INTO apps 
        (appName, productID, publisherHash, riskLevel, riskScore, vulRiskFactor, predictedAttackSurface, patch, vulExploit, ProductUpdatedAt) 
        VALUES (%(appName)s, %(productID)s, %(publisherHash)s, %(riskLevel)s, %(riskScore)s, %(vulRiskFactor)s, %(predictedAttackSurface)s, %(patch)s, %(vulExploit)s, %(ProductUpdatedAt)s)
        """

        for record in json_data:
            #print(json.dumps(record))
            #print(sql)
            cur.execute(sql, record)

        print(str(ct) + f"Records inserted into the table 'apps' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'apps':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def clean_table_apps(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'apps')")
    exists = cur.fetchone()[0]

    if exists:
        cur.execute("DELETE FROM apps;")
        print(str(ct) + "The table 'apps' was dropped with great success")
    else:
        print(str(ct) + "The table 'apps'  does not exist")

    cur.close()
    conn.close()

def check_create_table_scriptActivity(host,port,user,password,database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'scriptactivity')")
    exists = cur.fetchone()[0]

    if not exists:
        create_table_query = """
        CREATE TABLE scriptactivity (
            id SERIAL PRIMARY KEY,
            startTime TIMESTAMP,
            endTime TIMESTAMP,
            errors TEXT,
            reports TEXT

        );
        """
        cur.execute(create_table_query)
        print("The table 'scriptactivity' was created successfully!")
    else:
        print("The table 'scriptactivity' already exists!")
        repair_table_scriptActivity(host, port, user, password, database)
    cur.close()
    conn.close()

def insert_into_table_scriptActivity(json_data,host,port,user,password,database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    # Insert data into the "assetspatchs" table
    try:
        sql = """
        INSERT INTO scriptactivity 
        (starttime,endtime,errors,reports) 
        VALUES (%(starttime)s, %(endtime)s, %(errors)s, %(reports)s)
        """


        #print(json.dumps(json_data))
        #print(sql)
        cur.execute(sql, json_data)

        print(str(ct) + f"Records inserted into the table 'scriptactivity' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'scriptactivity':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql))

    # Close connection
    cur.close()
    conn.close()

def print_first_row(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Selecionar a primeira linha dThe table "activevulnerabilities"
    cur.execute("SELECT MAX(created_at_nano) FROM incident LIMIT 1")
    first_row = cur.fetchone()

    if first_row:
        print(first_row)
    else:
        print("The table 'activevulnerabilities' está vazia.")

    # Fechar conexão
    cur.close()
    conn.close()

def display_all_entries(host, port, user, password, database,table):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    try:
        # Consultar todos os registros dThe table "groupendpoints"
        cur.execute("SELECT * FROM "+table+";")
        rows = cur.fetchall()

        # Exibir os registros
        if rows:
            print("Registros encontrados nThe table 'endpointgroups':")
            for row in rows:
                print(row)
                #groupname, hostname, hash_value = row
                #print(f"Groupname: {groupname}, Hostname: {hostname}, Hash: {hash_value}")
        else:
            print("Nenhum registro encontrado nThe table 'endpointgroups'.")

    except psycopg2.Error as e:
        print("Ocorreu um erro ao exibir os registros dThe table 'endpointgroups':", e)

    # Fechar conexão
    cur.close()
    conn.close()

def load_table_to_df(host, port, user, password, database, table):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Create connection string
    # Load table into DataFrame
    try:
        df = pd.read_sql(f"SELECT * FROM {table}",con=engine)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None
    
def check_create_table_Events(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "incidente" deve ser verificada/criada
    }
    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "incidente" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'events')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "incidente" se não existir
        create_table_query = """
        CREATE TABLE events (
            endpoint_id INTEGER,
            asset TEXT,
            event_type TEXT,
            publisher TEXT,
            product TEXT,
            created_at_milli NUMERIC,
            updated_at_milli NUMERIC,
            create_at_nano NUMERIC,
            h_created_at TIMESTAMP,
            h_updated_at TIMESTAMP,
            PRIMARY KEY (create_at_nano)
        )
        """
        try:
            cur.execute(create_table_query)
            print("The table 'events' was created!")

        except Exception as e:
            print (e)


    else:
        print("The table  'events' exist!")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_events(json_data, host, port, user, password, database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    # Insert data into the "incident" table
    try:
        sql = """
        INSERT INTO events (endpoint_id, asset, event_type, publisher, product, created_at_milli, updated_at_milli, create_at_nano, h_created_at, h_updated_at) VALUES (%(assetId)s, %(asset)s, %(eventType)s, %(publisher)s, %(product)s, 
        %(created_at_milli)s, %(updated_at_milli)s, %(create_at_nano)s, %(created_at)s, %(updated_at)s)
        """

        for record in json_data:
            #print(record)
            cur.execute(sql, record)

        print(str(ct) + "The data was inserted to the table 'events' quite successfully!")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'events':()", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def load_Event_to_df(host, port, user, password, database, minDate):
    table = "event"
    column = "create_at_nano"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        sql = (f"select {column} from {table} where {table}.{column} > {minDate} Order BY {column} DESC LIMIT 1")
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        df['create_at_nano'] = df['create_at_nano'].astype(np.int64)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def check_create_table_xProtectEvents(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "incidente" deve ser verificada/criada
    }
    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "incidente" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'xprotectevents')")
    exists = cur.fetchone()[0]

    if not exists:
        # Criar The table "incidente" se não existir
        create_table_query = """
        CREATE TABLE xprotectevents (
            endpoint_id INTEGER,
            asset TEXT,
            event_type TEXT,
            victim_process TEXT,
            src_parent_process TEXT,
            src_process TEXT,
            src_user TEXT,
            status Text,
            created_at_milli NUMERIC,
            updated_at_milli NUMERIC,
            create_at_nano NUMERIC,
            h_created_at TIMESTAMP,
            h_updated_at TIMESTAMP,
            PRIMARY KEY (create_at_nano)
        )
        """
        try:
            cur.execute(create_table_query)
            print("The table 'xprotectevents' was created!")

        except Exception as e:
            print (e)


    else:
        print("The table  'xprotectevents' exist!")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_xProtectEvents(json_data, host, port, user, password, database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    # Insert data into the "incident" table
    try:
        sql = """
        INSERT INTO xprotectevents (endpoint_id, asset, event_type, victim_process, src_parent_process, src_process, src_user, status, created_at_milli, updated_at_milli, create_at_nano, h_created_at, h_updated_at) VALUES (%(assetId)s, %(asset)s, %(eventType)s, %(victimprocess)s, %(srcparentprocessName)s, 
        %(srcprocessName)s,%(srcuser)s,%(status)s,%(created_at_milli)s, %(updated_at_milli)s, %(create_at_nano)s, %(created_at)s, %(updated_at)s)
        """

        for record in json_data:
            #print(record)
            cur.execute(sql, record)

        print(str(ct) + "The data was inserted to the table 'xprotectevents' quite successfully!")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'xprotectevents':()", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def load_xProtectEvents_to_df(host, port, user, password, database, minDate):
    table = "xprotectevents"
    column = "create_at_nano"
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    enpassword = urllib.parse.quote_plus(password)
    # Create connection string
    engine = sa.create_engine(f"postgresql://{user}:{enpassword}@{host}:{port}/{database}")
    # Load table into DataFrame
    try:
        sql = (f"select {column} from {table} where {table}.{column} > {minDate} Order BY {column} DESC LIMIT 1")
        #df = pd.read_sql_query(sql,con=engine,dtype={{column}:np.int64})
        df = pd.read_sql_query(sql,con=engine)
        df['create_at_nano'] = df['create_at_nano'].astype(np.int64)
        return df
    except Exception as e:
        print(f"Error loading table {table} into DataFrame: {e}")
        return None

def drop_all_tables(host, port, user, password, database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "incidente" deve ser verificada/criada
    } 

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()
    views = ["endpoint_groups_view","incident_view", "mitigation_time_view", "mitigation_performance_view", "incidents_group_view","mitigation_detection_active"]
    for view in views:
        drop_view(cur, view)
    tables = ['incident','activevulnerabilities','tasks','assetspatchs','apps','endpoints','endpointgroups','xprotectevents','events']
    for table in tables:
        drop_table(cur, table)
    
    cur.close()
    conn.close()

def get_cve_count_by_endpoint_hash(host, port, user, password, database, specific_endpoint_hash=None):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    try:
        # Check if the table "activevulnerabilities" exists
        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'activevulnerabilities')")
        exists = cur.fetchone()[0]

        if not exists:
            print("The table 'activevulnerabilities' does not exist!")
            return None

        # Query to get count of rows by endpoint_hash
        if specific_endpoint_hash:
            count_query = """
            SELECT COUNT(*) as row_count
            FROM activevulnerabilities
            WHERE endpoint_hash = %s
            """
            cur.execute(count_query, (specific_endpoint_hash,))
            result = cur.fetchone()
            return result[0] if result else 0
        else:
            count_query = """
            SELECT endpoint_hash, COUNT(*) as row_count
            FROM activevulnerabilities
            GROUP BY endpoint_hash
            """
            cur.execute(count_query)
            results = cur.fetchall()
            return {row[0]: row[1] for row in results}

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    finally:
        # Close connection
        cur.close()
        conn.close()

def delete_activevulnerabilities_by_endpoint_hash(host, port, user, password, database, endpoint_hash):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    try:
        # Check if the table "activevulnerabilities" exists
        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'activevulnerabilities')")
        exists = cur.fetchone()[0]

        if not exists:
            print("The table 'activevulnerabilities' does not exist!")
            return None

        # Delete query
        delete_query = """
        DELETE FROM activevulnerabilities
        WHERE endpoint_hash = %s
        """
        
        cur.execute(delete_query, (endpoint_hash,))
        
        # Get the number of deleted rows
        deleted_count = cur.rowcount
        
        print(f"Successfully deleted {deleted_count} records with endpoint_hash: {endpoint_hash}")
        
        return deleted_count

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    finally:
        # Close connection
        cur.close()
        conn.close()

def get_patch_count_by_endpoint_hash(host, port, user, password, database, specific_endpoint_hash=None):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    try:
        # Check if the table "assetspatchs" exists
        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'assetspatchs')")
        exists = cur.fetchone()[0]

        if not exists:
            print("The table 'assetspatchs' does not exist!")
            return None

        # Query to get count of rows by endpoint_hash
        if specific_endpoint_hash:
            count_query = """
            SELECT COUNT(*) as row_count
            FROM assetspatchs
            WHERE endpoint_hash = %s
            """
            cur.execute(count_query, (specific_endpoint_hash,))
            result = cur.fetchone()
            return result[0] if result else 0
        else:
            count_query = """
            SELECT endpoint_hash, COUNT(*) as row_count
            FROM assetspatchs
            GROUP BY endpoint_hash
            """
            cur.execute(count_query)
            results = cur.fetchall()
            return {row[0]: row[1] for row in results}

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    finally:
        # Close connection
        cur.close()
        conn.close()

def delete_assetpatchs_by_endpoint_hash(host, port, user, password, database, endpoint_hash):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Create cursor
    cur = conn.cursor()

    try:
        # Check if the table "assetspatchs" exists
        cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'assetspatchs')")
        exists = cur.fetchone()[0]

        if not exists:
            print("The table 'assetspatchs' does not exist!")
            return None

        # Delete query
        delete_query = """
        DELETE FROM assetspatchs
        WHERE endpoint_hash = %s
        """
        
        cur.execute(delete_query, (endpoint_hash,))
        
        # Get the number of deleted rows
        deleted_count = cur.rowcount
        
        print(f"Successfully deleted {deleted_count} records with endpoint_hash: {endpoint_hash}")
        
        return deleted_count

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    finally:
        # Close connection
        cur.close()
        conn.close()

def check_create_table_groups(host,port,user,password,database):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groups')")
    exists = cur.fetchone()[0]

    if not exists:
        create_table_query = """
        CREATE TABLE groups (
            groupIndex SERIAL PRIMARY KEY,
            groupId INTEGER,
            groupName TEXT,
            groupTeamName TEXT,
            groupTeamId INTEGER,
            groupassetcount INTEGER
        );
        """
        cur.execute(create_table_query)
        print("The table 'groups' was created successfully!")
    else:
        print("The table 'groups' already exists!")
    cur.close()
    conn.close()

def insert_into_table_groups(json_data,host,port,user,password,database):
    #print(json_data)
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    # Insert data into the "assetspatchs" table
    try:
        sql = """
        INSERT INTO groups 
        (groupid, groupname, groupteamname, groupteamid, groupassetcount) 
        VALUES (%(groupId)s, %(groupName)s, %(groupTeamName)s, %(groupTeamId)s, %(groupAssetCount)s);
        """

        for record in json_data:
            #print(json.dumps(record))
            #print(sql)
            cur.execute(sql, record)

        print(str(ct) + f"Records inserted into the table 'groups' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'groups':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def check_create_table_endpointgroups(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" deve ser verificada/criada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Criar The table "groupendpoints" se não existir
    create_table_query = """
    CREATE TABLE IF NOT EXISTS endpointgroups (
        groupId INT,
        groupname TEXT,
        endpointName TEXT,
        endpoint_id BIGINT,
        endpoint_hash TEXT
    );
    """
    #,
    #      PRIMARY KEY (groupname, hostname, endpoint_id, endpoint_hash)
    cur.execute(create_table_query)
    print("The table 'endpointgroups' was created or already exists")

    # Fechar conexão
    cur.close()
    conn.close()

def insert_into_table_endpointgroups(json_data, host, port, user, password, database):
    # Connection parameters
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }
    ct = datetime.datetime.now()
    # Connect to PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    # Insert data into the "assetspatchs" table
    try:
        sql = """
        INSERT INTO endpointgroups 
        (groupid, groupname, endpointName, endpoint_id, endpoint_hash) 
        VALUES (%(groupId)s, %(groupName)s, %(endpointName)s, %(endpointId)s, %(endpointHash)s)
        """

        for record in json_data:
            #print(json.dumps(record))
            #print(sql)
            cur.execute(sql, record)

        print(str(ct) + f"Records inserted into the table 'endpointgroups' successfully:  {len (json_data)}")

    except psycopg2.Error as e:
        print(str(ct) + "An error occurred while inserting data into the table 'endpointgroups':", e)
        # Printing the last executed query can help in debugging
        print(cur.mogrify(sql, record))

    # Close connection
    cur.close()
    conn.close()

def clean_table_endpointgroups(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "groupendpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'endpointgroups')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "groupendpoints"
        cur.execute("DELETE FROM endpointgroups;")
        #cur.execute("DROP TABLE groupendpoints;")
        print("The table  'endpointgroups' was dropped with great success")
    else:
        print("The table  'endpointgroups'  does not exist")

    #add column to groupendpoints
    #table="endpointgroups"
    #column = [
    #    "endpoint_hash text"
    #]
    #column="endpoint_hash"
    #add_column_to_table(cur,table,column)
    #cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} TEXT;")
    # Fechar conexão
    cur.close()
    conn.close()

def clean_table_groups(host, port, user, password, database):
    # Parâmetros de conexão
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database  # Nome do banco de dados onde The table "groupendpoints" está localizada
    }

    # Conectar ao PostgreSQL
    conn = psycopg2.connect(**db_params)
    conn.autocommit = True

    # Criar cursor
    cur = conn.cursor()

    # Verificar se The table "groupendpoints" existe
    cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groups')")
    exists = cur.fetchone()[0]

    if exists:
        # Limpar The table "groupendpoints"
        cur.execute("DELETE FROM groups;")
        #cur.execute("DROP TABLE groupendpoints;")
        print("The table  'groups' was dropped with great success")
    else:
        print("The table  'groups'  does not exist")

    #add column to groupendpoints
    #table="endpointgroups"
    #column = [
    #    "endpoint_hash text"
    #]
    #column="endpoint_hash"
    #add_column_to_table(cur,table,column)
    #cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} TEXT;")
    # Fechar conexão
    cur.close()
    conn.close()
