import psycopg2
import pandas as pd
import datetime
import sqlalchemy as sa
import urllib.parse 
import numpy as np
import manage_postgres_db as mpgdb
import logging
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import string
import random
import json

def termiante_db_users(host,port,user,password):
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
    database = "metabase"
    cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'metabase';")
    conn.commit()
    conn.close()

def drop_metabase_db(host,port,user,password):
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
    database = "metabase"
    try:
        cur.execute("SELECT 1 FROM pg_database WHERE datname='" + database + "'")
    except:
        termiante_db_users(host,port,user,password)
        cur.execute("SELECT 1 FROM pg_database WHERE datname='" + database + "'")
    exists = cur.fetchone()
    if not exists:
        dbexisted = False
        conn.close()
    else:
        # Drop the database
        cur.execute("DROP DATABASE metabase")
        conn.commit()
        conn.close()

def create_db_metabase(host,port,user,password):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': 'postgres'  # Banco de dados padrão para conexão inicial
    }
    database = "metabase"
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
        #cur.execute("CREATE DATABASE " + database)
        #print("New database " + database + " is created")
        
        #print("restoring database with dashboards")

        #restore_database(host,port,user,password)
        dbexisted = False

    else:
        print("The database " + database + " exist, skipping creation...")
        dbexisted = True

    # Fechar conexão
    cur.close()
    conn.close()
    return dbexisted

def create_user_metabase(host,port,user,password):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': 'postgres'  # Banco de dados padrão para conexão inicial
    }
    print("Creating user for metabase")
    conn = psycopg2.connect(**db_params)
    #conn.autocommit = True
    username = "mbbackup"

    print("User: "  + username)
    def generate_random_string(length):
        letters = string.ascii_uppercase + string.digits
        random_string = ''.join(random.choice(letters) for i in range(length))
        return random_string

    def check_User_Exists(username):
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname='" + username + "'")
        exists = cur.fetchone()
        cur.close()
        return exists
    userExists = check_User_Exists(username)
    if userExists:
        print("User exists, skipping creation...")
        print("changing password for user")
        password = generate_random_string(10)
        sql = f"""ALTER Role {username} WITH PASSWORD '{password}';"""
        cur = conn.cursor()
        cur.execute(sql)
        cur.execute("COMMIT")
        cur.close()
        conn.close()
    else:
        # Example usage: generate a random string of length 10
        random_string = generate_random_string(10)
        print(random_string)
        password = random_string
        sql = f"""CREATE Role {username} WITH 
            LOGIN 
            SUPERUSER 
            NOCREATEDB 
            NOCREATEROLE 
            NOINHERIT
            NOREPLICATION 
            CONNECTION LIMIT 1 
            PASSWORD '{password}';"""
        print(sql)
        cur = conn.cursor()
        cur.execute(sql)
        cur.execute("COMMIT")
        cur.close()
        conn.close()
    dict  =  {
        "username": username,
        "password": password
    }
    #print(dict)
    json_obj = json.dumps(dict,indent=8)
    #print(json_obj)
    #write username password to json file for restore later
    with open("mbuser.json", "w") as outfile:
        outfile.write(json_obj)

def restore_database(host,port):
    #read username password from json file
    with open('mbuser.json', 'r') as f:
        data = f.read()
    #parse file
    obj = json.loads(data)
    username = obj['username']
    password = obj['password']

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    postgres_host = host
    postgres_port = port
    postgres_db = "metabase"
    postgres_restore = "{}_restore".format(postgres_db)
    postgres_user = username
    postgres_password = password
    timestr = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = 'backup-{}-{}.dump'.format(timestr, postgres_db)
    filename_compressed = '{}.gz'.format(filename)
    restore_filename = '/usr/src/app/scripts/metabase/mb-datatemplate.dump.gz'
    restore_uncompressed = '/usr/src/app/scripts/metabase/mb-datatemplate.dump'

    #Restoring Database from backup
    ext_file = mpgdb.extract_file(restore_filename)
    logger.info("Extracted to : {}".format(ext_file))
    logger.info("Creating temp database for restore : {}".format(postgres_restore))
    tmp_database = mpgdb.create_db(postgres_host,
                postgres_restore,
                postgres_port,
                postgres_user,
                postgres_password)
    logger.info("Created temp database for restore : {}".format(tmp_database))
    logger.info("Restore starting")
    result = mpgdb.restore_postgres_db(postgres_host,
                postgres_restore,
                postgres_port,
                postgres_user,
                postgres_password,
                restore_uncompressed,
                True)
    #print(result)
    for line in result.splitlines():
        logger.info(line)
    logger.info("Restore complete")
    restored_db_name = postgres_db
    logger.info("Switching restored database with new one : {} > {}".format(
        postgres_restore, restored_db_name
    ))
    mpgdb.swap_restore_new(postgres_host,
                        postgres_restore,
                        restored_db_name,
                        postgres_port,
                        postgres_user,
                        postgres_password)
    logger.info("Database restored and active.")

def restore_databaseold(host,port,user,password):
    dbname="metabase"
    sql_file="metabase/metabase-DB.sql"
    try:
        conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)
        cur = conn.cursor()

        with open(sql_file, 'r') as f:
            sql_commands = f.read()

        cur.execute(sql_commands)
        conn.commit()

        print('Database restored successfully.')
    except (Exception, psycopg2.Error) as error:
        print(f'Error while restoring database: {error}')
    finally:
        if conn:
            cur.close()
            conn.close()

def create_db_n8n(host,port,user,password):
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': 'postgres'  # Banco de dados padrão para conexão inicial
    }
    database = "n8n"
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
        #print("Creating n8n user")
        #cur.execute("CREATE USER n8nuser WITH PASSWORD '" + password + "'")
        #cur.execute("GRANT ALL PRIVILEGES ON DATABASE n8n TO n8nuser;")

    else:
        print("The database " + database + " exist, skipping creation...")

    # Fechar conexão
    cur.close()
    conn.close()    

def back_postgresDB(host,port):
    with open('mbuser.json', 'r') as f:
        data = f.read()
    #parse file
    obj = json.loads(data)
    username = obj['username']
    password = obj['password']
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    postgres_host = host
    postgres_port = port
    postgres_db = "metabase"
    #postgres_restore = "{}_restore".format(postgres_db)
    postgres_user = username
    postgres_password = password
    timestr = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = 'backup-{}-{}.dump'.format(timestr, postgres_db)
    #filename_compressed = '{}.gz'.format(filename)
    #restore_filename = '/usr/src/app/scripts/metabase/mb-datatemplate.dump.gz'
    #restore_uncompressed = '/usr/src/app/scripts/metabase/mb-datatemplate.dump'
    #sql_file=f"metabase/{timestr}-mb-datatemplate.dump.gz"
    BACKUP_PATH = './metabase/'
    local_file_path = '{}{}'.format(BACKUP_PATH, filename)
    f = open(local_file_path, "x")  # create the file
    f.close()

    #Begin Backup 

    logger.info('Backing up {} database to {}'.format(postgres_db, local_file_path))
    result = mpgdb.backup_postgres_db(postgres_host,
                                postgres_db,
                                postgres_port,
                                postgres_user,
                                postgres_password,
                                local_file_path, True)
    for line in result.splitlines():
        logger.info(line)

    logger.info("Backup complete")
    logger.info("Compressing {}".format(local_file_path))
    comp_file = mpgdb.compress_file(local_file_path)
    logger.info("Compressed to : {}".format(comp_file))

def termiante_db_users(host,port,user,password):
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
    database = "metabase"
    cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'metabase';")
    conn.commit()
    conn.close()