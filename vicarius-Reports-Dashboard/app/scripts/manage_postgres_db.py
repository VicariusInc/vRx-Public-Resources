#!/usr/bin/python3
import argparse
import logging
import subprocess
import os
import tempfile
from tempfile import mkstemp
import gzip
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import datetime

from shutil import move

BACKUP_PATH = './backup/'


def backup_postgres_db(host, database_name, port, user, password, dest_file, verbose):
    """
    Backup postgres db to a file.
    """
    if verbose:
        try:
            process = subprocess.Popen(
                ['pg_dump',
                 '--dbname=postgresql://{}:{}@{}:{}/{}'.format(user, password, host, port, database_name),
                 '-Fc',
                 '-f', dest_file,
                 '-v'],
                stdout=subprocess.PIPE
            )
            output = process.communicate()[0]
            if int(process.returncode) != 0:
                print('Command failed. Return code : {}'.format(process.returncode))
                exit(1)
            return output
        except Exception as e:
            print(e)
            exit(1)
    else:

        try:
            process = subprocess.Popen(
                ['pg_dump',
                 '--dbname=postgresql://{}:{}@{}:{}/{}'.format(user, password, host, port, database_name),
                 '-f', dest_file],
                stdout=subprocess.PIPE
            )
            output = process.communicate()[0]
            if process.returncode != 0:
                print('Command failed. Return code : {}'.format(process.returncode))
                exit(1)
            return output
        except Exception as e:
            print(e)
            exit(1)

def compress_file(src_file):
    compressed_file = "{}.gz".format(str(src_file))
    with open(src_file, 'rb') as f_in:
        with gzip.open(compressed_file, 'wb') as f_out:
            for line in f_in:
                f_out.write(line)
    return compressed_file

def extract_file(src_file):
    extracted_file, extension = os.path.splitext(src_file)
    #print(extracted_file)
    with gzip.open(src_file, 'rb') as f_in:
        with open(extracted_file, 'wb') as f_out:
            for line in f_in:
                f_out.write(line)
    return extracted_file

def remove_faulty_statement_from_dump(src_file):

    temp_file, _ = tempfile.mkstemp()

    try:
        with open(temp_file, 'w+') as dump_temp:
            process = subprocess.Popen(
                ['pg_restore',
                 '-l'
                 '-v',
                 src_file],
                stdout=subprocess.PIPE
            )
            output = subprocess.check_output(('grep','-v','"EXTENSION - plpgsql"'), stdin=process.stdout)
            process.wait()
            if int(process.returncode) != 0:
                print('Command failed. Return code : {}'.format(process.returncode))
                exit(1)

            os.remove(src_file)
            with open(src_file, 'w+') as cleaned_dump:
                subprocess.call(
                    ['pg_restore',
                     '-L'],
                    stdin=output,
                    stdout=cleaned_dump
                )

    except Exception as e:
        print("Issue when modifying dump : {}".format(e))

def change_user_from_dump(source_dump_path, old_user, new_user):
    fh, abs_path = mkstemp()
    with os.fdopen(fh, 'w') as new_file:
        with open(source_dump_path) as old_file:
            for line in old_file:
                new_file.write(line.replace(old_user, new_user))
    # Remove original file
    os.remove(source_dump_path)
    # Move new file
    move(abs_path, source_dump_path)

def restore_postgres_db(db_host, db, port, user, password, backup_file, verbose):
    """
    Restore postgres db from a file.
    """

    if verbose:
        try:
            #print(user,password,db_host,port,db,backup_file)
            process = subprocess.Popen(
                ['pg_restore',
                 '--no-owner',
                 '--dbname=postgresql://{}:{}@{}:{}/{}'.format(user,
                                                               password,
                                                               db_host,
                                                               port, db),
                 '-v',
                 backup_file],
                stdout=subprocess.PIPE
            )
            output = process.communicate()[0]
            if int(process.returncode) != 0:
                print('Command failed. Return code : {}'.format(process.returncode))

            return output
        except Exception as e:
            print("Issue with the db restore : {}".format(e))
    else:
        try:
            process = subprocess.Popen(
                ['pg_restore',
                 '--no-owner',
                 '--dbname=postgresql://{}:{}@{}:{}/{}'.format(user,
                                                                      password,
                                                                      db_host,
                                                                      port, db),
                 backup_file],
                stdout=subprocess.PIPE
            )
            output = process.communicate()[0]
            if int(process.returncode) != 0:
                print('Command failed. Return code : {}'.format(process.returncode))

            return output
        except Exception as e:
            print("Issue with the db restore : {}".format(e))

def create_db(db_host, database, db_port, user_name, user_password):
    try:
        con = psycopg2.connect(dbname='postgres', port=db_port,
                               user=user_name, host=db_host,
                               password=user_password)

    except Exception as e:
        print(e)
        exit(1)

    con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = con.cursor()
    try:
        cur.execute("DROP DATABASE {} ;".format(database))
    except Exception as e:
        print('DB does not exist, nothing to drop')
    cur.execute("CREATE DATABASE {} ;".format(database))
    cur.execute("GRANT ALL PRIVILEGES ON DATABASE {} TO {} ;".format(database, user_name))
    return database

def swap_restore_active(db_host, restore_database, active_database, db_port, user_name, user_password):
    try:
        con = psycopg2.connect(dbname='postgres', port=db_port,
                               user=user_name, host=db_host,
                               password=user_password)
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        cur.execute("SELECT pg_terminate_backend( pid ) "
                    "FROM pg_stat_activity "
                    "WHERE pid <> pg_backend_pid( ) "
                    "AND datname = '{}'".format(active_database))
        cur.execute("DROP DATABASE {}".format(active_database))
        cur.execute('ALTER DATABASE "{}" RENAME TO "{}";'.format(restore_database, active_database))
    except Exception as e:
        print(e)
        exit(1)

def swap_restore_new(db_host, restore_database, new_database, db_port, user_name, user_password):
    try:
        con = psycopg2.connect(dbname='postgres', port=db_port,
                               user=user_name, host=db_host,
                               password=user_password)
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        cur.execute('ALTER DATABASE "{}" RENAME TO "{}";'.format(restore_database, new_database))
    except Exception as e:
        print(e)
        exit(1)

def main():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    args_parser = argparse.ArgumentParser(description='Postgres database management')
    args_parser.add_argument("--action",
                             metavar="action",
                             choices=['list', 'list_dbs', 'restore', 'backup'],
                             required=True)
    args_parser.add_argument("--date",
                             metavar="YYYY-MM-dd",
                             help="Date to use for restore (show with --action list)")
    args_parser.add_argument("--dest-db",
                             metavar="dest_db",
                             default=None,
                             help="Name of the new restored database")
    args_parser.add_argument("--verbose",
                             default=True,
                             help="verbose output")
    args = args_parser.parse_args()

    #backup dest
    postgres_host = ""
    postgres_port = "5433"
    postgres_db = "metabase"
    postgres_restore = "{}_restore".format(postgres_db)
    postgres_user = "mbbackup"
    postgres_password = "usNDrdidTHkaqew3i2DUy"
    timestr = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = 'backup-{}-{}.dump'.format(timestr, postgres_db)
    filename_compressed = '{}.gz'.format(filename)
    restore_filename = 'backup/restore/mb-datatemplate.dump.gz'
    restore_uncompressed = './backup/restore/mb-datatemplate.dump'
    local_file_path = '{}{}'.format(BACKUP_PATH, filename)
    f = open(local_file_path, "x")  # create the file
    f.close()
    # list task

    # backup task
    if args.action == "backup":
        logger.info('Backing up {} database to {}'.format(postgres_db, local_file_path))

        result = backup_postgres_db(postgres_host,
                                    postgres_db,
                                    postgres_port,
                                    postgres_user,
                                    postgres_password,
                                    local_file_path, args.verbose)
        for line in result.splitlines():
            logger.info(line)

        logger.info("Backup complete")
        logger.info("Compressing {}".format(local_file_path))
        comp_file = compress_file(local_file_path)
        logger.info('Uploading {} to Amazon S3...'.format(comp_file))
        #upload_to_s3(comp_file, filename_compressed)
        logger.info("Uploaded to {}".format(filename_compressed))
    # restore task
    elif args.action == "restore":
        if not args.date:
            print("no date error")
        else:
            
            ext_file = extract_file(restore_filename)
            # cleaned_ext_file = remove_faulty_statement_from_dump(ext_file)
            logger.info("Extracted to : {}".format(ext_file))
            logger.info("Creating temp database for restore : {}".format(postgres_restore))
            tmp_database = create_db(postgres_host,
                      postgres_restore,
                      postgres_port,
                      postgres_user,
                      postgres_password)
            logger.info("Created temp database for restore : {}".format(tmp_database))
            logger.info("Restore starting")
            result = restore_postgres_db(postgres_host,
                                         postgres_restore,
                                         postgres_port,
                                         postgres_user,
                                         postgres_password,
                                         restore_uncompressed,
                                         args.verbose)
            for line in result.splitlines():
                logger.info(line)
            logger.info("Restore complete")
            if args.dest_db is not None:
                restored_db_name = args.dest_db
                logger.info("Switching restored database with new one : {} > {}".format(
                    postgres_restore, restored_db_name
                ))
                swap_restore_new(postgres_host,
                                    postgres_restore,
                                    restored_db_name,
                                    postgres_port,
                                    postgres_user,
                                    postgres_password)
            else:
                restored_db_name = postgres_db
                logger.info("Switching restored database with active one : {} > {}".format(
                    postgres_restore, restored_db_name
                ))
                swap_restore_active(postgres_host,
                                    postgres_restore,
                                    restored_db_name,
                                    postgres_port,
                                    postgres_user,
                                    postgres_password)
            logger.info("Database restored and active.")
    else:
        logger.warn("No valid argument was given.")
        logger.warn(args)

