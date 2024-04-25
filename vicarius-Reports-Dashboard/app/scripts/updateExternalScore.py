# epss_data_loader.py

import requests
import gzip
import pandas as pd
from sqlalchemy import create_engine, text, Table, Column, String, Float, MetaData
from datetime import datetime

def download_and_load_epss_data(db_host, db_port, db_username, db_password, db_name):

    table_name = 'epssdata'

    # Mimic a common User-Agent
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

    # Get today's date in the correct format
    today = (datetime.now() - - timedelta(days=1)).strftime('%Y-%m-%d')

    url = f"https://epss.cyentia.com/epss_scores-{today}.csv.gz"

    print (url)
    # Download the file
    response = requests.get(url)
    print (response)
    if response.status_code == 200:
        # Save the gzip file
        with open("epss_scores.csv.gz", "wb") as file:
            file.write(response.content)

        # Extract the gzip file
        with gzip.open("epss_scores.csv.gz", "rb") as f_in:
            with open("epss_scores.csv", "wb") as f_out:
                f_out.write(f_in.read())

        # Load the CSV into a DataFrame
        df = pd.read_csv("epss_scores.csv")

        # Connect to the PostgreSQL database
        engine = create_engine(f'postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}')
        metadata = MetaData()

        # Define the table structure
        table = Table(table_name, metadata,
                    Column('cve', String, primary_key=True),
                    Column('epss', Float),
                    Column('percentile', Float),
                    Column('score_date', String))

        # Check if the table exists, create it if not
        if not engine.dialect.has_table(engine, table_name):
            table.create(engine)

        # Check if data already exists for today
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT EXISTS(SELECT 1 FROM {table_name} WHERE score_date = :date)"), {'date': today}).scalar()
            if result:
                # If data exists, delete it
                conn.execute(text(f"DELETE FROM {table_name} WHERE score_date = :date"), {'date': today})

        # Insert new data
        df.to_sql(table_name, engine, if_exists='append', index=False)

        print("Data inserted successfully.")
    else:
        print(f"Failed to download the file. Status code: {response.status_code}")

if __name__ == "__main__":
    download_and_load_epss_data()
