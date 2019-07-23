# Script to import event set from csv into mongodb

from pymongo import MongoClient
import pandas as pd

client = MongoClient('localhost', 27017)
db = client.project
events = db.events
events.drop()
events = db.events
filename = input("Enter CSV filename (with extension) to read events from: ")
try:
    df = pd.read_csv(filename)
except IOError:
    print("File {} does not exist".format(filename))
    exit() 
records = df.to_dict(orient = 'records')
db.events.insert_many(records)
print("Successfully imported event set")