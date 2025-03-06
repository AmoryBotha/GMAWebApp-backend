from pymongo import MongoClient

client = MongoClient("mongodb+srv://keanugma:uLaHaWKB1ppuG5tC@gmacluster.sedo2.mongodb.net/gma_user?retryWrites=true&w=majority")
db = client['gma_user']
collection = db['gma']

for document in collection.find():
    print(document)
