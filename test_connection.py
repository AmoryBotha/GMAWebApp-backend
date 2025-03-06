from mongoengine import connect
from api.models import User

connect(
    db='gma_user',
    host='mongodb+srv://keanugma:uLaHaWKB1ppuG5tC@gmacluster.sedo2.mongodb.net/gma_user?retryWrites=true&w=majority'
)

print("Connected to MongoDB!")

users = User.objects.all()
for user in users:
    print(user.firstname, user.lastname)
