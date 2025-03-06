from mongoengine import Document, StringField, IntField, ReferenceField, ObjectIdField, CASCADE

class User(Document):
    meta = {'collection': 'gma'}

    idnumber = IntField(required=True, unique=True)
    firstname = StringField(max_length=100, required=True)
    lastname = StringField(max_length=100, required=True)
    mobilenumber = StringField(max_length=15, required=True)
    email = StringField(max_length=100, required=True, unique=True)
    password = StringField(max_length=100, required=True)

    def __str__(self):
        return f"{self.firstname} {self.lastname}"

class OwnerAccount(Document):
    meta = {'collection': 'owner_account'}

    user = ObjectIdField(required=True)
    owner_account_name = StringField(required=True, max_length=255)
    registration_id = StringField(required=True, max_length=255)
    phone_number = StringField(required=True, max_length=20)
    email = StringField(required=True)

    def __str__(self):
        return self.owner_account_name

class LevyAccount(Document):
    meta = {'collection': 'levy_account'}

    owner_account = ObjectIdField(required=True)
    levy_name = StringField(required=True, max_length=100)
    building = StringField(required=True)
    door_number = StringField(required=True)
    current_balance = StringField(required=True)

    def __str__(self):
        return self.levy_name
