from rest_framework import serializers
from .models import OwnerAccount, LevyAccount, User

class UserSerializer(serializers.Serializer):
    firstname = serializers.CharField(required=True, max_length=50)
    lastname = serializers.CharField(required=True, max_length=50)
    mobilenumber = serializers.CharField(required=True, max_length=15)
    idnumber = serializers.CharField(required=True, max_length=20)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class OwnerAccountSerializer(serializers.Serializer):
    id = serializers.CharField()
    owner_account_name = serializers.CharField()
    registration_id = serializers.CharField()
    phone_number = serializers.CharField()
    email = serializers.EmailField()

class LevyAccountSerializer(serializers.Serializer):
    id = serializers.CharField()
    owner_account = serializers.CharField()
    levy_name = serializers.CharField()
    building = serializers.CharField()
    door_number = serializers.CharField()
    current_balance = serializers.CharField()