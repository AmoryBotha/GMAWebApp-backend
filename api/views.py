import jwt
from bson import ObjectId
import requests
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.http import JsonResponse
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer, OwnerAccountSerializer, LevyAccountSerializer
from .models import OwnerAccount, LevyAccount, User
from .utils import update_friendly_reminder, get_levy_account_details_view, generate_reset_token, send_reset_email, get_dataverse_token, register_user_in_dataverse, check_if_user_exists, get_user_from_dataverse, update_password_in_dataverse, link_contact_to_user, create_contact_in_dataverse, get_contact_from_dataverse, get_accounts_for_user, link_accounts_to_user_profile, fetch_static_info, create_internal_task, send_registration_email, get_accounts_for_userprofile, find_contact, get_trustee_access, get_contractor_access, get_owner_access, determine_user_access, get_user_profile, update_user_profile, get_account_details, update_account_info, download_pdf_statement, download_excel_statement, get_dataverse_token
SECRET_KEY = settings.SECRET_KEY

# Create a persistent session to reuse TCP connections across external HTTP calls.
_session = requests.Session()

@api_view(['GET'])
def get_users(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def get_user_by_id(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        serializer = UserSerializer(user)
        return Response(serializer.data)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)

@api_view(['POST'])
def create_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = User(**serializer.validated_data)
        user.save()
        return Response(UserSerializer(user).data)
    return Response(serializer.errors, status=400)

@api_view(['PUT'])
def update_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            for key, value in serializer.validated_data.items():
                setattr(user, key, value)
            user.save()
            return Response(UserSerializer(user).data)
        return Response(serializer.errors, status=400)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=404)
    
@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    print(f"🔹 Incoming Login Request: Email={email}")

    if not email or not password:
        print("❌ Missing email or password")
        return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

    dataverse_token = get_dataverse_token()
    if not dataverse_token:
        print("❌ Failed to retrieve Dataverse token")
        return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    print(f"✅ Dataverse Token Retrieved: {dataverse_token[:30]}... (truncated)")

    user_data = get_user_from_dataverse(email, dataverse_token)
    if "error" in user_data:
        print(f"❌ Dataverse Error: {user_data['error']}")
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    stored_password = user_data.get("cj_password")
    user_id = user_data.get("cj_userprofileid")

    print(f"✅ Retrieved User from Dataverse: ID={user_id}, Stored Password={stored_password}")

    if stored_password != password:
        print("❌ Passwords do not match!")
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    payload = {
        "id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=24),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    print("✅ Login Successful. Token Generated.")

    return Response({"message": "Login successful", "token": token}, status=status.HTTP_200_OK)
    
def send_reset_email(email, token):
    reset_link = f"https://gmawebapp-frontend.onrender.com/"
    subject = "Password Reset Request"
    message = f"""
    Hello,

    You requested to reset your password. Click the link below to reset your password:
    {reset_link}

    If you did not make this request, please ignore this email.

    Thank you,
    Your Website Team
    """
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        print(f"Reset email sent to {email}.")
    except Exception as e:
        print(f"Failed to send reset email: {e}")

@api_view(['POST'])
def forgot_password(request):
    try:
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(email, dataverse_token)
        if "error" in user_data:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        user_id = user_data.get("cj_userprofileid")

        payload = {
            'user_id': user_id,
            'exp': datetime.now(tz=timezone.utc) + timedelta(minutes=30),
            'iat': datetime.now(timezone.utc)
        }
        reset_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        send_reset_email(email, reset_token)

        return Response({"message": "Reset password email sent successfully"}, status=status.HTTP_200_OK)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@api_view(['POST'])
def reset_password(request):
    try:
        print("📩 Incoming Reset Password Request:", request.data)

        token = request.data.get("token")
        new_password = request.data.get("new_password")

        if not token or not new_password:
            return Response({"error": "Token and new password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("user_id")
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token has expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        update_response = update_password_in_dataverse(user_id, new_password, dataverse_token)
        if "error" in update_response:
            return Response({"error": update_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)

    except Exception as e:
        print("🔥 Reset Password Error:", str(e))
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
@api_view(['GET'])
def get_owner_accounts(request):
    try:
        print("🔍 Fetching Owner & Levy Accounts...")

        token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not token:
            print("❌ No token provided")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_email = decoded_token.get("email")
        if not user_email:
            print("❌ Invalid token: No email found")
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        print(f"✅ Extracted User Email: {user_email}")

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            print("❌ Failed to get Dataverse token")
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(user_email, dataverse_token)
        if "error" in user_data:
            print(f"❌ Error retrieving `cj_userprofileid` for {user_email}")
            return Response({"error": "Failed to retrieve user profile ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cj_userprofileid = user_data.get("cj_userprofileid")
        print(f"✅ Extracted cj_userprofileid: {cj_userprofileid}")

        contact_id = user_data.get("_cj_linkedcontactlookup_value")
        print(f"✅ Extracted contact ID: {contact_id}")

        if not contact_id:
            print("⚠️ No linked contact found. Cannot fetch owner accounts.")
            return Response([], status=status.HTTP_200_OK)

        # 🔹 Fetch owner accounts for this contact
        owner_accounts = get_accounts_for_user(user_email, contact_id, dataverse_token)
        print(f"✅ Retrieved Owner Account IDs: {owner_accounts}")

        if not owner_accounts:
            print("⚠️ No Owner Accounts found.")
            return Response([], status=status.HTTP_200_OK)

        # 🔹 Prepare owner account data
        owner_accounts_list = []
        headers = {
            "Authorization": f"Bearer {dataverse_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        for owner_id in owner_accounts:
            owner_details_url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts({owner_id})?$select=name,emailaddress1,telephone1,cj_registrationidpassport"
            owner_details_response = _session.get(owner_details_url, headers=headers)

            if owner_details_response.status_code != 200:
                print(f"⚠️ Failed to fetch details for Owner ID: {owner_id}")
                continue

            owner_details = owner_details_response.json()

            levy_url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_gmaaccountnumbers?$filter=_cj_responsibleperson_value eq {owner_id}&$select=cj_sageaccountnumber,cj_gmaaccountnumberid,cj_agetotal,cj_doornumber&$expand=cj_LinkedBuilding($select=cj_buildingname,cj_gmabuildingid)"
            levy_response = _session.get(levy_url, headers=headers)

            levy_accounts = []
            if levy_response.status_code == 200:
                levy_data = levy_response.json()
                levy_accounts = [
                    {
                        "id": levy["cj_gmaaccountnumberid"],
                        "levy_name": levy["cj_sageaccountnumber"],
                        "building": levy.get("cj_LinkedBuilding", {}).get("cj_buildingname", "N/A"),
                        "door_number": levy["cj_doornumber"],
                        "current_balance": levy.get("cj_agetotal", 0) or 0,
                    }
                    for levy in levy_data.get("value", [])
                ]

            owner_accounts_list.append({
                "id": owner_id,
                "owner_account_name": owner_details.get("name", "N/A"),
                "registration_id": owner_details.get("cj_registrationidpassport", "N/A"),
                "phone_number": owner_details.get("telephone1", "N/A"),
                "email": owner_details.get("emailaddress1", "N/A"),
                "levy_accounts": levy_accounts
            })

        print(f"📤 Sending Final Owner Accounts Response: {owner_accounts_list}")
        return Response(owner_accounts_list, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"🔥 Unexpected Error: {str(e)}")
        return Response({"error": "No Accounts Found"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error: {e}")
        return Response({"error": "Failed to fetch data from Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except jwt.ExpiredSignatureError:
        print("❌ Token expired")
        return Response({"error": "Token expired"}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        print("❌ Invalid token")
        return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

    
@api_view(['GET'])
def test_dataverse_auth(request):
    """
    Test API authentication with Dataverse.
    """
    token = get_dataverse_token()
    if not token:
        return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    headers = {"Authorization": f"Bearer {token}"}
    test_url = "https://orgcd873c19.api.crm4.dynamics.com/api/data/v9.1/accounts"

    try:
        response = _session.get(test_url, headers=headers)
        response.raise_for_status()
        return Response(response.json(), status=status.HTTP_200_OK)

    except requests.RequestException as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#OLD REGISTER BEFORE 26/02/2025
#@api_view(['POST'])
#def register_user(request):
    print("🔹 Incoming Registration Request Data:", request.data)

    first_name = request.data.get('firstname')
    last_name = request.data.get('lastname')
    mobile_number = request.data.get('mobilenumber')
    email = request.data.get('email')
    password = request.data.get('password')

    if not all([first_name, last_name, mobile_number, email, password]):
        print("❌ Missing fields in request!")
        return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

    dataverse_token = get_dataverse_token()
    if not dataverse_token:
        print("❌ Failed to get Dataverse token")
        return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    existing_user = get_user_from_dataverse(email, dataverse_token)
    if existing_user and "cj_userprofileid" in existing_user:
        print("⚠️ User already exists. Redirecting to login.")
        return Response({"message": "User already exists. Please log in."}, status=status.HTTP_400_BAD_REQUEST)

    registration_response = register_user_in_dataverse(first_name, last_name, mobile_number, email, password, dataverse_token)
    if "error" in registration_response:
        print(f"❌ Dataverse API Error: {registration_response['error']}")
        return Response({"error": registration_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    user_id = registration_response.get("location", "").split("(")[-1].split(")")[0]
    print(f"✅ Extracted user_id: {user_id}")

    user_data = get_user_from_dataverse(email, dataverse_token)
    if "error" in user_data:
        print("❌ Error retrieving `cj_userprofileid`")
        return Response({"error": "Failed to retrieve user ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    cj_userprofileid = user_data.get("cj_userprofileid")
    print(f"✅ Extracted cj_userprofileid: {cj_userprofileid}")

    contact_id = get_contact_from_dataverse(email, dataverse_token)
    
    if contact_id:
        print(f"✅ Contact found: {contact_id}. Proceeding to link user.")
    else:
        print("⚠️ No contact found. Creating a new contact.")

        contact_creation_response = create_contact_in_dataverse(
            first_name=first_name,
            last_name=last_name,
            mobile_number=mobile_number,
            email=email,
            cj_userprofileid=cj_userprofileid,
            token=dataverse_token
        )

        if "error" in contact_creation_response:
            return Response({"error": contact_creation_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        contact_id = contact_creation_response.get("location", "").split("(")[-1].split(")")[0]
        print(f"✅ New Contact Created: {contact_id}")

    print(f"📤 Linking contact {contact_id} to user profile {cj_userprofileid}")
    link_response = link_contact_to_user(cj_userprofileid, contact_id, dataverse_token)
    if "error" in link_response:
        return Response({"error": link_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    print(f"✅ Contact {contact_id} successfully linked to User Profile {cj_userprofileid}")

    print("📤 Fetching default owner accounts using API A...")
    default_accounts = get_accounts_for_user(email, contact_id, dataverse_token)

    if default_accounts:
        print(f"✅ Found {len(default_accounts)} Default Accounts. Proceeding to link.")
        link_accounts_to_user_profile(cj_userprofileid, default_accounts, dataverse_token)
    else:
        print("⚠️ No Default Accounts found for user.")

    print("✅ Registration Completed Successfully")
    return Response({"message": "Registration successful"}, status=status.HTTP_201_CREATED)



def check_if_contact_exists(email, token):
    """
    Check if a contact exists for the given email in Dataverse.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/contacts?$filter=emailaddress1 eq '{email}' and statecode eq 0&$select=contactid&$top=1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Checking if contact exists: {url}")
        response = _session.get(url, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        data = response.json()

        contacts = data.get("value", [])
        contact_ids = [contact["contactid"] for contact in contacts]

        return contact_ids

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Check Contact Exists): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

@api_view(['GET'])
def get_real_time_owner_accounts(request):
    try:
        print("🔍 Fetching Owner & Levy Accounts...")

        token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not token:
            print("❌ No token provided")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_email = decoded_token.get("email")
        if not user_email:
            print("❌ Invalid token: No email found")
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        print(f"✅ Extracted User Email: {user_email}")

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            print("❌ Failed to get Dataverse token")
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(user_email, dataverse_token)
        if "error" in user_data:
            print(f"❌ Error retrieving `cj_userprofileid` for {user_email}")
            return Response({"error": "Failed to retrieve user profile ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cj_userprofileid = user_data.get("cj_userprofileid")
        print(f"✅ Extracted cj_userprofileid: {cj_userprofileid}")

        # 🔹 Fetch owner accounts for this contact
        owner_accounts = get_accounts_for_userprofile(cj_userprofileid, dataverse_token)
        print(f"✅ Retrieved Owner Account IDs: {owner_accounts}")

        if not owner_accounts:
            print("⚠️ No Owner Accounts found.")
            return Response([], status=status.HTTP_200_OK)

        # 🔹 Prepare owner account data
        owner_accounts_list = []
        headers = {
            "Authorization": f"Bearer {dataverse_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        for owner_id in owner_accounts:
            owner_details_url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts({owner_id})?$select=name,emailaddress1,telephone1,cj_registrationidpassport"
            owner_details_response = _session.get(owner_details_url, headers=headers)

            if owner_details_response.status_code != 200:
                print(f"⚠️ Failed to fetch details for Owner ID: {owner_id}")
                continue

            owner_details = owner_details_response.json()

            levy_url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_gmaaccountnumbers?$filter=_cj_responsibleperson_value eq {owner_id}&$select=cj_sageaccountnumber,cj_gmaaccountnumberid,cj_agetotal,cj_doornumber&$expand=cj_LinkedBuilding($select=cj_buildingname,cj_gmabuildingid)"
            levy_response = _session.get(levy_url, headers=headers)

            levy_accounts = []
            if levy_response.status_code == 200:
                levy_data = levy_response.json()
                levy_accounts = [
                    {
                        "id": levy["cj_gmaaccountnumberid"],
                        "levy_name": levy["cj_sageaccountnumber"],
                        "building": levy.get("cj_LinkedBuilding", {}).get("cj_buildingname", "N/A"),
                        "door_number": levy["cj_doornumber"],
                        "current_balance": levy.get("cj_agetotal", 0) or 0,
                    }
                    for levy in levy_data.get("value", [])
                ]

            owner_accounts_list.append({
                "id": owner_id,
                "owner_account_name": owner_details.get("name", "N/A"),
                "registration_id": owner_details.get("cj_registrationidpassport", "N/A"),
                "phone_number": owner_details.get("telephone1", "N/A"),
                "email": owner_details.get("emailaddress1", "N/A"),
                "levy_accounts": levy_accounts
            })

        print(f"📤 Sending Final Owner Accounts Response: {owner_accounts_list}")
        return Response(owner_accounts_list, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"🔥 Unexpected Error: {str(e)}")
        return Response({"error": "No Accounts Found"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error: {e}")
        return Response({"error": "Failed to fetch data from Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except jwt.ExpiredSignatureError:
        print("❌ Token expired")
        return Response({"error": "Token expired"}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        print("❌ Invalid token")
        return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
def get_user_profile_info(request):
    try:
        print("🔍 Fetching User Profile Info")

        token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not token:
            print("❌ No token provided")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_email = decoded_token.get("email")
        if not user_email:
            print("❌ Invalid token: No email found")
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        print(f"✅ Extracted User Email: {user_email}")

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            print("❌ Failed to get Dataverse token")
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(user_email, dataverse_token)
        if "error" in user_data:
            print(f"❌ Error retrieving `cj_userprofileid` for {user_email}")
            return Response({"error": "Failed to retrieve user profile ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cj_userprofileid = user_data.get("cj_userprofileid")
        firstName = user_data.get("cj_userprofileid")
        lastName = user_data.get("cj_userprofileid")
        cj_userprofileid = user_data.get("cj_userprofileid")
        cj_userprofileid = user_data.get("cj_userprofileid")
        cj_userprofileid = user_data.get("cj_userprofileid")
        print(f"✅ Extracted cj_userprofileid: {cj_userprofileid}")


    except Exception as e:
        print(f"🔥 Unexpected Error: {str(e)}")
        return Response({"error": "No Accounts Found"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error: {e}")
        return Response({"error": "Failed to fetch data from Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except jwt.ExpiredSignatureError:
        print("❌ Token expired")
        return Response({"error": "Token expired"}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        print("❌ Invalid token")
        return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

#Works 26/02/2025
@api_view(['POST'])
def register_user(request):
    print("🔹 Incoming Registration Request Data:", request.data)

    first_name = request.data.get('firstname')
    last_name = request.data.get('lastname')
    mobile_number = request.data.get('mobilenumber')
    email = request.data.get('email')
    password = request.data.get('password')
    id_number = request.data.get('id_number')

    if not all([first_name, last_name, mobile_number, email, password, id_number]):
        print("❌ Missing fields in request!")
        return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

    dataverse_token = get_dataverse_token()
    if not dataverse_token:
        print("❌ Failed to get Dataverse token")
        return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # 🔍 **Check if a user profile already exists with this email**
    existing_user = get_user_from_dataverse(email, dataverse_token)

    if existing_user and "cj_userprofileid" in existing_user:
        print("⚠️ User profile with this email already exists. Redirecting to login.")
        return Response({"error": "This email is already registered. Please log in."}, status=status.HTTP_400_BAD_REQUEST)

    # 🔍 **Find contact ID first**
    contact_id = find_contact(id_number, email, mobile_number, dataverse_token)

    if contact_id:
        print(f"✅ Contact found: {contact_id}. Proceeding to link user profile...")
    else:
        print("⚠️ No contact found. Creating a new contact.")

        # 🔍 **Fetch Static Info for Webflow Query User**
        static_info = fetch_static_info(dataverse_token)

        if static_info:
            print(f"✅ Webflow Query User Found: {static_info['fullname']} ({static_info['internalemailaddress']})")
        else:
            print("⚠️ No Webflow Query User found.")

        # **Create Internal Task**
        create_internal_task(email, static_info, dataverse_token)

        # **Send Notification Email**
        send_registration_email(email, static_info)

    # **Create a new user profile**
    registration_response = register_user_in_dataverse(first_name, last_name, mobile_number, email, password, dataverse_token)

    if "error" in registration_response:
        print(f"❌ Dataverse API Error: {registration_response['error']}")
        return Response({"error": registration_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    user_id = registration_response.get("location", "").split("(")[-1].split(")")[0]
    print(f"✅ New user profile created: {user_id}")

    # Fetch the newly created user profile
    user_data = get_user_from_dataverse(email, dataverse_token)
    if not user_data or "error" in user_data:
        print("❌ Error retrieving newly created user profile.")
        return Response({"error": "Failed to retrieve newly created user profile."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    cj_userprofileid = user_data.get("cj_userprofileid")
    print(f"✅ Extracted cj_userprofileid: {cj_userprofileid}")

    if not contact_id:
        # **Create a contact for the new user**
        contact_creation_response = create_contact_in_dataverse(
            first_name=first_name,
            last_name=last_name,
            mobile_number=mobile_number,
            email=email,
            cj_userprofileid=id_number,
            token=dataverse_token
        )

        if "error" in contact_creation_response:
            return Response({"error": contact_creation_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        contact_id = contact_creation_response.get("location", "").split("(")[-1].split(")")[0]
        print(f"✅ New Contact Created: {contact_id}")

    # **Link Contact to User Profile**
    print(f"📤 Linking contact {contact_id} to user profile {cj_userprofileid}")
    link_response = link_contact_to_user(cj_userprofileid, contact_id, dataverse_token)
    if "error" in link_response:
        return Response({"error": link_response["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    print(f"✅ Contact {contact_id} successfully linked to User Profile {cj_userprofileid}")

    # **Fetch and Link Default Owner Accounts**
    print("📤 Fetching default owner accounts...")
    default_accounts = get_accounts_for_user(email, contact_id, dataverse_token)

    if default_accounts:
        print(f"✅ Found {len(default_accounts)} Default Accounts. Proceeding to link.")
        link_accounts_to_user_profile(cj_userprofileid, default_accounts, dataverse_token)
    else:
        print("⚠️ No Default Accounts found for user.")

    print("✅ Registration Completed Successfully")
    return Response({"message": "Registration successful"}, status=status.HTTP_201_CREATED)

#Works 26/02/2025
@api_view(['POST'])
def api_find_contact(request):
    """
    Searches for a contact using multiple methods in a sequence.
    """
    try:
        id_number = request.data.get("id_number")
        email = request.data.get("email")
        mobile_number = request.data.get("mobile_number")

        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        contact_id = find_contact(id_number, email, mobile_number, token)
        if contact_id:
            return Response({"contact_id": contact_id}, status=status.HTTP_200_OK)
        
        return Response({"error": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#Works Tested 26/02/2025
@api_view(['POST'])
def api_get_trustee_access(request):
    """
    Checks if the contact has trustee access.
    """
    try:
        contact_id = request.data.get("contact_id")

        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = get_trustee_access(contact_id, token)
        return Response(response, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#Works Tested 26/02/2025
@api_view(['POST'])
def api_get_contractor_access(request):
    """
    Checks if the contact has contractor access.
    """
    try:
        contact_id = request.data.get("contact_id")

        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = get_contractor_access(contact_id, token)
        return Response(response, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#Works Tested 26/02/2025
@api_view(['POST'])
def api_get_owner_access(request):
    """
    Checks if the contact has owner access.
    """
    try:
        contact_id = request.data.get("contact_id")
        email = request.data.get("email")

        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = get_owner_access(email, contact_id, token)
        return Response(response, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#Works Tested 26/02/2025
@api_view(['POST'])
def api_determine_user_access(request):
    """
    Determines and returns the user's access levels.
    """
    try:
        print(f"📥 Incoming Request Data: {request.data}")

        email = request.data.get('email')
        contact_id = request.data.get('contact_id')

        if not email:
            print("❌ Missing email in request!")
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not contact_id:
            print("⚠️ No contact ID provided. Checking if user has linked contact...")
            dataverse_token = get_dataverse_token()
            if not dataverse_token:
                return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            user_data = get_user_from_dataverse(email, dataverse_token)
            if "error" in user_data:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            contact_id = user_data.get("_cj_linkedcontactlookup_value")

        if not contact_id:
            print("⚠️ No linked contact found. User has no access levels.")
            return Response({
                "contact_id": None,
                "email": email,
                "access": [],
                "linked_accounts": [],
                "linked_contractors": []
            }, status=status.HTTP_200_OK)

        print(f"✅ Extracted Contact ID: {contact_id}")

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = determine_user_access(contact_id, email, dataverse_token)
        return Response(response, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"🔥 Error in `api_determine_user_access`: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def api_get_user_profile(request, user_profile_id):
    """
    Retrieves a user profile by profile ID.
    """
    try:
        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = get_user_profile(user_profile_id, token)
        return Response(response, status=status.HTTP_200_OK if "error" not in response else status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def api_get_user_profile_by_email(request, email):
    """
    Retrieves a user profile by email.
    """
    try:
        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(email, token)
        if "error" in user_data:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response(user_data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PATCH'])
def api_update_user_profile(request, user_id):
    """
    Updates a user profile.
    """
    try:
        update_data = request.data

        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = update_user_profile(user_id, update_data, token)
        return Response(response, status=status.HTTP_200_OK if "error" not in response else status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def api_get_account_details(request, account_id):
    """
    Retrieves account details using account ID.
    """
    try:
        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = get_account_details(account_id, token)
        return Response(response, status=status.HTTP_200_OK if "error" not in response else status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PATCH'])
def api_update_account_info(request, account_id):
    """
    Updates an account's details.
    """
    try:
        update_data = request.data

        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = update_account_info(account_id, update_data, token)
        return Response(response, status=status.HTTP_200_OK if "error" not in response else status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def api_get_levy_account_details(request, levy_account_id, responsible_person_id):
    """
    Retrieves levy account details for a given levy account ID.
    """
    try:
        token = get_dataverse_token()
        if not token:
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = get_levy_account_details_view(levy_account_id, responsible_person_id, token)
        print("📥 Final Response to Frontend:", response)

        if "error" in response:
            return Response(response, status=status.HTTP_404_NOT_FOUND)

        return Response(response, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"🚨 Unexpected Error in API: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PATCH'])
def api_update_friendly_reminder(request, levy_account_id):
    """
    Updates the Friendly Reminder setting for a given levy account ID.
    """
    try:
        token = get_dataverse_token()
        if not token:
            return Response({"error": "Unauthorized request - Missing Token"}, status=status.HTTP_401_UNAUTHORIZED)

        print(f"Received Token: {token}")

        data = request.data
        response = update_friendly_reminder(levy_account_id, data.get("cj_sendfriendlyreminder"), token)

        if response.status_code == 204:
            return Response({"message": "Friendly Reminder updated successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Failed to update Friendly Reminder"}, status=response.status_code)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
   
@api_view(['POST'])
def api_download_pdf_statement(request):
    """
    Requests and downloads a PDF statement.
    """
    try:
        token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not token:
            print("❌ No token provided")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_email = decoded_token.get("email")
        if not user_email:
            print("❌ Invalid token: No email found")
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        email = user_email
        start_date = request.data.get("from")
        end_date = request.data.get("to")

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            print("❌ Failed to get Dataverse token")
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(user_email, dataverse_token)
        if "error" in user_data:
            print(f"❌ Error retrieving `cj_userprofileid` for {user_email}")
            return Response({"error": "Failed to retrieve user profile ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cj_userprofileid = user_data.get("cj_userprofileid")
        contact_id = request.data.get("gmaAccountNumberID")
        user_profile_id = cj_userprofileid

        if not contact_id:
            print(f"❌ Contact ID not found for user: {user_email}")
            return Response({"error": "Missing required contact details."}, status=status.HTTP_400_BAD_REQUEST)

        response = download_pdf_statement(email, contact_id, start_date, end_date, user_profile_id)
        return Response(response, status=status.HTTP_200_OK if "error" not in response else status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def api_download_excel_statement(request):
    """
    Requests and downloads an Excel statement.
    """
    try:
        token = request.headers.get("Authorization", "").split("Bearer ")[-1]
        if not token:
            print("❌ No token provided")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_email = decoded_token.get("email")
        if not user_email:
            print("❌ Invalid token: No email found")
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        email = user_email
        start_date = request.data.get("from")
        end_date = request.data.get("to")

        dataverse_token = get_dataverse_token()
        if not dataverse_token:
            print("❌ Failed to get Dataverse token")
            return Response({"error": "Failed to authenticate with Dataverse"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user_data = get_user_from_dataverse(user_email, dataverse_token)
        if "error" in user_data:
            print(f"❌ Error retrieving `cj_userprofileid` for {user_email}")
            return Response({"error": "Failed to retrieve user profile ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cj_userprofileid = user_data.get("cj_userprofileid")
        contact_id = request.data.get("gmaAccountNumberID")
        user_profile_id = cj_userprofileid

        if not contact_id:
            print(f"❌ Contact ID not found for user: {user_email}")
            return Response({"error": "Missing required contact details."}, status=status.HTTP_400_BAD_REQUEST)

        response = download_excel_statement(email, contact_id, start_date, end_date, user_profile_id)
        return Response(response, status=status.HTTP_200_OK if "error" not in response else status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
