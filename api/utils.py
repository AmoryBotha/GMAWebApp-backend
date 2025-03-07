import jwt
import json 
import requests
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings

# Create a persistent session to reuse TCP connections across API calls.
_session = requests.Session()

def generate_reset_token(email):
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

def send_reset_email(email, reset_token):
    reset_link = f"https://gmawebapp-frontend.onrender.com/"
    subject = "Password Reset Request"
    message = f"Click the link below to reset your password:\n\n{reset_link}\n\nThis link will expire in 30 minutes."
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        print(f"✅ Reset email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send reset email: {str(e)}")

def get_dataverse_token():
    """
    Request an API token from Microsoft Dataverse.
    Automatically refreshes token if it expires.
    """
    url = settings.DATAVERSE_TOKEN_URL
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "client_id": settings.DATAVERSE_CLIENT_ID,
        "client_secret": settings.DATAVERSE_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": settings.DATAVERSE_SCOPE,
    }

    try:
        response = _session.post(url, headers=headers, data=data)
        response.raise_for_status()
        token_data = response.json()
        return token_data["access_token"]
    except requests.RequestException as e:
        print(f"❌ Dataverse Authentication Failed: {str(e)}")
        return None

def register_user_in_dataverse(first_name, last_name, mobile_number, email, password, token):
    """
    Registers a new user in Dataverse using their API.
    """
    url = "https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    payload = {
        "cj_password": password,
        "cj_name": first_name,
        "cj_lastname": last_name,
        "cj_cellnumber": mobile_number,
        "cj_email": email
    }

    try:
        print(f"📤 Sending request to Dataverse: {url}")
        response = _session.post(url, json=payload, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()

        return {"location": response.headers.get("OData-EntityId", "")}  # ✅ Return user_id from Location header

    except requests.RequestException as e:
        print(f"❌ Dataverse API error: {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def check_if_user_exists(email, token):
    """
    Check if a user with the given email exists in Dataverse.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles?$filter=cj_email eq '{email}'&$top=1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    try:
        response = _session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        return len(data.get("value", [])) > 0

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Check User Exists): {e}")
        return False

def get_user_from_dataverse(email, token):
    """
    Retrieve user details from Dataverse using email.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles?$filter=cj_email eq '{email}'&$top=1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    print(f"📤 Sending request to Dataverse: {url}")
    print(f"🛠 Headers: {headers}")

    try:
        response = _session.get(url, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        data = response.json()

        if not data.get("value"):
            print("❌ No user found in Dataverse!")
            return {"error": "User not found"}

        print(f"✅ Dataverse Response Parsed Successfully: {data['value'][0]}")
        return data["value"][0]

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error: {str(e)}")
        return {"error": f"Dataverse API Error: {str(e)}"}

def update_password_in_dataverse(user_id, new_password, token):
    """
    Updates a user's password in Dataverse using their `cj_userprofileid`.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles({user_id})"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    payload = {"cj_password": new_password}

    try:
        print(f"📤 Sending Password Update Request to Dataverse: {url}")
        response = _session.patch(url, json=payload, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status() 

        return {"message": "Password updated successfully"} if response.status_code == 204 else response.json()

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Update Password): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def get_contact_from_dataverse(email, token):
    """
    Retrieves the most recent contact ID if it exists in Dataverse.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/contacts?$filter=emailaddress1 eq '{email}' and statecode eq 0&$select=contactid&$top=5"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        response = _session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if not data.get("value"):
            print(f"❌ No contact found for {email}")
            return None

        contact_ids = [contact["contactid"] for contact in data["value"]]
        print(f"✅ Retrieved Contact IDs: {contact_ids}")  # Debug all possible contacts

        return contact_ids[0]  # Always return the **latest** contact

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Get Contact): {str(e)}")
        return None

def create_contact_in_dataverse(first_name, last_name, mobile_number, email, cj_userprofileid, token):
    """
    Creates a new contact in Dataverse.
    """
    url = "https://gmacc.crm4.dynamics.com/api/data/v9.2/contacts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    payload = {
        "emailaddress1": email,
        "mobilephone": mobile_number,
        "cj_idnumber": cj_userprofileid,
        "firstname": first_name,
        "lastname": last_name
    }

    try:
        print(f"📤 Creating new contact in Dataverse: {url}")
        response = _session.post(url, json=payload, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()

        return {"location": response.headers.get("OData-EntityId", "")}

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Create Contact): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def link_contact_to_user(cj_userprofileid, contact_id, token):
    """
    Links a contact to a user profile in Dataverse.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles({cj_userprofileid})"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    payload = {
        "cj_LinkedContactLookup@odata.bind": f"/contacts({contact_id})"
    }

    try:
        print(f"📤 Linking Contact to User: {cj_userprofileid} -> {contact_id}")
        print(f"🔍 Request URL: {url}")
        print(f"🛠 Headers: {headers}")
        print(f"📦 Payload: {json.dumps(payload, indent=2)}")

        response = _session.patch(url, json=payload, headers=headers)
        
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        return {"message": "Contact linked successfully"} if response.status_code == 204 else response.json()

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Link Contact to User): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}
    
def get_accounts_for_user(email, contact_id, token):
    """
    Retrieve Accounts associated with the user via email or contact ID.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts?$filter=emailaddress1 eq '{email}' or _primarycontactid_value eq {contact_id} and statecode eq 0&$select=accountid"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Fetching Accounts for User: {url}")
        response = _session.get(url, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        data = response.json()
        accounts = [account["accountid"] for account in data.get("value", [])]

        print(f"✅ Retrieved {len(accounts)} Accounts for user.")
        return accounts

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Get Accounts): {str(e)}")
        return []

def link_accounts_to_user_profile(cj_userprofileid, account_ids, token):
    """
    Links multiple accounts to a user profile in Dataverse.
    """
    url_base = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles({cj_userprofileid})/cj_UserProfile_Account_Account/$ref"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    print(f"ACCOUTN IDS:{account_ids}")

    for account_id in account_ids:
        payload = {
            "@odata.id": f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts({account_id})"
        }

        try:
            print(f"📤 Linking Account {account_id} to User {cj_userprofileid}: {url_base}")
            response = _session.post(url_base, json=payload, headers=headers)
            print(f"🔄 Dataverse Response Status Code: {response.status_code}")

            response.raise_for_status()
            print(f"✅ Successfully linked Account {account_id} to User.")

        except requests.RequestException as e:
            print(f"❌ Dataverse API Error (Link Account): {str(e)}")

def fetch_static_info(token):
    """
    Retrieves static information for Webflow query users.
    """
    url = "https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_staticinformations?$filter=statecode eq 0&$select=cj_staticinformationid&$expand=cj_WebflowQueryUser($select=systemuserid,fullname,internalemailaddress)&$top=1"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    try:
        response = _session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get("value", [])

        if not data:
            print("⚠️ No Webflow Query User found in static info.")
            return None

        print(f"✅ Retrieved Webflow Query User: {data[0]['cj_WebflowQueryUser']}")
        return data[0]["cj_WebflowQueryUser"]

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Fetch Static Info): {str(e)}")
        return None

def create_internal_task(user_email, static_info, token):
    """
    Creates an internal task when no contact is found.
    """
    if not static_info:
        print(f"⚠️ Skipping internal task creation – No Webflow Query User found.")
        return

    url = "https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_internaltaskses"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {
        "cj_name": f"Website Profile Contact Not Found - {user_email}",
        "cr446_tasktype": 121510010,
        "cj_priority": 121510004,
        "cj_progress": 121510000,
        "cj_fulldescription": f"No Contact was Found for {user_email}.",
        "cj_AssignedTo@odata.bind": f"/systemusers({static_info['systemuserid']})"
    }

    try:
        response = _session.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print(f"✅ Internal Task Created for {user_email}")
    except requests.RequestException as e:
        print(f"❌ Failed to create internal task: {str(e)}")

def send_registration_email(user_email, static_info):
    """
    Sends an email to the user when no contact is found.
    """
    if not static_info:
        print(f"⚠️ Skipping email notification – No Webflow Query User found.")
        return

    subject = "Not Registered by GMA"
    message = f"Good day,\n\nNo records were found in GMA. Contact {static_info['fullname']} at {static_info['internalemailaddress']} for verification.\n\nRegards,\nThe GMA Team"

    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user_email], fail_silently=False)
        print(f"✅ Registration Email Sent to {user_email}")
    except Exception as e:
        print(f"❌ Failed to send registration email: {str(e)}")

def get_accounts_for_userprofile(userprofile_id, token):
    """
    Retrieve Account IDs linked to a User Profile via cj_userprofile_accountset.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofile_accountset?$filter=cj_userprofileid eq {userprofile_id}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Fetching Linked Accounts for User Profile: {url}")
        response = _session.get(url, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        data = response.json()

        accounts = [account["accountid"] for account in data.get("value", [])]

        print(f"✅ Retrieved {len(accounts)} Accounts for user profile {userprofile_id}.")
        return accounts

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Get Accounts for User Profile): {str(e)}")
        return []

def find_contact(id_number, email, mobile_number, token):
    """
    Searches for a contact in Dataverse using multiple fallback API calls.
    1. Search by ID number.
    2. Search by email and mobile number.
    3. Search by email only.
    Returns the first found contact ID or None if no contact is found.
    """
    
    # Step 1: Search Active Contacts with ID Number
    url_1 = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/contacts?$filter=cj_idnumber eq '{id_number}' and statecode eq 0&$select=contactid&$top=1"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Searching Contact by ID: {url_1}")
        response = _session.get(url_1, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            contact_id = data["value"][0]["contactid"]
            print(f"✅ Found Contact ID by ID Number: {contact_id}")
            return contact_id  # Return first found contact ID

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Search by ID): {str(e)}")

    # Step 2: Search Active Contacts with Email and Tel No
    url_2 = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/contacts?$filter=emailaddress1 eq '{email}' and mobilephone eq '{mobile_number}' and statecode eq 0&$select=contactid&$top=1"

    try:
        print(f"📤 Searching Contact by Email and Mobile: {url_2}")
        response = _session.get(url_2, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            contact_id = data["value"][0]["contactid"]
            print(f"✅ Found Contact ID by Email and Mobile: {contact_id}")
            return contact_id  # Return first found contact ID

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Search by Email and Mobile): {str(e)}")

    # Step 3: Search Contacts with Email Only (Fallback)
    url_3 = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/contacts?$filter=emailaddress1 eq '{email}' and statecode eq 0&$select=contactid&$top=5"

    try:
        print(f"📤 Searching Contact by Email Only: {url_3}")
        response = _session.get(url_3, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            contact_ids = [contact["contactid"] for contact in data["value"]]
            print(f"✅ Found Contact IDs by Email: {contact_ids}")
            return contact_ids[0]  # Return the most recent contact ID

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Search by Email Only): {str(e)}")

    print("❌ No contact found in any search method.")
    return None  # Return None if no contact is found

def get_trustee_access(contact_id, token):
    """
    Searches the Trustee Table with contact ID.
    If the user exists in the trustee table, they get trustee access.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_gmabuilding_contact_trusteeconnectorset?$filter=contactid eq {contact_id}&$top=1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    try:
        response = _session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            print(f"✅ Trustee Access Granted: {contact_id}")
            return {"access": "trustee"}
        
        print("❌ No Trustee Access Found.")
        return {"access": "none"}

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Trustee Access): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def get_contractor_access(contact_id, token):
    """
    Searches the Contractor Table with contact ID.
    If the user exists in the contractor table, they get contractor access.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_contractors?$filter=_cj_owner_value eq {contact_id} and statecode eq 0&$select=cj_contractorid"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    try:
        response = _session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            print(f"✅ Contractor Access Granted: {contact_id}")
            return {"access": "contractor"}
        
        print("❌ No Contractor Access Found.")
        return {"access": "none"}

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Contractor Access): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def get_owner_access(email, contact_id, token):
    """
    Searches the Accounts Table with Email or Contact ID.
    If the user is found in the accounts table, they get owner access.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts?$filter=emailaddress1 eq '{email}' or _primarycontactid_value eq {contact_id} and statecode eq 0&$select=accountid"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    try:
        response = _session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            print(f"✅ Owner Access Granted: {contact_id} / {email}")
            return {"access": "owner"}
        
        print("❌ No Owner Access Found.")
        return {"access": "none"}

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Owner Access): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def determine_user_access(contact_id, email, token):
    """
    Determines and stores the user's access levels based on multiple API lookups.
    """
    if contact_id is None:
        print("⚠️ No contact ID found. User has no access levels.")
        return {
            "contact_id": None,
            "email": email,
            "access": [],
            "linked_accounts": [],
            "linked_contractors": []
        }

    access_levels = []
    linked_accounts = []
    linked_contractors = []

    # ✅ 1. Check for Active Accounts (Owner Access)
    url_accounts = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts?$filter=emailaddress1 eq '{email}' or _primarycontactid_value eq {contact_id} and statecode eq 0&$select=accountid"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    try:
        print("📤 Checking Active Accounts for Owner Access...")
        response = _session.get(url_accounts, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            linked_accounts = [account["accountid"] for account in data["value"]]
            access_levels.append("owner")
            print(f"✅ Owner Access Granted. Linked Accounts: {linked_accounts}")
        else:
            print("❌ No Owner Access Found.")

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Owner Access): {str(e)}")

    # ✅ 2. Check for Trustee Access
    url_trustee = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_gmabuilding_contact_trusteeconnectorset?$filter=contactid eq {contact_id}&$top=1"

    try:
        print("📤 Checking Trustee Access...")
        response = _session.get(url_trustee, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            access_levels.append("trustee")
            print("✅ Trustee Access Granted.")
        else:
            print("❌ No Trustee Access Found.")

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Trustee Access): {str(e)}")

    # ✅ 3. Check for Contractor Access
    url_contractor = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_contractors?$filter=_cj_owner_value eq {contact_id} and statecode eq 0&$select=cj_contractorid"

    try:
        print("📤 Checking Contractor Access...")
        response = _session.get(url_contractor, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            linked_contractors = [contractor["cj_contractorid"] for contractor in data["value"]]
            access_levels.append("contractor")
            print(f"✅ Contractor Access Granted. Linked Contractors: {linked_contractors}")
        else:
            print("❌ No Contractor Access Found.")

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Contractor Access): {str(e)}")

    # ✅ Store and return user access levels
    user_access = {
        "contact_id": contact_id,
        "email": email,
        "access": access_levels,
        "linked_accounts": linked_accounts,
        "linked_contractors": linked_contractors
    }

    print(f"🔹 Final User Access Levels: {user_access}")
    return user_access

def get_user_profile(user_profile_id, token):
    """
    Retrieves a user profile from Dataverse using the profile ID.
    
    Parameters:
    - user_profile_id (str): The ID of the user profile to retrieve.
    - token (str): The authentication token.
    
    Returns:
    - dict: User profile details if found, or an error message.
    """
    
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles?$filter=cj_userprofileid eq {user_profile_id}&$top=1"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"',
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Fetching User Profile for: {user_profile_id}")
        
        response = _session.get(url, headers=headers)
        
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        data = response.json()

        if data.get("value"):
            print(f"✅ Retrieved User Profile: {data['value'][0]}")
            return data["value"][0]  # Return the first user profile found

        print("❌ No User Profile Found.")
        return {"error": "User profile not found"}

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Get User Profile): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def update_user_profile(user_id, update_data, token):
    """
    Updates a user profile in Dataverse using their `cj_userprofileid`.
    
    Parameters:
    - user_id (str): The ID of the user profile to update.
    - update_data (dict): The fields to update (email, phone, ID number, etc.).
    - token (str): The authentication token.
    
    Returns:
    - dict: Success message if updated, error message otherwise.
    """
    
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_userprofiles({user_id})"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    try:
        print(f"📤 Updating User Profile: {user_id}")
        print(f"📦 Payload: {update_data}")

        response = _session.patch(url, json=update_data, headers=headers)
        
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        
        if response.status_code == 204:
            print(f"✅ User Profile Updated Successfully: {user_id}")
            return {"message": "User profile updated successfully"}
        else:
            return response.json()

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Update User Profile): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def get_account_details(account_id, token):
    """
    Retrieves account details from Dataverse using the account ID.
    
    Parameters:
    - account_id (str): The ID of the account to retrieve.
    - token (str): The authentication token.
    
    Returns:
    - dict: Account details if found, or an error message.
    """
    
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts({account_id})?$select=name,emailaddress1,telephone1,cj_registrationidpassport,address1_line1,address1_line2,address1_line3"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Fetching Account Details for: {account_id}")
        
        response = _session.get(url, headers=headers)
        
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")

        response.raise_for_status()
        data = response.json()

        print(f"✅ Retrieved Account Details: {data}")
        return data  # Returns the account details

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Get Account Details): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def update_account_info(account_id, update_data, token):
    """
    Updates account details in Dataverse using the account ID.
    
    Parameters:
    - account_id (str): The ID of the account to update.
    - update_data (dict): The fields to update (email, phone, registration ID, address, etc.).
    - token (str): The authentication token.
    
    Returns:
    - dict: Success message if updated, error message otherwise.
    """
    
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/accounts({account_id})"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0"
    }

    try:
        print(f"📤 Updating Account Info: {account_id}")
        print(f"📦 Payload: {update_data}")

        response = _session.patch(url, json=update_data, headers=headers)
        
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        
        if response.status_code == 204:
            print(f"✅ Account Info Updated Successfully: {account_id}")
            return {"message": "Account info updated successfully"}
        else:
            return response.json()

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error (Update Account Info): {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def get_levy_account_details_view(account_id, responsible_person_id, token):
    """
    Retrieves levy account details from Dataverse.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_gmaaccountnumbers({account_id})?$select=cj_sageaccountnumber,cj_gmaaccountnumberid,cj_agetotal,cj_doornumber,cj_billingaddress1,cj_billingaddress2,cj_billingaddress3,cj_agecurrent,cj_age30days,cj_age60days,cj_age90days,cj_age120days,cj_age150days,cj_age180days,cj_responsablepartyfullname,cj_legal,cj_activeaod,cj_sendfriendlyreminder"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        print(f"📤 Fetching Levy Account Details for Account ID: {account_id}")

        response = _session.get(url, headers=headers)
        print(f"🔄 Dataverse Response Status Code: {response.status_code}")
        print(f"🔽 Raw Response Content: {response.text}")  # Debugging

        response.raise_for_status()
        data = response.json()

        # **Fix: Check if response is a direct object, not an array**
        if data and "cj_gmaaccountnumberid" in data:
            print(f"✅ Successfully Retrieved Levy Account Details: {data}")
            return data  # Correctly return the single object

        print("❌ No Levy Account Found in Dataverse.")
        return {"error": "Levy account not found"}

    except requests.RequestException as e:
        print(f"❌ Dataverse API Error: {str(e)}")
        return {"error": f"Dataverse API error: {str(e)}"}

def update_friendly_reminder(levy_account_id, friendly_reminder, token):
    """
    Sends a PATCH request to update the Friendly Reminder setting in Dataverse.
    """
    url = f"https://gmacc.crm4.dynamics.com/api/data/v9.2/cj_gmaaccountnumbers({levy_account_id})"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json;odata.metadata=minimal",
        "OData-Version": "4.0",
    }
    payload = {
        "cj_sendfriendlyreminder": friendly_reminder,
    }
    
    try:
        response = _session.patch(url, headers=headers, json=payload)
        return response
    except requests.RequestException as e:
        return {"error": f"Dataverse API error: {str(e)}"}
    
def download_pdf_statement(email, contact_id, start_date, end_date, user_profile_id):
    """
    Requests a PDF statement from an external service and returns the response.

    Parameters:
    - email (str): The user's email address.
    - contact_id (str): The contact ID linked to the statement.
    - start_date (str): The start date for the statement period.
    - end_date (str): The end date for the statement period.
    - user_profile_id (str): The user profile ID requesting the statement.

    Returns:
    - dict: Response from the API or an error message.
    """
    
    url = "https://prod-235.westeurope.logic.azure.com:443/workflows/20fd3ee4d8f34f22a0dc2cd46404b9ff/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=i8HCRlS3NDZXQpt5-Q6sHztHY5YXdWDgXQ5H6EpAGSE"

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "Type": "AccNumbState",
        "End": "end",
        "email": email,
        "ID": contact_id,
        "from": start_date,
        "to": end_date,
        "userProfileID": user_profile_id
    }

    try:
        print(f"📤 Sending request to download PDF statement for Email: {email}")
        print(f"📦 Payload: {payload}")

        response = _session.post(url, json=payload, headers=headers)
        
        print(f"🔄 API Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ PDF statement request successful.")
            return response.json()  # Return API response (might contain download link)
        else:
            return response.json()

    except requests.RequestException as e:
        print(f"❌ API Error (Download PDF Statement): {str(e)}")
        return {"error": f"API error: {str(e)}"}

def download_excel_statement(email, contact_id, start_date, end_date, user_profile_id):
    """
    Requests an Excel statement from an external service and returns the response.

    Parameters:
    - email (str): The user's email address.
    - contact_id (str): The contact ID linked to the statement.
    - start_date (str): The start date for the statement period.
    - end_date (str): The end date for the statement period.
    - user_profile_id (str): The user profile ID requesting the statement.

    Returns:
    - dict: Response from the API or an error message.
    """
    
    url = "https://prod-73.westeurope.logic.azure.com:443/workflows/486474e82cfd4e26a831e171282bb59a/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SmMHwN-vqCyjt9bEA2f_orViEyCWDm9YCiH6ux71yJE"

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "Type": "AccNumbState",
        "End": "end",
        "email": email,
        "ID": contact_id,
        "from": start_date,
        "to": end_date,
        "userProfileID": user_profile_id
    }

    try:
        print(f"📤 Sending request to download Excel statement for Email: {email}")
        print(f"📦 Payload: {payload}")

        response = _session.post(url, json=payload, headers=headers)
        
        print(f"🔄 API Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Excel statement request successful.")
            return response.json()  # Return API response (might contain download link)
        else:
            return response.json()

    except requests.RequestException as e:
        print(f"❌ API Error (Download Excel Statement): {str(e)}")
        return {"error": f"API error: {str(e)}"}
