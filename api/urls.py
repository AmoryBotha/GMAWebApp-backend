from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .views import (get_users, create_user, get_user_by_id, login, register_user, forgot_password, reset_password, get_owner_accounts, test_dataverse_auth,get_real_time_owner_accounts,api_find_contact,api_get_trustee_access,api_get_contractor_access,api_get_owner_access,
    api_determine_user_access,
    api_get_user_profile,
    api_update_user_profile,
    api_get_account_details,
    api_update_account_info,
    api_download_pdf_statement,
    api_download_excel_statement,
    api_get_user_profile_by_email,
    api_get_levy_account_details,
    api_update_friendly_reminder,
    )

def cors_preflight_response(request):
    response = JsonResponse({"message": "CORS preflight successful"})
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response["Access-Control-Allow-Headers"] = "*"
    return response

urlpatterns = [
    path('users/', get_users),
    path('users/create/', create_user),
    path('users/<int:user_id>/', get_user_by_id), 
    path('login/', login),
    path('register/', register_user),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/', reset_password, name='reset_password'),
    path('owner-accounts/', get_owner_accounts, name="owner-accounts"),
    path('owner-accounts-linked/', get_real_time_owner_accounts, name="owner-accounts-linked"),
    path('test-dataverse-auth/', test_dataverse_auth, name='test-dataverse-auth'),
    path('contact/find/', api_find_contact, name="find-contact"),
    path('contact/trustee-access/', api_get_trustee_access, name="get-trustee-access"),
    path('contact/contractor-access/', api_get_contractor_access, name="get-contractor-access"),
    path('contact/owner-access/', api_get_owner_access, name="get-owner-access"),
    path('contact/determine-access/', api_determine_user_access, name="determine-user-access"),
    
    path('user-profile/<str:user_profile_id>/', api_get_user_profile, name="get-user-profile"),
    path('user-profile/update/<str:user_id>/', api_update_user_profile, name="update-user-profile"),
    path('user-profile/email/<str:email>/', api_get_user_profile_by_email, name="get-user-profile-by-email"),


    path('account/<str:account_id>/', api_get_account_details, name="get-account-details"),
    path('account/update/<str:account_id>/', api_update_account_info, name="update-account-info"),

    path('levy-account/<str:levy_account_id>/<str:responsible_person_id>/', api_get_levy_account_details, name="get-levy-account-details"),
    path('update-friendly-reminder/<str:levy_account_id>/', api_update_friendly_reminder, name="update-friendly-reminder"),

    path('statement/download/pdf/', api_download_pdf_statement, name="download-pdf-statement"),
    path('statement/download/excel/', api_download_excel_statement, name="download-excel-statement"),

]