# pylint: disable=broad-exception-caught, too-many-locals, import-self
"""CRUD Operation to handle keycloak users"""
from base64 import b64decode
import ast
import json
import logging
from urllib.parse import urljoin

from cryptography.hazmat.primitives import serialization
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException
import jwt
from jwt.exceptions import DecodeError, InvalidTokenError

import requests
from keycloak import KeycloakAdmin, KeycloakOpenID
from app.config import config
from app.models.keycloak import BaseKeyCloak
from app.crud.general import generate_id
from app.crud.smtp import send_email
from app.constant import CONTENT_TYPE, DISABLED_USER_STATUS

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{config['keycloak_url']}/realms/{config['keycloak_realm']}/protocol/openid-connect/token")



def keycloak_instance():
    """Initialize KeycloakAdmin instance"""
    keycloak_admin = KeycloakAdmin(server_url=config['keycloak_url'], client_id=config['keycloak_client_id'],
                                   client_secret_key=config['keycloak_client_secret'],
                                   realm_name=config['keycloak_realm'], verify=True)
    return keycloak_admin


def keycloak_openid_instance():
    """Initialize KeycloakOpenID instance"""
    keycloak_openid = KeycloakOpenID(
        server_url=config['keycloak_url'], client_id=config['keycloak_client_open_id'],
        realm_name=config['keycloak_realm'], client_secret_key=config['keycloak_client_secret'])
    return keycloak_openid


def roles_in_list(roles: dict):
    """Returns list of roles"""
    role_list = [role for role, value in roles.items() if value == 1]
    role_list = str(role_list)
    return role_list


def keycloak_create_user(data_in: BaseKeyCloak):
    """Creating a user in keycloak"""
    try:

        password = "ecg123"
        all_attributes = {}
        if data_in.roles:
            role_list = roles_in_list(data_in.roles)
            all_attributes["roles"] = role_list
        if data_in.sp_role:
            sp_role = [data_in.sp_role]
            all_attributes["sp_role"] = str(sp_role)
        if data_in.sa_role:
            sa_role = [data_in.sa_role]
            all_attributes["sa_role"] = str(sa_role)

        if data_in.cfid:
            all_attributes["cfid"] = data_in.cfid
        if data_in.service_provider_id:
            all_attributes["service_provider_id"] = data_in.service_provider_id

        all_attributes["user_id"] = data_in.user_id

        user_data = {
            'username': data_in.mobile,
            'email': data_in.email,
            'firstName': data_in.first_name,
            'lastName': data_in.last_name,
            'enabled': True,
            'attributes': all_attributes,
            'credentials': [
                {
                    'type': 'password',
                    'value': password,
                    'temporary': False
                }
            ]
        }

        keycloak_admin = keycloak_instance()
        created_user = keycloak_admin.create_user(user_data)
        return [created_user]
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["errorMessage"]
        return [None, error_message]


def get_keycloak_user(keycloak_user_id):
    """Get a user by keycloak user id"""
    try:
        keycloak_admin = keycloak_instance()
        user = keycloak_admin.get_user(keycloak_user_id)
        return user
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["error"]
        return error_message


def get_keycloak_users():
    """Get all users in the realm"""
    keycloak_admin = keycloak_instance()
    users = keycloak_admin.get_users()
    return users


def delete_all_keycloak_users():
    """Delete all the users in the keycloak"""
    keycloak_admin = keycloak_instance()
    all_users = get_keycloak_users()
    for user in all_users:
        keycloak_admin.delete_user(user['id'])
    return True


def delete_keycloak_user(keycloak_user_id):
    """Delete a user using keycloak user id"""
    try:
        keycloak_admin = keycloak_instance()
        keycloak_admin.delete_user(keycloak_user_id)
        return True
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["error"]
        return error_message


def update_keycloak_user(user_id: str, new_attributes: dict):
    """Update a user's attributes"""
    try:
        keycloak_admin = keycloak_instance()
        user = keycloak_admin.get_user(user_id)
        if 'roles' in new_attributes:
            user['attributes']['roles'] = roles_in_list(
                new_attributes['roles'])
        if 'email' in new_attributes:
            user['email'] = new_attributes['email']
        if 'mobile' in new_attributes:
            user['username'] = new_attributes['mobile']
        keycloak_admin.update_user(user_id, user)
        return True
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["error"]
        return error_message


async def update_keycloak_user_password(user_id: str):
    """Update a user's password"""
    try:
        keycloak_admin = keycloak_instance()
        user = keycloak_admin.get_user(user_id)
        recipient_email = user['email']
        new_temp_password = await generate_id(8)
        body = "This is your new temporary password to login: " + \
            str(new_temp_password)+'\n'+'\n'+'Regards,'+'\n'+'ECGVue Team'

        keycloak_admin.set_user_password(
            user_id=user_id, password=new_temp_password, temporary=True)
        success = send_email(recipient_email, body)
        if not success:
            raise HTTPException(status_code=403, detail="Mail was not send")
        return True
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["error"]
        return error_message


def update_keycloak_user_status(user_id: str, is_enabled: bool):
    """Update a user's attributes"""
    try:
        keycloak_admin = keycloak_instance()
        user = keycloak_admin.get_user(user_id)
        user['enabled'] = is_enabled
        keycloak_admin.update_user(user_id, user)
        return True
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["error"]
        return error_message

def get_user_by_token(token: str = Depends(oauth2_scheme)):
    """Get user details using token"""
    # import pdb; pdb.set_trace()
    try:
        data = keycloak_openid_instance()
        key_der_base64 = data.public_key()
        key_der = b64decode(key_der_base64.encode())
        public_key = serialization.load_der_public_key(key_der)
        user_base_detail = jwt.decode(token, public_key, algorithms=["RS256"], audience='account')

        keycloak_admin = keycloak_instance()

        # Check if the token is active
        if user_base_detail['sub']:
            user = keycloak_admin.get_user(user_base_detail['sub'])
            # Add user details as needed
            enabled = user.get("enabled")
            if not enabled:
                raise HTTPException(
                    status_code=401, detail=DISABLED_USER_STATUS)

            roles = user.get('attributes', {}).get('roles', [])
            roles = roles[0] if roles else None
            sp_role = user.get('attributes', {}).get('sp_role', [])
            sp_role = sp_role[0] if sp_role else None
            output_list_sp_role = ast.literal_eval(
                sp_role) if sp_role else None
            sp_role = output_list_sp_role[0] if sp_role else None
            cfid = user.get('attributes', {}).get('cfid', [])
            cfid = cfid[0] if cfid else None
            sa_role = user.get('attributes', {}).get('sa_role', [])
            sa_role = sa_role[0] if sa_role else None
            output_list = ast.literal_eval(sa_role) if sa_role else None
            sa_role = output_list[0] if sa_role else None
            service_provider_id = user.get(
                'attributes', {}).get('service_provider_id', [])
            if service_provider_id:
                service_provider_id = service_provider_id[0]

            print(user)
            print("+++++++++++++++++++++++++++++++++++++++++++")
            user_details = {
                'user_id': user['attributes']['user_id'][0],
                'email': user.get('email'),
                'username': user['username'],
                'first_name': user['firstName'],
                'last_name': user['lastName'],
                'roles': roles,
                'sp_role': sp_role,
                'cfid': cfid,
                'sa_role': sa_role,
                'service_provider_id': service_provider_id
            }

            return user_details
        raise HTTPException(
            status_code=401, detail="Invalid Token No user is matching with the given token")

    except (DecodeError, InvalidTokenError) as exception:
        # Handle the specific exception(s) raised by jwt.decode()
        raise HTTPException(
            status_code=401, detail="Invalid Token") from exception

    except HTTPException as exception:
        raise HTTPException(
            status_code=401, detail=exception.detail) from exception

    except Exception as exception:
        # Handle any exceptions that occur during the process
        raise HTTPException(
            status_code=401, detail=str(exception)) from exception


def create_token(username: str, password: str):
    """Creates token for given username and password"""
    try:
        keycloak_openid = keycloak_openid_instance()
        user_token = keycloak_openid.token(
            username=username, password=password, grant_type='password')
        return user_token['access_token']
    except Exception as exception:
        response_text = exception.args[0].decode('utf-8')
        response_json = json.loads(response_text)
        error_message = response_json["error_description"]
        return error_message
