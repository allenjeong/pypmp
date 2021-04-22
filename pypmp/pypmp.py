#!/usr/bin/env python3
# coding: utf-8

import json
import logging

import requests


LOGGER = logging.getLogger(__name__)


class PasswordManagerProClient(object):
    def __init__(self, hostname, token, port=443, verify=True, debug=False):
        self.token = token
        self.verify = verify
        self.debug = debug
        self._API_URL = f"https://{hostname}:{port}/restapi/json/v1"
        self._PKI_API_URL = f"https://{hostname}:{port}/api/pki/restapi"

        if self.debug:
            LOGGER.setLevel(logging.DEBUG)

    def _pki_request(self, method, endpoint, raw=False, params=None, jdata=None):
        if not params:
            params = {}
        params["AUTHTOKEN"] = self.token
        if method == "get" and jdata:
            params.update({"INPUT_DATA": json.dumps(jdata)})
            jdata = None
        res = requests.request(
            method=method,
            url=f"{self._PKI_API_URL}/{endpoint}",
            data={"INPUT_DATA": json.dumps(jdata)} if jdata else None,
            params=params,
            verify=self.verify,
        )
        LOGGER.debug(f"URL: {res.url}\nRAW Response: {res.text}")
        res.raise_for_status()
        if raw:
            return res.text
        jres = res.json()
        LOGGER.info(f'Result: {jres["result"]}')
        if jres["result"]["status"] != "Success":
            LOGGER.warning(f'Request to {res.url} failed: {jres["result"]["message"]}')
        return jres

    def _rest_request(self, method, endpoint, raw=False, params=None, jdata=None):
        # Special acrobatics for GET since data is unsupported here
        # Used by generate_password
        if method == "get" and jdata:
            params = {"INPUT_DATA": json.dumps(jdata)}
            jdata = None

        res = requests.request(
            method=method,
            url=f"{self._API_URL}/{endpoint}",
            headers={"AUTHTOKEN": self.token, "Content-Type": "text/json"},
            data={"INPUT_DATA": json.dumps(jdata)} if jdata else None,
            params=params,
            verify=self.verify,
        )
        LOGGER.debug(f"RAW Response: {res.text}")
        res.raise_for_status()
        jres = res.json()
        LOGGER.info(f'Result: {jres["operation"]["result"]}')
        if jres["operation"]["result"]["status"] != "Success":
            LOGGER.warning(
                f'Request to {res.url} failed: {jres["operation"]["result"]["message"]}'
            )
            # Always return 'None' on both of failed and succeed of resource creation 
            return jres["operation"]["result"]["status"]
        return jres.get("operation", {}).get("Details")

    def _get(self, endpoint, params=None, jdata=None, pki_api=False, raw=False):
        if pki_api:
            return self._pki_request(
                method="get", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )
        else:
            return self._rest_request(
                method="get", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )

    def _post(self, endpoint, params=None, jdata=None, pki_api=False, raw=False):
        if pki_api:
            return self._pki_request(
                method="post", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )
        else:
            return self._rest_request(
                method="post", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )

    def _put(self, endpoint, params=None, jdata=None, pki_api=False, raw=False):
        if pki_api:
            return self._pki_request(
                method="put", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )
        else:
            return self._rest_request(
                method="put", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )

    def _delete(self, endpoint, params=None, jdata=None, pki_api=False, raw=False):
        if pki_api:
            return self._pki_request(
                method="delete", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )
        else:
            return self._rest_request(
                method="delete", endpoint=endpoint, params=params, jdata=jdata, raw=raw
            )

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getresource
    def get_resources(self):
        return self._get("resources")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getaccounts
    def get_accounts(self, resource_id):
        return self._get(f"resources/{resource_id}/accounts")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getaccountdetails
    def get_account(self, resource_id, account_id):
        return self._get(f"resources/{resource_id}/accounts/{account_id}")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getpwd
    def get_account_password(self, resource_id, account_id):
        data = self._get(f"resources/{resource_id}/accounts/{account_id}/password")
        return data.get("PASSWORD")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getid
    def get_account_and_resource_ids(self, resource_name, account_name):
        return self._get(
            endpoint="resources/getResourceIdAccountId",
            params={"RESOURCENAME": resource_name, "ACCOUNTNAME": account_name},
        )

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getresid
    def get_resource_id(self, resource_name):
        res = self._get(endpoint=f"resources/resourcename/{resource_name}")
        return res.get("RESOURCEID")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#createresource
    # Example custom_fields:
    # {"ACCOUNTCUSTOMFIELD": [
    #     {"CUSTOMLABEL": "Secure Account", "CUSTOMVALUE": "YES"}
    # ]}
    def create_resource(
        self,
        resource_name,
        account_name,
        password,
        resource_type="",
        notes="",
        url="",
        resourcegroupname="default",
        resource_password_policy="Strong",
        account_password_policy="Strong",
        ownername='admin',
        dnsname='',
        location='',
        custom_fields=None
    ):
        data = {
            "operation": {
                "Details": {
                    "RESOURCENAME": resource_name,
                    "ACCOUNTNAME": account_name,
                    "RESOURCETYPE": resource_type,
                    "PASSWORD": password,
                    "OWNERNAME": ownername,
                    "RESOURCEPASSWORDPOLICY": resource_password_policy,
                    "ACCOUNTPASSWORDPOLICY": account_password_policy,
                    "NOTES": notes,
                    "RESOURCEURL": url,
                    "DNSNAME": dnsname,
                    "LOCATION": location,
                    "RESOURCEGROUPNAME": resourcegroupname
                }
            }
        }
        # Add custom fields if set
        if custom_fields:
            data["operation"]["Details"].update(custom_fields)
        return self._post("resources", jdata=data)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#deletepmp
    def delete_resource(self, resource_id):
        return self._delete(f"resources/{resource_id}")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#faausers
    def get_associated_users(self):
        return self._get("getAllAssociatedUsers", pki_api=True)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getcert
    def get_certificate(self, common_name, serial_number=None):
        data = {"operation": {"Details": {"common_name": common_name}}}
        if serial_number:
            data["operation"]["Details"]["serial_number"] = serial_number
        return self._get("getCertificate", pki_api=True, raw=True, jdata=data)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getcertkeystore
    def get_certificate_keystore(self, common_name, serial_number=None):
        data = {"operation": {"Details": {"common_name": common_name}}}
        if serial_number:
            data["operation"]["Details"]["serial_number"] = serial_number
        return self._get("getCertificateKeyStore", pki_api=True, raw=True, jdata=data)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getcertpassphrase
    def get_certificate_passphrase(self, common_name, serial_number):
        data = {
            "operation": {
                "Details": {"common_name": common_name, "serial_number": serial_number}
            }
        }
        # Get the raw JSON response and extract the actual password from jres["result"]["message"]
        res = self._get("getCertificatePassphrase", pki_api=True, raw=True, jdata=data)
        jres = json.loads(res)
        msg = jres.get("result", {}).get("message", "")
        if "Private key passphrase of certificate" in msg:
            return msg.split(" ")[-1]

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getcertdetail
    def get_certificate_details(self, common_name):
        data = {"operation": {"Details": {"common_name": common_name}}}
        res = self._get("getCertificateDetails", pki_api=True, jdata=data)
        # We need to only return what's under the $cert_id key (eg. "1")
        fres = [res[k] for k in set(res.keys()) - set(["name", "result"])]
        return fres[0] if len(fres) == 1 else fres

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getallcert
    def get_all_certificates(self):
        res = self._get("getAllSSLCertificates", pki_api=True)
        return res.get("SSLCertificates")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getallcertexpiry
    def get_all_certificate_expiry(self):
        res = self._get("getAllSSLCertificates", pki_api=True)
        return res.get("SSLCertificates")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#createuser
    def create_user(
        self,
        username,
        password,
        first_name="",
        last_name="",
        full_name="",
        role="Password User",
        email="",
        department="",
        hostname="",
        location="",
        password_policy="Strong",
        api_user=False,
        superadmin=False,
        expiration="NeverExpires",
    ):
        # bool -> str
        superadmin = str(superadmin).lower()
        api_user = str(api_user).lower()

        data = {
            "operation": {
                "Details": {
                    "USERNAME": username,
                    "FIRSTNAME": first_name,
                    "LASTNAME": last_name,
                    "FULLNAME": full_name,
                    "EMAIL": email,
                    "POLICY": password_policy,
                    "ROLE": role,
                    "ISSUPERADMIN": superadmin,
                    "PASSWORD": password,
                    "DEPARTMENT": department,
                    "LOCATION": location,
                    "ISAPIUSER": api_user,
                    "HOSTNAME": hostname,
                    "EXPIRYDATE": expiration,
                }
            }
        }
        return self._post("user", jdata=data)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#deleteuser
    def delete_user(self, user_id):
        return self._delete(f"user/{user_id}")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getID
    def get_user_id(self, username):
        res = self._get(endpoint="user/getUserId", params={"USERNAME": username})
        return res.get("USERID") if res else None

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#unlockUser
    def unlock_user(self, username):
        return self._put(endpoint="user/unlock", params={"USERNAME": username})

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#lockUser
    def lock_user(self, username):
        return self._put(endpoint="user/lock", params={"USERNAME": username})

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#generatepswd
    def generate_password(self, password_policy="Strong"):
        data = {"operation": {"Details": {"POLICY": password_policy}}}
        res = self._get("passwords/generate", jdata=data)
        return res.get("PASSWORD") if res else None

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#fetchssh
    def get_ssh_keys(self):
        res = self._get("getAllSSHKeys", pki_api=True)
        return res.get("SSHKeys")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#fpssh
    # FIXME This API seems to be broken
    def get_ssh_key(self, name):
        data = {"operation": {"Details": {"keyName": name}}}
        # FIXME The doc states POST ¯\_(ツ)_/¯
        res = self._post("getSSHKey", pki_api=True)
        return res

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#exportssh
    # FIXME This API seems to be broken
    def export_ssh_key(self, name):
        data = {"operation": {"Details": {"keyName": name}}}
        # FIXME The doc states POST ¯\_(ツ)_/¯
        res = self._post("exportSSHKey", pki_api=True)
        return res

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getlist
    def get_password_requests(self):
        return self._get("accounts/passwordaccessrequests")

    # Shortcuts
    def get_resource_by_name(self, name):
        for res in self.get_resources():
            if res.get("RESOURCE NAME") == name:
                return res

    def get_account_by_name(self, resource_name, account_name):
        resource = self.get_resource_by_name(resource_name)
        for acc in [
            x
            for x in self.get_accounts(resource.get("RESOURCE ID")).get("ACCOUNT LIST")
        ]:
            if acc.get("ACCOUNT NAME") == account_name:
                return acc

    def get_password(self, resource_name, account_name):
        res = self.get_account_and_resource_ids(resource_name, account_name)
        return self.get_account_password(res.get("RESOURCEID"), res.get("ACCOUNTID"))

    def delete_user_by_username(self, username):
        user_id = self.get_user_id(username)
        return self.delete_user(user_id)

    def delete_resource_by_name(self, resource_name):
        resource_id = self.get_resource_id(resource_name)
        return self.delete_resource(resource_id)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#addaccounts
    # add account into existing resource
    def add_account(
        self, 
        username, 
        password, 
        resourceid,
        accountpasswordpolicy="Strong", 
        notes=""
        ):
        data = {
            "operation": {
                "Details": {
                    "ACCOUNTLIST": [
                        {
                            "ACCOUNTNAME": username,
                            "PASSWORD": password,
                            "ACCOUNTPASSWORDPOLICY": accountpasswordpolicy,
                            "NOTES": notes
                        }
                    ]
                }
            }
        }
        return self._post("resources/{}/accounts".format(resourceid), jdata=data)
