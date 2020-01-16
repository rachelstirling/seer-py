"""
Module for handling authentication with Seer Cloud.

Copyright 2017 Seer Medical Pty Ltd, Inc. or its affiliates. All Rights Reserved.
"""

import getpass
import json
import os
import requests


class SeerAuth:
    """Class to handle authorising login to Seer Cloud"""
    home = os.path.expanduser('~')
    cookie_file = '/.seerpy/cookie'

    def __init__(self, api_url: str, email: str = None, password: str = None):
        self.api_url = api_url
        self.cookie = None

        self.read_cookie()
        if self.verify_login() == 200:
            print('Login Successful')
            return

        self.email = email
        self.password = password
        allowed_attempts = 3

        for i in range(allowed_attempts):
            if not self.email or not self.password:
                self.login_details()
            self.login()
            response = self.verify_login()
            if response == requests.codes.ok:  # pylint: disable=maybe-no-member
                print('Login Successful')
                break
            if i < allowed_attempts - 1:
                print('\nLogin error, please re-enter your email and password: \n')
                self.cookie = None
                self.password = None
            else:
                print('Login failed. please check your username and password or go to',
                      'app.seermedical.com to reset your password')
                self.cookie = None
                self.password = None
                raise InterruptedError('Authentication Failed')

    def login(self):
        """Log in to platform"""
        login_url = self.api_url + '/api/auth/login'
        body = {'email': self.email, 'password': self.password}
        response = requests.post(url=login_url, data=body)
        print("login status_code", response.status_code)
        if (response.status_code == requests.codes.ok  # pylint: disable=maybe-no-member
                and response.cookies):
            self.cookie = {'seer.sid': response.cookies['seer.sid']}
            # Save latest cookie locally
            self.write_cookie()
        else:
            self.cookie = None

    def verify_login(self):
        """Attempt to verify login using cookie details"""
        if self.cookie is None:
            return 401

        verify_url = self.api_url + '/api/auth/verify'
        response = requests.get(url=verify_url, cookies=self.cookie)
        if response.status_code != requests.codes.ok:  # pylint: disable=maybe-no-member
            print("API verify call returned", response.status_code, "status code")
            return 401

        json_response = response.json()
        if not json_response or not json_response['session'] == "active":
            print("API verify call did not return an active session")
            return 401

        return response.status_code

    def login_details(self):
        """Get email and password, either from credentials file or std in"""
        pswdfile = self.home + '/.seerpy/credentials'
        if os.path.isfile(pswdfile):
            with open(pswdfile, 'r') as f:
                lines = f.readlines()
                self.email = lines[0].rstrip()
                self.password = lines[1].rstrip()
        else:
            self.email = input('Email Address: ')
            self.password = getpass.getpass('Password: ')

    def write_cookie(self):
        """Write information from API response to 'cookie' file"""
        if not os.path.isdir(self.home + '/.seerpy'):
            os.mkdir(self.home + '/.seerpy')
        try:
            with open(self.home + self.cookie_file, 'w') as f:
                f.write(json.dumps(self.cookie))
        except Exception:  # pylint:disable=broad-except
            pass

    def read_cookie(self):
        """Read details from cookie file"""
        if os.path.isfile(self.cookie_file):
            with open(self.cookie_file, 'r') as f:
                self.cookie = json.loads(f.read().strip())

    def destroy_cookie(self):
        """Delete local cookie file"""
        if os.path.isfile(self.cookie_file):
            os.remove(self.cookie_file)
        self.cookie = None
