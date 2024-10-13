import jwt
import yaml
import bcrypt
import streamlit as st
from yaml.loader import SafeLoader
from datetime import datetime, timedelta
import extra_streamlit_components as stx
import streamlit.components.v1 as components
from googleapiclient.discovery import build
from google.oauth2 import service_account

_RELEASE = True

class Hasher:
    def __init__(self, passwords):
        """Create a new instance of "Hasher".
        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        Returns
        -------
        list
            The list of hashed passwords.
        """
        self.passwords = passwords

    def hash(self, password):
        """
        Parameters
        ----------
        password: str
            The plain text password to be hashed.
        Returns
        -------
        str
            The hashed password.
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def generate(self):
        """
        Returns
        -------
        list
            The list of hashed passwords.
        """
        hashedpw = []

        for password in self.passwords:
            hashedpw.append(self.hash(password))
        return hashedpw

class Authenticate:
    def __init__(self, names, usernames, passwords, cookie_name, key, key_rute, spreadsheet_id, sheet_page_name, email_column, password_column, name_column, cookie_expiry_days=30, max_lenth=1000, header=True):
        """Create a new instance of "Authenticate".
        Parameters
        ----------
        names: list
            The list of names of users.
        usernames: list
            The list of usernames in the same order as names.
        passwords: list
            The list of hashed passwords in the same order as names.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for passwordless reauthentication.
        key: str
            The key to be used for hashing the signature of the JWT cookie.
        cookie_expiry_days: int
            The number of days before the cookie expires on the client's browser.
        Returns
        -------
        str
            Name of authenticated user.
        boolean
            The status of authentication, None: no credentials entered, False: incorrect credentials, True: correct credentials.
        str
            Username of authenticated user.
        """
        self.names = names
        self.usernames = usernames
        self.passwords = passwords
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days
        self.key_rute = key_rute
        self.spreadsheet_id = spreadsheet_id
        self.sheet_page_name = sheet_page_name
        self.email_column = email_column
        self.password_column = password_column
        self.name_column = name_column
        self.max_length = max_lenth
        self.header = header
        self.cookie_manager = stx.CookieManager()


        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None

    def token_encode(self):
        """
        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode({'name':st.session_state['name'],
        'username':st.session_state['username'],
        'exp_date':self.exp_date}, self.key, algorithm='HS256')

    def token_decode(self):
        """
        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        try:
            return jwt.decode(self.token, self.key, algorithms=['HS256'])
        except:
            return False

    def exp_date(self):
        """
        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def check_pw(self):
        """
        Returns
        -------
        boolean
            The validation state for the input password by comparing it to the hashed password on disk.
        """
        return bcrypt.checkpw(self.password.encode(), self.passwords[self.index].encode())

    def login(self, form_name, location='main'):
        """Create a new instance of "authenticate".
        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of authenticated user.
        boolean
            The status of authentication, None: no credentials entered, False: incorrect credentials, True: correct credentials.
        str
            Username of authenticated user.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")

        if not st.session_state.get('authentication_status'):
            self.token = self.cookie_manager.get(self.cookie_name)
            if self.token is not None:
                self.token = self.token_decode()
                if self.token is not False:
                    if not st.session_state.get('logout'):
                        if self.token['exp_date'] > datetime.utcnow().timestamp():
                            if 'name' in self.token and 'username' in self.token:
                                st.session_state['name'] = self.token['name']
                                st.session_state['username'] = self.token['username']
                                st.session_state['authentication_status'] = True

            if st.session_state.get('authentication_status') != True:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')

                login_form.subheader(form_name)
                self.username = login_form.text_input('Email')
                st.session_state['username'] = self.username
                self.password = login_form.text_input('Password', type='password')

                # Create two columns for placing buttons side by side
                col1, col2 = login_form.columns(2)

                # Place the "Login" button in the first column
                login_clicked = col1.form_submit_button('Login')

                # Place the "Register" button in the second column
                register_clicked = col2.form_submit_button('Register')

                if login_clicked:
                    self.index = None
                    for i in range(len(self.usernames)):
                        if self.usernames[i] == self.username:
                            self.index = i
                    if self.index is not None:
                        try:
                            if self.check_pw():
                                st.session_state['name'] = self.names[self.index]
                                self.exp_date = self.exp_date()
                                self.token = self.token_encode()
                                self.cookie_manager.set(self.cookie_name, self.token,
                                                        expires_at=datetime.now() + timedelta(
                                                            days=self.cookie_expiry_days))
                                st.session_state['authentication_status'] = True
                            else:
                                st.session_state['authentication_status'] = False
                        except Exception as e:
                            print(e)
                    else:
                        st.session_state['authentication_status'] = False

                # Handle the "Register" button click
                if register_clicked:
                    st.session_state['register'] = True  # Flag for opening the registration window

            # Check if "Register" button was clicked and show registration form
            if st.session_state.get('register'):
                self.registration()

        return st.session_state.get('name'), st.session_state.get('authentication_status'), st.session_state.get(
            'username')

    def registration(self):
        """Display a registration form."""
        st.title("Register a New Account")
        new_username = st.text_input('Email')
        new_password = st.text_input('New Password', type='password')
        confirm_password = st.text_input('Confirm Password', type='password')

        if st.button('Submit'):
            if new_username in self.usernames:

                if new_password == confirm_password:
                    # Logic to register the new user (e.g., add to database)
                    sheets_interact(self.key_rute, self.spreadsheet_id, self.sheet_page_name, self.email_column, self.password_column, self.name_column).writte_passwords(confirm_password, new_username)
                    st.success('Registration successful! You can now log in.')
                else:
                    st.error("Passwords do not match. Please try again.")
            else:
                st.error("Your email is not in the database of the AAMA, please contact with a meber of the AAMA if you think that you should have an account to access to this privet page.")

    def logout(self, button_name, location='main'):
        """Creates a logout button.
        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")

        if location == 'main':
            if st.button(button_name):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None
        elif location == 'sidebar':
            if st.sidebar.button(button_name):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None

if not _RELEASE:

    #hashed_passwords = Hasher(['123', '456']).generate()

    with open('../config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    authenticator = Authenticate(
        config['credentials']['names'],
        config['credentials']['usernames'],
        config['credentials']['passwords'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days']
    )

    name, authentication_status, username = authenticator.login('Login', 'main')

    if authentication_status:
        authenticator.logout('Logout', 'main')
        st.write(f'Welcome *{name}*')
        st.title('Some content')
    elif authentication_status == False:
        st.error('Username/password is incorrect')
    elif authentication_status == None:
        st.warning('Please enter your username and password')

    # Alternatively you use st.session_state['name'] and
    # st.session_state['authentication_status'] to access the name and
    # authentication_status.

    # if st.session_state['authentication_status']:
    #     authenticator.logout('Logout', 'main')
    #     st.write(f'Welcome *{st.session_state["name"]}*')
    #     st.title('Some content')
    # elif st.session_state['authentication_status'] == False:
    #     st.error('Username/password is incorrect')
    # elif st.session_state['authentication_status'] == None:
    #     st.warning('Please enter your username and password')

class sheets_interact:
    def __init__(self,key_rute: str, spreadsheet_id: str,sheet_page_name: str, email_column: str ,password_column: str, name_column: str, max_lenth:int =1000, header:bool = True):
        self.key_rute = key_rute
        self.spreadsheet_id = spreadsheet_id
        self.sheet_page_name = sheet_page_name
        self.email_column = email_column
        self.password_column = password_column
        self.name_column = name_column
        self.max_length = max_lenth
        self.header = header



    def extract_all(self, extract_type:str):
        '''
        Devuelve una matriz y cada array es un string con el valor que contiene la celda del excel en el que se lee
        '''

        sheet_page_name = self.sheet_page_name
        max_lenth = self.max_length
        email_column = self.email_column
        password_column = self.password_column
        name_column = self.name_column

        SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
        KEY = self.key_rute
        # Escribe el ID de tu documento parte de la url entre /d/.../edit
        SPREADSHEET_ID = self.spreadsheet_id
        creds = service_account.Credentials.from_service_account_file(KEY, scopes=SCOPES)

        service = build('sheets', 'v4', credentials=creds)
        # El objeto sheets contendrá la hoja de excel con la que interactuaremos desde python
        sheet = service.spreadsheets()

        if self.header:
            lower_row = 2
        else:
            lower_row = 1
        # Llama a la api
        result = sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=str(sheet_page_name)+'!'+str(email_column)+str(lower_row)+':'+str(email_column)+str(max_lenth)).execute()
        length = len(flatten_list(result.get('values')))

        if extract_type == 'password':
            result = sheet.values().get(spreadsheetId=SPREADSHEET_ID,
                                        range=str(sheet_page_name)+'!'+str(password_column)+str(lower_row)+':'+str(password_column) + str(length + 1)).execute()
        elif extract_type == 'name':
            result = sheet.values().get(spreadsheetId=SPREADSHEET_ID,
                                        range=str(sheet_page_name)+'!'+str(name_column)+str(lower_row)+':'+str(name_column) + str(length + 1)).execute()
        elif extract_type == 'email':
            pass
        else:
            raise ValueError('You introduce a wrong extract type: The options of extract type are only "password", "name" or "email"')

        # Extraemos values del resultado
        values = flatten_list(result.get('values'))
        return values

    def writte_passwords(self, value, id):
        SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
        KEY = self.key_rute
        # Escribe el ID de tu documento parte de la url entre /d/.../edit
        SPREADSHEET_ID = self.spreadsheet_id
        creds = service_account.Credentials.from_service_account_file(KEY, scopes=SCOPES)

        service = build('sheets', 'v4', credentials=creds)
        # El objeto sheets contendrá la hoja de excel con la que interactuaremos desde python
        sheet = service.spreadsheets()

        # EL valor debe ser una matriz [[]]
        value_mat = [[hash(value)]]

        # Encuentra en qeu posición del excel debe escribir
        all_ids = self.extract_all('email')
        existing_email = False
        if self.header:
            lower_row = 2
        else:
            lower_row = 1
        for position_id, existing_id in enumerate(all_ids):

            if existing_id == id:
                existing_email = True
                # Llama a la api
                sheet.values().update(spreadsheetId=SPREADSHEET_ID,
                                      range=str(self.sheet_page_name)+'!'+ str(self.password_column) + str(position_id + lower_row),
                                      valueInputOption='USER_ENTERED',
                                      body={'values': value_mat}).execute()
            else:
                pass

        return existing_email

def extract_string(needed_list):
    return needed_list[0][0]

def flatten_list(needed_list):
    return [item[0] for item in needed_list]