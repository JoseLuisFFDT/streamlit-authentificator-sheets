# Streamlit-Authenticator [![Downloads](https://pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator)
A secure authentication module to validate user credentials in a Streamlit application.

## Installation

Streamlit-Authenticator-Sheets is distributed via [PyPI](https://pypi.org/project/streamlit-authenticator/):

```python
pip install streamlit-authenticator-sheets
```

## Example

Using Streamlit-Authenticator_Sheets is as simple as importing the module and calling it to verify your predefined users' credentials.

```python
import streamlit as st
import streamlit_authenticator as stauth
```

### 1. Hashing Passwords

* Initially define your users' names, usernames, plain text passwords, and reauthentication cookie settings in a YAML configuration file.

```python
credentials:
  names: ['John Smith', 'Rebecca Briggs']
  usernames: ['jsmith', 'rbriggs']
  passwords: ['123', '456'] # To be replaced with hashed passwords
cookie:
  name: 'some_cookie_name'
  key: 'some_signature_key'
  expiry_days: 30
```

* Then use the Hasher module to convert the plain text passwords to hashed passwords.

```python
hashed_passwords = stauth.Hasher(['123', '456']).generate()
```

Finally replace the plain text passwords in the configuration file with the hashed passwords.

### 2. Creating Login Widget

* Subsequently import the configuration file into your script to create an authentication object. Here you will need to enter a name for the JWT cookie that will be stored on the client's browser and used to reauthenticate the user without re-entering their credentials. In addition, you will need to provide any random key to be used to hash the cookie's signature. Finally, you will need to specify the number of days to use the cookie for, if you do not require passwordless reauthentication, you may set this to 0.

```python
with open('../config.yaml') as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config['credentials']['names'],
    config['credentials']['usernames'],
    config['credentials']['passwords'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days']
)
```

* Then finally render the login module as follows. Here you will need to provide a name for the login form, and specify where the form should be located i.e. main body or sidebar (will default to main body).

```python
name, authentication_status, username = authenticator.login('Login', 'main')
```
![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/login_form.PNG)

### 3. Authenticating Users

* You can then use the returned name and authentication status to allow your verified user to proceed to any restricted content. In addition, you have the ability to add an optional logout button at any location on your main body or sidebar (will default to main body).

```python
if authentication_status:
    authenticator.logout('Logout', 'main')
    st.write(f'Welcome *{name}*')
    st.title('Some content')
elif authentication_status == False:
    st.error('Username/password is incorrect')
elif authentication_status == None:
    st.warning('Please enter your username and password')
```

* Should you require access to the persistent name, authentication status, and username variables, you may retrieve them through Streamlit's session state using **st.session_state['name']**, **st.session_state['authentication_status']**, and **st.session_state['username']**. This way you can use Streamlit-Authenticator to authenticate users across multiple pages.

```python
if st.session_state['authentication_status']:
    authenticator.logout('Logout', 'main')
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state['authentication_status'] == False:
    st.error('Username/password is incorrect')
elif st.session_state['authentication_status'] == None:
    st.warning('Please enter your username and password')
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/logged_in.PNG)

Or prompt an unverified user to enter a correct username and password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/incorrect_login.PNG)

Please note that logging out will revert the authentication status to **None** and will delete the associated reauthentication cookie as well.

## Credits
- Mohamed Abdou for the highly versatile cookie manager in [Extra-Streamlit-Components](https://github.com/Mohamed-512/Extra-Streamlit-Components).
