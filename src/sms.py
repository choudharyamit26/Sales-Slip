# from twilio.rest import Client
#
# #######TEST Credentials for fatortech twilio
# # test_account_sid = 'ACf066c909ca372ae45c816bc3b6a7f484'
# # test_auth_token = 'f469cbff870b601b3ef84763c19487ae'
# # client = Client(test_account_sid, test_auth_token)
#
# #######LIVE Credentials for fatortech twilio
# account_sid = 'ACf02ece6f59b345778bdd512e693c8e3e'
# auth_token = '427991ea9201b5e360ab49532d703157'
# client = Client(account_sid, auth_token)
# client.messages.create(
#     body='test message using twilio for fatortech',
#     from_='+19412579649',
#     # to='+' + str(966545184720)
#     to='+' + str(966509344498)
# )


import requests
country = +91
number = 7678689353
values = '''{{
"userName": "fatortech",
  "numbers": "{country}{number}",
  "userSender": "fatortech",
  "apiKey": "2b180dec7a0cb74e02f9ca525aab993e",
  "msg": "FOURTH TEST MESSAGE"
}}'''.format(country=str(country), number=str(number))
headers = {
    'Content-Type': 'application/json'
}
# values = values.format(country=str(country), number=str(number))
response = requests.post('https://www.msegat.com/gw/sendsms.php', data=values, headers=headers)

print(response.status_code)
print(response.headers)
print(response.json())
