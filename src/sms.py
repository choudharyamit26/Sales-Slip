from twilio.rest import Client

#######TEST Credentials for fatortech twilio
# test_account_sid = 'ACf066c909ca372ae45c816bc3b6a7f484'
# test_auth_token = 'f469cbff870b601b3ef84763c19487ae'
# client = Client(test_account_sid, test_auth_token)

#######LIVE Credentials for fatortech twilio
account_sid = 'ACf02ece6f59b345778bdd512e693c8e3e'
auth_token = '427991ea9201b5e360ab49532d703157'
client = Client(account_sid, auth_token)
client.messages.create(
    body='Second message using twilio for fatortech',
    from_='+19412579649',
    to='+' + str(917678689353)
)
