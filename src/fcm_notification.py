from pyfcm import FCMNotification

push_service = FCMNotification(
    api_key="AAAApdN9byE:APA91bGpfuE8Pj2H8UAcnIu9G9syrPbnZPpWzlPcrtuKqRzo2ezztq2dT9B8PBkJ_ADqVAkcLCoAiz7PWrtza0_ohqLNBcXjt0XmkIjoSB6o_Afny8Fn7z8oqrjOfHDx8Mn24aHL5jLL")


# OR initialize with proxies

# proxy_dict = {
#     "http": "http://127.0.0.1"
# }
# push_service = FCMNotification(
#     api_key="AAAAfWTapmU:APA91bGQGqxcMJMF-RVQsbETEsiRS3Y0xTLIQS5Z4cUEOcZmQJ6casKERRJaNdDKBRiGEVaeRifp"
#             "-5CRX2S2423T_BVR8_5MPz1fQfXrYJHhmg-hCTPZ4NWaFnn0Fhm88QnJtsNJ5q5m",
#     proxy_dict=proxy_dict)


# Your api-key can be gotten from:  https://console.firebase.google.com/project/<project-name>/settings/cloudmessaging

# def send_to_one(registration_id, message_title, message_body, data_message):
def send_to_one(registration_id, data_message):
    # registration_id = "<device registration_id>"
    # message_title = "Uber update"
    # message_body = "Hi john, your customized news for today is ready"
    # data_message = {"New Booking": "You have a new task added to your Jobs", }
    # result = push_service.notify_single_device(registration_id, message_title, message_body, data_message)
    # print('------->>>>Data Message',data_message)
    result = push_service.single_device_data_message(
        registration_id=registration_id, data_message=data_message)
    print("<----------------------------------------------------->", result)


def send_another(registration_id, message_title, message_body, message_type):
    print(registration_id, message_title, message_body, message_type)
    result = push_service.notify_single_device(
        registration_id, message_body, message_title, message_type)
    print("<----------------------------------------------------->", result)


# Send to multiple devices by passing a list of ids.


def send_to_many(registration_ids, message_title, message_body, result):
    registration_ids = ["<device registration_id 1>",
                        "<device registration_id 2>"]
    message_title = "Uber update"
    message_body = "Hope you're having fun this weekend, don't forget to check today's news"
    # result = push_service.notify_multiple_devices(registration_ids=registration_ids, message_title=message_title, message_body=message_body)
    print("<---------------------------------------------------------->", result)
