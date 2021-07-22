import os
from random import randint

import pyqrcode
from django.core.files import File
from requests.structures import CaseInsensitiveDict

import requests
from django.core.mail import EmailMessage
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.generics import CreateAPIView, UpdateAPIView, ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK, HTTP_404_NOT_FOUND
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from twilio.rest import Client

from .fcm_notification import send_another, send_to_one
from .models import User, Settings, UserNotification, Otp, ScannedData, Merchant, Receipt, Category, OrderItem, FAQ, \
    TermsAndCondition, ContactUs, PrivacyPolicy, AboutUs, Branch, Banner
from .serializers import UserCreateSerializer, AuthTokenSerializer, ForgetPasswordSerializer, ChangePasswordSerializer, \
    UpdateNotificationSerializer, NotificationSerializer, OtpSerializer, UpdatePhoneSerializer, ScannedDataSerializer, \
    TermsandConditionSerializer, ContactUsSerializer, PrivacyPolicySerializer, LanguageSettingSerializer, \
    NotificationSettingSerializer, SettingsSerializer, FAQSerializer, LanguageSettingsSerializer, UpdateEmailSerializer


def remove_html_tags(text):
    """Remove html tags from a string"""
    import re
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)


class CheckPhoneNumber(APIView):

    def get(self, request, *args, **kwargs):
        phone_number = self.request.GET.get('phone_number')
        try:
            user = User.objects.get(phone_number=phone_number)
            if user:
                return Response(
                    {"message": "User with this phone number already exists", "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            print(e)
            return Response({"message": "No user is registered with this number", "status": HTTP_200_OK})


class CheckEmail(APIView):

    def get(self, request, *args, **kwargs):
        email = self.request.GET.get('email')
        try:
            user = User.objects.get(email=email)
            if user:
                return Response({"message": "User with this email already exists", "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            return Response({"message": "No user is registered with this email", "status": HTTP_200_OK})


@method_decorator(csrf_exempt, name='dispatch')
class UserCreateAPIView(CreateAPIView):
    """ Register a new user """
    serializer_class = UserCreateSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = UserCreateSerializer(data=request.data)
        first_name = self.request.data['first_name']
        last_name = self.request.data['last_name']
        email = self.request.data['email']
        # profile_pic = self.request.data.get('profile_pic' or None)
        profile_pic = self.request.data.get('profile_pic' or None)
        device_token = self.request.data.get('device_token' or None)
        device_type = self.request.data.get('device_type' or None)

        # profile_pic = self.request.data['profile_pic']
        # print(profile_pic)

        admin = User.objects.get(email='ereceipt@gmail.com')
        setting_obj = Settings.objects.get(user=admin)
        if setting_obj.notification:
            UserNotification.objects.create(
                to=admin,
                title='User Creation',
                body='A new user has registered on the platform'
            )
        password = self.request.data['password']
        confirm_password = self.request.data['confirm_password']
        country_code = self.request.data['country_code']
        phone_number = self.request.data['phone_number']
        if User.objects.filter(email=email):
            return Response({"message": "User with this email already exists", "status": HTTP_400_BAD_REQUEST})
        elif User.objects.filter(phone_number=phone_number):
            return Response({"message": "User with this phone number already exists", "status": HTTP_400_BAD_REQUEST})
        elif password != confirm_password:
            return Response({"message": "Password and Confirm Password did not match", "status": HTTP_400_BAD_REQUEST})
        if serializer.is_valid():
            user = User.objects.create(
                first_name=first_name,
                last_name=last_name,
                country_code=country_code,
                phone_number=phone_number,
                profile_pic=profile_pic,
                email=email.lower(),
                device_token=device_token
            )
            user.set_password(password)
            user.save()
            token = Token.objects.create(user=user)
            data = {
                "id": user.id,
                "first_name": first_name,
                "last_name": last_name,
                # "profile_pic":profile_pic,
                "email": email,
                "country_code": country_code,
                "phone_number": phone_number,
                "token": token.key
            }
            return Response({"message": "User created successfully", "status": HTTP_200_OK, "data": data})
        else:
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class LoginAPIView(ObtainAuthToken):
    """Create a new token for user"""
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        email = self.request.data['email']
        password = self.request.data['password']
        device_token = self.request.data['device_token']
        lang = self.request.data['lang']
        print('login---->>>>', device_token)
        try:
            if not email.isdigit():
                userObj = User.objects.get(email=email.lower())
                user_id = userObj.id
                check_pass = userObj.check_password(password)
                if check_pass:
                    token = Token.objects.get_or_create(user=userObj)
                    user_device_token = userObj.device_token
                    print('previous token ', user_device_token)
                    userObj.device_token = device_token
                    userObj.save(update_fields=['device_token'])
                    print('updated device token ', userObj.device_token)
                    token = token[0]
                    settings_obj = Settings.objects.get(user=userObj)
                    settings_obj.language = lang
                    settings_obj.save(update_fields=['language'])
                    data = {
                        "token": token.key,
                        "id": user_id,
                        "first_name": userObj.first_name,
                        "last_name": userObj.last_name,
                        "email": userObj.email,
                        "country_code": userObj.country_code,
                        "phone_number": userObj.phone_number
                    }
                    return Response({"message": "User logged in successfully", "data": data, "status": HTTP_200_OK})
                else:
                    return Response({"message": "Wrong password", "status": HTTP_400_BAD_REQUEST})
            else:
                userObj = User.objects.get(phone_number=email)
                user_id = userObj.id
                check_pass = userObj.check_password(password)
                if check_pass:
                    token = Token.objects.get_or_create(user=userObj)
                    user_device_token = userObj.device_token
                    print('previous token ', user_device_token)
                    userObj.device_token = device_token
                    userObj.save(update_fields=['device_token'])
                    settings_obj = Settings.objects.get(user=userObj)
                    settings_obj.language = lang
                    settings_obj.save(update_fields=['language'])
                    print('updated device token ', userObj.device_token)
                    token = token[0]
                    data = {
                        "token": token.key,
                        "id": user_id,
                        "first_name": userObj.first_name,
                        "last_name": userObj.last_name,
                        "email": userObj.email,
                        "country_code": userObj.country_code,
                        "phone_number": userObj.phone_number
                    }
                    return Response({"message": "User logged in successfully", "data": data, "status": HTTP_200_OK})
                else:
                    return Response({"message": "Wrong password", "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            print(e)
            return Response({"message": "User does not exists", "status": HTTP_400_BAD_REQUEST})


@method_decorator(csrf_exempt, name='dispatch')
class ForgetPasswordAPIView(CreateAPIView):
    """
    Forget password api.
    Enter phone number or email in phone number field to reset password.
    """
    serializer_class = ForgetPasswordSerializer

    def post(self, request, *args, **kwargs):
        data = self.request.data
        # country_code = data['country_code']
        phone_number = data['phone_number']
        password = data['password']
        confirm_password = data['confirm_password']
        if phone_number.isdigit():
            try:
                user = User.objects.get(phone_number=phone_number)
                if password == confirm_password:
                    user.set_password(password)
                    user.save()
                    return Response({"message": "Password updated successfully", "status": HTTP_200_OK})
                else:
                    return Response(
                        {"message": "Password and Confirm password did not match", "status": HTTP_400_BAD_REQUEST})
            except Exception as e:
                print(e)
                return Response({"message": "User does not exists", "status": HTTP_400_BAD_REQUEST})
        else:
            try:
                user = User.objects.get(email=phone_number)
                if password == confirm_password:
                    user.set_password(password)
                    user.save()
                    return Response({"message": "Password updated successfully", "status": HTTP_200_OK})
                else:
                    return Response(
                        {"message": "Confirm password and password does not match", "status": HTTP_400_BAD_REQUEST})
            except Exception as e:
                print(e)
                return Response({"message": "User does not exists", "status": HTTP_400_BAD_REQUEST})


@method_decorator(csrf_exempt, name='dispatch')
class ChangePasswordAPIView(UpdateAPIView):
    """Change password api"""
    queryset = User.objects.all()
    serializer_class = ChangePasswordSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)
        try:
            if serializer.is_valid():
                old_password = request.data["old_password"]
                new_password = request.data["new_password"]
                confirm_new_password = request.data["confirm_new_password"]
                lang_setting_obj = Settings.objects.get(user=user)
                if not user.check_password(old_password):
                    if lang_setting_obj.language == 'English':
                        return Response(
                            {"message": "Incorrect old password", "status": HTTP_400_BAD_REQUEST, "detail": ""})
                    else:
                        return Response(
                            {"message": "كلمة السر القديمة غير صحيحة", "status": HTTP_400_BAD_REQUEST, "detail": ""})
                elif new_password != confirm_new_password:
                    if lang_setting_obj.language == 'English':
                        return Response(
                            {"message": "Password and confirm password didn't match", "status": HTTP_400_BAD_REQUEST,
                             "detail": ""})
                    else:
                        return Response(
                            {"message": "كلمة المرور وتأكيد كلمة المرور غير متطابقتين", "status": HTTP_400_BAD_REQUEST,
                             "detail": ""})
                else:
                    user.set_password(new_password)
                    user.save()
                    admin = User.objects.get(email='ereceipt@gmail.com')
                    setting_obj = Settings.objects.get(user=admin)
                    if setting_obj.notification:
                        UserNotification.objects.create(
                            to=user,
                            title='Password Changed',
                            body='User with user id USER {} changed his/her passowrd'.format(
                                user.id)
                        )
                    user_setting_obj = Settings.objects.get(user=user)
                    if user_setting_obj.notification:
                        if user_setting_obj.language == 'English':
                            UserNotification.objects.create(
                                to=user,
                                title='Password Changed',
                                body='Password changed successfully',
                            )
                            fcm_token = user.device_token
                            # try:
                            #     data_message = {"data": {"title": "Password Changed",
                            #                              "body": "Password changed successfully",
                            #                              "type": "passwordUpdate"}}
                            #     respo = send_to_one(fcm_token, data_message)
                            #     print("FCM Response===============>0", respo)
                            #     # title = "Phone Number Update"
                            #     title = "Password Changed"
                            #     body = "Password changed successfully"
                            #     message_type = "passwordUpdate"
                            #     respo = send_another(
                            #         fcm_token, title, body, message_type)
                            #     print("FCM Response===============>0", respo)
                            # except:
                            #     pass
                        else:
                            UserNotification.objects.create(
                                to=user,
                                title='تم تغيير كلمة السر',
                                body='تم تغيير الرقم السري بنجاح',
                            )
                            fcm_token = user.device_token
                            # try:
                            #     data_message = {"data": {"title": "تم تغيير كلمة السر",
                            #                              "body": "تم تغيير الرقم السري بنجاح",
                            #                              "type": "تحديث كلمة المرور"}}
                            #     respo = send_to_one(fcm_token, data_message)
                            #     print("FCM Response===============>0", respo)
                            #     title = "تم تغيير كلمة السر"
                            #     body = "تم تغيير الرقم السري بنجاح"
                            #     message_type = "تحديث كلمة المرور"
                            #     respo = send_another(
                            #         fcm_token, title, body, message_type)
                            #     print("FCM Response===============>0", respo)
                            # except:
                            #     pass
                    else:
                        pass
                    # if hasattr(user, 'auth_token'):
                    #     user.auth_token.delete()
                    # token, created = Token.objects.get_or_create(user=user)
                    if lang_setting_obj.language == 'English':
                        return Response({"message": "Your Password has been changed successfully",
                                         "status": HTTP_200_OK, "detail": ""})
                    else:
                        return Response({"message": "تم تغيير كلمة المرور الخاصة بك بنجاح",
                                         "status": HTTP_200_OK, "detail": ""})
        except Exception as e:
            print(e)
            return Response({"message": serializer.errors, "status": HTTP_400_BAD_REQUEST, "detail": ""})


class Logout(APIView):

    def get(self, request, *args, **kwargs):
        # user = self.request.user
        request.user.auth_token.delete()
        return Response({"message": "Logged out successfully", "status": HTTP_200_OK})


class SendOtpEmail(APIView):
    serializer_class = OtpSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        otp = randint(100000, 999999)
        email = self.request.GET.get('email')
        try:
            user = self.request.user
            if user:
                otp = Otp.objects.create(user=user, otp=otp)
                email = EmailMessage(
                    'Your Password Reset OTP',
                    'OTP to reset password of your E-Receipt Account : ' +
                    str(otp.otp),
                    to=[email]
                )
                email.send()
                return Response({"message": "Otp sent", "status": HTTP_200_OK})
        except Exception as e:
            return Response({"message": "Failed to send OTP to specified email.Please check your E-Mail ID",
                             "status": HTTP_400_BAD_REQUEST})


class VerifyEmailOtp(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        otp = self.request.data['otp']
        try:
            otpObj = Otp.objects.get(otp=otp)
            # email = otpObj.user.email
            # userObj = User.objects.get(email=email)
            if int(otp) == otpObj.otp:
                # token = Token.objects.get_or_create(user=userObj)
                # token = token[0]
                otpObj.delete()
                return Response(
                    {"message": "Otp verified successfully", "status": HTTP_200_OK})
            else:
                return Response({"message": "Incorrect Otp", "status": HTTP_400_BAD_REQUEST})

        except Exception as e:
            print(e)
            return Response({"message": "Incorrect Otp", "status": HTTP_400_BAD_REQUEST})


class ResendOtp(APIView):
    serializer_class = OtpSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        otp = randint(100000, 999999)
        email = self.request.GET.get('email')
        try:
            user = self.request.user
            if user:
                otp = Otp.objects.create(user=user, otp=otp)
                email = EmailMessage(
                    'Your Password Reset OTP',
                    'OTP to reset password of your E-Receipt Account : ' +
                    str(otp.otp),
                    to=[email]
                )
                email.send()
                return Response({"message": "Otp sent", "status": HTTP_200_OK})
        except Exception as e:
            return Response({"message": "Failed to send OTP to specified email.Please check your E-Mail ID",
                             "status": HTTP_400_BAD_REQUEST})


class GetNotificationList(APIView):
    model = UserNotification
    serializer_class = NotificationSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    # queryset = UserNotification.objects.all()

    def get(self, request, *args, **kwargs):
        try:
            user = self.request.user
            # qs = UserNotification.objects.filter(to=user).filter(read=False)
            qs = UserNotification.objects.filter(to=user)
            return Response({"data": qs.values(), "status": HTTP_200_OK})
        except:
            return Response({"message": "User does not exists", "status": HTTP_400_BAD_REQUEST})


class UpdateNotification(APIView):
    model = UserNotification
    serializer_class = UpdateNotificationSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = UserNotification.objects.all()

    def get(self, request, *args, **kwargs):
        # serializer = NotificationSerializer(data=request.data)
        # instance = self.get_object()
        # instance.read = True
        # if serializer.is_valid():
        #     instance.save(update_fields=['read'])
        user = self.request.user
        # user = User.objects.get(to=user.id)
        notifications = UserNotification.objects.filter(
            to=user.id).filter(read=False)
        for obj in notifications:
            obj.read = True
            obj.save()
        return Response({"message": "Notification read successfully", "status": HTTP_200_OK})
        # else:
        #     return Response({"message": serializer.errors, "status": HTTP_400_BAD_REQUEST})


class NotificationCount(APIView):
    model = UserNotification
    serializer_class = UpdateNotificationSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = UserNotification.objects.all()

    def get(self, request, *args, **kwargs):
        user = self.request.user
        notifications = UserNotification.objects.filter(
            to=user.id).filter(read=False).count()
        return Response(
            {'message': 'Notification count fetched successfully', 'count': notifications, 'status': HTTP_200_OK})


class DeleteNotification(APIView):
    model = UserNotification
    serializer_class = NotificationSerializer
    queryset = UserNotification.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user = self.request.user
        id = self.request.data['id']
        obj = UserNotification.objects.get(id=id)
        lang_setting_obj = Settings.objects.get(user=user)
        if obj:
            obj.delete()
            if lang_setting_obj.language == 'English':
                return Response({"message": "Notification deleted successfully", "status": HTTP_200_OK})
            else:
                return Response({"message": "تم حذف الإخطار بنجاح", "status": HTTP_200_OK})
        else:
            if lang_setting_obj.language == 'English':
                return Response(
                    {"message": "Notification with this id does not exists", "status": HTTP_400_BAD_REQUEST})
            else:
                return Response({"message": "إعلام بهذا المعرف غير موجود", "status": HTTP_400_BAD_REQUEST})


@method_decorator(csrf_exempt, name='dispatch')
class GetUserDetailApiView(APIView):
    """Logged in users detail"""
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.GET.get('id')
        try:
            userObj = User.objects.get(id=user)
            if userObj.profile_pic:
                if userObj.email.isdigit():
                    userdetail = {
                        'id': userObj.id,
                        'first_name': userObj.first_name,
                        'last_name': userObj.last_name,
                        'email': '',
                        'country_code': userObj.country_code,
                        'phone_number': userObj.email,
                        'profile_pic': userObj.profile_pic.url,
                    }
                    return Response({"data": userdetail, "status": HTTP_200_OK, "detail": ""})
                else:
                    userdetail = {
                        'id': userObj.id,
                        'first_name': userObj.first_name,
                        'last_name': userObj.last_name,
                        'email': userObj.email,
                        'country_code': userObj.country_code,
                        'phone_number': userObj.phone_number,
                        'profile_pic': userObj.profile_pic.url,
                    }
                    return Response({"data": userdetail, "status": HTTP_200_OK, "detail": ""})
            else:
                if userObj.email.isdigit():
                    userdetail = {
                        'id': userObj.id,
                        'first_name': userObj.first_name,
                        'last_name': userObj.last_name,
                        'email': '',
                        'country_code': userObj.country_code,
                        'phone_number': userObj.email,
                        'profile_pic': '',
                    }
                    return Response({"data": userdetail, "status": HTTP_200_OK, "detail": ""})
                else:
                    userdetail = {
                        'id': userObj.id,
                        'first_name': userObj.first_name,
                        'last_name': userObj.last_name,
                        'email': userObj.email,
                        'country_code': userObj.country_code,
                        'phone_number': userObj.phone_number,
                        'profile_pic': '',
                    }
                    return Response({"data": userdetail, "status": HTTP_200_OK, "detail": ""})
        except Exception as e:
            return Response({"message": "User does not exists", "status": HTTP_400_BAD_REQUEST, "detail": ""})


class UpdateUserDetailApiView(UpdateAPIView):
    """Update users  details"""
    serializer_class = UpdatePhoneSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = User.objects.all()

    def update(self, request, *args, **kwargs):
        try:
            user = self.request.user
            print(user)
            # if user:
            lang_setting_obj = Settings.objects.get(user=user)
            print(lang_setting_obj)
            serializer = UpdatePhoneSerializer(data=request.data)
            instance = self.get_object()
            # user = User.objects.get(id=instance.id)
            # instance.country_code = request.data.get('country_code')
            instance.email = request.data.get('email')
            instance.first_name = request.data.get('first_name')
            instance.last_name = request.data.get('last_name')
            # instance.country_code = request.data.get('country_code')
            # instance.phone_number = request.data.get('phone_number')
            instance.profile_pic = request.data.get('profile_pic')
            if serializer.is_valid():
                if request.data.get('profile_pic') is not None:
                    print('_____________inside if ', request.data.get('profile_pic'))
                    instance.save(
                        update_fields=['email', 'first_name', 'last_name', 'profile_pic'])
                else:
                    print('_____________inside else ', request.data.get('profile_pic'))
                    instance.save(
                        update_fields=['email', 'first_name', 'last_name'])

                # if Settings.user == user and Settings.notification:
                admin = User.objects.get(email='ereceipt@gmail.com')
                setting_obj = Settings.objects.get(user=admin)
                if setting_obj.notification:
                    UserNotification.objects.create(
                        to=admin,
                        title='Profile Update',
                        body='User with user id USER {} updated his/her profile'.format(
                            user.id),
                    )
                user_setting_obj = Settings.objects.get(user=user)
                if user_setting_obj.notification:
                    if user_setting_obj.language == 'English':
                        UserNotification.objects.create(
                            to=user,
                            title='Profile Update',
                            body='Your profile has been updated successfully',
                        )
                        fcm_token = user.device_token
                        try:
                            data_message = {"data": {"title": "Profile Update",
                                                     "body": "Your profile has been updated successfully",
                                                     "type": "profileUpdate"}}
                            # data_message = json.dumps(data_message)
                            title = "Profile Update"
                            body = "Your profile has been updated successfully"
                            message_type = "profileUpdate"
                            respo = send_another(
                                fcm_token, title, body, message_type)
                            respo = send_to_one(fcm_token, data_message)
                            print("FCM Response===============>0", respo)
                            # title = "Profile Update"
                            # body = "Your profile has been updated successfully"
                            # respo = send_to_one(fcm_token, title, body)
                            # print("FCM Response===============>0", respo)
                        except:
                            pass
                    else:
                        UserNotification.objects.create(
                            to=user,
                            title='تحديث الملف الشخصي',
                            body='تم تحديث ملفك الشخصي بنجاح',
                        )
                        fcm_token = user.device_token
                        try:
                            data_message = {"data": {"title": "تحديث الملف الشخصي",
                                                     "body": "تم تحديث ملفك الشخصي بنجاح",
                                                     "type": "تحديث"}}
                            # data_message = json.dumps(data_message)
                            respo = send_to_one(fcm_token, data_message)
                            title = "تحديث الملف الشخصي"
                            body = "تم تحديث ملفك الشخصي بنجاح"
                            message_type = "تحديث"
                            respo = send_another(
                                fcm_token, title, body, message_type)
                            print("FCM Response===============>0", respo)
                        except:
                            pass
                else:
                    pass
                if lang_setting_obj.language == 'English':
                    if instance.profile_pic.url is not None:
                        data = {
                            "id": instance.id,
                            "first_name": instance.first_name,
                            "last_name": instance.last_name,
                            "profile_pic": instance.profile_pic.url,
                            "email": instance.email,
                            "country_code": instance.country_code,
                            "phone_number": instance.phone_number,
                            # "token": token.key
                        }
                        return Response(
                            {"message": "Profile updated successfully", "status": HTTP_200_OK, "data": data})
                    else:
                        data = {
                            "id": instance.id,
                            "first_name": instance.first_name,
                            "last_name": instance.last_name,
                            # "profile_pic": instance.profile_pic.url,
                            "email": instance.email,
                            "country_code": instance.country_code,
                            "phone_number": instance.phone_number,
                            # "token": token.key
                        }
                else:
                    if instance.profile_pic.url is not None:
                        data = {
                            "id": instance.id,
                            "first_name": instance.first_name,
                            "last_name": instance.last_name,
                            "profile_pic": instance.profile_pic.url,
                            "email": instance.email,
                            "country_code": instance.country_code,
                            "phone_number": instance.phone_number,
                            # "token": token.key
                        }
                        return Response({"message": "تم تحديث الملف الشخصي بنجاح", "status": HTTP_200_OK, "data": data})
                    else:

                        data = {
                            "id": instance.id,
                            "first_name": instance.first_name,
                            "last_name": instance.last_name,
                            # "profile_pic": instance.profile_pic.url,
                            "email": instance.email,
                            "country_code": instance.country_code,
                            "phone_number": instance.phone_number,
                            # "token": token.key
                        }
                        return Response({"message": "تم تحديث الملف الشخصي بنجاح", "status": HTTP_200_OK, "data": data})
            else:
                return Response({"message": serializer.errors, "status": HTTP_400_BAD_REQUEST})
            # else:
            #     return Response({"message": "User does not exists", "status": HTTP_404_NOT_FOUND})
        except Exception as e:
            print(e)
            x = {"Error": str(e)}
            return Response({"message": x["Error"], "status": HTTP_400_BAD_REQUEST})


class UpdatePhoneNumberView(UpdateAPIView):
    """Update users phone number """
    serializer_class = UpdatePhoneSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = User.objects.all()

    def update(self, request, *args, **kwargs):
        try:
            user = self.request.user
            lang_setting_obj = Settings.objects.get(user=user)
            serializer = UpdatePhoneSerializer(data=request.data)
            instance = self.get_object()
            instance.country_code = request.data.get('country_code')
            instance.phone_number = request.data.get('phone_number')
            if serializer.is_valid():
                instance.save(
                    update_fields=['country_code', 'phone_number'])
                # if Settings.user == user and Settings.notification:
                admin = User.objects.get(email='ereceipt@gmail.com')
                setting_obj = Settings.objects.get(user=admin)
                if setting_obj.notification:
                    UserNotification.objects.create(
                        to=admin,
                        title='Phone Number Update',
                        body='User with user id USER {} updated his/her phone number'.format(
                            user.id)
                    )
                user_setting_obj = Settings.objects.get(user=user)
                if user_setting_obj.notification:
                    if user_setting_obj.language == 'English':
                        UserNotification.objects.create(
                            to=user,
                            title='Phone Number Update',
                            body='Your phone number has been updated successfully',
                        )
                        fcm_token = user.device_token
                        try:
                            data_message = {"data": {"title": "Phone Number Update",
                                                     "body": "Your phone number has been updated successfully",
                                                     "type": "phoneNumberUpdate"}}
                            respo = send_to_one(fcm_token, data_message)
                            print("FCM Response===============>0", respo)
                            title = "Phone Number Update"
                            body = "Your phone number has been updated successfully"
                            message_type = "phoneNumberUpdate"
                            respo = send_another(
                                fcm_token, title, body, message_type)
                            print("FCM Response===============>0", respo)
                        except:
                            pass
                    else:
                        UserNotification.objects.create(
                            to=user,
                            title='تحديث رقم الهاتف',
                            body='تم تحديث رقم هاتفك بنجاح',
                        )
                        fcm_token = user.device_token
                        try:
                            data_message = {"data": {"title": "تحديث رقم الهاتف",
                                                     "body": "تم تحديث رقم هاتفك بنجاح",
                                                     "type": "تحديث رقم الهاتف"}}
                            respo = send_to_one(fcm_token, data_message)
                            print("FCM Response===============>0", respo)
                            title = "تحديث رقم الهاتف"
                            body = "تم تحديث رقم هاتفك بنجاح"
                            message_type = "تحديث رقم الهاتف"
                            respo = send_another(
                                fcm_token, title, body, message_type)
                            print("FCM Response===============>0", respo)
                        except:
                            pass
                else:
                    pass
                if lang_setting_obj.language == 'English':
                    data = {'country_code': instance.country_code, 'phone_number': instance.phone_number}
                    return Response(
                        {"message": "Phone number updated successfully", 'data': data, "status": HTTP_200_OK})
                else:
                    data = {'country_code': instance.country_code, 'phone_number': instance.phone_number}
                    return Response({"message": "تم تحديث رقم الهاتف بنجاح", 'data': data, "status": HTTP_200_OK})
            else:
                return Response({"message": serializer.errors, "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            print(e)
            return Response({"message": "User does not exists", "status": HTTP_404_NOT_FOUND})


class ScannedDataView(CreateAPIView):
    model = ScannedData
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = ScannedDataSerializer(data=request.data)
        merchant = self.request.data['merchant']
        order = self.request.data['order']
        if serializer.is_valid():
            user = self.request.user
            merchant_obj = Merchant.objects.get(id=merchant)
            order_obj = Receipt.objects.get(id=order)
            scanned_data_obj = ScannedData.objects.create(
                user=user,
                merchant=merchant_obj,
                order=order_obj
            )
            # return Response({"data": serializer.data, "status": HTTP_200_OK})
            return Response({"message": "Data scanned successfully", "id": scanned_data_obj.id, "status": HTTP_200_OK})
        else:
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


class GetScannedDataDetail(ListAPIView):
    model = ScannedData

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        receipt_id = self.request.GET.get('id')
        try:
            receipt_object = {}
            receipt_obj = Receipt.objects.get(id=receipt_id)
            receipt_object['merchant'] = str(receipt_obj.branch.shop_no) + ',' + str(
                receipt_obj.branch.street) + ',' + str(receipt_obj.branch.landmark) + ',' + str(
                receipt_obj.branch.city) + ',' + str(receipt_obj.branch.postal_code)
            receipt_object['merchant_id'] = receipt_obj.merchant.id
            receipt_object['receipt_id'] = receipt_obj.id
            receipt_object['merchant_name'] = receipt_obj.merchant.full_name
            # receipt_object['merchant_category'] = receipt_obj.merchant.category.category_name
            receipt_object['user'] = receipt_obj.user.email
            receipt_object['created_at'] = receipt_obj.created_at
            # receipt_object.update({'merchant_id': receipt_obj.merchant})
            print(receipt_object)
            print(receipt_obj.merchant)
            i = 1
            total = 0
            product_list = []
            for obj in receipt_obj.order.all():
                # receipt_object.update({'product_{}'.format(i): obj.product})
                # receipt_object.update({'product_{}_price'.format(i): obj.price})
                # receipt_object.update({'product_{}_quantity'.format(i): obj.quantity})

                product_list.append({'product_name': obj.product, 'product_price': obj.price,
                                     'product_quantity': obj.quantity, 'product_vat': obj.vat,
                                     'product_vat_percent': obj.vat_percent})
                total = obj.total
                i += 1
                print(obj.id)
                print(obj.product)
                receipt_object['total'] = receipt_obj.total
                receipt_object['vat'] = receipt_obj.vat
                receipt_object['order_amount'] = receipt_obj.amount
                receipt_object['products'] = product_list
            # print(receipt_obj.created_at)
            # print(receipt_obj.user)
            return Response({'data': receipt_object, "status": HTTP_200_OK})
        except Exception as e:
            x = {"Error": str(e)}
            return Response({'error': x['Error'], "status": HTTP_400_BAD_REQUEST})


class GetUserTransactions(ListAPIView):
    model = ScannedData
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        receipt_obj = Receipt.objects.filter(user=user)
        receipt_list = []
        for obj in receipt_obj:
            data = {}
            data['receipt_id'] = obj.id
            data['merchant'] = obj.merchant.email
            data['merchant_id'] = obj.merchant.id
            data['merchant_name'] = obj.merchant.full_name
            # data['merchant_category'] = obj.merchant.category.category_name
            data['created_at'] = obj.created_at
            product_list = []
            for order_obj in obj.order.all():
                product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                     'product_quantity': order_obj.quantity, 'product_vat': order_obj.vat,
                                     'product_vat_percent': order_obj.vat_percent})
                data.update({'products': product_list})
            data.update({'total': obj.total})
            receipt_list.append(data)
        return Response({"data": receipt_list, 'message': 'Receipts fetched successfully', "status": HTTP_200_OK})


class ReceiptSearchView(ListAPIView):
    model = Receipt
    # model = ScannedData
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        receipt_id = self.request.GET.get('id')
        try:
            # receipt_obj = ScannedData.objects.get(id=receipt_id)
            receipt_obj = Receipt.objects.get(id=receipt_id)
            data_list = []
            data = {'id': receipt_obj.id, 'merchant': receipt_obj.merchant.email,
                    'merchant_id': receipt_obj.merchant.id, 'merchant_name': receipt_obj.merchant.full_name,
                    # 'merchant_category': receipt_obj.merchant.category.category_name,
                    'created_at': receipt_obj.created_at}
            total = 0
            vat = 0
            amount = 0
            i = 1
            c = 0
            for obj in receipt_obj.order.all():
                # data.update({'product_name': obj.product})
                # data.update({'product_price': obj.price})
                # data.update({'product_quantity': obj.quantity})
                # data.update({'product_{}_name'.format(i): obj.product})
                # data.update({'product_{}_price'.format(i): obj.price})
                # data.update({'product_{}_quantity'.format(i): obj.quantity})
                data_list.append(
                    {'product_name': obj.product, 'product_price': obj.price, 'product_quantity': obj.quantity,
                     'product_vat': obj.vat, 'product_vat_percent': obj.vat_percent})
                # data_list.append({'product_price': obj.price})
                # data_list.append({'product_quantity': obj.quantity})
                i += 1
                c = i
                total = receipt_obj.total
                vat = receipt_obj.vat
                amount = receipt_obj.amount
                # data.update({'total': obj.total})
            data.update({'order_amount': amount})
            data.update({'vat': vat})
            data.update({'total': total})
            # data_list.append(data)
            # data_list.append(data)

            print(data_list)
            return Response(
                {'data': data_list, "status": HTTP_200_OK, 'data2': data, "message": "Fetched data successfully"})
        except Exception as e:
            print(e)
            return Response({'message': "Data not found", "status": HTTP_400_BAD_REQUEST})


class FilterByCategory(ListAPIView):
    model = Receipt
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        category = self.request.GET.get('category')
        print(category)
        try:
            merchant_obj = Merchant.objects.filter(category=category)
            receipt_list = []
            for obj in merchant_obj:
                # print('Inside for loop ', obj)
                receipts = Receipt.objects.filter(user=self.request.user).filter(merchant=obj)
                print(receipts.count())
                if receipts.count() > 0:
                    # receipts_list.append(receipts)
                    total = 0
                    i = 1
                    j = 1
                    for x in receipts:
                        data = {}
                        # data['receipt_id_{}'.format(j)] = x.id
                        # data['merchant_id_{}'.format(j)] = x.merchant.id
                        # data['merchant_email_{}'.format(j)] = x.merchant.email
                        # data['created_at_{}'.format(j)] = x.created_at
                        data['receipt_id'] = x.id
                        data['merchant'] = x.merchant.email
                        data['merchant_id'] = x.merchant.id
                        data['merchant_name'] = x.merchant.full_name
                        # data['merchant_category'] = x.merchant.category.category_name
                        data['created_at'] = x.created_at
                        for order_obj in x.order.all():
                            # print(i)
                            product_list = []
                            product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                                 'product_quantity': order_obj.quantity, 'product_vat': order_obj.vat,
                                                 'product_vat_percent': order_obj.vat_percent})

                            data.update({'products': product_list})
                        data.update({'total': x.total})
                        receipt_list.append(data)
                        #     data.update({'receipt_id_{}_product_{}_name'.format(j, i): order_obj.product})
                        #     data.update({'receipt_id_{}_product_{}_price'.format(j, i): order_obj.price})
                        #     data.update({'receipt_id_{}_product_{}_quantity'.format(j, i): order_obj.quantity})
                        #     data.update({'total_{}'.format('receipt_id_{}'.format(j)): order_obj.total})
                        #     i += 1
                        # i = 1
                        # j += 1
                else:
                    pass
            return Response(
                {'data': receipt_list, 'message': 'Receipts filtered successfully by category', "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            return Response({"error": 'data not found', "status": HTTP_400_BAD_REQUEST})


class FilterByDate(ListAPIView):
    model = Receipt
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            from_date = self.request.GET.get('from_date')
            to_date = self.request.GET.get('to_date')
            print(from_date)
            print(to_date)
            receipt_obj = Receipt.objects.filter(user=self.request.user).filter(created_at__gte=from_date).filter(
                created_at__lte=to_date)
            print(receipt_obj.count())
            receipt_list = []
            if receipt_obj.count() > 0:
                # receipts_list.append(receipts)
                # total = 0
                i = 1
                j = 1
                for x in receipt_obj:
                    data = {}
                    # data['receipt_id_{}'.format(j)] = x.id
                    # data['merchant_id_{}'.format(j)] = x.merchant.id
                    # data['merchant_email_{}'.format(j)] = x.merchant.email
                    # data['created_at_{}'.format(j)] = x.created_at
                    data['receipt_id'] = x.id
                    data['merchant'] = x.merchant.email
                    data['merchant_id'] = x.merchant.id
                    data['merchant_name'] = x.merchant.full_name
                    # data['merchant_category'] = x.merchant.category.category_name
                    data['created_at'] = x.created_at
                    product_list = []
                    for order_obj in x.order.all():
                        # print(i)
                        product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                             'product_quantity': order_obj.quantity, 'product_vat': order_obj.vat,
                                             'product_vat_percent': order_obj.vat_percent})
                        data.update({'products': product_list})
                    data.update({'total': x.total})
                    receipt_list.append(data)
                    #     data.update({'receipt_id_{}_product_{}_name'.format(j, i): order_obj.product})
                    #     data.update({'receipt_id_{}_product_{}_price'.format(j, i): order_obj.price})
                    #     data.update({'receipt_id_{}_product_{}_quantity'.format(j, i): order_obj.quantity})
                    #     data.update({'total_{}'.format('receipt_id_{}'.format(j)): order_obj.total})
                    #     i += 1
                    # i = 1
                    # j += 1
            else:
                pass
            return Response(
                {'data': receipt_list, 'message': 'Receipts filtered successfully by date', "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            return Response({'error': "data not found", "status": HTTP_400_BAD_REQUEST})


class GetCategoryList(APIView):
    model = Category

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        return Response({'data': Category.objects.all().values(), 'status': HTTP_200_OK})


class AddToCart(CreateAPIView):
    model = OrderItem
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user = self.request.user
        merchant_id = self.request.data['merchant_id']
        category = self.request.data['category']
        date_of_purchase = self.request.data['date_of_purchase']
        time_of_purchase = self.request.data['time_of_purchase']
        # order_id = self.request.data['order_id']
        order_amount = self.request.data['order_amount']
        product_name = self.request.data['product_name']
        product_cost = self.request.data['product_cost']
        product_quantity = self.request.data['product_quantity']
        product_vat = self.request.data['product_vat']
        product_vat_percent = self.request.data['product_vat_percent']
        order_obj = OrderItem.objects.create(
            user=user,
            product=product_name,
            price=product_cost,
            quantity=product_quantity,
            total=order_amount,
            vat=product_vat,
            vat_percent=product_vat_percent
            # order_id=order_id
        )
        return Response({"message": "Item added successfully", "id": order_obj.id, "status": HTTP_200_OK})


class CreateReceiptManually(CreateAPIView):
    model = Receipt
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        # print('BODY DATA  ', self.request.data)
        print(self.request.data)
        # print(self.request)
        user = self.request.user
        merchant_id = self.request.data['merchant_id']
        merchant_name = self.request.data['merchant_name']
        category = self.request.data['category']
        date_of_purchase = self.request.data['date_of_purchase']
        time_of_purchase = self.request.data['time_of_purchase']
        # order_id = self.request.data['order_id']
        order_amount = self.request.data['order_amount']
        vat_amount = self.request.data['vat_amount']
        total_amount = self.request.data['total_amount']
        ordered_items = self.request.data['ordered_items']
        branch = self.request.data['branch']
        # customer_name = self.request.data['customer_name']
        # product_name = self.request.data['product_name']
        # product_cost = self.request.data['product_cost']
        # product_quantity = self.request.data['product_quantity']
        branch_obj = Branch.objects.get(code=branch)
        merchant_obj = Merchant.objects.get(id=merchant_id)
        if merchant_obj.blocked:
            lang_setting_obj = Settings.objects.get(user=user)
            if lang_setting_obj.language == 'English':
                return Response({'message': "Merchant with this id does not exists", 'status': HTTP_400_BAD_REQUEST})
            else:
                return Response({'message': "التاجر بهذا المعرف غير موجود", 'status': HTTP_400_BAD_REQUEST})
        elif branch_obj.blocked:
            lang_setting_obj = Settings.objects.get(user=user)
            if lang_setting_obj.language == 'English':
                return Response({'message': "Branch with this id does not exists", 'status': HTTP_400_BAD_REQUEST})
            else:
                return Response({'message': "الفرع بهذا المعرف غير موجود", 'status': HTTP_400_BAD_REQUEST})
        else:
            category_obj = Category.objects.get(id=category)
            print('branch-----------------', branch_obj)
            # final_item = zip(product_name, product_cost, product_quantity)
            # order_id = get_random_string(16)
            # for item in final_item:
            #     order_obj = OrderItem.objects.create(
            #         user=user,
            #         product=item[0],
            #         price=item[1],
            #         quantity=item[2],
            #         total=order_amount,
            #         order_id=order_id
            #     )
            # ordered_items = OrderItem.objects.filter(order_id=order_id)
            receipt_obj = Receipt.objects.create(
                user=self.request.user,
                merchant=merchant_obj,
                total=total_amount,
                vat=vat_amount,
                amount=order_amount,
                branch=branch_obj
            )
            for item in ordered_items:
                receipt_obj.order.add(OrderItem.objects.get(id=item))
            scanned_data_obj = ScannedData.objects.create(
                user=self.request.user,
                merchant=merchant_obj,
                order=receipt_obj
            )

            lang_setting_obj = Settings.objects.get(user=user)
            if lang_setting_obj.language == 'English':
                return Response({"message": "Order created successfully", 'id': receipt_obj.id, "status": HTTP_200_OK})
            else:
                return Response({"message": "تم إنشاء الطلب بنجاح", 'id': receipt_obj.id, "status": HTTP_200_OK})


class GetLatestTransactions(ListAPIView):
    model = Receipt
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        receipts = Receipt.objects.filter(user=user)
        # print(receipts[::-1])
        if receipts.count() > 2:
            # for receipt in receipts[:5:-1]:
            #     print(receipt.created_at)
            # i = 1
            # j = 1
            receipt_list = []
            c = receipts.count()
            for x in receipts[(c - 2):]:
                data = {}
                data['receipt_id'] = x.id
                data['merchant_id'] = x.merchant.id
                data['merchant_name'] = x.merchant.full_name
                # data['merchant_category'] = x.merchant.category.category_name
                data['merchant_email'] = x.merchant.email
                data['created_at'] = x.created_at
                product_list = []
                for order_obj in x.order.all():
                    # print(i)
                    # data.update({'receipt_id_{}_product_{}_name'.format(j, i): order_obj.product})
                    # data.update({'receipt_id_{}_product_{}_price'.format(j, i): order_obj.price})
                    # data.update({'receipt_id_{}_product_{}_quantity'.format(j, i): order_obj.quantity})
                    # data.update({'total_{}'.format('receipt_id_{}'.format(j)): order_obj.total})
                    product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                         'product_quantity': order_obj.quantity, 'product_vat': order_obj.vat,
                                         'product_vat_percent': order_obj.vat_percent})
                    data.update({'products': product_list})
                data.update({'total': x.total})
                receipt_list.append(data)
        else:
            receipt_list = []
            for x in receipts[::-1]:
                data = {}
                data['receipt_id'] = x.id
                data['merchant_id'] = x.merchant.id
                data['merchant_name'] = x.merchant.full_name
                # data['merchant_category'] = x.merchant.category.category_name
                data['merchant_email'] = x.merchant.email
                data['created_at'] = x.created_at
                product_list = []
                for order_obj in x.order.all():
                    # print(i)
                    # data.update({'receipt_id_{}_product_{}_name'.format(j, i): order_obj.product})
                    # data.update({'receipt_id_{}_product_{}_price'.format(j, i): order_obj.price})
                    # data.update({'receipt_id_{}_product_{}_quantity'.format(j, i): order_obj.quantity})
                    # data.update({'total_{}'.format('receipt_id_{}'.format(j)): order_obj.total})
                    product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                         'product_quantity': order_obj.quantity, 'product_vat': order_obj.vat,
                                         'product_vat_percent': order_obj.vat_percent})

                    data.update({'products': product_list})
                data.update({'total': x.total})
                receipt_list.append(data)
                # i += 1
                # i = 1
                # j += 1
        return Response(
            {"data": receipt_list, 'message': "Latest receipts fetched successfully", "status": HTTP_200_OK})


class FAQApiView(ListAPIView):
    """App's Faq api"""
    model = FAQ
    serializer_class = FAQSerializer
    queryset = FAQ.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        lang_setting_obj = Settings.objects.get(user=user)
        faq = FAQ.objects.all().order_by('id')
        # faq = remove_html_tags(faq)
        x = []
        if lang_setting_obj.language == 'English':
            for object in faq:
                data = {
                    'id': object.id,
                    'question': remove_html_tags(object.question),
                    'answer': remove_html_tags(object.answer)
                }
                x.append(data)
            print(x)
            return Response({"data": x, "status": HTTP_200_OK})
        else:
            for object in faq:
                data = {
                    'id': object.id,
                    'question': remove_html_tags(object.question_in_arabic),
                    'answer': remove_html_tags(object.answer_in_arabic)
                }
                x.append(data)
            return Response({"data": x, "status": HTTP_200_OK})


@method_decorator(csrf_exempt, name='dispatch')
class ChangeNotificationApiView(UpdateAPIView):
    """ Change User's notification settings """
    serializer_class = NotificationSettingSerializer
    queryset = Settings.objects.all()


@method_decorator(csrf_exempt, name='dispatch')
class ChangeLanguageApiView(UpdateAPIView):
    """Change User's language settings"""
    serializer_class = LanguageSettingSerializer
    queryset = Settings.objects.all()


class UpdateUserNotificationSettingsApi(UpdateAPIView):
    model = Settings
    serializer_class = SettingsSerializer
    queryset = Settings.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def update(self, request, *args, **kwargs):
        try:
            user = self.request.user
            print(user)
            lang_setting_obj = Settings.objects.get(user=user)
            print(lang_setting_obj)
            serializer = SettingsSerializer(data=request.data)
            instance = self.get_object()
            print(request.data.get('notification'))
            notification = request.data.get('notification')
            instance.notification = notification
            # instance.notification = notification.capitalize()
            if serializer.is_valid():
                instance.save(
                    update_fields=['notification'])
                if lang_setting_obj.language == 'English':
                    return Response({"message": "Notification setting updated successfully", "status": HTTP_200_OK})
                else:
                    return Response({"message": "تم تحديث إعداد الإعلام بنجاح", "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            x = {"Error": str(e)}
            return Response({"message": x['Error'], "status": HTTP_400_BAD_REQUEST})


class UpdateUserLanguageSettingApiView(UpdateAPIView):
    model = Settings
    serializer_class = LanguageSettingsSerializer
    queryset = Settings.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def update(self, request, *args, **kwargs):
        try:
            user = self.request.user
            lang_setting_obj = Settings.objects.get(user=user)
            serializer = LanguageSettingsSerializer(data=request.data)
            instance = self.get_object()
            language = request.data.get('language')
            instance.language = language.capitalize()
            if serializer.is_valid():
                instance.save(
                    update_fields=['language'])
                if lang_setting_obj.language == 'English':
                    return Response({"message": "Language setting updated successfully", "status": HTTP_200_OK})
                else:
                    return Response({"message": "تم تحديث إعداد اللغة بنجاح", "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            x = {"Error": str(e)}
            return Response({"message": x['Error'], "status": HTTP_400_BAD_REQUEST})


class GetUserNotificationSettingsApi(ListAPIView):
    model = Settings
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        setting = Settings.objects.get(user=user)
        return Response(
            {"message": "Fetched user settings successfully", "data": setting.notification, "id": setting.id,
             "status": HTTP_200_OK})


class UserLanguageSettingApiView(APIView):
    model = Settings
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        settings_obj = Settings.objects.get(user=user)
        lang = settings_obj.language
        return Response({"language": lang, "id": settings_obj.id, "status": HTTP_200_OK,
                         "message": "Fetched user language successfully"})


# @method_decorator(csrf_exempt, name='dispatch')
# class ChangeNotificationApiView(UpdateAPIView):
#     """ Change User's notification settings """
#     serializer_class = NotificationSettingSerializer
#     queryset = Settings.objects.all()
#
#
# @method_decorator(csrf_exempt, name='dispatch')
# class ChangeLanguageApiView(UpdateAPIView):
#     """Change User's language settings"""
#     serializer_class = LanguageSettingSerializer
#     queryset = Settings.objects.all()


class PrivacyPolicyApiView(APIView):
    """App's Privacy policy"""
    model = PrivacyPolicy
    serializer_class = PrivacyPolicySerializer
    queryset = PrivacyPolicy.objects.all()

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        policy = PrivacyPolicy.objects.all()
        data = ''
        lang_setting_obj = Settings.objects.get(user=user)
        if lang_setting_obj.language == 'English':
            for x in policy:
                data = {
                    "privacy_policy": remove_html_tags(x.policy)
                }
            return Response({"data": data, "status": HTTP_200_OK})
        else:
            for x in policy:
                data = {
                    "privacy_policy": remove_html_tags(x.policy_in_arabic)
                }
            return Response({"data": data, "status": HTTP_200_OK})


class ContactUsApiView(ListAPIView):
    """Admin Contact detail """
    model = ContactUs
    serializer_class = ContactUsSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = ContactUs.objects.all()

    def get(self, request, *args, **kwargs):
        phone_number = ContactUs.objects.all()[0].phone_number
        email = ContactUs.objects.all()[0].email
        company_name = ContactUs.objects.all()[0].company_name
        return Response(
            {"company_name": company_name, "phone_number": phone_number, "email": email, "status": HTTP_200_OK})


class TermsandConditionApiView(APIView):
    """App's Terms and condition """
    model = TermsAndCondition
    serializer_class = TermsandConditionSerializer
    queryset = TermsAndCondition.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        terms_condition = TermsAndCondition.objects.all()
        data = ''
        lang_setting_obj = Settings.objects.get(user=user)
        if lang_setting_obj.language == 'English':
            for x in terms_condition:
                data = {
                    "terms_condition": remove_html_tags(x.conditions)
                }
            return Response({"data": data, "status": HTTP_200_OK})
        else:
            for x in terms_condition:
                data = {
                    "terms_condition": remove_html_tags(x.conditions_in_arabic)
                }
            return Response({"data": data, "status": HTTP_200_OK})


class SignUpTermsandConditionApiView(APIView):
    model = TermsAndCondition
    serializer_class = TermsandConditionSerializer
    queryset = TermsAndCondition.objects.all()

    def get(self, request, *args, **kwargs):
        terms_condition = TermsAndCondition.objects.all()
        data = ''
        for x in terms_condition:
            data = {
                "terms_condition": remove_html_tags(x.conditions)
            }
        return Response({'data': data, 'status': HTTP_200_OK})


class GetUnreadMessageCount(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        count = UserNotification.objects.filter(to=user.id).filter(read=False).count()
        print(count)
        return Response({"count": count, "status": HTTP_200_OK})


class CheckMobileOrPhoneNumber(APIView):

    def get(self, request, *args, **kwargs):
        email_or_phone = self.request.GET.get('email_or_phone')
        try:
            if email_or_phone.isdigit():
                user_obj = User.objects.get(phone_number=email_or_phone)
                if user_obj:
                    return Response(
                        {"message": "User with this email or phone number already exists",
                         "status": HTTP_400_BAD_REQUEST})
            else:
                user_obj = User.objects.get(email=email_or_phone)
                if user_obj:
                    return Response(
                        {"message": "User with this email or phone number already exists",
                         "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            return Response({"meassge": "User not found", "status": HTTP_404_NOT_FOUND})


class AboutUsView(APIView):
    model = AboutUs
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        about_us = AboutUs.objects.first()
        return Response({"message": "About us fetched successfully", "data": about_us.content, "status": HTTP_200_OK})


class UpdateEmailView(UpdateAPIView):
    model = User
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = User.objects.all()

    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        print(user)
        serializer = UpdateEmailSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = request.data['email']
                print(email)
                user.email = email.lower()
                user.save()
                return Response({"message": "Email updated successfully", "email": email, "status": HTTP_200_OK})
            else:
                return Response({"message": serializer.errors, "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            x = {"Error": str(e)}
            return Response({'message': x['Error'], "status": HTTP_400_BAD_REQUEST})


class FirstViewSet(ModelViewSet):
    serializer_class = UserCreateSerializer
    queryset = User.objects.all()


class POSOrder(CreateAPIView):
    queryset = Receipt.objects.all()
    serializer_class = UserCreateSerializer

    def post(self, request, *args, **kwargs):
        country_code = self.request.data['country_code']
        user_mobile_no = self.request.data['user_mobile_no']
        merchant_id = self.request.data['merchant_id']
        merchant_name = self.request.data['merchant_name']
        branch = self.request.data['branch']
        category = self.request.data['category']
        date_of_purchase = self.request.data['date_of_purchase']
        time_of_purchase = self.request.data['time_of_purchase']
        customer_email = self.request.data['customer_email']
        product_name = self.request.data['product_name']
        product_cost = self.request.data['product_cost']
        product_quantity = self.request.data['product_quantity']
        order_amount = self.request.data['order_amount']
        vat_percent = self.request.data['vat_percent']
        print('-------------------------------------', self.request.data)
        try:
            # check_user = User.objects.get(phone_number=user_mobile_no)
            # if check_user:
            merchant_obj = Merchant.objects.get(id=merchant_id)
            # user = User.objects.get(phone_number=user_mobile_no)
            user = User.objects.get(email=customer_email)
            category_obj = Category.objects.get(id=category)
            order_id = get_random_string(16)
            final_item = zip(product_name, product_cost, product_quantity)
            for item in final_item:
                order_obj = OrderItem.objects.create(
                    user=user,
                    product=item[0],
                    price=item[1],
                    quantity=item[2],
                    vat=(vat_percent / 100) * order_amount,
                    vat_percent=vat_percent,
                    total=order_amount + (vat_percent / 100) * order_amount,
                    order_id=order_id
                )
            ordered_items = OrderItem.objects.filter(order_id=order_id)
            receipt_obj = Receipt.objects.create(
                user=user,
                vat=(vat_percent / 100) * order_amount,
                amount=order_amount,
                total=(vat_percent / 100) * order_amount + order_amount,
                merchant=merchant_obj,
                branch=Branch.objects.get(code=branch)
            )
            for item in ordered_items:
                receipt_obj.order.add(item)
            scanned_data_obj = ScannedData.objects.create(
                user=user,
                merchant=merchant_obj,
                order=receipt_obj
            )
            return Response({"message": "Order created successfully", "status": HTTP_200_OK})
            # else:
            #     user = User.objects.create(
            #         # first_name=first_name,
            #         # last_name=last_name,
            #         country_code=country_code,
            #         phone_number=user_mobile_no,
            #         # profile_pic=profile_pic,
            #         # email=email,
            #         # device_token=device_token
            #     )
            #     user.set_password('FatorTech@001')
            #     user.save()
            #     token = Token.objects.create(user=user)
            #
            #     merchant_obj = Merchant.objects.get(id=merchant_id)
            #     user = User.objects.get(email=customer_email)
            #     category_obj = Category.objects.get(id=category)
            #     final_item = zip(product_name, product_cost, product_quantity)
            #     order_id = get_random_string(16)
            #     for item in final_item:
            #         order_obj = OrderItem.objects.create(
            #             user=user,
            #             product=item[0],
            #             price=item[1],
            #             quantity=item[2],
            #             vat=vat_percent,
            #             total=order_amount + (vat_percent / 100) * order_amount,
            #             order_id=order_id
            #         )
            #         print('Inside else---',order_obj)
            #     ordered_items = OrderItem.objects.filter(order_id=order_id)
            #     receipt_obj = Receipt.objects.create(
            #         user=user,
            #         merchant=merchant_obj,
            #         branch=Branch.objects.get(code=branch)
            #     )
            #     for item in ordered_items:
            #         receipt_obj.order.add(item)
            #     scanned_data_obj = ScannedData.objects.create(
            #         user=user,
            #         merchant=merchant_obj,
            #         order=receipt_obj
            #     )
            #     return Response({"message": "Order created successfully", "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            print('Inside except block---->>', self.request.data)
            user = User.objects.create(
                # first_name=first_name,
                # last_name=last_name,
                country_code=country_code,
                phone_number=user_mobile_no,
                # profile_pic=profile_pic,
                email=customer_email,
                # device_token=device_token
            )
            user.set_password('FatorTech@001')
            user.save()
            token = Token.objects.create(user=user)
            merchant_obj = Merchant.objects.get(id=merchant_id)
            user = User.objects.get(email=customer_email)
            category_obj = Category.objects.get(id=category)
            final_item = zip(product_name, product_cost, product_quantity)
            order_id = get_random_string(16)
            for item in final_item:
                order_obj = OrderItem.objects.create(
                    user=user,
                    product=item[0],
                    price=item[1],
                    quantity=item[2],
                    vat=(vat_percent / 100) * order_amount,
                    vat_percent=vat_percent,
                    total=order_amount + (vat_percent / 100) * order_amount,
                    order_id=order_id
                )
                print('>>>>>>>>>>>ORDER OBJ<<<<<', order_obj)
            ordered_items = OrderItem.objects.filter(order_id=order_id)
            receipt_obj = Receipt.objects.create(
                user=user,
                vat=(vat_percent / 100) * order_amount,
                amount=order_amount,
                total=(vat_percent / 100) * order_amount + order_amount,
                merchant=merchant_obj,
                branch=Branch.objects.get(code=branch)
            )
            for item in ordered_items:
                receipt_obj.order.add(item)
            scanned_data_obj = ScannedData.objects.create(
                user=user,
                merchant=merchant_obj,
                order=receipt_obj
            )
            return Response({"message": "Order created successfully", "status": HTTP_200_OK})


class GetCartItemDetail(APIView):
    model = OrderItem
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        item_id = self.request.GET.get('item_id')
        try:
            item_obj = OrderItem.objects.get(id=item_id)
            print(item_obj)
            data_dict = {
                # 'merchant_id': item_obj.merchant.id,
                # 'merchant_name': item_obj.merchant.full_name,
                # 'merchant_email': item_obj.merchant.email,
                # 'merchant_category': item_obj.merchant.category.category_name,
                'item_name': item_obj.product,
                'item_price': item_obj.price,
                'item_quantity': item_obj.quantity,
                'item_vat': item_obj.vat,
                'item_vat_percent': item_obj.vat_percent
            }
            return Response({'data': data_dict, 'message': 'Item details fetched successfully', 'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class GetMerchantNameAndCategory(APIView):
    model = Merchant

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        # merchant_id = self.request.GET.get('merchant_name')
        merchant_id = self.request.POST['merchant_name']
        print('-----------------------', merchant_id)
        merchants = []
        try:
            merchant_obj = Merchant.objects.filter(full_name=merchant_id)
            print('>>>>>>>>>>>>>>>>>>>', merchant_obj)
            for merchant in merchant_obj:
                branches = []
                if merchant.blocked:
                    pass
                    # return Response({'message': 'Merchant does not exists', 'status': HTTP_400_BAD_REQUEST})
                else:
                    # for merchant in merchant_obj:
                    branch_obj = Branch.objects.filter(merchant_name=merchant).filter(blocked=False)
                    print('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<', branch_obj)
                    for branch in branch_obj:
                        branches.append({'branch_id': branch.id, 'branch_code': branch.code})
                        print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>', branches)
                    # return Response({'name': merchant.full_name, 'category_id': merchant.category.id,
                    #                  'category': merchant.category.category_name, 'branches': branches,
                    #                  'status': HTTP_200_OK})
                    merchants.append(
                        {'id': merchant.id, 'name': merchant.full_name, 'category_id': merchant.category.id,
                         'category': merchant.category.category_name, 'branches': branches})
            return Response({'data': merchants, 'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class FilterExpenseDataByMonth(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        year = self.request.POST['year']
        try:
            receipts = Receipt.objects.filter(user=self.request.user).filter(created_at__icontains=year)
            receipts_total = []
            for receipt in receipts:
                receipts_total.append({'month': receipt.created_at.month, 'total': receipt.total})
            final = []
            for y in receipts_total:
                if len(final) > 0:
                    i = -1
                    for z in range(len(final)):
                        if y['month'] == final[z]['month']:
                            i = z
                        else:
                            pass
                    if i == -1:
                        final.append(y)
                    else:
                        final[i]['total'] = final[i]['total'] + y['total']
                else:
                    final.append(y)
            return Response({'expense_data_by_month': final, 'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class FilterExpenseDataByCategory(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        year = self.request.POST['year']
        try:
            receipts = Receipt.objects.filter(created_at__icontains=year).filter(user=self.request.user)
            receipt_list = []
            for receipt in receipts:
                receipt_list.append({'category': receipt.merchant.category.category_name, 'total': receipt.total})
            final = []
            for y in receipt_list:
                if len(final) > 0:
                    i = -1
                    for z in range(len(final)):
                        if y['category'] == final[z]['category']:
                            i = z
                        else:
                            pass
                    if i == -1:
                        final.append(y)
                    else:
                        final[i]['total'] = final[i]['total'] + y['total']
                else:
                    final.append(y)
            return Response({'expense_data_by_category': final, 'status': HTTP_200_OK})
        except Exception as e:
            print(e)
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class AutoOrderCreation(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        print(self.request.data)
        # print(self.request)
        user = self.request.user
        merchant_id = self.request.data['merchant_id']
        merchant_name = self.request.data['merchant_name']
        category = self.request.data['category']
        date_of_purchase = self.request.data['date_of_purchase']
        time_of_purchase = self.request.data['time_of_purchase']
        # order_id = self.request.data['order_id']
        order_amount = self.request.data['order_amount']
        vat_amount = self.request.data['vat_amount']
        total_amount = self.request.data['total_amount']
        ordered_items = self.request.data['ordered_items']
        branch = self.request.data['branch']
        # month = self.request.data['month']
        merchant_obj = Merchant.objects.get(id=merchant_id)
        category_obj = Category.objects.get(id=category)
        branch_obj = Branch.objects.get(code=branch)
        today = timezone.now()
        print(today)
        date_time_str = (date_of_purchase + ' ' + time_of_purchase)
        print('---------->>>>', date_time_str)
        from datetime import datetime
        r = receipt_obj = Receipt.objects.create(
            user=self.request.user,
            merchant=merchant_obj,
            total=total_amount,
            vat=vat_amount,
            amount=order_amount,
            branch=branch_obj,
            created_at=datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S')
        )
        for item in ordered_items:
            receipt_obj.order.add(OrderItem.objects.get(id=item))
        print('----------------------------------', r.created_at)
        scanned_data_obj = ScannedData.objects.create(
            user=self.request.user,
            merchant=merchant_obj,
            order=receipt_obj
        )
        return Response({'message': 'order created successfully', 'status': HTTP_200_OK})


class GetBannersView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            banners = Banner.objects.all()
            images = []
            for banner in banners:
                images.append(banner.image.url)
            return Response({'banners': images, 'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class UpdateProfilePic(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def patch(self, request, *args, **kwargs):
        print(self.request.data)
        user = self.request.user
        profile_pic = self.request.data['profile_pic']
        user.profile_pic = profile_pic
        user.save()
        return Response({'message': "Profile pic updated successfully ", 'status': HTTP_200_OK})


class GetMerchantDetail(APIView):

    def get(self, request, *args, **kwargs):
        merchant_id = self.request.GET.get('merchant_id')
        try:
            # merchant_obj = Merchant.objects.get(id=merchant_id)
            # print(Merchant.objects.get(id=merchant_id).explain())
            merchant_obj = Merchant.objects.select_related('category').get(id=merchant_id)
            # print(Merchant.objects.select_related('category').get(id=merchant_id).explain())
            branches = []
            merchant_detail = []
            # branch_obj = Branch.objects.filter(merchant_name=merchant_obj)
            # print('>>>>', branch_obj.explain())
            branch_obj = Branch.objects.select_related('merchant_name').filter(merchant_name=merchant_obj)
            print('<<<<<', branch_obj.explain())
            for branch in branch_obj:
                branches.append({'branch_id': branch.id, 'branch_code': branch.code})
            merchant_detail.append(
                {'id': merchant_obj.id, 'name': merchant_obj.full_name, 'category_id': merchant_obj.category.id,
                 'category': merchant_obj.category.category_name, 'branches': branches})
            return Response({'data': merchant_detail, 'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class FoodicsAPI(APIView):

    def get(self, request, *args, **kwargs):
        client_id = '934f88da-2f2a-425d-8246-1f784b5a24be'
        state = 'random'
        return redirect(f"https://console-sandbox.foodics.com/authorize?client_id={client_id}&state={state}")


class GetParamsfromUrl(APIView):
    def get(self, request, *args, **kwargs):
        # client_id = '934f88da-2f2a-425d-8246-1f784b5a24be'
        client_id = '934f88da-2f2a-425d-8246-1f784b5a24be'
        # client_secret = 'vlUwxMcASxqxKgaomUZQQuzYozOKsd5lido3XFzn'
        client_secret = 'vlUwxMcASxqxKgaomUZQQuzYozOKsd5lido3XFzn'
        code = self.request.GET.get('code')
        print(code)
        headers = 'Content-Type: Application/json'
        state = self.request.GET.get('state')
        # headers = {'Content-Type': 'Application/json'}
        # x = requests.post('https://api-sandbox.foodics.com/oauth/token',
        #                   data={"grant_type": "authorization_code",
        #                         "code": code,
        #                         "client_id": client_id,
        #                         "client_secret": client_secret,
        #                         "redirect_uri": "https://fatortech.net/api/foodics-success"}
        #                   )
        request.session['code'] = code

        # return Response({'data': x.json()})
        return redirect("src:foodics-token")

    def post(self, request, *args, **kwargs):
        print('Foodics webhook data--->>>', self.request.data)
        return Response(status=HTTP_200_OK)


class GetFoodicsToken(APIView):
    def get(self, request, *args, **kwargs):
        client_id = '934f88da-2f2a-425d-8246-1f784b5a24be'
        client_secret = 'vlUwxMcASxqxKgaomUZQQuzYozOKsd5lido3XFzn'
        code = request.session['code']
        x = requests.post('https://api-sandbox.foodics.com/oauth/token',
                          data={"grant_type": "authorization_code",
                                "code": code,
                                "client_id": client_id,
                                "client_secret": client_secret,
                                "redirect_uri": "https://fatortech.net/api/foodics-success"})
        # request.session['access_token'] = x.json()['access_token']
        # request.session['refresh_token'] = x.json()['refresh_token']
        # request.session['code'] = code
        return Response({'data': x.json()})


class FoodicsWebHookUrl(APIView):

    def get(self, request, *args, **kwargs):
        print(self.request.GET)
        print('<<<---- GET METHOD From foodics web hook------>>>>', self.request.POST)
        print('---- GET METHOD From foodics web hook------', request.data)
        # webhook_data = request.data
        #     webhook_data = {
        #         'timestamp': 1626438646,
        #         'event': 'customer.order.created',
        #         'business': {
        #             'name': 'FATORTECH',
        #             'reference': 298946
        #         },
        #         'order': {
        #             'branch': {
        #                 'id': '934f9698-fc23-4084-b19f-ea09e0669a64',
        #                 'name': 'Branch 2',
        #                 'name_localized': None,
        #                 'reference': 'B02',
        #                 'type': 1,
        #                 'latitude': None,
        #                 'longitude': None,
        #                 'phone': None,
        #                 'opening_from': '00:00',
        #                 'opening_to': '00:00',
        #                 'inventory_end_of_day_time': '00:00',
        #                 'receipt_header': None,
        #                 'receipt_footer': None,
        #                 'created_at': '2021-04-29 12:46:23',
        #                 'updated_at': '2021-04-29 12:46:23',
        #                 'deleted_at': None,
        #                 'receives_online_orders': True,
        #                 'accepts_reservations': False,
        #                 'reservation_duration': 30,
        #                 'reservation_times': None
        #             },
        #             'promotion': None,
        #             'original_order': None,
        #             'table': None,
        #             'creator': {
        #                 'pin': '*****',
        #                 'is_owner': True,
        #                 'id': '934f966a-ec55-4f08-8916-422d260d7b3f',
        #                 'name': 'hussain Ali',
        #                 'number': None,
        #                 'email': 'hussain@fatortech.net',
        #                 'phone': None,
        #                 'lang': 'en',
        #                 'display_localized_names': False,
        #                 'email_verified': True,
        #                 'must_use_fingerprint': False,
        #                 'last_console_login_at': '2021-07-16 10:05:33',
        #                 'last_cashier_login_at': None,
        #                 'created_at': '2021-04-29 12:46:22',
        #                 'updated_at': '2021-07-16 10:05:33',
        #                 'deleted_at': None
        #             },
        #             'closer': {
        #                 'pin': '*****',
        #                 'is_owner': True,
        #                 'id': '934f966a-ec55-4f08-8916-422d260d7b3f',
        #                 'name': 'hussain Ali',
        #                 'number': None,
        #                 'email': 'hussain@fatortech.net',
        #                 'phone': None,
        #                 'lang': 'en',
        #                 'display_localized_names': False,
        #                 'email_verified': True,
        #                 'must_use_fingerprint': False,
        #                 'last_console_login_at': '2021-07-16 10:05:33',
        #                 'last_cashier_login_at': None,
        #                 'created_at': '2021-04-29 12:46:22',
        #                 'updated_at': '2021-07-16 10:05:33',
        #                 'deleted_at': None
        #             },
        #             'driver': None,
        #             'customer': {
        #                 'id': '938fd5bf-2ff0-4546-923a-afbd455c594b',
        #                 'name': 'BINIT',
        #                 'dial_code': 91,
        #                 'phone': '7678689353',
        #                 'email': 'ravichoudhary766@gmail.com',
        #                 'gender': None,
        #                 'birth_date': None,
        #                 'is_blacklisted': False,
        #                 'is_house_account_enabled': False,
        #                 'house_account_limit': None,
        #                 'is_loyalty_enabled': False,
        #                 'order_count': 2,
        #                 'last_order_at': '2021-07-16 12:29:45',
        #                 'created_at': '2021-05-31 11:15:56',
        #                 'updated_at': '2021-07-16 12:30:46',
        #                 'deleted_at': None
        #             },
        #             'customer_address': None,
        #             'discount': None,
        #             'tags': [
        #
        #             ],
        #             'coupon': None,
        #             'gift_card': None,
        #             'charges': [
        #
        #             ],
        #             'payments': [
        #                 {
        #                     'user': {
        #                         'pin': '*****',
        #                         'is_owner': True,
        #                         'id': '934f966a-ec55-4f08-8916-422d260d7b3f',
        #                         'name': 'hussain Ali',
        #                         'number': None,
        #                         'email': 'hussain@fatortech.net',
        #                         'phone': None,
        #                         'lang': 'en',
        #                         'display_localized_names': False,
        #                         'email_verified': True,
        #                         'must_use_fingerprint': False,
        #                         'last_console_login_at': '2021-07-16 10:05:33',
        #                         'last_cashier_login_at': None,
        #                         'created_at': '2021-04-29 12:46:22',
        #                         'updated_at': '2021-07-16 10:05:33',
        #                         'deleted_at': None
        #                     },
        #                     'payment_method': {
        #                         'id': '934f9699-0a44-4bf9-bf7e-efc48f9eef19',
        #                         'name': 'Cash',
        #                         'name_localized': 'Cash',
        #                         'type': 1,
        #                         'code': None,
        #                         'auto_open_drawer': True,
        #                         'is_active': True,
        #                         'created_at': '2021-04-29 12:46:23',
        #                         'updated_at': '2021-04-29 12:46:23',
        #                         'deleted_at': None,
        #                         'index': 0
        #                     },
        #                     'meta': [
        #
        #                     ],
        #                     'amount': 230,
        #                     'tendered': 230,
        #                     'tips': 0,
        #                     'business_date': '2021-07-16',
        #                     'added_at': '2021-07-16 12:30:42'
        #                 }
        #             ],
        #             'products': [
        #                 {
        #                     'product': {
        #                         'category': {
        #                             'id': '93820e96-ee8a-4a71-8a74-bc3d693e6302',
        #                             'name': 'Sandwiches',
        #                             'name_localized': None,
        #                             'reference': None,
        #                             'image': None,
        #                             'created_at': '2021-05-24 14:53:18',
        #                             'updated_at': '2021-05-24 14:53:18',
        #                             'deleted_at': None
        #                         },
        #                         'ingredients': [
        #
        #                         ],
        #                         'id': '93820f4b-94dd-459d-ba26-5ac2f584b3b9',
        #                         'sku': 'Burg-002',
        #                         'barcode': None,
        #                         'name': 'Double buger',
        #                         'name_localized': None,
        #                         'description': None,
        #                         'description_localized': None,
        #                         'image': None,
        #                         'is_active': True,
        #                         'is_stock_product': False,
        #                         'is_ready': True,
        #                         'pricing_method': 1,
        #                         'selling_method': 1,
        #                         'costing_method': 1,
        #                         'preparation_time': None,
        #                         'price': 20,
        #                         'cost': 10,
        #                         'calories': None,
        #                         'created_at': '2021-05-24 14:55:16',
        #                         'updated_at': '2021-05-24 14:55:16',
        #                         'deleted_at': None
        #                     },
        #                     'promotion': None,
        #                     'discount': None,
        #                     'options': [
        #
        #                     ],
        #                     'taxes': [
        #
        #                     ],
        #                     'timed_events': [
        #
        #                     ],
        #                     'void_reason': None,
        #                     'creator': {
        #                         'pin': '*****',
        #                         'is_owner': True,
        #                         'id': '934f966a-ec55-4f08-8916-422d260d7b3f',
        #                         'name': 'hussain Ali',
        #                         'number': None,
        #                         'email': 'hussain@fatortech.net',
        #                         'phone': None,
        #                         'lang': 'en',
        #                         'display_localized_names': False,
        #                         'email_verified': True,
        #                         'must_use_fingerprint': False,
        #                         'last_console_login_at': '2021-07-16 10:05:33',
        #                         'last_cashier_login_at': None,
        #                         'created_at': '2021-04-29 12:46:22',
        #                         'updated_at': '2021-07-16 10:05:33',
        #                         'deleted_at': None
        #                     },
        #                     'voider': None,
        #                     'discount_type': None,
        #                     'quantity': 5,
        #                     'returned_quantity': 0,
        #                     'unit_price': 20,
        #                     'discount_amount': 0,
        #                     'total_price': 100,
        #                     'total_cost': 50,
        #                     'tax_exclusive_discount_amount': 0,
        #                     'tax_exclusive_unit_price': 20,
        #                     'tax_exclusive_total_price': 100,
        #                     'status': 3,
        #                     'is_ingredients_wasted': 0,
        #                     'delay_in_seconds': None,
        #                     'kitchen_notes': None,
        #                     'meta': {
        #                         'foodics': {
        #                             'uuid': 'e2416f99-0543-4300-9214-609490cb0a21'
        #                         }
        #                     },
        #                     'added_at': '2021-07-16 12:29:45',
        #                     'closed_at': '2021-07-16 12:30:42'
        #                 },
        #                 {
        #                     'product': {
        #                         'category': {
        #                             'id': '93820e85-ea34-4c83-83d7-a3185dee3c8b',
        #                             'name': 'Drinks',
        #                             'name_localized': None,
        #                             'reference': None,
        #                             'image': None,
        #                             'created_at': '2021-05-24 14:53:06',
        #                             'updated_at': '2021-05-24 14:53:06',
        #                             'deleted_at': None
        #                         },
        #                         'ingredients': [
        #
        #                         ],
        #                         'id': '93821031-a68f-4313-8476-f6d58ad3e83a',
        #                         'sku': 'sk-0006',
        #                         'barcode': None,
        #                         'name': 'Cola',
        #                         'name_localized': None,
        #                         'description': None,
        #                         'description_localized': None,
        #                         'image': None,
        #                         'is_active': True,
        #                         'is_stock_product': False,
        #                         'is_ready': True,
        #                         'pricing_method': 1,
        #                         'selling_method': 1,
        #                         'costing_method': 1,
        #                         'preparation_time': None,
        #                         'price': 6,
        #                         'cost': 2,
        #                         'calories': None,
        #                         'created_at': '2021-05-24 14:57:47',
        #                         'updated_at': '2021-05-24 14:57:59',
        #                         'deleted_at': None
        #                     },
        #                     'promotion': None,
        #                     'discount': None,
        #                     'options': [
        #
        #                     ],
        #                     'taxes': [
        #
        #                     ],
        #                     'timed_events': [
        #
        #                     ],
        #                     'void_reason': None,
        #                     'creator': {
        #                         'pin': '*****',
        #                         'is_owner': True,
        #                         'id': '934f966a-ec55-4f08-8916-422d260d7b3f',
        #                         'name': 'hussain Ali',
        #                         'number': None,
        #                         'email': 'hussain@fatortech.net',
        #                         'phone': None,
        #                         'lang': 'en',
        #                         'display_localized_names': False,
        #                         'email_verified': True,
        #                         'must_use_fingerprint': False,
        #                         'last_console_login_at': '2021-07-16 10:05:33',
        #                         'last_cashier_login_at': None,
        #                         'created_at': '2021-04-29 12:46:22',
        #                         'updated_at': '2021-07-16 10:05:33',
        #                         'deleted_at': None
        #                     },
        #                     'voider': None,
        #                     'discount_type': None,
        #                     'quantity': 5,
        #                     'returned_quantity': 0,
        #                     'unit_price': 6,
        #                     'discount_amount': 0,
        #                     'total_price': 30,
        #                     'total_cost': 10,
        #                     'tax_exclusive_discount_amount': 0,
        #                     'tax_exclusive_unit_price': 6,
        #                     'tax_exclusive_total_price': 30,
        #                     'status': 3,
        #                     'is_ingredients_wasted': 0,
        #                     'delay_in_seconds': None,
        #                     'kitchen_notes': None,
        #                     'meta': {
        #                         'foodics': {
        #                             'uuid': 'd36c75af-6553-48da-b1e9-80299ecf3f50'
        #                         }
        #                     },
        #                     'added_at': '2021-07-16 12:30:08',
        #                     'closed_at': '2021-07-16 12:30:42'
        #                 },
        #                 {
        #                     'product': {
        #                         'category': {
        #                             'id': '93820e78-fbe2-4855-af62-56c3ee888740',
        #                             'name': 'Fries',
        #                             'name_localized': None,
        #                             'reference': None,
        #                             'image': None,
        #                             'created_at': '2021-05-24 14:52:58',
        #                             'updated_at': '2021-05-24 14:52:58',
        #                             'deleted_at': None
        #                         },
        #                         'ingredients': [
        #
        #                         ],
        #                         'id': '93820f9e-cf33-42e4-897a-b7f4237e7963',
        #                         'sku': 'sk-0004',
        #                         'barcode': None,
        #                         'name': 'Amazing fried potato',
        #                         'name_localized': None,
        #                         'description': None,
        #                         'description_localized': None,
        #                         'image': None,
        #                         'is_active': True,
        #                         'is_stock_product': False,
        #                         'is_ready': True,
        #                         'pricing_method': 1,
        #                         'selling_method': 1,
        #                         'costing_method': 1,
        #                         'preparation_time': None,
        #                         'price': 20,
        #                         'cost': 10,
        #                         'calories': None,
        #                         'created_at': '2021-05-24 14:56:10',
        #                         'updated_at': '2021-05-24 14:56:10',
        #                         'deleted_at': None
        #                     },
        #                     'promotion': None,
        #                     'discount': None,
        #                     'options': [
        #
        #                     ],
        #                     'taxes': [
        #
        #                     ],
        #                     'timed_events': [
        #
        #                     ],
        #                     'void_reason': None,
        #                     'creator': {
        #                         'pin': '*****',
        #                         'is_owner': True,
        #                         'id': '934f966a-ec55-4f08-8916-422d260d7b3f',
        #                         'name': 'hussain Ali',
        #                         'number': None,
        #                         'email': 'hussain@fatortech.net',
        #                         'phone': None,
        #                         'lang': 'en',
        #                         'display_localized_names': False,
        #                         'email_verified': True,
        #                         'must_use_fingerprint': False,
        #                         'last_console_login_at': '2021-07-16 10:05:33',
        #                         'last_cashier_login_at': None,
        #                         'created_at': '2021-04-29 12:46:22',
        #                         'updated_at': '2021-07-16 10:05:33',
        #                         'deleted_at': None
        #                     },
        #                     'voider': None,
        #                     'discount_type': None,
        #                     'quantity': 5,
        #                     'returned_quantity': 0,
        #                     'unit_price': 20,
        #                     'discount_amount': 0,
        #                     'total_price': 100,
        #                     'total_cost': 50,
        #                     'tax_exclusive_discount_amount': 0,
        #                     'tax_exclusive_unit_price': 20,
        #                     'tax_exclusive_total_price': 100,
        #                     'status': 3,
        #                     'is_ingredients_wasted': 0,
        #                     'delay_in_seconds': None,
        #                     'kitchen_notes': None,
        #                     'meta': {
        #                         'foodics': {
        #                             'uuid': '84af87df-41ff-4cdb-8971-0b14bdc91d20'
        #                         }
        #                     },
        #                     'added_at': '2021-07-16 12:30:22',
        #                     'closed_at': '2021-07-16 12:30:42'
        #                 }
        #             ],
        #             'combos': [
        #
        #             ],
        #             'device': {
        #                 'id': '934f9699-07ad-4191-85bc-57d32a604c0a',
        #                 'name': 'Cashier 2',
        #                 'code': '19379',
        #                 'reference': 'C02',
        #                 'type': 1
        #             },
        #             'id': 'f7ed9b2d-414e-430e-ac19-4fbac94b9761',
        #             'app_id': '8f9eb3f6-7987-4f66-aa8c-478c34d0c568',
        #             'promotion_id': None,
        #             'discount_type': None,
        #             'reference_x': None,
        #             'number': 3,
        #             'type': 2,
        #             'source': 1,
        #             'status': 4,
        #             'delivery_status': None,
        #             'guests': 1,
        #             'kitchen_notes': None,
        #             'customer_notes': None,
        #             'business_date': '2021-07-16',
        #             'subtotal_price': 230,
        #             'discount_amount': 0,
        #             'rounding_amount': 0,
        #             'total_price': 230,
        #             'tax_exclusive_discount_amount': 0,
        #             'delay_in_seconds': None,
        #             'meta': {
        #                 'foodics': {
        #                     'device_id': '934f9699-07ad-4191-85bc-57d32a604c0a',
        #                     'products_kitchen': [
        #
        #                     ]
        #                 }
        #             },
        #             'opened_at': '2021-07-16 12:29:45',
        #             'accepted_at': None,
        #             'due_at': None,
        #             'driver_assigned_at': None,
        #             'dispatched_at': None,
        #             'driver_collected_at': None,
        #             'delivered_at': None,
        #             'closed_at': '2021-07-16 12:30:42',
        #             'created_at': '2021-07-16 12:30:46',
        #             'updated_at': '2021-07-16 12:30:46',
        #             'reference': 27,
        #             'check_number': 100003
        #         }
        #     }
        #     branch = None
        #     merchant = None
        #     user = None
        #     new_user = None
        #     order_item = []
        #     try:
        #         merchant = Merchant.objects.get(email=webhook_data['order']['creator']['email'])
        #     except Exception as e:
        #         merchant = Merchant.objects.create(email=webhook_data['order']['creator']['email'],
        #                                            full_name=webhook_data['order']['creator']['name'])
        #     try:
        #         branch = Branch.objects.get(code=webhook_data['order']['branch']['name'])
        #     except Exception as e:
        #         branch = Branch.objects.create(code=webhook_data['order']['branch']['name'], merchant_name=merchant)
        #     try:
        #         user = User.objects.get(email=webhook_data['order']['customer']['email'])
        #     except Exception as e:
        #         user = User.objects.create(first_name=webhook_data['order']['customer']['name'],
        #                                    email=webhook_data['order']['customer']['email'],
        #                                    country_code=webhook_data['order']['customer']['dial_code'],
        #                                    phone_number=webhook_data['order']['customer']['phone'])
        #         user.set_password('Test@123')
        #         user.save()
        #         new_user = user
        #     print('NEW USER----->>', new_user)
        #     print(webhook_data['order']['branch']['name'])
        #     print(webhook_data['order']['creator']['name'])
        #     print(webhook_data['order']['customer']['name'], webhook_data['order']['customer']['dial_code'],
        #           webhook_data['order']['customer']['phone'],
        #           webhook_data['order']['customer']['email'])
        #     print('Payment--', webhook_data['order']['payments'][0]['payment_method']['name'])
        #     print('Payment--', webhook_data['order']['payments'][0]['amount'])
        #
        #     for i in range(len(webhook_data['order']['products'])):
        #         print(webhook_data['order']['products'][i]['product']['category']['name'])
        #         print(webhook_data['order']['products'][i]['product']['name'])
        #         print(webhook_data['order']['products'][i]['product']['price'])
        #         print(webhook_data['order']['products'][i]['quantity'])
        #         print(webhook_data['order']['products'][i]['unit_price'])
        #         print(webhook_data['order']['products'][i]['total_price'])
        #         order_item_obj = OrderItem.objects.create(
        #             user=user,
        #             product=webhook_data['order']['products'][i]['product']['name'],
        #             price=webhook_data['order']['products'][i]['product']['price'],
        #             quantity=webhook_data['order']['products'][i]['quantity'],
        #             total=webhook_data['order']['products'][i]['total_price'],
        #             vat_percent=0
        #         )
        #         order_item.append(order_item_obj)
        #     print(webhook_data['order']['payments'][0]['amount'])
        #     receipt_obj = Receipt.objects.create(
        #         user=user,
        #         merchant=merchant,
        #         branch=branch,
        #         vat=0,
        #         amount=webhook_data['order']['payments'][0]['amount'],
        #         total=webhook_data['order']['payments'][0]['amount'],
        #         order_created_from = 'FOODICS API'
        #
        #     )
        #     for item in order_item:
        #         receipt_obj.order.add(OrderItem.objects.get(id=item.id))
        #     receipt_id = 0
        #     try:
        #         receipt_obj = Receipt.objects.last()
        #         receipt_id = receipt_obj.id + 1
        #     except Exception as e:
        #         print(e)
        #         receipt_id += 1
        #     item_string = ''
        #     item_string += ', Order Id : ' + str(receipt_obj.id)
        #     url = pyqrcode.create(item_string, encoding='utf-8')
        #     url.png(f'media/{receipt_id}.png', scale=6)
        #     qr = os.path.basename(f'{receipt_id}.png'), File(open(f'media/{receipt_id}.png', 'rb'))
        #     receipt_obj.qr_code = qr[1]
        #     receipt_obj.save(update_fields=['qr_code'])
        #     scanned_data_obj = ScannedData.objects.create(
        #         user=user,
        #         merchant=merchant,
        #         order=receipt_obj
        #     )
        #     try:
        #         if new_user:
        #             account_sid = 'ACf02ece6f59b345778bdd512e693c8e3e'
        #             auth_token = '427991ea9201b5e360ab49532d703157'
        #             client = Client(account_sid, auth_token)
        #             client.messages.create(
        #                 body=f'Your receipt with receipt id-{receipt_obj.id} has been generated.'
        #                      f'Please download the app to view th receipt. '
        #                      f'Please login using credentials are email: {user.email} and password:Test@123',
        #                 from_='+19412579649',
        #                 to='+' + str(str(user.country_code) + str(user.phone_number))
        #             )
        #     except Exception as e:
        #         print('Exception from twilio---', e)
        #         pass
        #     print(webhook_data['order']['customer']['name'])
        #
        return Response({'message': 'Success', 'status': HTTP_200_OK})

    def post(self, request, *args, **kwargs):
        print('<<<----From foodics web hook------>>>>', self.request.POST)
        # print('----From foodics web hook------', request.data)
        webhook_data = request.data
        print('WEB HOOK DATA FROM POST METHOD ', webhook_data)
        # webhook_data = {'timestamp': 1626778337, 'event': 'customer.order.created', 'business': {'name': 'FATORTECH', 'reference': 298946}, 'order': {'branch': {'id': '934f9698-f08c-40c4-ba2e-0411749b4857', 'name': 'Branch 1', 'name_localized': None, 'reference': 'B01', 'type': 1, 'latitude': None, 'longitude': None, 'phone': None, 'opening_from': '00:00', 'opening_to': '00:00', 'inventory_end_of_day_time': '00:00', 'receipt_header': None, 'receipt_footer': None, 'created_at': '2021-04-29 12:46:23', 'updated_at': '2021-04-29 12:46:23', 'deleted_at': None, 'receives_online_orders': True, 'accepts_reservations': False, 'reservation_duration': 30, 'reservation_times': None}, 'promotion': None, 'original_order': None, 'table': None, 'creator': {'pin': '*****', 'is_owner': True, 'id': '934f966a-ec55-4f08-8916-422d260d7b3f', 'name': 'hussain Ali', 'number': None, 'email': 'hussain@fatortech.net', 'phone': None, 'lang': 'en', 'display_localized_names': False, 'email_verified': True, 'must_use_fingerprint': False, 'last_console_login_at': '2021-07-20 09:07:53', 'last_cashier_login_at': None, 'created_at': '2021-04-29 12:46:22', 'updated_at': '2021-07-20 09:07:53', 'deleted_at': None}, 'closer': {'pin': '*****', 'is_owner': True, 'id': '934f966a-ec55-4f08-8916-422d260d7b3f', 'name': 'hussain Ali', 'number': None, 'email': 'hussain@fatortech.net', 'phone': None, 'lang': 'en', 'display_localized_names': False, 'email_verified': True, 'must_use_fingerprint': False, 'last_console_login_at': '2021-07-20 09:07:53', 'last_cashier_login_at': None, 'created_at': '2021-04-29 12:46:22', 'updated_at': '2021-07-20 09:07:53', 'deleted_at': None}, 'driver': None, 'customer': {'id': '93f44e67-0e9f-4b0d-bd69-00f90eb2fc29', 'name': 'Ali', 'dial_code': 966, 'phone': '545982710', 'email': 'test@email.com', 'gender': None, 'birth_date': None, 'is_blacklisted': False, 'is_house_account_enabled': False, 'house_account_limit': None, 'is_loyalty_enabled': False, 'order_count': 3, 'last_order_at': '2021-07-20 10:51:41', 'created_at': '2021-07-20 09:56:06', 'updated_at': '2021-07-20 10:52:09', 'deleted_at': None}, 'customer_address': None, 'discount': None, 'tags': [], 'coupon': None, 'gift_card': None, 'charges': [], 'payments': [{'user': {'pin': '*****', 'is_owner': True, 'id': '934f966a-ec55-4f08-8916-422d260d7b3f', 'name': 'hussain Ali', 'number': None, 'email': 'hussain@fatortech.net', 'phone': None, 'lang': 'en', 'display_localized_names': False, 'email_verified': True, 'must_use_fingerprint': False, 'last_console_login_at': '2021-07-20 09:07:53', 'last_cashier_login_at': None, 'created_at': '2021-04-29 12:46:22', 'updated_at': '2021-07-20 09:07:53', 'deleted_at': None}, 'payment_method': {'id': '934f9699-0a44-4bf9-bf7e-efc48f9eef19', 'name': 'Cash', 'name_localized': 'Cash', 'type': 1, 'code': None, 'auto_open_drawer': True, 'is_active': True, 'created_at': '2021-04-29 12:46:23', 'updated_at': '2021-04-29 12:46:23', 'deleted_at': None, 'index': 0}, 'meta': [], 'amount': 58, 'tendered': 58, 'tips': 0, 'business_date': '2021-07-20', 'added_at': '2021-07-20 10:51:58'}], 'products': [{'product': {'category': {'id': '93820e96-ee8a-4a71-8a74-bc3d693e6302', 'name': 'Sandwiches', 'name_localized': None, 'reference': None, 'image': None, 'created_at': '2021-05-24 14:53:18', 'updated_at': '2021-05-24 14:53:18', 'deleted_at': None}, 'ingredients': [], 'id': '93820ef8-ea71-4fca-835a-34f015e03ac7', 'sku': 'Burg-01', 'barcode': None, 'name': 'King burger', 'name_localized': None, 'description': None, 'description_localized': None, 'image': None, 'is_active': True, 'is_stock_product': False, 'is_ready': True, 'pricing_method': 1, 'selling_method': 1, 'costing_method': 1, 'preparation_time': None, 'price': 20, 'cost': 10, 'calories': None, 'created_at': '2021-05-24 14:54:22', 'updated_at': '2021-05-24 14:54:22', 'deleted_at': None}, 'promotion': None, 'discount': None, 'options': [], 'taxes': [], 'timed_events': [], 'void_reason': None, 'creator': {'pin': '*****', 'is_owner': True, 'id': '934f966a-ec55-4f08-8916-422d260d7b3f', 'name': 'hussain Ali', 'number': None, 'email': 'hussain@fatortech.net', 'phone': None, 'lang': 'en', 'display_localized_names': False, 'email_verified': True, 'must_use_fingerprint': False, 'last_console_login_at': '2021-07-20 09:07:53', 'last_cashier_login_at': None, 'created_at': '2021-04-29 12:46:22', 'updated_at': '2021-07-20 09:07:53', 'deleted_at': None}, 'voider': None, 'discount_type': None, 'quantity': 1, 'returned_quantity': 0, 'unit_price': 20, 'discount_amount': 0, 'total_price': 20, 'total_cost': 10, 'tax_exclusive_discount_amount': 0, 'tax_exclusive_unit_price': 20, 'tax_exclusive_total_price': 20, 'status': 3, 'is_ingredients_wasted': 0, 'delay_in_seconds': None, 'kitchen_notes': None, 'meta': {'foodics': {'uuid': '44dac135-20fe-40a5-b862-a49726a9e21b'}}, 'added_at': '2021-07-20 10:51:41', 'closed_at': '2021-07-20 10:51:58'}, {'product': {'category': {'id': '93820e96-ee8a-4a71-8a74-bc3d693e6302', 'name': 'Sandwiches', 'name_localized': None, 'reference': None, 'image': None, 'created_at': '2021-05-24 14:53:18', 'updated_at': '2021-05-24 14:53:18', 'deleted_at': None}, 'ingredients': [], 'id': '93820f4b-94dd-459d-ba26-5ac2f584b3b9', 'sku': 'Burg-002', 'barcode': None, 'name': 'Double buger', 'name_localized': None, 'description': None, 'description_localized': None, 'image': None, 'is_active': True, 'is_stock_product': False, 'is_ready': True, 'pricing_method': 1, 'selling_method': 1, 'costing_method': 1, 'preparation_time': None, 'price': 20, 'cost': 10, 'calories': None, 'created_at': '2021-05-24 14:55:16', 'updated_at': '2021-05-24 14:55:16', 'deleted_at': None}, 'promotion': None, 'discount': None, 'options': [], 'taxes': [], 'timed_events': [], 'void_reason': None, 'creator': {'pin': '*****', 'is_owner': True, 'id': '934f966a-ec55-4f08-8916-422d260d7b3f', 'name': 'hussain Ali', 'number': None, 'email': 'hussain@fatortech.net', 'phone': None, 'lang': 'en', 'display_localized_names': False, 'email_verified': True, 'must_use_fingerprint': False, 'last_console_login_at': '2021-07-20 09:07:53', 'last_cashier_login_at': None, 'created_at': '2021-04-29 12:46:22', 'updated_at': '2021-07-20 09:07:53', 'deleted_at': None}, 'voider': None, 'discount_type': None, 'quantity': 1, 'returned_quantity': 0, 'unit_price': 20, 'discount_amount': 0, 'total_price': 20, 'total_cost': 10, 'tax_exclusive_discount_amount': 0, 'tax_exclusive_unit_price': 20, 'tax_exclusive_total_price': 20, 'status': 3, 'is_ingredients_wasted': 0, 'delay_in_seconds': None, 'kitchen_notes': None, 'meta': {'foodics': {'uuid': '678a086a-3b64-406b-b12f-77e7b1c72b34'}}, 'added_at': '2021-07-20 10:51:42', 'closed_at': '2021-07-20 10:51:58'}, {'product': {'category': {'id': '93820e78-fbe2-4855-af62-56c3ee888740', 'name': 'Fries', 'name_localized': None, 'reference': None, 'image': None, 'created_at': '2021-05-24 14:52:58', 'updated_at': '2021-05-24 14:52:58', 'deleted_at': None}, 'ingredients': [], 'id': '93820ff5-628f-4311-a116-9e4adb64c1cb', 'sku': 'sk-0005', 'barcode': None, 'name': 'Wicked fries', 'name_localized': None, 'description': None, 'description_localized': None, 'image': None, 'is_active': True, 'is_stock_product': False, 'is_ready': True, 'pricing_method': 1, 'selling_method': 1, 'costing_method': 1, 'preparation_time': None, 'price': 18, 'cost': 12, 'calories': None, 'created_at': '2021-05-24 14:57:07', 'updated_at': '2021-05-24 14:57:07', 'deleted_at': None}, 'promotion': None, 'discount': None, 'options': [], 'taxes': [], 'timed_events': [], 'void_reason': None, 'creator': {'pin': '*****', 'is_owner': True, 'id': '934f966a-ec55-4f08-8916-422d260d7b3f', 'name': 'hussain Ali', 'number': None, 'email': 'hussain@fatortech.net', 'phone': None, 'lang': 'en', 'display_localized_names': False, 'email_verified': True, 'must_use_fingerprint': False, 'last_console_login_at': '2021-07-20 09:07:53', 'last_cashier_login_at': None, 'created_at': '2021-04-29 12:46:22', 'updated_at': '2021-07-20 09:07:53', 'deleted_at': None}, 'voider': None, 'discount_type': None, 'quantity': 1, 'returned_quantity': 0, 'unit_price': 18, 'discount_amount': 0, 'total_price': 18, 'total_cost': 12, 'tax_exclusive_discount_amount': 0, 'tax_exclusive_unit_price': 18, 'tax_exclusive_total_price': 18, 'status': 3, 'is_ingredients_wasted': 0, 'delay_in_seconds': None, 'kitchen_notes': None, 'meta': {'foodics': {'uuid': '23bc0c9d-d5fc-4be2-9628-0052354cd731'}}, 'added_at': '2021-07-20 10:51:45', 'closed_at': '2021-07-20 10:51:58'}], 'combos': [], 'device': {'id': '934f9699-04f1-4a53-98c9-2c68c0304981', 'name': 'Cashier 1', 'code': '16341', 'reference': 'C01', 'type': 1}, 'id': '8531fd47-0649-44d8-a439-d06651e9d20f', 'app_id': '8f9eb3f6-7987-4f66-aa8c-478c34d0c568', 'promotion_id': None, 'discount_type': None, 'reference_x': None, 'number': 10, 'type': 2, 'source': 1, 'status': 4, 'delivery_status': None, 'guests': 1, 'kitchen_notes': None, 'customer_notes': None, 'business_date': '2021-07-20', 'subtotal_price': 58, 'discount_amount': 0, 'rounding_amount': 0, 'total_price': 58, 'tax_exclusive_discount_amount': 0, 'delay_in_seconds': None, 'meta': {'foodics': {'device_id': '934f9699-04f1-4a53-98c9-2c68c0304981', 'products_kitchen': []}}, 'opened_at': '2021-07-20 10:51:41', 'accepted_at': None, 'due_at': None, 'driver_assigned_at': None, 'dispatched_at': None, 'driver_collected_at': None, 'delivered_at': None, 'closed_at': '2021-07-20 10:51:58', 'created_at': '2021-07-20 10:52:09', 'updated_at': '2021-07-20 10:52:09', 'reference': 46, 'check_number': 100027}}
        branch = None
        merchant = None
        user = None
        new_user = None
        order_item = []
        print('before try----->>>')
        try:
            merchant = Merchant.objects.get(email=webhook_data['order']['creator']['email'])
        except Exception as e:
            print('MERCHANT EXCEPTION', e)
            merchant = Merchant.objects.create(email=webhook_data['order']['creator']['email'],
                                               full_name=webhook_data['order']['creator']['name'])
        try:
            branch = Branch.objects.get(code=webhook_data['order']['branch']['name'])
        except Exception as e:
            print('BRANCH EXCEPTION', e)
            branch = Branch.objects.create(code=webhook_data['order']['branch']['name'], merchant_name=merchant)
        try:
            user = User.objects.get(email=webhook_data['order']['customer']['email'])
        except Exception as e:
            user = User.objects.create(first_name=webhook_data['order']['customer']['name'],
                                       email=webhook_data['order']['customer']['email'],
                                       country_code=webhook_data['order']['customer']['dial_code'],
                                       phone_number=webhook_data['order']['customer']['phone'])
            user.set_password('Test@123')
            user.save()
            new_user = user

        print(webhook_data['order']['branch']['name'])
        print(webhook_data['order']['creator']['name'])
        print(webhook_data['order']['customer']['name'], webhook_data['order']['customer']['dial_code'],
              webhook_data['order']['customer']['phone'],
              webhook_data['order']['customer']['email'])
        print('Payment--', webhook_data['order']['payments'][0]['payment_method']['name'])
        print('Payment--', webhook_data['order']['payments'][0]['amount'])

        for i in range(len(webhook_data['order']['products'])):
            print(webhook_data['order']['products'][i]['product']['category']['name'])
            print(webhook_data['order']['products'][i]['product']['name'])
            print(webhook_data['order']['products'][i]['product']['price'])
            print(webhook_data['order']['products'][i]['quantity'])
            print(webhook_data['order']['products'][i]['unit_price'])
            print(webhook_data['order']['products'][i]['total_price'])
            order_item_obj = OrderItem.objects.create(
                user=user,
                product=webhook_data['order']['products'][i]['product']['name'],
                price=webhook_data['order']['products'][i]['product']['price'],
                quantity=webhook_data['order']['products'][i]['quantity'],
                total=webhook_data['order']['products'][i]['total_price'],
                vat_percent=0
            )
            order_item.append(order_item_obj)
        print(webhook_data['order']['payments'][0]['amount'])
        receipt_obj = Receipt.objects.create(
            user=user,
            merchant=merchant,
            branch=branch,
            vat=0,
            amount=webhook_data['order']['payments'][0]['amount'],
            total=webhook_data['order']['payments'][0]['amount'],
            order_created_from='FOODICS API'
        )
        for item in order_item:
            receipt_obj.order.add(OrderItem.objects.get(id=item.id))
        receipt_id = 0
        try:
            receipt_obj = Receipt.objects.last()
            receipt_id = receipt_obj.id + 1
        except Exception as e:
            print('RECEIPT EXCEPTION', e)
            receipt_id += 1
        item_string = ''
        item_string += ', Order Id : ' + str(receipt_obj.id)
        url = pyqrcode.create(item_string, encoding='utf-8')
        url.png(f'media/{receipt_id}.png', scale=6)
        qr = os.path.basename(f'{receipt_id}.png'), File(open(f'media/{receipt_id}.png', 'rb'))
        receipt_obj.qr_code = qr[1]
        receipt_obj.save(update_fields=['qr_code'])
        scanned_data_obj = ScannedData.objects.create(
            user=user,
            merchant=merchant,
            order=receipt_obj
        )
        try:
            if new_user:
                account_sid = 'ACf02ece6f59b345778bdd512e693c8e3e'
                auth_token = '427991ea9201b5e360ab49532d703157'
                client = Client(account_sid, auth_token)
                client.messages.create(
                    body=f'Your receipt with receipt id-{receipt_obj} has been generated.'
                         f'Please download the app to view th receipt. '
                         f'Please login using credentials given in this message. Login Email: {user.email}, Login Password:Test@123',
                    from_='+19412579649',
                    to='+' + str((user.country_code) + str(user.phone_number))
                )
        except Exception as e:
            print('TWILIO EXCEPTION ', e)
            pass
        # print(webhook_data['order']['customer']['name'])

        return Response({'status': HTTP_200_OK, 'message': 'success'})


class NewFoodicsWebHookUrl(APIView):
    def get(self, request, *args, **kwargs):
        return Response({'message': 'Success', 'status': HTTP_200_OK})

    def post(self, request, *args, **kwargs):
        print('Data from post method of foodics web hook url', self.request.POST)
        print('Data from post method of foodics web hook url args', *args)
        print('Data from post method of foodics web hook url', **kwargs)
        return Response(status=HTTP_200_OK)


class FetchDataFromFoodicsApi(APIView):

    def get(self, request, *args, **kwargs):
        # api-sandbox.foodics.com/v5
        # get settings
        # access_token = request.session['access_token']
        # refresh_token = request.session['refresh_token']
        access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6ImVjMDg1ZDQwODk4ODgwYmFkYjY3NDM0NTRmNGQ3OWI3NjEwMDJmMGJjOTVkYmU1NjM4ZjA1M2M0NDQ3OTFkNTFjNjg1YzQ3ZDU3MWNlNTUxIn0.eyJhdWQiOiI5MzRmODhkYS0yZjJhLTQyNWQtODI0Ni0xZjc4NGI1YTI0YmUiLCJqdGkiOiJlYzA4NWQ0MDg5ODg4MGJhZGI2NzQzNDU0ZjRkNzliNzYxMDAyZjBiYzk1ZGJlNTYzOGYwNTNjNDQ0NzkxZDUxYzY4NWM0N2Q1NzFjZTU1MSIsImlhdCI6MTYyMTMzNzYxNywibmJmIjoxNjIxMzM3NjE3LCJleHAiOjE3NzkxMDQwMTcsInN1YiI6IjkzNGY5NjZhLWVjNTUtNGYwOC04OTE2LTQyMmQyNjBkN2IzZiIsInNjb3BlcyI6W10sImJ1c2luZXNzIjoiOTM0Zjk2NmItMDIwYi00NWM5LWI5ZWQtZTUwMDk5ZmE2MzYxIiwicmVmZXJlbmNlIjoiMjk4OTQ2In0.fIxwO6pPLRLrr1Nif1_RhOQGFoWHchyiL2hqPc2dtcIpcnY6w13Jg7fpfW9sTPiYGosdUzTCR2PZ7FIVkHegGGV0idnnYXpgcT4zJBvMmuCUTvbl1cg8dG0lKasJyxCOIqFULnIzOynczg94mxrpj2Hot-ZPGovaHfqvIolvphSoVkeKCp84Ld2Dm7YCrPFCplmAgJGYXi0X6ex0R4GBjTEEPhQL3jeRJtDJUINZtfJf6zZXu2T6WZ8w481Hry9xF2x9tvLRxKbWU4shCOp9aQ4jK7uoDj4xJy9IVvN2L2StCipr2FthnD37POvVuedygljkrT6uh_gKl9beYFjO3sdqCvSDwjT9RAlUAjCcVR_Om-mRm2S_2BWL2D9bhdZDEFSzzTdqISr4omyVUt0hc4EqoFehEHm-tPYjwkYq0YIWHT8rLYlCvElRUBfr-wuYfoOQhPE9OKTgm-isPcr8Xhgjz3_LURmXRRN_d8nTjc-bC1S61FGl9recLyzo3sq0gpIGy_FO08O_6RePrChG5RgQ4YcrEEXquJF3_SnLBR67Kjin52xztoAtRZV9ZN2iN9UA5WTfa45ucZyU3d6WgqnN4WTtYMhcZJ7w6iVo4FH9oWi1nznC1EXAEJhCAvmTVYDvQPzv2OjSgyVAjFO4SgGmAgmmYqqTF63NJ2FbvkI'
        # header = {'authorization': 'Bearer {}'.format(refresh_token)}
        # if request.is_secure():
        #     protocol = "https"
        # else:
        #     protocol = "http"
        # domain = request.META['HTTP_HOST']
        # print(protocol)
        # print(domain)
        # print(f'{protocol}://{domain}/api/foodics-api')
        # y = requests.get(f'{protocol}://{domain}/api/foodics-api')
        # print(y)
        # print(y.json())
        # access_token = y.json()['access_token']
        headers = CaseInsensitiveDict()
        headers["Accept"] = "application/json"
        headers["Authorization"] = f"Bearer {access_token}"
        x = requests.get('https://api-sandbox.foodics.com/v5/settings',
                         headers=headers)
        print(x.status_code)
        return Response({'data': x.json(), 'status': x.status_code})
