from random import randint

from django.core.mail import EmailMessage
from django.shortcuts import render
from rest_framework.generics import CreateAPIView, UpdateAPIView, ListAPIView
from django.utils.decorators import method_decorator

from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK, HTTP_404_NOT_FOUND

from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView

from django.utils.crypto import get_random_string
from .fcm_notification import send_another, send_to_one
from .models import User, Settings, UserNotification, Otp, ScannedData, Merchant, Receipt, Category, OrderItem, FAQ, \
    TermsAndCondition, ContactUs, PrivacyPolicy, AboutUs
from .serializers import UserCreateSerializer, AuthTokenSerializer, ForgetPasswordSerializer, ChangePasswordSerializer, \
    UpdateNotificationSerializer, NotificationSerializer, OtpSerializer, UpdatePhoneSerializer, ScannedDataSerializer, \
    TermsandConditionSerializer, ContactUsSerializer, PrivacyPolicySerializer, LanguageSettingSerializer, \
    NotificationSettingSerializer, SettingsSerializer, FAQSerializer, LanguageSettingsSerializer, UpdateEmailSerializer

from rest_framework.settings import api_settings
from rest_framework.viewsets import ModelViewSet


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
                email=email,
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
                userObj = User.objects.get(email=email)
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
            email = otpObj.user.email
            userObj = User.objects.get(email=email)
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

    def get(self, request, *args, **kwargs):
        otp = randint(100000, 999999)
        email = self.request.GET.get('email')
        try:
            user = User.objects.get(email=email)
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
            receipt_object['merchant'] = receipt_obj.merchant.email
            receipt_object['merchant_id'] = receipt_obj.merchant.id
            receipt_object['receipt_id'] = receipt_obj.id
            receipt_object['merchant_name'] = receipt_obj.merchant.full_name
            receipt_object['merchant_category'] = receipt_obj.merchant.category.category_name
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
                                     'product_quantity': obj.quantity})
                total = obj.total
                i += 1
                print(obj.id)
                print(obj.product)
                receipt_object['total'] = total
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
            data['merchant_category'] = obj.merchant.category.category_name
            data['created_at'] = obj.created_at
            product_list = []
            for order_obj in obj.order.all():
                product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                     'product_quantity': order_obj.quantity})
                data.update({'total': order_obj.total})
                data.update({'products': product_list})
            receipt_list.append(data)
        return Response({"data": receipt_list, "status": HTTP_200_OK})


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
                    'merchant_category': receipt_obj.merchant.category.category_name,
                    'created_at': receipt_obj.created_at}
            total = 0
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
                    {'product_name': obj.product, 'product_price': obj.price, 'product_quantity': obj.quantity})
                # data_list.append({'product_price': obj.price})
                # data_list.append({'product_quantity': obj.quantity})
                i += 1
                c = i
                total = obj.total
                # data.update({'total': obj.total})
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
            data = {}
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
                        data['merchant_category'] = x.merchant.category.category_name
                        data['created_at'] = x.created_at
                        for order_obj in x.order.all():
                            # print(i)
                            product_list = []
                            product_list.append({'product_name': order_obj.product, 'product_price': order_obj.price,
                                                 'product_quantity': order_obj.quantity})
                            data.update({'total': order_obj.total})
                            data.update({'products': product_list})
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
            return Response({'data': receipt_list, "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            return Response({"error": 'data not found', "status": HTTP_400_BAD_REQUEST})


class FilterByDate(ListAPIView):
    model = Receipt
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        data = {}
        try:
            from_date = self.request.GET.get('from_date')
            to_date = self.request.GET.get('to_date')
            print(from_date)
            print(to_date)
            receipt_obj = Receipt.objects.filter(user=self.request.user).filter(created_at__gte=from_date).filter(
                created_at__lte=to_date)
            print(receipt_obj.count())
            if receipt_obj.count() > 0:
                # receipts_list.append(receipts)
                # total = 0
                i = 1
                j = 1
                for x in receipt_obj:
                    data['receipt_id_{}'.format(j)] = x.id
                    data['merchant_id_{}'.format(j)] = x.merchant.id
                    data['merchant_email_{}'.format(j)] = x.merchant.email
                    data['created_at_{}'.format(j)] = x.created_at
                    for order_obj in x.order.all():
                        # print(i)
                        data.update({'receipt_id_{}_product_{}_name'.format(j, i): order_obj.product})
                        data.update({'receipt_id_{}_product_{}_price'.format(j, i): order_obj.price})
                        data.update({'receipt_id_{}_product_{}_quantity'.format(j, i): order_obj.quantity})
                        data.update({'total_{}'.format('receipt_id_{}'.format(j)): order_obj.total})
                        i += 1
                    i = 1
                    j += 1
            else:
                pass
            return Response({'data': data, "status": HTTP_200_OK})
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
        order_id = self.request.data['order_id']
        order_amount = self.request.data['order_amount']
        product_name = self.request.data['product_name']
        product_cost = self.request.data['product_cost']
        product_quantity = self.request.data['product_quantity']
        order_obj = OrderItem.objects.create(
            user=user,
            product=product_name,
            price=product_cost,
            quantity=product_quantity,
            total=order_amount,
            order_id=order_id
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
        # order_amount = self.request.data['order_amount']
        ordered_items = self.request.data['ordered_items']
        # customer_name = self.request.data['customer_name']
        # product_name = self.request.data['product_name']
        # product_cost = self.request.data['product_cost']
        # product_quantity = self.request.data['product_quantity']
        merchant_obj = Merchant.objects.get(id=merchant_id)
        category_obj = Category.objects.get(id=category)
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
        )
        for item in ordered_items:
            receipt_obj.order.add(OrderItem.objects.get(id=item))
        scanned_data_obj = ScannedData.objects.create(
            user=self.request.user,
            merchant=merchant_obj,
            order=receipt_obj
        )
        return Response({"message": "Order created successfully", "status": HTTP_200_OK})


class GetLatestTransactions(ListAPIView):
    model = Receipt
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user
        receipts = Receipt.objects.filter(user=user)
        # print(receipts[::-1])
        # print(receipts)
        if receipts.count() > 5:
            # for receipt in receipts[:5:-1]:
            #     print(receipt.created_at)
            # i = 1
            # j = 1
            receipt_list = []
            for x in receipts[:5:-1]:
                data = {}
                data['receipt_id'] = x.id
                data['merchant_id'] = x.merchant.id
                data['merchant_name'] = x.merchant.full_name
                data['merchant_category'] = x.merchant.category.category_name
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
                                         'product_quantity': order_obj.quantity})
                    data.update({'total': order_obj.total})
                    data.update({'products': product_list})
                receipt_list.append(data)
                # i += 1
                # i = 1
                # j += 1
        else:
            # print('inside else')
            # for receipt in receipts[:2:-1]:
            #     print(receipt.created_at)
            # i = 1
            # j = 1
            receipt_list = []
            for x in receipts[::-1]:
                data = {}
                data['receipt_id'] = x.id
                data['merchant_id'] = x.merchant.id
                data['merchant_name'] = x.merchant.full_name
                data['merchant_category'] = x.merchant.category.category_name
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
                                         'product_quantity': order_obj.quantity})
                    data.update({'total': order_obj.total})
                    data.update({'products': product_list})
                receipt_list.append(data)
                # i += 1
                # i = 1
                # j += 1
        return Response({"data": receipt_list, "status": HTTP_200_OK})


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
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

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
                user.email = email
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

    def post(self, request, *args, **kwargs):
        country_code = self.request.data['country_code']
        user_mobile_no = self.request.data['user_mobile_no']
        merchant_id = self.request.data['merchant_id']
        merchant_name = self.request.data['merchant_name']
        category = self.request.data['category']
        date_of_purchase = self.request.data['date_of_purchase']
        time_of_purchase = self.request.data['time_of_purchase']
        customer_email = self.request.data['customer_email']
        product_name = self.request.data['product_name']
        product_cost = self.request.data['product_cost']
        product_quantity = self.request.data['product_quantity']
        order_amount = self.request.data['order_amount']
        vat_percent = self.request.data['vat_percent']
        try:
            check_user = User.objects.get(phone_number=user_mobile_no)
            if check_user:
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
                        vat=vat_percent,
                        total=order_amount + (15 / 100) * order_amount,
                        order_id=order_id
                    )
                ordered_items = OrderItem.objects.filter(order_id=order_id)
                receipt_obj = Receipt.objects.create(
                    user=user,
                    merchant=merchant_obj,
                )
                for item in ordered_items:
                    receipt_obj.order.add(item)
                scanned_data_obj = ScannedData.objects.create(
                    user=user,
                    merchant=merchant_obj,
                    order=receipt_obj
                )
                return Response({"message": "Order created successfully", "status": HTTP_200_OK})
            else:
                user = User.objects.create(
                    # first_name=first_name,
                    # last_name=last_name,
                    country_code=country_code,
                    phone_number=user_mobile_no,
                    # profile_pic=profile_pic,
                    # email=email,
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
                        vat=vat_percent,
                        total=order_amount + (15 / 100) * order_amount,
                        order_id=order_id
                    )
                ordered_items = OrderItem.objects.filter(order_id=order_id)
                receipt_obj = Receipt.objects.create(
                    user=user,
                    merchant=merchant_obj,
                )
                for item in ordered_items:
                    receipt_obj.order.add(item)
                scanned_data_obj = ScannedData.objects.create(
                    user=user,
                    merchant=merchant_obj,
                    order=receipt_obj
                )
                return Response({"message": "Order created successfully", "status": HTTP_200_OK})
        except Exception as e:
            print(e)
            user = User.objects.create(
                # first_name=first_name,
                # last_name=last_name,
                country_code=country_code,
                phone_number=user_mobile_no,
                # profile_pic=profile_pic,
                # email=email,
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
                    vat=vat_percent,
                    total=order_amount + (15 / 100) * order_amount,
                    order_id=order_id
                )
            ordered_items = OrderItem.objects.filter(order_id=order_id)
            receipt_obj = Receipt.objects.create(
                user=user,
                merchant=merchant_obj,
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
            }
            return Response({'data': data_dict, 'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})


class GetMerchantNameAndCategory(APIView):
    model = Merchant

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        merchant_id = self.request.GET.get('merchant_id')
        try:
            merchant_obj = Merchant.objects.get(id=merchant_id)
            return Response({'name': merchant_obj.full_name, 'category': merchant_obj.category.category_name,
                             'status': HTTP_200_OK})
        except Exception as e:
            x = {'error': str(e)}
            return Response({'message': x['error'], 'status': HTTP_400_BAD_REQUEST})
