from random import randint

from django.core.mail import EmailMessage
from django.shortcuts import render
from rest_framework.generics import CreateAPIView, UpdateAPIView
from django.utils.decorators import method_decorator

from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK

from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView

from .models import User, Settings, UserNotification, Otp
from .serializers import UserCreateSerializer, AuthTokenSerializer, ForgetPasswordSerializer, ChangePasswordSerializer, \
    UpdateNotificationSerializer, NotificationSerializer, OtpSerializer

from rest_framework.settings import api_settings


class CheckPhoneNumber(APIView):

    def get(self, request, *args, **kwargs):
        phone_number = self.request.GET.get('phone_number')
        try:
            user = User.objects.get(phone_number=phone_number)
            if user:
                return Response({"msg": "User with this phone number already exists", "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            print(e)
            return Response({"msg": "No user is registered with this number", "status": HTTP_200_OK})


class CheckEmail(APIView):

    def get(self, request, *args, **kwargs):
        email = self.request.GET.get('email')
        try:
            user = User.objects.get(email=email)
            if user:
                return Response({"msg": "User with this email already exists", "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
            return Response({"msg": "No user is registered with this email", "status": HTTP_200_OK})


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
        # profile_pic = self.request.POST.get('profile_pic' or None)
        profile_pic = self.request.POST.get('profile_pic' or None)
        device_token = self.request.POST.get('device_token' or None)
        device_type = self.request.POST.get('device_type' or None)

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
                    return Response({"Token": token.key, "id": user_id, "status": HTTP_200_OK})
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
                    print('updated device token ', userObj.device_token)
                    token = token[0]
                    return Response({"Token": token.key, "id": user_id, "status": HTTP_200_OK})
                else:
                    return Response({"message": "Wrong password", "status": HTTP_400_BAD_REQUEST})
        except Exception as e:
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
                            {"success": "Incorrect old password", "status": HTTP_400_BAD_REQUEST, "detail": ""})
                    else:
                        return Response(
                            {"success": "كلمة السر القديمة غير صحيحة", "status": HTTP_400_BAD_REQUEST, "detail": ""})
                elif new_password != confirm_new_password:
                    if lang_setting_obj.language == 'English':
                        return Response(
                            {"success": "Password and confirm password didn't match", "status": HTTP_400_BAD_REQUEST,
                             "detail": ""})
                    else:
                        return Response(
                            {"success": "كلمة المرور وتأكيد كلمة المرور غير متطابقتين", "status": HTTP_400_BAD_REQUEST,
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
                        return Response({"success": "Your Password has been changed successfully",
                                         "status": HTTP_200_OK, "detail": ""})
                    else:
                        return Response({"success": "تم تغيير كلمة المرور الخاصة بك بنجاح",
                                         "status": HTTP_200_OK, "detail": ""})
        except Exception as e:
            return Response({"message": serializer.errors, "status": HTTP_400_BAD_REQUEST, "detail": ""})


class Logout(APIView):

    def get(self, request, *args, **kwargs):
        # user = self.request.user
        request.user.auth_token.delete()
        return Response({"msg": "Logged out successfully", "status": HTTP_200_OK})


class SendOtpEmail(APIView):
    serializer_class = OtpSerializer

    def get(self, request, *args, **kwargs):
        otp = randint(100000, 999999)
        email = self.request.GET.get('email')
        try:
            user = User.objects.get(email=email)
            if user:
                otp = Otp.objects.create(user=user, otp=otp)
                email = EmailMessage(
                    'Your Password Reset OTP',
                    'OTP to reset password of your Snapic Account : ' +
                    str(otp.otp),
                    to=[email]
                )
                email.send()
                return Response({"msg": "Otp sent", "status": HTTP_200_OK})
        except Exception as e:
            return Response({"msg": "Failed to send OTP to specified email.Please check your E-Mail ID",
                             "status": HTTP_400_BAD_REQUEST})


class VerifyEmailOtp(APIView):

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
                    {"msg": "Otp verified successfully", "status": HTTP_200_OK})
            else:
                return Response({"msg": "Incorrect Otp", "status": HTTP_400_BAD_REQUEST})

        except Exception as e:
            print(e)
            return Response({"msg": "Incorrect Otp", "status": HTTP_400_BAD_REQUEST})


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
                    'OTP to reset password of your Snapic Account : ' +
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
