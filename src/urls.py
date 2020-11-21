from django.urls import path
from .views import UserCreateAPIView, LoginAPIView, ForgetPasswordAPIView, ChangePasswordAPIView, Logout, SendOtpEmail, \
    VerifyEmailOtp, ResendOtp, CheckPhoneNumber, CheckEmail

app_name = 'src'

urlpatterns = [
    path('user-create/', UserCreateAPIView.as_view(), name='user-create'),
    path('user-login/', LoginAPIView.as_view(), name='user-login'),
    path('forget-password/', ForgetPasswordAPIView.as_view(), name='forget-password'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('logout/', Logout.as_view(), name='logout'),
    path('check-phone-number/', CheckPhoneNumber.as_view(), name='check-phone-number'),
    path('check-email/', CheckEmail.as_view(), name='check-email'),
    path('send-otp/', SendOtpEmail.as_view(), name='otp-email'),
    path('verify-otp/', VerifyEmailOtp.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOtp.as_view(), name='resend-otp'),
]
