from django.urls import path

from rest_framework.routers import DefaultRouter
from .views import UserCreateAPIView, LoginAPIView, ForgetPasswordAPIView, ChangePasswordAPIView, Logout, SendOtpEmail, \
    VerifyEmailOtp, ResendOtp, CheckPhoneNumber, CheckEmail, UpdatePhoneNumberView, UpdateUserDetailApiView, \
    ScannedDataView, GetScannedDataDetail, GetUserTransactions, ReceiptSearchView, FilterByCategory, FilterByDate, \
    CreateReceiptManually, GetLatestTransactions, FAQApiView, GetNotificationList, DeleteNotification, \
    UpdateNotification, UpdateUserNotificationSettingsApi, UpdateUserLanguageSettingApiView, GetUnreadMessageCount, \
    UserLanguageSettingApiView, GetUserNotificationSettingsApi, ChangeLanguageApiView, ChangeNotificationApiView, \
    PrivacyPolicyApiView, ContactUsApiView, TermsandConditionApiView, GetUserDetailApiView, CheckMobileOrPhoneNumber, \
    FirstViewSet, AboutUsView, UpdateEmailView, AddToCart, GetCategoryList, POSOrder, GetCartItemDetail, \
    GetMerchantNameAndCategory, FilterExpenseDataByMonth, FilterExpenseDataByCategory,AutoOrderCreation,GetBannersView

app_name = 'src'
# router = DefaultRouter()
# router.register(r'users', FirstViewSet, basename='user')
# urlpatterns = router.urls

urlpatterns = [
    path('user-create/', UserCreateAPIView.as_view(), name='user-create'),
    path('user-detail/', GetUserDetailApiView.as_view(), name='user-detail'),
    path('user-login/', LoginAPIView.as_view(), name='user-login'),
    path('forget-password/', ForgetPasswordAPIView.as_view(), name='forget-password'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('logout/', Logout.as_view(), name='logout'),
    path('check-phone-number/', CheckPhoneNumber.as_view(), name='check-phone-number'),
    path('check-email/', CheckEmail.as_view(), name='check-email'),
    path('send-otp/', SendOtpEmail.as_view(), name='otp-email'),
    path('verify-otp/', VerifyEmailOtp.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOtp.as_view(), name='resend-otp'),
    path('update-user-phone-number/<int:pk>/', UpdatePhoneNumberView.as_view(), name='update-user-phone-number'),
    path('user-update/<int:pk>/', UpdateUserDetailApiView.as_view(), name='user-update'),
    path('update-user-email/<int:pk>/', UpdateEmailView.as_view(), name='update-user-email'),
    path('scanned-data/', ScannedDataView.as_view(), name='scanned-data'),
    path('scanned-data-detail/', GetScannedDataDetail.as_view(), name='scanned-data-detail'),
    path('cart-item-detail/', GetCartItemDetail.as_view(), name='cart-item-detail'),
    path('scanned-data-list/', GetUserTransactions.as_view(), name='scanned-data-list'),
    path('search-scanned-data/', ReceiptSearchView.as_view(), name='search-scanned-data'),
    path('filter-by-category/', FilterByCategory.as_view(), name='filter-by-category'),
    path('filter-by-date/', FilterByDate.as_view(), name='filter-by-date'),
    path('expense-by-month/', FilterExpenseDataByMonth.as_view(), name='expense-by-month'),
    path('expense-by-category/', FilterExpenseDataByCategory.as_view(), name='expense-by-category'),
    path('create-order/', CreateReceiptManually.as_view(), name='create-order'),
    path('pos-order/', POSOrder.as_view(), name='pos-order'),
    path('add-to-cart/', AddToCart.as_view(), name='add-to-cart'),
    path('latest-transactions/', GetLatestTransactions.as_view(), name='latest-transactions'),
    # path('faq/', FAQApiView.as_view(), name='faq'),
    path('contact-us/', ContactUsApiView.as_view(), name='contact-us'),
    path('category-list/', GetCategoryList.as_view(), name='category-list'),
    path('terms-and-condition/', TermsandConditionApiView.as_view(),
         name='terms-and-condition'),
    path('privacy-policy/', PrivacyPolicyApiView.as_view(), name='privacy-policy'),
    path('user-notification/', GetNotificationList.as_view(),
         name='user-notification'),
    path('delete-user-notification/', DeleteNotification.as_view(),
         name='delete-user-notification'),
    path('update-user-notification/',
         UpdateNotification.as_view(), name='update-user-notification'),
    path('get-user-fcm-setting/', GetUserNotificationSettingsApi.as_view(),
         name='get-user-fcm-setting'),
    path('update-user-fcm-setting/<int:pk>/', UpdateUserNotificationSettingsApi.as_view(),
         name='update-user-fcm-setting'),
    path('get-user-lang/', UserLanguageSettingApiView.as_view(), name='get-user-lang'),
    path('update-user-lang/<int:pk>/',
         UpdateUserLanguageSettingApiView.as_view(), name='update-user-lang'),
    path('get-user-unread-message-count/', GetUnreadMessageCount.as_view(), name='get-user-unread-message-count'),
    path('check-mobile-or-phone-number/', CheckMobileOrPhoneNumber.as_view(), name='check-mobile-or-phone-number'),
    path('get-merchant-name-and-category/', GetMerchantNameAndCategory.as_view(),
         name='get-merchant-name-and-category'),
    path('about-us/', AboutUsView.as_view(), name='about-us'),
    path('auto-order-creation/', AutoOrderCreation.as_view(), name='auto-order-creation'),
    path('get-banners/', GetBannersView.as_view(), name='get-banners'),
]
