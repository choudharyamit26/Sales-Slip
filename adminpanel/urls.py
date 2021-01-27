from django.urls import path
from .views import Login, Dashboard, NotificationView, UsersList, AddMerchant, MerchantList, ReceiptList, UserDetail, \
    MerchantDetail, NotificationCount, ReadNotifications, SetAdminNotificationSetting, GetAdminNotificationSetting, \
    SendNotification, TermsAndConditionView, UpdateTermsAndCondition, UpdateContactUsView, UpdatePrivacyPolicyView, \
    UpdateAboutUsView, ReportView, CreateCategory, CategoryList, UserDelete, MerchantDelete, ReceiptDetail, AddSubAdmin, \
    SubAdminList, AddBranch, BranchList, BannerView, BannerList, UpdateMerchant, BannerDetail, UpdateBanner, \
    DeleteBanner, SubAdminDetail, UpdateSubAdminDetail, DeleteSubAdmin, UpdateBranch,DeleteBranch

app_name = 'adminpanel'

urlpatterns = [
    path('', Login.as_view(), name='login'),
    path('dashboard/', Dashboard.as_view(), name='dashboard'),
    path('notification/', NotificationView.as_view(), name='notification'),
    path('users-list/', UsersList.as_view(), name='users-list'),
    path('user-delete/<int:pk>/', UserDelete.as_view(), name='user-delete'),
    path('add-merchant/', AddMerchant.as_view(), name='add-merchant'),
    path('add-sub-admin/', AddSubAdmin.as_view(), name='add-sub-admin'),
    path('add-branch/', AddBranch.as_view(), name='add-branch'),
    path('update-branch/<int:pk>/', UpdateBranch.as_view(), name='update-branch'),
    path('delete-branch/<int:pk>/', DeleteBranch.as_view(), name='delete-branch'),
    path('branch-list/', BranchList.as_view(), name='branch-list'),
    path('sub-admin-list/', SubAdminList.as_view(), name='sub-admin-list'),
    path('merchant-list/', MerchantList.as_view(), name='merchant-list'),
    path('merchant-delete/<int:pk>/', MerchantDelete.as_view(), name='merchnat-delete'),
    path('receipt-list/', ReceiptList.as_view(), name='receipt-list'),
    path('receipt-detail/<int:pk>/', ReceiptDetail.as_view(), name='receipt-detail'),
    path('user-detail/<int:pk>/', UserDetail.as_view(), name='user-detail'),
    path('merchant-detail/<int:pk>/', MerchantDetail.as_view(), name='merchant-detail'),
    path('notification-count/', NotificationCount.as_view(),
         name='notification-count'),
    path('read-notification/', ReadNotifications.as_view(),
         name='read-notification'),
    path('notification-setting/', SetAdminNotificationSetting.as_view(),
         name='notification-setting'),
    path('get-notification-setting/', GetAdminNotificationSetting.as_view(),
         name='get-notification-setting'),
    path('send-notification/', SendNotification.as_view(),
         name='send-notification'),
    path('static-content/', TermsAndConditionView.as_view(), name='static-content'),
    path('update-terms-and-condition/<int:pk>/',
         UpdateTermsAndCondition.as_view(), name='update-terms-and-condition'),
    path('update-contact-us/<int:pk>/',
         UpdateContactUsView.as_view(), name='update-contact-us'),
    path('update-privacy-policy/<int:pk>/',
         UpdatePrivacyPolicyView.as_view(), name='update-privacy-policy'),
    path('update-about-us/<int:pk>/',
         UpdateAboutUsView.as_view(), name='update-about-us'),
    path('update-merchant/<int:pk>/', UpdateMerchant.as_view(), name='update-merchant'),
    path('reports/', ReportView.as_view(), name='reports'),
    path('category/', CreateCategory.as_view(), name='category'),
    path('banner/', BannerView.as_view(), name='banner'),
    path('banner-list/', BannerList.as_view(), name='banner-list'),
    path('banner-detail/<int:pk>/', BannerDetail.as_view(), name='banner-detail'),
    path('sub-admin-detail/<int:pk>/', SubAdminDetail.as_view(), name='sub-admin-detail'),
    path('update-banner/<int:pk>/', UpdateBanner.as_view(), name='update-banner'),
    path('delete-banner/<int:pk>/', DeleteBanner.as_view(), name='delete-banner'),
    path('update-sub-admin/<int:pk>/', UpdateSubAdminDetail.as_view(), name='update-sub-admin'),
    path('delete-sub-admin/<int:pk>/', DeleteSubAdmin.as_view(), name='delete-sub-admin'),
    path('category-list/', CategoryList.as_view(), name='category-list'),
]
