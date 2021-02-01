from django.contrib.auth import views as auth_views
from django.urls import path

from .views import MerchantLogin, MerchantDashBoard, MerchantLogout, PasswordResetConfirmView, PasswordResetView, \
    CreateOrder, OrderDetail, OrderList, ApiIntegrationTutorial, StaticContent, MyProfile, PasswordChangeView, \
    PasswordChangeDoneView, NotificationCount, ReadNotifications, SetAdminNotificationSetting, \
    GetAdminNotificationSetting, NotificationView, PrintQRCode, UpdateProfilePicView, SendOnBoardMessage, AddBranch, \
    BranchList, UpdateBranch, DeleteBranch, BranchPerformance

app_name = 'merchant'

urlpatterns = [

    path('login/', MerchantLogin.as_view(), name='login'),
    path('dashboard/', MerchantDashBoard.as_view(), name='dashboard'),
    path('logout/', MerchantLogout.as_view(), name='logout'),
    path('password-reset/',
         PasswordResetView.as_view(),
         name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),

    path('password-reset-done/',
         auth_views.PasswordResetDoneView.as_view(
             template_name='password_reset_done.html'
         ),
         name='password_reset_done'),

    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name='merchant/password_reset_complete.html'
         ),
         name='password_reset_complete'),
    path('change-password/', PasswordChangeView.as_view(template_name='merchant/change_password.html'),
         name='change_password'),
    path('password-change-done/', PasswordChangeDoneView.as_view(template_name='merchant/change_password_done.html'),
         name='password_change_done'),
    path('create-order/', CreateOrder.as_view(), name='create-order'),
    path('on-board/', SendOnBoardMessage.as_view(), name='on-board'),
    path('order-detail/<int:pk>/', OrderDetail.as_view(), name='order-detail'),
    path('order-list/', OrderList.as_view(), name='order-list'),
    path('api-tutorial/', ApiIntegrationTutorial.as_view(), name='api-tutorial'),
    path('static-content/', StaticContent.as_view(), name='static-content'),
    path('profile/', MyProfile.as_view(), name='profile'),
    path('notification/', NotificationView.as_view(), name='notification'),
    path('notification-count/', NotificationCount.as_view(),
         name='notification-count'),
    path('read-notification/', ReadNotifications.as_view(),
         name='read-notification'),
    path('notification-setting/', SetAdminNotificationSetting.as_view(),
         name='notification-setting'),
    path('get-notification-setting/', GetAdminNotificationSetting.as_view(),
         name='get-notification-setting'),
    path('print-qr/<int:pk>/', PrintQRCode.as_view(), name='print-qr'),
    path('update-profile/<int:pk>/', UpdateProfilePicView.as_view(), name='update-profile'),
    path('add-branch/', AddBranch.as_view(), name='add-branch'),
    path('branch-list/', BranchList.as_view(), name='branch-list'),
    path('update-branch/<int:pk>/', UpdateBranch.as_view(), name='update-branch'),
    path('delete-branch/<int:pk>/', DeleteBranch.as_view(), name='delete-branch'),
    path('branch-performance/', BranchPerformance.as_view(), name='branch-performance'),
]
