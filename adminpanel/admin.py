from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext as _
from src.models import *


class UserAdmin(BaseUserAdmin):
    ordering = ['id']
    list_display = ['email', 'first_name', 'last_name']
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'),
         {'fields': ('first_name', 'last_name', 'profile_pic', 'phone_number', 'device_token', 'is_merchant')}),
        (_('Permissions'),
         {'fields': ('is_active', 'is_staff', 'is_superuser')}),
        (_('Important Dates'), {'fields': ('last_login',)})
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password', 'confirm_password')
        }),
    )


admin.site.register(User, UserAdmin)
admin.site.register(Category)
admin.site.register(Merchant)
admin.site.register(OrderItem)
admin.site.register(Receipt)
admin.site.register(ScannedData)
admin.site.register(Settings)
admin.site.register(UserNotification)
admin.site.register(ContactUs)
admin.site.register(PrivacyPolicy)
admin.site.register(TermsAndCondition)
admin.site.register(AboutUs)
