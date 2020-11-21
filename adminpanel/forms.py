from django import forms
from src.models import User, Merchant, UserNotification, TermsAndCondition, ContactUs, PrivacyPolicy, AboutUs, Category
from django.contrib.auth.password_validation import validate_password, MinimumLengthValidator
from ckeditor.widgets import CKEditorWidget


class LoginForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False, widget=forms.CheckboxInput())

    class Meta:
        model = User
        fields = ['email', 'password', 'remember_me']


class MerchantForm(forms.ModelForm):
    # password = forms.CharField(widget=forms.PasswordInput, validators=[validate_password])

    class Meta:
        model = Merchant
        fields = ('full_name', 'category', 'email', 'password', 'confirm_password')


class UserNotificationForm(forms.ModelForm):
    class Meta:
        model = UserNotification
        fields = ('to', 'body')


class UpdateTnCForm(forms.ModelForm):
    conditions = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = TermsAndCondition
        fields = ('conditions',)


class UpdateContactusForm(forms.ModelForm):
    # phone_number = forms.CharField(widget=CKEditorWidget())
    phone_number = forms.CharField()
    # email = forms.CharField(widget=CKEditorWidget())
    email = forms.EmailField()

    class Meta:
        model = ContactUs
        fields = ('phone_number', 'email')


class UpdatePrivacyPolicyForm(forms.ModelForm):
    policy = forms.CharField(widget=CKEditorWidget())

    # policy_in_arabic = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = PrivacyPolicy
        fields = ('policy',)


class UpdateAboutUsForm(forms.ModelForm):
    content = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = AboutUs
        fields = ('content',)


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ('category_name',)
