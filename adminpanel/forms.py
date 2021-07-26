from django import forms
from src.models import User, Merchant, UserNotification, TermsAndCondition, ContactUs, PrivacyPolicy, AboutUs, Category, \
    Branch, Banner
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
        fields = ('full_name', 'category', 'commercial_id', 'email', 'address', 'password', 'confirm_password')


class MerchantUpdateForm(forms.ModelForm):
    category = forms.ModelChoiceField(queryset=Category.objects.all(),
                                      widget=forms.TextInput())

    class Meta:
        model = Merchant
        fields = ('full_name', 'category', 'commercial_id', 'email', 'address')


class SubAdminForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password', 'confirm_password')


class BranchForm(forms.ModelForm):
    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     print(kwargs)
    #     print(args)
    # self.fields['Responsable'].queryset =
    # self.fields['InformationsInstitution'].initial = user_initial

    class Meta:
        model = Branch
        fields = '__all__'


class UserNotificationForm(forms.ModelForm):
    class Meta:
        model = UserNotification
        fields = ('to', 'body')


class UpdateTnCForm(forms.ModelForm):
    conditions = forms.CharField(widget=CKEditorWidget())
    conditions_in_arabic = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = TermsAndCondition
        fields = ('conditions', 'conditions_in_arabic')


class UpdateContactusForm(forms.ModelForm):
    # phone_number = forms.CharField(widget=CKEditorWidget())
    phone_number = forms.CharField()
    # email = forms.CharField(widget=CKEditorWidget())
    email = forms.EmailField()

    class Meta:
        model = ContactUs
        fields = ('company_name', 'phone_number', 'email')


class UpdatePrivacyPolicyForm(forms.ModelForm):
    policy = forms.CharField(widget=CKEditorWidget())
    policy_in_arabic = forms.CharField(widget=CKEditorWidget())

    # policy_in_arabic = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = PrivacyPolicy
        fields = ('policy', 'policy_in_arabic')


class UpdateAboutUsForm(forms.ModelForm):
    content = forms.CharField(widget=CKEditorWidget())
    content_in_arabic = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = AboutUs
        fields = ('content','content_in_arabic')


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ('category_name',)


class BannerForms(forms.ModelForm):
    class Meta:
        model = Banner
        fields = '__all__'
