from src.models import User, OrderItem, Product, Merchant, Banner
from django import forms
from django.forms import modelformset_factory, inlineformset_factory


#
# class CustomMMCF(forms.ModelMultipleChoiceField):
#     def label_from_instance(self, product):
#         return "%s" % product.item__name


class MerchantLoginForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False, widget=forms.CheckboxInput())

    class Meta:
        model = User
        fields = ['email', 'password', 'remember_me']


class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = '__all__'


class OrderForm(forms.ModelForm):
    # products = CustomMMCF(queryset=Product.objects.all(), widget=forms.CheckboxSelectMultiple)
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = User.objects.all().exclude(is_merchant=True).exclude(is_superuser=True)
        print('from forms----', [x.phone_number for x in self.fields['user'].queryset])

    class Meta:
        model = OrderItem
        fields = ['user']


OrderFormSet = modelformset_factory(OrderItem, fields=('product', 'quantity', 'vat_percent', 'price'), widgets={
    'product': forms.TextInput(
        attrs={
            # 'class': 'form-control',
            'required': 'required',
            # 'remove':'remove'
        },
    ),
    'quantity': forms.TextInput(
        attrs={
            # 'width': '200px',
            # 'class': 'form-control',
            'required': 'required',
            'style': 'width:180px'
        }
    ),
    'vat_percent': forms.TextInput(
        attrs={
            # 'class': 'form-control',
            'required': 'required',
            'style': 'width:180px'
        }
    ),
    'price': forms.TextInput(
        attrs={
            # 'class': 'form-control',
            'required': 'required',
        }
    )

})


class MerchantUpdateForm(forms.ModelForm):
    full_name = forms.CharField(widget=forms.TextInput(attrs={'readonly': 'readonly', 'class': 'form-control'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'readonly': 'readonly', 'class': 'form-control'}))

    class Meta:
        model = Merchant
        fields = ('full_name', 'email', 'profile_pic')


class OnBoardMessageForm(forms.ModelForm):
    country_code = forms.IntegerField(widget=forms.TextInput({'required': 'required'}))
    phone_number = forms.IntegerField(widget=forms.TextInput({'required': 'required'}))

    class Meta:
        model = User
        fields = ('country_code', 'phone_number')


class BranchForm(forms.ModelForm):
    class Meta:
        model = Banner
        fields = '__all__'
        exclude = ('merchant_name',)
