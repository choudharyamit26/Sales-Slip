from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST
from .models import UserNotification, Otp, ScannedData, TermsAndCondition, ContactUs, PrivacyPolicy, Settings, FAQ

User = get_user_model()


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for user creation"""
    phone_number = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'},
                                     write_only=True)

    confirm_password = serializers.CharField(style={'input_type': 'password'},
                                             write_only=True, min_length=8)

    class Meta:
        model = get_user_model()
        fields = ('id',
                  'first_name', 'last_name', 'profile_pic', 'email', 'country_code', 'phone_number', 'password',
                  'confirm_password')
        extra_kwargs = {'password': {'write_only': True, 'min_length': 8}}

    def create(self, validated_data):
        """Create user after checking phone number and email"""
        # password = validated_data['password']
        # confirm_password = validated_data['confirm_password']
        # phone_number = validated_data['phone_number']
        # if User.objects.filter(phone_number=phone_number):
        #     raise serializers.ValidationError("User with this phone number already exists")
        # elif password != confirm_password:
        #     raise serializers.ValidationError("Password and Confirm Password did not match")
        # else:
        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        """Update a user, setting the password correctly and return it"""
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for the user authentication object"""
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the user using phone number or email in email field"""
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            if not email.isdigit():
                user = authenticate(
                    request=self.context.get('request'),
                    username=email,
                    password=password
                )
                attrs['user'] = user
                return attrs
            else:
                user = User.objects.get(phone_number=email)
                email = user.email
                user = authenticate(
                    request=self.context.get('request'),
                    username=email,
                    password=password
                )
                if user:
                    attrs['user'] = user
                    return attrs
                else:
                    return Response("User does not exists", HTTP_400_BAD_REQUEST)
        except Exception as e:
            print('---->>>', e)
            return Response(e, HTTP_400_BAD_REQUEST)


class ForgetPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('phone_number', 'password', 'confirm_password')


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer to change password of a logged in user"""
    old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password = serializers.CharField(max_length=128, write_only=True, required=True)
    confirm_new_password = serializers.CharField(max_length=128, write_only=True, required=True)

    # def validate_old_password(self, value):
    #     user = self.context['request'].user
    #     if not user.check_password(value):
    #         return serializers.ValidationError('Your old password was entered incorrectly. Please enter it again.')
    #     return value
    #
    # def validate(self, data):
    #     if data['new_password'] != data['confirm_new_password']:
    #         raise serializers.ValidationError({'confirm_new_password': "The two password fields didn't match."})
    #     password_validation.validate_password(data['new_password'], self.context['request'].user)
    #     return data
    #
    # def save(self, **kwargs):
    #     password = self.validated_data['new_password']
    #     user = self.context['request'].user
    #     user.set_password(password)
    #     user.save()
    #     return user


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notification"""

    class Meta:
        model = UserNotification
        fields = '__all__'


class UpdateNotificationSerializer(serializers.ModelSerializer):
    """Update Notification serializer"""

    class Meta:
        model = UserNotification
        fields = ('read',)


class OtpSerializer(serializers.ModelSerializer):
    """Email otp serializer"""

    class Meta:
        model = Otp
        fields = '__all__'


class UpdatePhoneSerializer(serializers.ModelSerializer):
    """Serializer to update user's phone number"""

    class Meta:
        model = User
        fields = ("country_code", "phone_number")


class ScannedDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScannedData
        exclude = ('user', 'created_at')


class ContactUsSerializer(serializers.ModelSerializer):
    """Serializer for contact details of admin"""

    class Meta:
        model = ContactUs
        fields = '__all__'


class TermsandConditionSerializer(serializers.ModelSerializer):
    """Serializer for app's usage terms and condition"""

    class Meta:
        model = TermsAndCondition
        fields = '__all__'


class PrivacyPolicySerializer(serializers.ModelSerializer):
    """Serializer for privacy policy"""

    class Meta:
        model = PrivacyPolicy
        fields = '__all__'


class FAQSerializer(serializers.ModelSerializer):
    """Serializer for frequently asked questions"""

    class Meta:
        model = FAQ
        fields = '__all__'


class NotificationSettingSerializer(serializers.ModelSerializer):
    """Serializer for user's notification settings"""

    class Meta:
        model = Settings
        fields = ('user', 'notification')


class LanguageSettingSerializer(serializers.ModelSerializer):
    """Serializer for user's language settings"""

    class Meta:
        model = Settings
        fields = ('user', 'language')


class SettingsSerializer(serializers.ModelSerializer):
    """Settings Serializer"""

    class Meta:
        model = Settings
        fields = ('notification',)


class LanguageSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Settings
        fields = ('language',)
