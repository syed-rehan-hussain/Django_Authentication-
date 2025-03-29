from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers

from .models import Guide, BaseUser, UserRole


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaseUser
        fields = ['id', 'email', 'first_name', 'last_name', 'phone_number', 'address', 'city', 'country',
                  'postal_code']


class GuideSerializer(serializers.ModelSerializer):
    class Meta:
        model = Guide
        fields = ['id', 'email', 'role', 'passport_image', 'cnic_front_image', 'cnic_back_image', 'additional_document',
                  'bank_account_number']


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaseUser
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = BaseUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data["email"], password=data["password"])  # ✅ Use 'username'

        if user is None:
            raise serializers.ValidationError("Invalid email or password")  # ✅ Fix error message
        return user


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        model = BaseUser
        fields = ['email']


class UpdatePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    new_password = serializers.CharField()

    class Meta:
        model = BaseUser
        fields = ['email', 'password', 'new_password', ]
