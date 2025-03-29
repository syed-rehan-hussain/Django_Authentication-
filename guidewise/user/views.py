import string
import random
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Guide, UserOTP, BaseUser
from .serializers import UserSerializer, GuideSerializer, RegisterSerializer, LoginSerializer, UpdatePasswordSerializer, \
    ForgotPasswordSerializer
from guidewise import settings
from guidewise.helper.helper import createJWTtoken


def generate_otp():
    if settings.ALLOW_SAME_OTP:
        return 1234
    return randint(1111, 9999)


def generate_password():
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(10))
    return result_str


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# user register
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            payload = {'email': user.email, 'pk': user.pk}
            token = createJWTtoken(payload)

            response = Response({"message": "Login Successfully",
                                 "data": {"user": user, "access_token": token['access_token'],
                                          "refresh_token": token['refresh_token']}},
                                status=status.HTTP_200_OK)
            response.set_cookie(
                key="refresh_token",
                value=token['refresh_token'],
                httponly=settings.COOKIE_HTTPONLY,
                samesite=settings.COOKIE_SAMESITE,
                secure=settings.COOKIE_SECURE,
                max_age=settings.COOKIE_MAX_AGE
            )
            return response

            # return Response({'user': serializer.data, 'token': token}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GuideRegisterView(generics.CreateAPIView):
    queryset = Guide.objects.all()
    serializer_class = GuideSerializer
    permission_classes = [AllowAny]


# user login
class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user_obj = BaseUser.objects.filter(email=email).first()

        if not user_obj:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)

        if not user_obj.is_active:
            return Response({'error': 'User account is disabled'}, status=status.HTTP_400_BAD_REQUEST)

        if not check_password(password, user_obj.password):
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)

        payload = {'email': user_obj.email, 'pk': user_obj.pk}
        token = createJWTtoken(payload)

        response = Response({
            "message": "Login Successfully",
            "data": {
                "user": {
                    "id": user_obj.pk,
                    "email": user_obj.email
                },
                "access_token": token['access_token'],
                "refresh_token": token['refresh_token']
            }
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key="refresh_token",
            value=token['refresh_token'],
            httponly=settings.COOKIE_HTTPONLY,
            samesite=settings.COOKIE_SAMESITE,
            secure=settings.COOKIE_SECURE,
            max_age=settings.COOKIE_MAX_AGE
        )

        return response


# user retrieve his password
class ProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.authuser


# user change his profile
class UpdateProfileView(APIView):

    def put(self, request):
        user = request.authuser  # Get authenticated user from middleware
        serializer = UserSerializer(user, data=request.data, partial=True)  # Allow partial updates

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile updated successfully", "user": serializer.data},
                            status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPView(generics.CreateAPIView):
    queryset = UserOTP.objects.filter()
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            if not BaseUser.objects.filter(email=email).exists():
                return Response({'message': 'User Not Found'}, status=status.HTTP_404_NOT_FOUND)

            existing_otps = UserOTP.objects.filter(email=email)

            if existing_otps.exists():
                latest_otp = existing_otps.latest('created_at')

                # Check if OTP is expired
                if not latest_otp.is_expired():
                    return Response({'message': 'User is already in the system, OTP still valid'},
                                    status=status.HTTP_302_FOUND)
                else:
                    # If expired, delete the old OTP and generate a new one
                    latest_otp.delete()

            user_otp = UserOTP.objects.create(email=email, otp=generate_otp())


            res = send_mail(
                subject="Your Password Reset OTP",
                message=f"Your OTP for password reset is: {str(user_otp.otp)}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user_otp.email],
            )

            if res:
                return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'OTP has not been sent'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# user change his password
class UserChangePasswordView(generics.UpdateAPIView):
    queryset = BaseUser.objects.filter()

    def put(self, request, *args, **kwargs):
        try:
            email = request.data["email"]
            serializer = UpdatePasswordSerializer(data=request.data)

            serializer.is_valid(raise_exception=True)

            if request.data["password"] != request.data["new_password"]:

                user_details = BaseUser.objects.filter(email=email, is_deleted=False)
                if user_details.count() > 0:
                    if check_password(request.data['password'], user_details[0].password):
                        user_details.update(password=make_password(request.data["new_password"]))

                        return Response({"message": "Password update sucesssfully"}, status=status.HTTP_200_OK)
                    else:
                        return Response({"message": "Invalid password"}, status=status.HTTP_403_FORBIDDEN)

                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({"message": "Use an other password!"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTP(generics.UpdateAPIView):
    permission_classes = [AllowAny]

    def patch(self, request, *args, **kwargs):
        try:
            otp_verify = UserOTP.objects.filter(email=request.data.get("email"),
                                                otp=request.data.get("otp"))
            if otp_verify:
                verify = UserOTP.objects.get(email=request.data.get("email"))
                verify.status = UserOTP.VERIFY_CHOICES[1][0]
                verify.save()
                return Response({'message': 'OTP Verified'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Invalid OTP provided'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ResendOTP(generics.UpdateAPIView):
    permission_classes = [AllowAny]

    def patch(self, request, *args, **kwargs):
        try:
            user_otp = UserOTP.objects.filter(email=request.data.get("email")).first()

            if user_otp is None:
                return Response({'message': 'OTP not found'}, status=status.HTTP_404_NOT_FOUND)

            user_otp.otp = generate_otp()
            user_otp.save()
            print(f"Debug Otp {user_otp.otp}")
            # sms otp to user
            # send_sms(request.data['phone_number'], 'Your OTP is ' + str(user_otp.otp))
            send_mail(
                subject="Your Password Reset OTP",
                message=f"Your OTP for password reset is: {str(user_otp.otp)}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=user_otp.email,
            )
            return Response({'message': 'An otp has been sent on your email'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# user forgot his password
class UserForgotPasswordView(generics.CreateAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            serializer = ForgotPasswordSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_details = BaseUser.objects.filter(email=request.data['email'], is_deleted=False)

            if user_details.count() > 0:
                gen_pass = generate_password()

                print(f"Debug New Password: {gen_pass}")
                user = user_details.first()
                new_pass = gen_pass
                user.password = make_password(new_pass)
                user.save()

                email_context = {'email': user.email, 'new_password': new_pass}
                # hook_set.forgot_password_email(email_context)
                return Response({"message": "password send on Register email address sucesssfully"},
                                status=status.HTTP_200_OK)

            return Response({"message": "Email does not exist"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
