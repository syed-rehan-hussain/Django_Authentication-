from django.urls import path

from .views import *

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    # path('guide/register/', GuideRegisterView.as_view(), name='guide-register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('update-profile/', UpdateProfileView.as_view(), name='profile'),
    # path('otp/', OTPView.as_view(), name='user_otp'),
    path('change-password/', UserChangePasswordView.as_view(), name='user_change_password'),

    path('forgot-password/', UserForgotPasswordView.as_view(), name="user_forgot_password"),
    # path('otp/verify', VerifyOTP.as_view(), name='user_activation'),
    # path('otp/resend-otp', ResendOTP.as_view(), name='user_otp_resend'),
]
