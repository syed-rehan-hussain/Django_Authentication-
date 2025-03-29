import os

import jwt
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from rest_framework import status
from datetime import datetime
from user.models import BaseUser
import base64
from django.http import HttpResponseForbidden
from functools import wraps


def simple_middleware(get_response):
    def middleware(request):
        if any(route in request.path for route in [
            'register', 'login', 'reset-password', 'refresh', 'swagger', 'favicon', 'redoc', 'forgot-password',
            'verify-otp-forget', 'admin'
        ]):
            response = get_response(request)

        else:
            if 'HTTP_AUTHORIZATION' not in request.META:
                return JsonResponse({'error': "Authorization Token is Required"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                # print(request.META['HTTP_AUTHORIZATION'])
                decoded_dict = jwt.decode(request.META['HTTP_AUTHORIZATION'], os.getenv("SECRET_KEY"),
                                          algorithms=['HS256'], verify=True)
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
            except (jwt.InvalidTokenError, ValidationError):
                return JsonResponse({'error': 'Some error'}, status=status.HTTP_401_UNAUTHORIZED)

            email = decoded_dict['email']
            expiry = decoded_dict['expiry']

            current_time = datetime.now().timestamp()
            if current_time > expiry:
                return JsonResponse({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)

            user = BaseUser.objects.filter(email=email).first()
            if user is None:
                return JsonResponse({'error': 'Invalid Token'}, status=status.HTTP_401_UNAUTHORIZED)

            request.authuser = user
            response = get_response(request)

        return response

    return middleware