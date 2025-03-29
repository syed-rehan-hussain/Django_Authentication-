from datetime import timedelta
from enum import Enum
from random import random

from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.db import models
from django.utils.timezone import now


# Create your models here.
class UserRole(Enum):
    ADMIN = "admin"
    GUIDE = "guide"
    USER = "user"


class BaseModel(models.Model):
    is_deleted = models.BooleanField(null=False, default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def delete(self):
        self.is_deleted = True
        self.save()

    def restore(self):
        self.is_deleted = False
        self.save()


# Custom User Manager
# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, role=UserRole.USER.value, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        extra_fields['role'] = role

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('role', UserRole.ADMIN.value)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)


# Base User Model
class BaseUser(BaseModel, AbstractUser):
    username = models.CharField(max_length=255, unique=True, blank=True)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=[(tag.value, tag.value) for tag in UserRole], default=UserRole.USER.value)
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    postal_code = models.CharField(max_length=20, null=True, blank=True)

    groups = models.ManyToManyField(Group, related_name="custom_user_set", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_user_set", blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email  # Ensure username is set to email
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email


# Guide Model
class Guide(BaseUser):
    passport_image = models.ImageField(upload_to='guides/passports/', null=True, blank=True)
    cnic_front_image = models.ImageField(upload_to='guides/cnic/', null=True, blank=True)
    cnic_back_image = models.ImageField(upload_to='guides/cnic/', null=True, blank=True)
    additional_document = models.FileField(upload_to='guides/documents/', null=True, blank=True)
    bank_account_number = models.CharField(max_length=30, null=True, blank=True)


class UserOTP(models.Model):
    VERIFY_CHOICES = (
        ('1', 'UnVerified'),
        ('2', 'Verified'),
    )
    email = models.EmailField(unique=True)
    otp = models.IntegerField()
    status = models.CharField(max_length=10,default= VERIFY_CHOICES[0][0], null=True, choices=VERIFY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user otp'
        verbose_name = 'user otp'
        verbose_name_plural = 'users otp'

    def __str__(self):
        return str(self.otp)

    def is_expired(self):
        """Check if OTP is expired (5 minutes old)"""
        return now() > self.created_at + timedelta(minutes=5)
