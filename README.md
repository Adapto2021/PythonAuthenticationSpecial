Django Auth Example

Environment:authenv

PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial> django-admin startproject authapi1
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial> cd authapi1
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1> django-admin startapp api
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1> activate authenv

(authenv) C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1>conda.bat activate authenv
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1>

PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial> pip freeze
asgiref @ file:///home/conda/feedstock_root/build_artifacts/asgiref_1642912811357/work
Django @ file:///D:/bld/django_1646775829781/work
djangorestframework==3.13.1
pytz==2022.1
sqlparse @ file:///home/conda/feedstock_root/build_artifacts/sqlparse_1631317292236/work
typing_extensions @ file:///home/conda/feedstock_root/build_artifacts/typing_extensions_1644850595256/work
tzdata @ file:///home/conda/feedstock_root/build_artifacts/python-tzdata_1647621564023/work
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial>


Now we have to install Simple Jwt:

pip install djangorestframework-simplejwt


asgiref @ file:///home/conda/feedstock_root/build_artifacts/asgiref_1642912811357/work
Django @ file:///D:/bld/django_1646775829781/work
djangorestframework==3.13.1
djangorestframework-simplejwt==5.1.0
PyJWT==2.3.0
pytz==2022.1
sqlparse @ file:///home/conda/feedstock_root/build_artifacts/sqlparse_1631317292236/work
typing_extensions @ file:///home/conda/feedstock_root/build_artifacts/typing_extensions_1644850595256/work
tzdata @ file:///home/conda/feedstock_root/build_artifacts/python-tzdata_1647621564023/work
check out : https://django-rest-framework-simplejwt.readthedocs.io/en/latest/getting_started.html

Then, your django project must be configured to use the library. In settings.py, add rest_framework_simplejwt.authentication.JWTAuthentication to the list of authentication classes:

Settings.py:

 

from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': False,
    'UPDATE_LAST_LOGIN': False,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'api',
]


For SIMPLE_JWT we are using as final:

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=20),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',

    'JTI_CLAIM': 'jti',

    }


Now to solve CORS problem we deploy a new package DJANGO CORS HEADER:This is required whenever a front end needs to connect with the api

https://pypi.org/

 


PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1> pip install django-cors-headers
Collecting django-cors-headers
  Downloading django_cors_headers-3.11.0-py3-none-any.whl (12 kB)
Requirement already satisfied: Django>=2.2 in c:\users\soviw\anaconda3\envs\authenv\lib\site-packages (from django-cors-headers) (4.0.3)
Requirement already satisfied: sqlparse>=0.2.2 in c:\users\soviw\anaconda3\envs\authenv\lib\site-packages (from Django>=2.2->django-cors-headers) (0.4.2)
Requirement already satisfied: tzdata in c:\users\soviw\anaconda3\envs\authenv\lib\site-packages (from Django>=2.2->django-cors-headers) (2022.1)
Requirement already satisfied: asgiref<4,>=3.4.1 in c:\users\soviw\anaconda3\envs\authenv\lib\site-packages (from Django>=2.2->django-cors-headers) (3.5.0)
Installing collected packages: django-cors-headers
Successfully installed django-cors-headers-3.11.0
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1>

PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1> pip freeze
asgiref @ file:///home/conda/feedstock_root/build_artifacts/asgiref_1642912811357/work
Django @ file:///D:/bld/django_1646775829781/work
django-cors-headers==3.11.0
djangorestframework==3.13.1
djangorestframework-simplejwt==5.1.0
PyJWT==2.3.0
pytz==2022.1
sqlparse @ file:///home/conda/feedstock_root/build_artifacts/sqlparse_1631317292236/work
typing_extensions @ file:///home/conda/feedstock_root/build_artifacts/typing_extensions_1644850595256/work
tzdata @ file:///home/conda/feedstock_root/build_artifacts/python-tzdata_1647621564023/work
check : https://pypi.org/project/django-cors-headers/

A list of origins that are authorized to make cross-site HTTP requests. Defaults to [].
An Origin is defined by the CORS RFC Section 3.2 as a URI scheme + hostname + port, or one of the special values ‘null’ or ‘file://’. Default ports (HTTPS = 443, HTTP = 80) are optional here.
The special value null is sent by the browser in “privacy-sensitive contexts”, such as when the client is running from a file:// domain. The special value file:// is sent accidentally by some versions of Chrome on Android as per this bug.
Example: For our project


CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


Custom Authentication:

https://docs.djangoproject.com/en/4.0/topics/auth/customizing/
Full Example:

https://docs.djangoproject.com/en/4.0/topics/auth/customizing/#a-full-example


Custom User Model:

from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


# Create your models here.
#1 User Manager

class UserManager(BaseUserManager):
    def create_user(self, email, name, tc, password=None , password2=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            tc=tc,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, tc, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
            tc=tc,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


#2 Custom User Model

class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    tc = models.BooleanField()
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','tc',]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


Now we migrate

Now to utilize the User created by us, we need to make a separate config in settings.py:

AUTH_USER_MODEL = 'api.User' –Note: This should be done prior to making migrations for the first time.

Create super user:

PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1> python manage.py createsuperuser
Email address: admin@example.com
Name: Admin
Tc: True
Password:
Password (again):
The password is too similar to the email address.
This password is too short. It must contain at least 8 characters.
This password is too common.
Bypass password validation and create user anyway? [y/N]: y
Superuser created successfully.
PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1>

Password:admin

Now we runserver,goto:localhost:8000/admin

 

O/P:
 


Now we register the model in admin.py:

from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin


# Register your models here.

class UserModelAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    # form = UserChangeForm
    # add_form = UserCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on auth.User.
    list_display = ('id','email', 'name', 'tc', 'is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('name','tc')}),
        ('Permissions', {'fields': ('is_admin',)}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name','tc', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email','id')
    filter_horizontal = ()


# Now register the new UserAdmin...
admin.site.register(User, UserModelAdmin)


O/P:

 

 



Change name of the admin:

 

Registration:
Urls:

from django.urls import path,include
from .views import UserRegistrationView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(),name='register'),

]

views:
#from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer

# Create your views here.


class UserRegistrationView(APIView):
    def post(self,request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            return Response({'msg':'Registration Success'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

Serializer:

from rest_framework import serializers
from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    We are writitng this because we need a password confirmation in the registration field
    """
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['id','email','name','password','password2','tc']
        extra_kwargs={'password':{'write_only':True}}

    #validate password and confirm password,note:attrs is the request.data in view
    def validate(self, attrs):
        password  = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password not same')
        return attrs

    def create(self,validate_data):
        return User.objects.create_user(**validate_data)


Login:



O/P:

Blank Test:
 

Input: Dadan Guha

 
O/P: From Admin Panel:

 

Login:
Urls.py:

path('login/', UserLoginView.as_view(),name='login')

view:
class UserLoginView(APIView):
    def post(self,request,format=None):
        serializer=UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email=serializer.data.get('email')
            password = serializer.data.get('password')
            user=authenticate(email=email,password=password)
            if user is not None:
                return Response({'msg': 'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['Email or password is incorrect']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


serializers:

class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password']


I/P:
 

O/P:Success

 

Custom JSON Renderers: To Render errors we need to make custom errors rendring
Renderers.py:
from rest_framework import renderers
import json

class UserRenderer(renderers.JSONRenderer):
    charset = 'utf-8'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        response=''
        if 'ErrorDetail' in str(data):
            response=json.dumps({'errors':data})
        else:
            response = json.dumps(data)
        return response
now import in views:
from .renderers import UserRenderer

Add render classes in view classes

renderer_classes = [UserRenderer]


O/P:

 

Implement JWT Token:

Ref doc: https://django-rest-framework-simplejwt.readthedocs.io/en/latest/creating_tokens_manually.html

Views.py:
#from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer,UserLoginSerializer
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken

#Get JWT Token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Create your views here.


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({'token':token,'msg':'Registration Success'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer=UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email=serializer.data.get('email')
            password = serializer.data.get('password')
            user=authenticate(email=email,password=password)
            if user is not None:
                token=get_tokens_for_user(user)
                return Response({'token':token,'msg': 'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['Email or password is incorrect']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

O/P:

 

User Profile:
Serializers:
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','name','tc']


views:

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        serializer=UserProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)

urls:

path('profile/', UserProfileView.as_view(),name='profile'),


O/P:

 

Password Change:
Serializers:
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password not same')
        user.set_password(password)
        user.save()
        return attrs
views:
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self,request,format=None):
        serializer=UserChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password Changed Successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
urls:

path('changepassword/', UserChangePasswordView.as_view(),name='changepassword'),




No Payload:
 

Payload:
 

Giving previous password
 

Password Reset: and sent mail reset:
Serializers:
from rest_framework import serializers
from .models import User
from xml.dom import ValidationErr
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    We are writitng this because we need a password confirmation in the registration field
    """
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['id','email','name','password','password2','tc']
        extra_kwargs={'password':{'write_only':True}}

    #validate password and confirm password,note:attrs is the request.data in view
    def validate(self, attrs):
        password  = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password not same')
        return attrs

    def create(self,validate_data):
        return User.objects.create_user(**validate_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','name','tc']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password not same')
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email']

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID",uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print("Password Reset Token",token)
            link='http://localhost:3000/api/user/reset/'+uid+'/'+token
            print("Password Reset Link: ",link)
            return attrs
        else:
            raise ValidationErr('You are not a valid user')
views:
class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    #permission_classes = [IsAuthenticated]
    def post(self,request,format=None):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset Email sent Successfully.Please check email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

urls:
path('send-reset-password-email/', SendPasswordResetEmailView.as_view(),name='send-reset-password-email'),


O/P:
 
Console output:
Encoded UID Mw
Password Reset Token b41n7a-29e2e97499ae01935583df8f83441277
Password Reset Link:  http://localhost:3000/api/user/reset/Mw/b41n7a-29e2e97499ae01935583df8f83441277
Reset Password Email:
Serializer:
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError('Password and Confirm Password not same')
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationErr("Token is not valid or has expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationErr("Token is not valid or has expired")


views:
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer=UserPasswordResetSerializer(data=request.data,context={'uid':uid,'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset Successfully'}, status=status.HTTP_200_OK)

urls:
path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(),name='reset-password'),

O/P:
First send email then reset with Uid and pwd
 

Send Email:

Install Django-dotenv

PS C:\Users\soviw\PycharmProjects\PythonAuthenticationSpecial\authapi1> pip install django-dotenv
Collecting django-dotenv
  Downloading django_dotenv-1.4.2-py2.py3-none-any.whl (3.8 kB)
Installing collected packages: django-dotenv
Successfully installed django-dotenv-1.4.2
WARNING: You are using pip version 22.0.3; however, version 22.0.4 is available.
You should consider upgrading via the 'C:\Users\soviw\AppData\Local\Programs\Python\Python310\python.exe -m pip install --upgrade pip' command.
Manage.py:
import os
import sys
import dotenv


def main():
    """Run administrative tasks."""
    dotenv.read_dotenv()
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authapi1.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()

Serializer:

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email']

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID",uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print("Password Reset Token",token)
            link='http://localhost:3000/api/user/reset-password/'+uid+'/'+token
            print("Password Reset Link: ",link)
            #Send Email
            body='CLick to reset Password'+link
            data={
                'subject':'Reset Your Password',
                'body':body,
                'to_email':user.email
            }
            Util.send_mail(data)
            return attrs
        else:
            raise ValidationErr('You are not a valid user')


utils.py:
from django.core.mail import EmailMessage
import os

class Util:
    @staticmethod
    def send_mail(data):
        email=EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=os.environ.get('EMAIL_FROM'),
            to=[data['to_email']]
        )
        email.send()
O/P:

 

 

 

Project Github: https://github.com/Adapto2021/PythonAuthenticationSpecial/blob/master/authapi1/

