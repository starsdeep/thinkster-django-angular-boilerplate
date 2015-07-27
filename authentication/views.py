#encoding=utf8
import json
from rest_framework import permissions
from django.contrib.auth import authenticate, login, logout
from rest_framework import status, views
from rest_framework.response import Response
from rest_framework import permissions, viewsets

from authentication.models import Account
from authentication.permissions import IsAccountOwner
from authentication.serializers import AccountSerializer


class AccountViewSet(viewsets.ModelViewSet):
    lookup_field = 'username'
    queryset = Account.objects.all()
    serializer_class = AccountSerializer

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return (permissions.AllowAny(),)

        if self.request.method == 'POST':
            return (permissions.AllowAny(),)

        return (permissions.IsAuthenticated(), IsAccountOwner(),)


    """
    When you create an object using the serializer's .save() method, the object's attributes are set literally. This means that a user registering with the password 'password' will have their password stored as 'password'. This is bad for a couple of reasons: 1) Storing passwords in plain text is a massive security issue. 2) Django hashes and salts passwords before comparing them, so the user wouldn't be able to log in using 'password' as their password.

    We solve this problem by overriding the .create() method for this viewset and using Account.objects.create_user() to create the Account object.

    这个教程很优秀的地方（不同于django rest 官方教程的地方在于，他告诉了我们应该怎么customize 原有的组件），正常情况下，我们的viewset 函数里面就已经包括了，

    """
    def create(self, request):
        print "in AccountViewSet, create"
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            print "is_valid"
            Account.objects.create_user(**serializer.validated_data)
            return Response(serializer.validated_data, status=status.HTTP_201_CREATED)

        print "is not valid"
        print str(request.data)
        return Response({
            'status': 'Bad request',
            'message': 'Account could not be created with received data.'
        }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(views.APIView):
    def post(self, request, format=None):


        print "in login view"
        data = json.loads(request.body)
        email = data.get('email', None)
        password = data.get('password', None)

        account = authenticate(email=email, password=password)

        if account is not None:
            if account.is_active:
                login(request, account)

                serialized = AccountSerializer(account)

                return Response(serialized.data)
            else:
                return Response({
                    'status': 'Unauthorized',
                    'message': 'This account has been disabled.'
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                'status': 'Unauthorized',
                'message': 'Username/password combination invalid.'
            }, status=status.HTTP_401_UNAUTHORIZED)




class LogoutView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, format=None):
        logout(request)

        return Response({}, status=status.HTTP_204_NO_CONTENT)