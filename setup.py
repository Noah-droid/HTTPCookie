
#Views.py
"""
This is the views that handle HTTPCookie only authentication
"""
class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        
        errors = {}

        # Validate username
        if not username:
            errors['username'] = 'Username is required.'
        elif not User.objects.filter(username=username).exists():
            errors['username'] = 'User with this username does not exist.'

        # Validate password
        if not password:
            errors['password'] = 'Password is required.'

        # If there are validation errors, return them
        if errors:
            joined_errors = " ".join(errors.values())
            return Response({'error': joined_errors}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            user_refresh_token = RefreshToken.for_user(user)
            response = self.set_tokens_to_cookies(user_refresh_token)

            # Check if the user has created a profile
            has_profile = UserProfile.objects.filter(user=user).exists()

            response_data = {
                'message': 'Login successful.',
                'has_profile': has_profile,
            }

            response.content = JsonResponse(response_data).content

            return response
        else:
            return Response({'error': 'Invalid credentials: Wrong username or password inputted'}, status=status.HTTP_401_UNAUTHORIZED)

    def set_tokens_to_cookies(self, user_refresh_token):
        """Set user refresh and access token to cookies"""
        response = JsonResponse({'message': 'Sign-in successful'}, status=200)

        refresh_token_lifetime = timedelta(days=REFRESH_TOKEN_LIFETIME)
        access_token_lifetime = timedelta(days=ACCESS_TOKEN_LIFETIME)

        response.set_cookie(
            'refresh_token',
            str(user_refresh_token),
            httponly=True,
            samesite="Lax",
            expires=(datetime.utcnow() + refresh_token_lifetime).strftime("%a, %d-%b-%Y %H:%M:%S GMT"),
            max_age=int(refresh_token_lifetime.total_seconds())
        )

        response.set_cookie(
            'auth_token',
            str(user_refresh_token.access_token),
            httponly=True,
            samesite="Lax",
            expires=(datetime.utcnow() + access_token_lifetime).strftime("%a, %d-%b-%Y %H:%M:%S GMT"),
            max_age=int(access_token_lifetime.total_seconds())
        )

        return response


class RefreshAccessTokenAPIView(TokenRefreshView):
    """Inheriting class for refreshing access token"""

    def post(self, request: Request, *args, **kwargs) -> Response:
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            # Extract the new tokens from the response data
            data = response.data
            refresh_token = data.get('refresh')
            access_token = data.get('access')
            
            # Set the new tokens in cookies
            refresh_token_lifetime = timedelta(days=REFRESH_TOKEN_LIFETIME)
            access_token_lifetime = timedelta(days=ACCESS_TOKEN_LIFETIME)

            response.set_cookie(
                'refresh_token',
                refresh_token,
                httponly=True,
                samesite="Lax",
                expires=(datetime.utcnow() + refresh_token_lifetime).strftime("%a, %d-%b-%Y %H:%M:%S GMT"),
                max_age=int(refresh_token_lifetime.total_seconds())
            )

            response.set_cookie(
                'auth_token',
                access_token,
                httponly=True,
                samesite="Lax",
                expires=(datetime.utcnow() + access_token_lifetime).strftime("%a, %d-%b-%Y %H:%M:%S GMT"),
                max_age=int(access_token_lifetime.total_seconds())
            )

        return response


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        response = Response({
            'message': 'Logout successful.'
        }, status=status.HTTP_200_OK)

        # Remove the authentication cookies
        response.delete_cookie('refresh_token')
        response.delete_cookie('auth_token')

        return response


#Middleware.py

from django.utils.deprecation import MiddlewareMixin

class TokenMiddleware(MiddlewareMixin):
    def process_request(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        access_token = request.COOKIES.get('auth_token')

        if access_token:
            request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
        elif refresh_token:
            # Optional: Handle token refresh logic here if needed
            pass


#Settings.py

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        # 'accounts.authenticate.CustomAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day'
    }
}

INSTALLED_APPS = [
   ...
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    # 'allauth',
]

MIDDLEWARE = [
 ...
    "corsheaders.middleware.CorsMiddleware",
    'accounts.middleware.TokenMiddleware',
]

CORS_ORIGIN_ALLOW_ALL = config('CORS_ORIGIN_ALLOW_ALL', default=False, cast=bool)
CORS_ALLOWED_ORIGINS = [origin.strip() for origin in config('CORS_ALLOWED_ORIGINS').split(',')]
CORS_ALLOW_METHODS = [method.strip() for method in config('CORS_ALLOW_METHODS').split(',')]
CORS_ALLOW_HEADERS = [header.strip() for header in config('CORS_ALLOW_HEADERS').split(',')]
CORS_ALLOW_CREDENTIALS = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTP_ONLY = True
CORS_EXPOSE_HEADERS = ["Content-Type", "X-CSRFToken"]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SAMESITE = "None"
