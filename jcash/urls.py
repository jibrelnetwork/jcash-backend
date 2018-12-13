"""jcash URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls import url, include
from django.contrib import admin
from rest_framework.documentation import include_docs_urls
from rest_framework.permissions import AllowAny
from jcash.api.views import ResendEmailConfirmationView, CustomUserDetailsView
from jcash.api.views import (
    ResendEmailConfirmationView, CustomUserDetailsView,
    RegisterView, CustomPasswordChangeView, CustomPasswordResetView,
    CustomPasswordResetConfirmView, CustomVerifyEmailView,
    CustomLogoutView, CustomLoginView, CheckTokenView, ValidatePasswordView,
    HealthcheckView,
)
from rest_auth.views import (
    LoginView
)


urlpatterns = [
    url(r'^docs/', include_docs_urls(title='jCash API', permission_classes=[AllowAny])),
    url(r'^admin/', admin.site.urls),

    # AUTH
    url(r'^auth/password/reset/$', CustomPasswordResetView.as_view(),
        name='rest_password_reset'),
    url(r'^auth/password/reset/confirm/$', CustomPasswordResetConfirmView.as_view(),
        name='rest_password_reset_confirm'),
    url(r'^auth/login/$', CustomLoginView.as_view(), name='rest_login'),
    url(r'^auth/logout/$', CustomLogoutView.as_view(), name='rest_logout'),
    url(r'^auth/user/$', CustomUserDetailsView.as_view(), name='rest_user_details'),
    url(r'^auth/password/change/$', CustomPasswordChangeView.as_view(),
        name='rest_password_change'),
    url(r'^auth/registration/$', RegisterView.as_view(), name='rest_register'),
    url(r'^auth/registration/verify-email/$', CustomVerifyEmailView.as_view(),
        name='rest_verify_email'),
    url(r'^auth/registration/confirm-email-resend/$', ResendEmailConfirmationView.as_view()),
    url(r'^auth/isalive/$', CheckTokenView.as_view()),
    url(r'^auth/validate-password/$', ValidatePasswordView.as_view()),

    # API
    url(r'^api/', include('jcash.api.urls')),

    # healthcheck
    url(r'^healthcheck', HealthcheckView.as_view()),
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
