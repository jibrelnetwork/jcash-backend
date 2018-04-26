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
from django.views.generic import TemplateView, RedirectView
from django.views.defaults import page_not_found
from django.http import HttpResponseNotFound


from allauth.account.views import ConfirmEmailView
from rest_framework.documentation import include_docs_urls
from rest_framework.permissions import AllowAny
from jcash.api.views import ResendEmailConfirmationView, UserDetailsView
from jcash.api.admin import export_csv


urlpatterns = [
    url(r'^docs/', include_docs_urls(title='jCash API', permission_classes=[AllowAny])),
    url(r'^admin/', admin.site.urls),
    # AUTH
    url(r'^auth/user/$', UserDetailsView.as_view(), name='rest_user_details'),
    url(r'^auth/', include('rest_auth.urls')),
    url(r'^auth/registration/', include('rest_auth.registration.urls')),
    url(r'^auth/registration/confirm-email-resend/', ResendEmailConfirmationView.as_view()),
    # API
    url(r'^api/', include('jcash.api.urls')),
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
