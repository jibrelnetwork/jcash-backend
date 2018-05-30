
from django.conf import settings
from django.conf.urls import url, include
from django.contrib import admin

from jcash.api import views

urlpatterns = [
    url(r'^account/', views.AccountView.as_view()),
    url(r'^address/$', views.AddressView.as_view()),
    url(r'^address-verify/$', views.AddressVerifyView.as_view()),
    url(r'^address-remove/$', views.RemoveAddressView.as_view()),
    url(r'^currency/', views.CurrencyView.as_view()),
    url(r'^currency-rates/', views.CurrencyRatesView.as_view()),
    url(r'^currency-rate/', views.CurrencyRateView.as_view()),
    url(r'^application/$', views.ApplicationView.as_view()),
    url(r'^application-confirm/', views.ApplicationConfirmView.as_view()),
    url(r'^application-refund/', views.ApplicationRefundView.as_view()),
    url(r'^application-cancel/', views.ApplicationCancelView.as_view()),
    url(r'^application-finish/', views.ApplicationFinishView.as_view()),
]
