
from django.conf import settings
from django.conf.urls import url, include
from django.contrib import admin

from jcash.api import views

urlpatterns = [
    url(r'^account/', views.AccountView.as_view()),
    url(r'^address/$', views.AddressView.as_view()),
    url(r'^address-remove/$', views.RemoveAddressView.as_view()),
    url(r'^currency/', views.CurrencyView.as_view()),
    url(r'^currency-rates/', views.CurrencyRatesView.as_view()),
    url(r'^currency-rate/', views.CurrencyRateView.as_view()),
    url(r'^application/$', views.ApplicationView.as_view()),
    url(r'^application/(?P<uuid>[0-9A-Fa-f\-]+)/$', views.ApplicationDetailView.as_view()),
    url(r'^application-confirm/', views.ApplicationConfirmView.as_view()),
    url(r'^application-refund/', views.ApplicationRefundView.as_view()),
    url(r'^application-cancel/', views.ApplicationCancelView.as_view()),
    url(r'^application-finish/', views.ApplicationFinishView.as_view()),
    url(r'^customers/', views.CustomersView.as_view()),
    url(r'^customer/personal/contact-info/', views.PersonalContactInfoView.as_view()),
    url(r'^customer/personal/address/', views.PersonalAddressView.as_view()),
    url(r'^customer/personal/income-info/', views.PersonalIncomeInfoView.as_view()),
    url(r'^customer/personal/documents/', views.PersonalDocumentsView.as_view()),
    url(r'^customer/corporate/company-info/', views.CorporateCompanyInfoView.as_view()),
    url(r'^customer/corporate/address/', views.CorporateAddressView.as_view()),
    url(r'^customer/corporate/income-info/', views.CorporateIncomeInfoView.as_view()),
    url(r'^customer/corporate/contact-info/', views.CorporateContactInfoView.as_view()),
    url(r'^customer/corporate/documents/', views.CorporateDocumentsView.as_view()),
    url(r'^residential-countries/', views.ResidentialCountriesView.as_view()),
    url(r'^citizenship-countries/', views.CitizenshipCountriesView.as_view()),
    url(r'^fee-jnt/', views.FeeJntView.as_view()),
]
