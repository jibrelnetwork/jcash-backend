from rest_framework.pagination import (
    PageNumberPagination,
)

from jcash.settings import LOGIC__PAGINATION_APPLICATIONS_PER_PAGE


class ApplicationPageNumberPagination(PageNumberPagination):
    page_size = LOGIC__PAGINATION_APPLICATIONS_PER_PAGE
