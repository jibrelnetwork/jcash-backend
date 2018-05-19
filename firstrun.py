import os

from django.contrib.auth.models import User

if not User.objects.filter(username="admin").exists():
    User.objects.create_superuser("admin", "admin@example.com", os.getenv("ADMIN_PASSWORD", "Koochoo7eishiD8iex5theexeisahHah"))
