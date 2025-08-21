from django.urls import path
from pr0cks_app.views import RunPr0cksView

urlpatterns = [
    path('', RunPr0cksView.as_view(), name='index'),
    path('vm/', RunPr0cksView.as_view(), name='vm_api'),
    path('binding/', RunPr0cksView.as_view(), name='binding_api'),
]
