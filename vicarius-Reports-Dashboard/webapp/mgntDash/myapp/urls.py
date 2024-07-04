from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('update_all_tables/', views.update_all_tables, name='update_all_tables'),
    path('update_metabase_template/', views.update_metabase_template, name='update_metabase_template'),
    path('create_mb_user/', views.create_mb_user, name='create_mb_user'),
    path('update_refresh_tables/', views.update_refresh_tables, name='update_refresh_tables'),
    path('update_sync_tables/', views.update_sync_tables, name='update_sync_tables'),
]
