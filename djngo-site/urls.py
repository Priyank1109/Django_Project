from django.conf import settings
from django.urls import include, path
from django.contrib import admin

from wagtail.admin import urls as wagtailadmin_urls
from wagtail import urls as wagtail_urls
from wagtail.documents import urls as wagtaildocs_urls

from search import views as search_views
from userapp import views as user_views
from blog import views as blog_views



urlpatterns = [
    
    path("django-admin/", admin.site.urls),
    path("admin/", include(wagtailadmin_urls)),
    path("documents/", include(wagtaildocs_urls)),
    path("search/", search_views.search, name="search"),
    # path('userapp/', user_views.userapp, name='userapp'),
    path('token/', user_views.token_send, name='token_send'),
    path('signup/', user_views.signup, name='signup'),
    path('home/', user_views.home, name='home'),
    path('logout_user/', user_views.logout_user, name='logout_user'),
    path('userlogin/', user_views.userlogin, name='userlogin'),
    path('forget_password/', user_views.forget_password, name='forget_password'),
    path('change_password/<ence_mail>/<key2>', user_views.change_password, name='change_password'),
    path('change_password2/', user_views.change_password2, name='change_password2'),
    path('reset_password/', user_views.reset_password, name='reset_password'),
    path('myprofile/', user_views.myprofile, name='myprofile'),
    path('verify/<str:auth_token>', user_views.verify, name='verify'),
    path('error', user_views.error_page, name='error_page'),
    path('header/', user_views.header, name='header'),
    path('footer/', user_views.footer, name='footer'),
    path('comments/', include('django_comments.urls')),
    path('comment/<int:post_id>', blog_views.CommentView.as_view(), name='comment'),
    path('comment_reply/<int:comment_id>/<int:post_id>', blog_views.CommentReplyView.as_view(), name='comment_reply'),
    path('summernote/', include('django_summernote.urls')),
    
]


if settings.DEBUG:
    from django.conf.urls.static import static
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns

    # Serve static and media files from development server
    urlpatterns += staticfiles_urlpatterns()
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns = urlpatterns + [
    # For anything not caught by a more specific rule above, hand over to
    # Wagtail's page serving mechanism. This should be the last pattern in
    # the list:
    path("", include(wagtail_urls)),
    path("auth/", include('allauth.urls')),



    
    
    # Alternatively, if you want Wagtail pages to be served from a subpath
    # of your site, rather than the site root:
    #    path("pages/", include(wagtail_urls)),
]
