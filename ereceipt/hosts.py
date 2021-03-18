from django.conf import settings
from django_hosts import patterns, host

host_patterns = patterns('',
                         host(r'www', settings.ROOT_URLCONF, name='www'),
                         host(r'admin', 'adminpanel.urls', name='admin'),
                         host(r'merchant', 'merchant.urls', name='merchant'),
                         )
