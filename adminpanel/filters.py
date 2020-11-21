import django_filters
from src.models import User, Merchant
from django_filters import DateFilter


class UserFilter(django_filters.FilterSet):
    from_date = DateFilter(field_name='created_at', lookup_expr='gte', label='From Date')
    to_date = DateFilter(field_name='created_at', lookup_expr='lte', label='To Date')

    class Meta:
        model = User
        fields = ('from_date', 'to_date')


class MerchantFilter(django_filters.FilterSet):
    from_date = DateFilter(field_name='created_at', lookup_expr='gte', label='From Date')
    to_date = DateFilter(field_name='created_at', lookup_expr='lte', label='To Date')

    class Meta:
        model = Merchant
        fields = ('from_date', 'to_date')
