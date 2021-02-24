from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.urls import reverse


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        """Creates and saves a new super user"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """ User model """
    first_name = models.CharField(default='first name', max_length=100)
    last_name = models.CharField(default='', max_length=100, null=True, blank=True)
    email = models.CharField(default='', max_length=255, unique=True)
    country_code = models.CharField(default='+91', max_length=10)
    phone_number = models.CharField(default='', max_length=18)
    profile_pic = models.ImageField(default='default_profile.png', null=True, blank=True)
    device_token = models.CharField(default='', max_length=500, null=True, blank=True)
    password = models.CharField(default='', max_length=100)
    confirm_password = models.CharField(default='', max_length=100)
    is_merchant = models.BooleanField(default=False)
    is_subadmin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    can_manage_merchant = models.BooleanField(default=False)
    can_manage_category = models.BooleanField(default=False)
    can_manage_branch = models.BooleanField(default=False)
    can_manage_receipts = models.BooleanField(default=False)
    can_manage_dashboard = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = 'email'

    class Meta:
        ordering = ('-created_at',)


class Category(models.Model):
    category_name = models.CharField(default='', max_length=100)


class Merchant(models.Model):
    full_name = models.CharField(default='', max_length=200)
    profile_pic = models.ImageField(default='default_profile.png', null=True, blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    email = models.EmailField()
    password = models.CharField(default='', max_length=100)
    confirm_password = models.CharField(default='', max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    commercial_id = models.CharField(default='', max_length=256)
    address = models.CharField(default='', max_length=2000)
    blocked = models.BooleanField(default=False)

    def __str__(self):
        return self.email


class Branch(models.Model):
    merchant_name = models.ForeignKey(Merchant, on_delete=models.CASCADE)
    shop_no = models.CharField(default='', max_length=2000)
    street = models.CharField(default='', max_length=2000)
    landmark = models.CharField(default='', max_length=2000, null=True, blank=True)
    city = models.CharField(default='', max_length=2000)
    postal_code = models.CharField(default='', max_length=2000)
    code = models.CharField(default='', max_length=100)
    blocked = models.BooleanField(default=False)

    def __str__(self):
        return self.code


class Product(models.Model):
    item_name = models.CharField(default='', max_length=100)
    # price = models.FloatField()
    # quantity = models.IntegerField()


class OrderItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    # products = models.ForeignKey(Product, on_delete=models.CASCADE)
    product = models.CharField(default='', max_length=1000)
    price = models.FloatField()
    quantity = models.IntegerField()
    total = models.FloatField(default=0.0)
    order_id = models.CharField(default='', max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    vat = models.FloatField(null=True, blank=True)
    vat_percent = models.FloatField()


class Receipt(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    merchant = models.ForeignKey(Merchant, null=True, on_delete=models.SET_NULL)
    branch = models.ForeignKey(Branch, null=True, on_delete=models.SET_NULL)
    order = models.ManyToManyField(OrderItem)
    vat = models.FloatField()
    amount = models.FloatField()
    total = models.FloatField()
    qr_code = models.ImageField(upload_to='QR')
    created_at = models.DateTimeField(auto_now_add=True)

    def get_absolute_url(self):
        return reverse("merchant:order-detail", kwargs={'pk': self.pk})


class ScannedData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE)
    order = models.ForeignKey(Receipt, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


class UserNotification(models.Model):
    """Notification model"""
    to = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(default='title', max_length=200)
    title_in_arabic = models.CharField(default='title', max_length=200)
    body = models.CharField(default='body', max_length=200)
    body_in_arabic = models.CharField(default='body', max_length=200)
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)


class Settings(models.Model):
    """User's Settings model"""
    user = models.ForeignKey(User, default=1, on_delete=models.CASCADE)
    notification = models.BooleanField(default=True)
    language = models.CharField(default='English', max_length=30)


class ContactUs(models.Model):
    """Contact us model"""
    company_name = models.CharField(default='', max_length=100)
    phone_number = models.CharField(default='+9199999', max_length=13)
    email = models.EmailField(default='support@snapic.com', max_length=100)


class PrivacyPolicy(models.Model):
    """Privacy Policy Model"""
    policy = models.TextField()
    policy_in_arabic = models.TextField()


class TermsAndCondition(models.Model):
    """Terms and condition Model"""
    conditions = models.TextField()
    conditions_in_arabic = models.TextField()


class AboutUs(models.Model):
    """About us Model"""
    content = models.TextField()
    content_in_arabic = models.TextField()


class Otp(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.IntegerField()


class FAQ(models.Model):
    """Frequently asked questions"""
    question = models.CharField(default='question', max_length=300)
    question_in_arabic = models.CharField(default='question', max_length=300)
    answer = models.TextField()
    answer_in_arabic = models.TextField(default='')


class SubAdmin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    can_manage_merchant = models.BooleanField(default=False)
    can_manage_category = models.BooleanField(default=False)
    can_manage_branch = models.BooleanField(default=False)
    can_manage_receipts = models.BooleanField(default=False)
    can_manage_dashboard = models.BooleanField(default=False)


class HiddenUsers(models.Model):
    receipt = models.ForeignKey(Receipt, on_delete=models.CASCADE)
    merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


class Banner(models.Model):
    # user = models.ForeignKey(User, on_delete=models.CASCADE)
    image = models.ImageField()
    # image_2 = models.ImageField()
    # image_3 = models.ImageField()
    # image_4 = models.ImageField()
    # image_5 = models.ImageField()
    # image_6 = models.ImageField()
    # image_7 = models.ImageField()
    # image_8 = models.ImageField()
    # image_9 = models.ImageField()
    # image_10 = models.ImageField()


@receiver(post_save, sender=User)
def setting(sender, instance, created, **kwargs):
    if created:
        user_id = instance.id
        user = User.objects.get(id=user_id)
        setting_obj = Settings.objects.create(
            user=user,
            notification=True,
            language='English'
        )
        return setting_obj
