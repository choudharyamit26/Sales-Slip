import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin
from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from src.models import User, Merchant, Category, Receipt, Settings, UserNotification, TermsAndCondition, AboutUs, \
    PrivacyPolicy, ContactUs, ScannedData, Branch, Banner, SubAdmin, HiddenUsers
from django.contrib.auth import get_user_model, login, authenticate, logout, update_session_auth_hash
from django.views.generic import View, ListView, DetailView, UpdateView, CreateView, DeleteView, FormView, TemplateView
from django.contrib.auth.password_validation import validate_password
from .filters import UserFilter, MerchantFilter
from .forms import LoginForm, MerchantForm, UserNotificationForm, UpdateAboutUsForm, UpdateContactusForm, \
    UpdatePrivacyPolicyForm, UpdateTnCForm, CategoryForm, SubAdminForm, BranchForm, BannerForms, MerchantUpdateForm

from django.utils.translation import gettext_lazy as _
from django.conf.global_settings import DEFAULT_FROM_EMAIL

from src.fcm_notification import send_to_one, send_another

user = get_user_model()


class Login(View):
    template_name = 'login.html'
    form_class = LoginForm

    def get(self, request, *args, **kwargs):
        form = LoginForm()
        try:
            # return render(self.request, 'login.html',
            #               {'form': form, 'cookie1': self.request.COOKIES.get('cid1'),
            #                'cookie2': self.request.COOKIES.get('cid2'),
            #                'cookie3': self.request.COOKIES.get('cid3')})
            if self.request.COOKIES.get('cid1') and self.request.COOKIES.get('cid2') and self.request.COOKIES.get(
                    'cid3'):
                return render(self.request, 'login.html',
                              {'form': form, 'cookie1': self.request.COOKIES.get('cid1'),
                               'cookie2': self.request.COOKIES.get('cid2'),
                               'cookie3': self.request.COOKIES.get('cid3')})
            else:
                return render(self.request, 'login.html', {'form': form})
        except:
            return render(self.request, 'login.html', {'form': form})

    def post(self, request, *args, **kwargs):
        email = self.request.POST['email']
        password = self.request.POST['password']
        remember_me = self.request.POST.get('remember_me' or None)
        print('inside Login-------')
        print('Email-------', email)
        print('Password-------', password)
        try:
            user_object = user.objects.get(email=email)
            if user_object.check_password(password):
                if user_object.is_superuser:
                    login(self.request, user_object)
                    messages.success(self.request, 'Logged in successfully')
                    # self.request.session['uid'] = self.request.POST['email']
                    if remember_me:
                        # print('inside remember me')
                        cookie_age = 60 * 60 * 24
                        self.request.session.set_expiry(1209600)
                        response = HttpResponse()
                        response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                        response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                        response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                        # return HttpResponse(json.dumps('is_superuser'), status=200)
                        return response
                    else:
                        self.request.session.set_expiry(0)
                    return redirect('adminpanel:dashboard')
                if user_object.is_subadmin:
                    login(self.request, user_object)
                    messages.success(self.request, 'Logged in successfully')
                    # self.request.session['uid'] = self.request.POST['email']
                    if remember_me:
                        # print('inside remember me')
                        cookie_age = 60 * 60 * 24
                        self.request.session.set_expiry(1209600)
                        response = HttpResponse()
                        response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                        response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                        response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                        # return HttpResponse(json.dumps('is_superuser'), status=200)
                        return response
                    else:
                        self.request.session.set_expiry(0)
                    return redirect('adminpanel:dashboard')
                else:
                    messages.error(self.request, "You are not authorised")
                    # return render(self.request, 'login.html', {"status": 400})
                    return HttpResponseRedirect(self.request.path_info, status=403)
            else:
                messages.error(self.request, "Incorrect Password")
                # return render(request, 'login.html', {"status": 400})
                return HttpResponseRedirect(self.request.path_info, status=403)
                # return HttpResponseBadRequest()
        except Exception as e:
            print(e)
            messages.error(self.request, "Email doesn't exists")
            # return render(self.request, 'login.html', {"status": 400})
            return HttpResponseRedirect(self.request.path_info, status=403)


class Dashboard(LoginRequiredMixin, ListView):
    model = User
    template_name = 'dashboard-ereceipt.html'

    def get(self, request, *args, **kwargs):
        users_count = User.objects.all().exclude(is_superuser=True).exclude(is_merchant=True).count()
        merchant_count = Merchant.objects.all().count()
        receipts_count = Receipt.objects.all().count()
        context = {
            'users_count': users_count,
            'merchant_count': merchant_count,
            'receipts_count': receipts_count
        }
        return render(self.request, "dashboard-ereceipt.html", context)


class PasswordResetConfirmView(View):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def get(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if token_generator.check_token(user_object, token):
            return render(request, 'password_reset_confirm.html')
        else:
            messages.error(request, "Link is Invalid")
            return render(request, 'password_reset_confirm.html')

    def post(self, request, *args, **kwargs):

        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if not token_generator.check_token(user_object, token):
            messages.error(self.request, "Link is Invalid")
            return render(request, 'password_reset_confirm.html')

        password1 = self.request.POST.get('new_password1')
        password2 = self.request.POST.get('new_password2')

        if password1 != password2:
            messages.error(self.request, "Passwords do not match")
            return render(request, 'password_reset_confirm.html')
        elif len(password1) < 8:
            messages.error(
                self.request, "Password must be atleast 8 characters long")
            return render(request, 'password_reset_confirm.html')
        elif password1.isdigit() or password2.isdigit() or password1.isalpha() or password2.isalpha():
            messages.error(
                self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'password_reset_confirm.html')
        else:
            token = kwargs['token']
            user_id_b64 = kwargs['uidb64']
            uid = urlsafe_base64_decode(user_id_b64).decode()
            user_object = user.objects.get(id=uid)
            user_object.set_password(password1)
            user_object.save()
            return HttpResponseRedirect('/password-reset-complete/')


class PasswordResetView(View):
    template_name = 'password_reset.html'

    def get(self, request, *args, **kwargs):
        return render(request, 'password_reset.html')

    def post(self, request, *args, **kwargs):
        user = get_user_model()
        email = request.POST.get('email')
        email_template = "password_reset_email.html"
        user_qs = user.objects.filter(email=email)
        if len(user_qs) == 0:
            messages.error(request, 'Email does not exists')
            return render(request, 'password_reset.html')

        elif len(user_qs) == 1:
            user_object = user_qs[0]
            email = user_object.email
            uid = urlsafe_base64_encode(force_bytes(user_object.id))
            token = default_token_generator.make_token(user_object)
            if request.is_secure():
                protocol = "https"
            else:
                protocol = "http"
            domain = request.META['HTTP_HOST']
            user = user_object
            site_name = "E-Receipt"

            context = {
                "email": email,
                "uid": uid,
                "token": token,
                "protocol": protocol,
                "domain": domain,
                "user": user,
                "site_name": site_name
            }
            subject = "Reset Password Link"
            email_body = render_to_string(email_template, context)
            send_mail(subject, email_body, DEFAULT_FROM_EMAIL,
                      [email], fail_silently=False)
            return redirect('/password-reset-done/')
        else:

            user_object = user_qs[0]
            email = user_object.email
            uid = urlsafe_base64_encode(force_bytes(user_object.id))
            token = default_token_generator.make_token(user_object)
            if request.is_secure():
                protocol = "https"
            else:
                protocol = "http"
            domain = request.META['HTTP_HOST']
            user = user_object
            site_name = "E-receipt"

            context = {
                "email": email,
                "uid": uid,
                "token": token,
                "protocol": protocol,
                "domain": domain,
                "user": user,
                "site_name": site_name
            }

            subject = "Reset Password Link"
            email_body = render_to_string(email_template, context)
            send_mail(subject, email_body, DEFAULT_FROM_EMAIL,
                      [email], fail_silently=False)
            return redirect('/password-reset-done/')


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('adminpanel:dashboard')

    # template_name = 'registration/password_change_form.html'
    title = _('Password change')

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        messages.success(self.request, 'Password changed successfully')
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    # template_name = 'registration/password_change_done.html'
    title = _('Password change successful')

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


class UsersList(LoginRequiredMixin, ListView):
    paginate_by = 5
    model = User
    template_name = 'user-management.html'

    def get(self, request, *args, **kwargs):
        qs = self.request.GET.get('qs')
        if qs:
            search = User.objects.filter(Q(first_name__icontains=qs) |
                                         Q(last_name__icontains=qs) |
                                         Q(email__icontains=qs) |
                                         Q(phone_number__icontains=qs) |
                                         Q(id__icontains=qs))

            search_count = len(search)
            context = {
                'search': search,
            }
            if search:
                messages.info(self.request, str(
                    search_count) + ' matches found')
                return render(self.request, 'user-management.html', context)
            else:
                messages.info(self.request, 'No results found')
                return render(self.request, 'user-management.html', context)
        else:
            # users = User.objects.all().exclude(is_superuser=True)
            users = User.objects.filter(is_merchant=False).exclude(is_superuser=True)
            myfilter = UserFilter(self.request.GET, queryset=users)
            users = myfilter.qs
            print(users.count())
            paginator = Paginator(users, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            context = {
                'object_list': users,
                'myfilter': myfilter,
                'pages': page_obj,
            }
            return render(self.request, "user-management.html", context)


class NotificationView(ListView):
    model = UserNotification
    template_name = 'notification.html'


class AddMerchant(View):
    model = Merchant
    template_name = 'merchant.html'
    form_class = MerchantForm

    def get(self, request, *args, **kwargs):
        form = MerchantForm
        category = Category.objects.all()
        return render(self.request, 'merchant.html', {'form': form, 'category': category})

    def post(self, request, *args, **kwargs):
        print('------', self.request.POST)
        full_name = self.request.POST['full_name']
        categories = self.request.POST['category']
        email = self.request.POST['email']
        commercial_id = self.request.POST['commercial_id']
        password = self.request.POST['password']
        confirm_password = self.request.POST['confirm_password']
        # address = self.request.POST['address']
        shop_no = self.request.POST['shop_no']
        street = self.request.POST['street']
        landmark = self.request.POST['landmark']
        city = self.request.POST['city']
        postal_code = self.request.POST['postal_code']
        category = Category.objects.all()
        if password != confirm_password:
            messages.error(self.request, 'Password and Confirm password do not match')
            return render(request, 'merchant.html', {'form': self.form_class, 'category': category})
        elif len(password) < 8 or len(confirm_password) < 8:
            messages.error(self.request, "Password must be atleast 8 characters long")
            return render(request, 'merchant.html', {'form': self.form_class, 'category': category})
        elif password.isdigit() or confirm_password.isdigit() or password.isalpha() or confirm_password.isalpha():
            messages.error(self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'merchant.html', {'form': self.form_class, 'category': category})
        else:
            try:
                print('inside try')
                user = User.objects.get(email=email)
                if user:
                    messages.info(self.request, "Merchant with this email already exists")
                    return render(request, 'merchant.html', {'form': self.form_class, 'category': category})
                else:
                    category_object = Category.objects.get(id=categories)
                    merchant_obj = Merchant.objects.create(
                        full_name=full_name,
                        category=category_object,
                        email=email,
                        commercial_id=commercial_id,
                        address=str(shop_no) + str(street) + str(landmark) + str(city) + str(postal_code),
                        password=password
                    )
                    merchant = User.objects.create(
                        email=email,
                        is_merchant=True
                    )
                    merchant.set_password(password)
                    merchant.save()
                    x = Branch.objects.create(
                        merchant_name=merchant_obj,
                        shop_no=shop_no,
                        street=street,
                        landmark=landmark,
                        city=city,
                        postal_code=postal_code,
                        code=0
                    )
                    x.code = (merchant_obj.full_name.replace(" ", "")).upper() + str(x.id)
                    x.save()
                    Settings.objects.create(
                        user=merchant
                    )
                    # from django.contrib.sites.models import Site
                    #
                    # current_site = Site.objects.get_current()
                    # print(current_site.domain)
                    protocol = ''
                    if self.request.is_secure():
                        protocol = 'https'
                    else:
                        protocol = 'http'
                    context = {
                        'email': self.request.POST['email'],
                        'password': self.request.POST['password'],
                        'domain': self.request.get_host(),
                        'protocol': protocol
                    }
                    user_email = self.request.POST['email']
                    email_template = 'merchant_signup_email.html'
                    email = render_to_string(email_template, context)
                    msg = EmailMultiAlternatives("Merchant Creation", email, 'servacnt@fatortech.net',
                                                 [user_email])
                    msg.content_subtype = "html"
                    msg.send()
                    messages.info(self.request, 'Merchant added successfully')
                    return redirect("adminpanel:merchant-list")
            except Exception as e:
                print('inside except', e)
                print('inside except GET HOST', self.request.get_host())
                print('inside except get_full_path()', self.request.is_secure())
                try:
                    user = User.objects.get(email=email)
                    if user:
                        messages.info(self.request, "Merchant with this email already exists")
                        return render(request, 'merchant.html', {'form': self.form_class, 'category': category})
                    else:
                        category_object = Category.objects.get(id=categories)
                        merchant_obj = Merchant.objects.create(
                            full_name=full_name,
                            category=category_object,
                            email=email,
                            commercial_id=commercial_id,
                            address=str(shop_no) + str(street) + str(landmark) + str(city) + str(postal_code),
                            password=password
                        )
                        merchant = User.objects.create(
                            email=email.lower(),
                            is_merchant=True
                        )
                        print(email)
                        merchant.set_password(password)
                        merchant.save()
                        shop_no = self.request.POST['shop_no']
                        street = self.request.POST['street']
                        landmark = self.request.POST['landmark']
                        city = self.request.POST['city']
                        postal_code = self.request.POST['postal_code']
                        x = Branch.objects.create(
                            merchant_name=merchant_obj,
                            shop_no=shop_no,
                            street=street,
                            landmark=landmark,
                            city=city,
                            postal_code=postal_code,
                            code=0
                        )
                        x.code = (merchant_obj.full_name.replace(" ", "")).upper() + str(x.id)
                        x.save()
                        Settings.objects.create(
                            user=merchant
                        )
                        protocol = ''
                        if self.request.is_secure():
                            protocol = 'https'
                        else:
                            protocol = 'http'
                        context = {
                            'email': self.request.POST['email'],
                            'password': self.request.POST['password'],
                            'domain': self.request.get_host(),
                            'protocol': protocol
                        }
                        user_email = self.request.POST['email']
                        email_template = 'merchant_signup_email.html'
                        email = render_to_string(email_template, context)
                        msg = EmailMultiAlternatives("Merchant Creation", email, 'ravichoudhary766@gmail.com',
                                                     [user_email])
                        msg.content_subtype = "html"
                        msg.send()
                        messages.info(self.request, 'Merchant added successfully')
                        return redirect("adminpanel:merchant-list")
                except Exception as e:
                    category_object = Category.objects.get(id=categories)
                    merchant_obj = Merchant.objects.create(
                        full_name=full_name,
                        category=category_object,
                        email=email,
                        commercial_id=commercial_id,
                        address=str(shop_no) + str(street) + str(landmark) + str(city) + str(postal_code),
                        password=password
                    )
                    merchant = User.objects.create(
                        email=email.lower(),
                        is_merchant=True
                    )
                    print(email)
                    merchant.set_password(password)
                    merchant.save()
                    shop_no = self.request.POST['shop_no']
                    street = self.request.POST['street']
                    landmark = self.request.POST['landmark']
                    city = self.request.POST['city']
                    postal_code = self.request.POST['postal_code']
                    x = Branch.objects.create(
                        merchant_name=merchant_obj,
                        shop_no=shop_no,
                        street=street,
                        landmark=landmark,
                        city=city,
                        postal_code=postal_code,
                        code=0
                    )
                    x.code = (merchant_obj.full_name.replace(" ", "")).upper() + str(x.id)
                    x.save()
                    Settings.objects.create(
                        user=merchant
                    )
                    protocol = ''
                    if self.request.is_secure():
                        protocol = 'https'
                    else:
                        protocol = 'http'
                    context = {
                        'email': self.request.POST['email'],
                        'password': self.request.POST['password'],
                        'domain': self.request.get_host(),
                        'protocol': protocol
                    }
                    user_email = self.request.POST['email']
                    email_template = 'merchant_signup_email.html'
                    email = render_to_string(email_template, context)
                    msg = EmailMultiAlternatives("Merchant Creation", email, 'ravichoudhary766@gmail.com',
                                                 [user_email])
                    msg.content_subtype = "html"
                    msg.send()
                    messages.info(self.request, 'Merchant added successfully')
                    return redirect("adminpanel:merchant-list")


class AddSubAdmin(LoginRequiredMixin, CreateView):
    login_url = 'adminpanel:login'
    model = User
    form_class = SubAdminForm
    template_name = 'sub-admin.html'

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        permissions = self.request.POST.getlist('category')
        first_name = self.request.POST['first_name']
        last_name = self.request.POST['last_name']
        email = self.request.POST['email']
        password = self.request.POST['password']
        confirm_password = self.request.POST['confirm_password']
        try:
            user = User.objects.get(email=email)
            messages.info(self.request,
                          'This email already exists, please try another email or contact admin')
            return render(self.request, 'sub-admin.html')
        except Exception as e:
            if password != confirm_password:
                messages.error(self.request, 'Password and Confirm password do not match')
                return render(request, 'sub-admin.html', {'form': self.form_class})
            elif len(password) < 8 or len(confirm_password) < 8:
                messages.error(self.request, "Password must be at least 8 characters long")
                return render(request, 'sub-admin.html', {'form': self.form_class})
            elif password.isdigit() or confirm_password.isdigit() or password.isalpha() or confirm_password.isalpha():
                messages.error(self.request, "Passwords must have a mix of numbers and characters")
                return render(request, 'sub-admin.html', {'form': self.form_class})
            else:
                user = User.objects.create(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    is_subadmin=True
                )
                user.set_password(password)
                user.save()
                for perm in permissions:
                    print('_'.join(perm.lower().split()))
                    if '_'.join(perm.lower().split()) == 'can_manage_merchant':
                        user.can_manage_merchant = True
                        user.save()
                    elif '_'.join(perm.lower().split()) == 'can_manage_category':
                        user.can_manage_category = True
                        user.save()
                    elif '_'.join(perm.lower().split()) == 'can_manage_branch':
                        user.can_manage_branch = True
                        user.save()
                    elif '_'.join(perm.lower().split()) == 'can_manage_dashboard':
                        user.can_manage_dashboard = True
                        user.save()
                    else:
                        user.can_manage_receipts = True
                        user.save()
                if self.request.is_secure():
                    protocol = 'https'
                else:
                    protocol = 'http'
                context = {
                    'email': self.request.POST['email'],
                    'password': self.request.POST['password'],
                    'domain': self.request.get_host(),
                    'protocol': protocol
                }
                user_email = self.request.POST['email']
                email_template = 'sub_admin_signup_email.html'
                email = render_to_string(email_template, context)
                msg = EmailMultiAlternatives("Sub Admin Creation", email, 'servacnt@fatortech.net',
                                             [user_email])
                msg.content_subtype = "html"
                msg.send()
                return redirect('adminpanel:sub-admin-list')


class SubAdminList(LoginRequiredMixin, ListView):
    login_url = 'adminpanel:login'
    model = User
    template_name = 'sub-admin-list.html'

    def get(self, request, *args, **kwargs):
        user = User.objects.filter(is_subadmin=True)
        return render(self.request, 'sub-admin-list.html', {'object_list': user})


class SubAdminDetail(LoginRequiredMixin, DetailView):
    login_url = 'adminpanel:login'
    model = User
    template_name = 'sub-admin-detail.html'

    def get(self, request, *args, **kwargs):
        user = User.objects.get(id=kwargs['pk'])
        return render(self.request, 'sub-admin-detail.html', {'object': user})


class UpdateSubAdminDetail(LoginRequiredMixin, UpdateView):
    login_url = 'adminpanel:login'
    model = User
    form_class = SubAdminForm
    template_name = 'update-sub-admin.html'
    success_url = reverse_lazy('adminpanel:sub-admin-list')

    def get(self, request, *args, **kwargs):
        print('GET METHOD', kwargs['pk'])
        email = User.objects.get(id=kwargs['pk'])
        return render(self.request, 'update-sub-admin.html',
                      {'email': email, 'first_name': email.first_name, 'last_name': email.last_name})

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        print(kwargs['pk'])
        sub_admin = User.objects.get(id=kwargs['pk'])
        print(sub_admin)
        sub_admin.first_name = self.request.POST['first_name']
        sub_admin.last_name = self.request.POST['last_name']
        # sub_admin.email = self.request.POST['email']
        sub_admin.password = self.request.POST['password']
        sub_admin.confirm_password = self.request.POST['confirm_password']
        sub_admin.category = self.request.POST.getlist('category')
        if self.request.POST['password'] != self.request.POST['confirm_password']:
            messages.error(self.request, 'Password and Confirm password do not match')
            return render(request, 'sub-admin.html', {'form': self.form_class})
        elif len(self.request.POST['password']) < 8 or len(self.request.POST['confirm_password']) < 8:
            messages.error(self.request, "Password must be at least 8 characters long")
            return render(request, 'sub-admin.html', {'form': self.form_class})
        elif self.request.POST['password'].isdigit() or self.request.POST['confirm_password'].isdigit() or \
                self.request.POST['password'].isalpha() or self.request.POST['confirm_password'].isalpha():
            messages.error(self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'sub-admin.html', {'form': self.form_class})
        else:
            sub_admin.set_password(self.request.POST['password'])
            sub_admin.save()
            for perm in self.request.POST.getlist('category'):
                print('_'.join(perm.lower().split()))
                if '_'.join(perm.lower().split()) == 'can_manage_merchant':
                    sub_admin.can_manage_merchant = True
                    sub_admin.save()
                elif '_'.join(perm.lower().split()) == 'can_manage_category':
                    sub_admin.can_manage_category = True
                    sub_admin.save()
                elif '_'.join(perm.lower().split()) == 'can_manage_branch':
                    sub_admin.can_manage_branch = True
                    sub_admin.save()
                elif '_'.join(perm.lower().split()) == 'can_manage_dashboard':
                    sub_admin.can_manage_dashboard = True
                    sub_admin.save()
                else:
                    sub_admin.can_manage_receipts = True
                    sub_admin.save()
        messages.info(self.request, 'Sub admin updated successfully')
        return redirect('adminpanel:sub-admin-list')


class DeleteSubAdmin(LoginRequiredMixin, DeleteView):
    login_url = 'adminpanel:login'
    model = User
    form_class = SubAdminForm
    template_name = 'delete-sub-admin.html'
    success_url = reverse_lazy('adminpanel:sub-admin-list')

    def get(self, request, *args, **kwargs):
        print(kwargs)
        # user = User.objects.get(id=kwargs['pk'])
        # user.delete()
        return render(self.request, 'delete-sub-admin.html')

    def post(self, request, *args, **kwargs):
        print(kwargs)
        user = User.objects.get(id=kwargs['pk'])
        user.delete()
        messages.info(self.request, 'Sub admin deleted successfully')
        return redirect('adminpanel:sub-admin-list')


class AddBranch(LoginRequiredMixin, CreateView):
    login_url = 'adminpanel:login'
    model = Branch
    form_class = BranchForm
    template_name = 'branch.html'

    # success_url = reverse('adminpanel:branch-list')
    def get(self, request, *args, **kwargs):
        return render(self.request, 'branch.html', {'merchants': Merchant.objects.all()})

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        merchant_id = self.request.POST['merchant_name']
        merchant_obj = Merchant.objects.get(id=merchant_id)
        shop_no = self.request.POST['shop_no']
        street = self.request.POST['street']
        landmark = self.request.POST['landmark']
        city = self.request.POST['city']
        postal_code = self.request.POST['postal_code']
        x = Branch.objects.create(
            merchant_name=merchant_obj,
            shop_no=shop_no,
            street=street,
            landmark=landmark,
            city=city,
            postal_code=postal_code,
            code=0
        )
        # print(merchant_obj.full_name.replace(" ", ""))
        # print((merchant_obj.full_name.replace(" ", "")).upper())
        x.code = (merchant_obj.full_name.replace(" ", "")).upper() + str(x.id)
        x.save()
        messages.info(self.request, 'Branch added successfully')
        return redirect('adminpanel:branch-list')


class BranchList(LoginRequiredMixin, ListView):
    login_url = 'adminpanel:login'
    model = Branch
    template_name = 'branch-list.html'

    def get(self, request, *args, **kwargs):
        qs = self.request.GET.get('qs')
        if qs:
            search = Branch.objects.filter(Q(code__icontains=qs) | Q(shop_no__icontains=qs)).exclude(blocked=True)
            search_count = len(search)
            if search:
                messages.info(self.request, str(search_count) + ' matches found')
                return render(self.request, 'branch-list.html', {'object_list': search})
            else:
                messages.info(self.request, 'No results found')
                return render(self.request, 'branch-list.html', {'object_list': search})
        return render(self.request, 'branch-list.html', {'object_list': Branch.objects.filter(blocked=False)})


class UpdateBranch(LoginRequiredMixin, UpdateView):
    login_url = 'adminpanel:login'
    model = Branch
    template_name = 'update-branch.html'
    form_class = BranchForm
    success_url = reverse_lazy('adminpanel:branch-list')

    def get(self, request, *args, **kwargs):
        print(kwargs['pk'])
        return render(self.request, 'update-branch.html',
                      {'merchants': Merchant.objects.all(), 'shop_number': Branch.objects.get(id=kwargs['pk']).shop_no,
                       'postal_code': Branch.objects.get(id=kwargs['pk']).postal_code,
                       'city': Branch.objects.get(id=kwargs['pk']).city,
                       'landmark': Branch.objects.get(id=kwargs['pk']).landmark,
                       'street': Branch.objects.get(id=kwargs['pk']).street})

    def post(self, request, *args, **kwargs):
        merchant_obj = Merchant.objects.get(id=self.request.POST['merchant_name'])
        branch_obj = Branch.objects.get(id=kwargs['pk'])
        branch_obj.merchant = merchant_obj
        branch_obj.shop_no = self.request.POST['shop_no']
        branch_obj.street = self.request.POST['street']
        branch_obj.landmark = self.request.POST['landmark']
        branch_obj.city = self.request.POST['city']
        branch_obj.postal_code = self.request.POST['postal_code']
        branch_obj.save()
        messages.info(self.request, 'Branch updated successfully')
        return redirect('adminpanel:branch-list')


class DeleteBranch(LoginRequiredMixin, DeleteView):
    login_url = 'adminpanel:login'
    model = Branch
    template_name = 'delete-branch.html'
    success_url = reverse_lazy('adminpanel:branch-list')

    def post(self, request, *args, **kwargs):
        branch = Branch.objects.get(id=kwargs['pk'])
        branch.blocked = True
        branch.save()
        return redirect('adminpanel:branch-list')


class MerchantList(LoginRequiredMixin, ListView):
    login_url = 'adminpanel:login'
    model = Merchant
    template_name = 'merchant_list.html'
    paginate_by = 5

    def get(self, request, *args, **kwargs):
        qs = self.request.GET.get('qs')
        print('---------', qs)
        print('---------', type(qs))
        try:
            merchant = Merchant.objects.filter(email=qs)
            print('>>>>>>>>>>>>>>>>', merchant)
        except Exception as e:
            print(e)
        if qs:
            search = Merchant.objects.filter(Q(full_name__icontains=qs) |
                                             Q(category__category_name__icontains=qs) |
                                             Q(email__icontains=qs) |
                                             Q(id__icontains=qs) |
                                             Q(commercial_id__icontains=qs)).exclude(blocked=True)

            search_count = len(search)
            context = {
                'search': search,
            }
            if search:
                messages.info(self.request, str(search_count) + ' matches found')
                return render(self.request, 'merchant_list.html', context)
            else:
                messages.info(self.request, 'No results found')
                return render(self.request, 'merchant_list.html', context)
        else:
            users = Merchant.objects.filter(blocked=False)
            myfilter = MerchantFilter(self.request.GET, queryset=users)
            users = myfilter.qs
            print(users.count())
            print('Commercial id ', [x.commercial_id for x in users])
            paginator = Paginator(users, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            context = {
                'object_list': users,
                'myfilter': myfilter,
                'pages': page_obj,
            }
            return render(self.request, "merchant_list.html", context)


class ReceiptList(LoginRequiredMixin, ListView):
    model = Receipt
    template_name = 'receipt_list.html'
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        qs = self.request.GET.get('qs')
        receipts = Receipt.objects.all()
        context = {
            'receipts': receipts,
            'merchants': Merchant.objects.all()
        }
        if qs:
            search = Receipt.objects.filter(Q(id__icontains=qs) |
                                            Q(merchant__category__category_name__icontains=qs) |
                                            Q(merchant__email__icontains=qs) |
                                            Q(user__email__contains=qs))
            print(search)
            print([x.user.email for x in search])

            search_count = len(search)
            context = {
                'search': search,
                'merchants': Merchant.objects.all()
            }
            if search:
                messages.success(self.request, str(search_count) + ' matches found')
                return render(self.request, 'receipt_list.html', context)
            else:
                messages.info(self.request, 'No results found')
                return render(self.request, 'receipt_list.html', context)
        return render(self.request, 'receipt_list.html', context)


class ReceiptDetail(LoginRequiredMixin, DetailView):
    model = Receipt
    template_name = 'receipt-details.html'
    login_url = 'adminpanel:login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        receipt = Receipt.objects.get(id=self.kwargs.get('pk'))
        print('>>>>>>>>>>>>>>>>>>>>>>>>>>>', receipt.qr_code)
        try:
            context['total_amount'] = receipt.order.all()[0].total
        except Exception as e:
            print(e)
        return context


class UserDetail(LoginRequiredMixin, DetailView):
    model = User
    template_name = 'user-details.html'

    def get_context_data(self, **kwargs):
        context = super(UserDetail, self).get_context_data()
        user_obj = User.objects.get(id=kwargs['object'].id)
        # print(Receipt.objects.filter(user=user_obj.id).count())
        context['receipts'] = Receipt.objects.filter(user=user_obj.id).count()
        return context


class MerchantDetail(LoginRequiredMixin, DetailView):
    model = Merchant
    template_name = 'merchant-details.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data()
        merchant_obj = Merchant.objects.get(id=kwargs['object'].id)
        context['receipts_count'] = Receipt.objects.filter(merchant=merchant_obj.id).count()
        context['qr_count'] = ScannedData.objects.filter(merchant=merchant_obj.id).count()
        return context


class NotificationCount(LoginRequiredMixin, ListView):
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        user = User.objects.get(email='ereceipt@gmail.com')
        count = UserNotification.objects.filter(
            to=user.id).filter(read=False).count()
        return HttpResponse(count)


class ReadNotifications(LoginRequiredMixin, ListView):
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        user = User.objects.get(email='ereceipt@gmail.com')
        notifications = UserNotification.objects.filter(
            to=user.id).filter(read=False)
        for obj in notifications:
            obj.read = True
            obj.save()
        return HttpResponse('Read all notifications')


class SetAdminNotificationSetting(LoginRequiredMixin, View):
    model = Settings
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        user = self.request.user
        x = self.request.GET.get('notification' or None)
        print(x)
        try:
            if x == 'true':
                settingObj = Settings.objects.get(user=user)
                settingObj.notification = True
                settingObj.save()
                return HttpResponseRedirect('/change-password/')
            else:
                settingObj = Settings.objects.get(user=user)
                settingObj.notification = False
                settingObj.save()
                return HttpResponseRedirect('/change-password/')
        except Exception as e:
            print(e)


class GetAdminNotificationSetting(LoginRequiredMixin, View):
    model = Settings
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        try:
            user = self.request.user
            settingObj = Settings.objects.get(user=user)
            x = settingObj.notification
            print('---------', x)
            if x:
                return HttpResponse(1)
            else:
                return HttpResponse('')
        except Exception as e:
            print(e)


class SendNotification(LoginRequiredMixin, View):
    model = UserNotification
    form_class = UserNotificationForm
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        users = User.objects.all().exclude(is_superuser=True).exclude(is_merchant=True)
        context = {
            "users": users
        }
        return render(self.request, 'send-notification.html', context)

    def post(self, request, *args, **kwargs):
        users_list = self.request.POST.getlist('to')
        print('From send notification --->>> ', users_list)
        title = self.request.POST['title']
        print(title)
        message = self.request.POST['body']
        print(message)
        for i in users_list:
            user = User.objects.get(id=i)
            fcm_token = user.device_token
            print(fcm_token)
            UserNotification.objects.create(
                to=user,
                title=title,
                body=message,
                read=False
            )
            try:
                # title = title
                # body = message
                # respo = send_to_one(fcm_token, title, body)
                # print("FCM Response===============>0", respo)
                data_message = {"data": {"title": title,
                                         "body": message, "type": "adminNOtification"}}
                print(title)
                print(message)
                respo = send_to_one(fcm_token, data_message)
                print("FCM Response===============>0", respo)
                message_type = "adminNOtification"
                respo = send_another(fcm_token, title, message, message_type)
                print(title)
                print(message)
                # fcm_token.send_message(data)
                print("FCM Response===============>0", respo)
            except:
                pass
        messages.success(self.request, "Notification sent successfully")
        return HttpResponseRedirect(self.request.path_info)


class TermsAndConditionView(LoginRequiredMixin, ListView):
    model = TermsAndCondition
    template_name = 'content-management.html'
    context_object_name = 'term_condition'
    login_url = 'adminpanel:login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['contactus'] = ContactUs.objects.all()
        context['privacypolicy'] = PrivacyPolicy.objects.all()
        context['termsandcondition'] = TermsAndCondition.objects.all()
        context['aboutus'] = AboutUs.objects.all()
        return context


class UpdateTermsAndCondition(LoginRequiredMixin, UpdateView):
    login_url = 'adminpanel:login'
    model = TermsAndCondition
    template_name = 'update-termsandcondition.html'
    form_class = UpdateTnCForm
    success_url = reverse_lazy("adminpanel:static-content")


class UpdatePrivacyPolicyView(LoginRequiredMixin, UpdateView):
    login_url = 'adminpanel:login'
    model = PrivacyPolicy
    template_name = 'update-privacy-policy.html'
    form_class = UpdatePrivacyPolicyForm
    success_url = reverse_lazy("adminpanel:static-content")


class UpdateContactUsView(LoginRequiredMixin, UpdateView):
    model = ContactUs
    template_name = 'update-contactus.html'
    form_class = UpdateContactusForm
    success_url = reverse_lazy("adminpanel:static-content")
    login_url = 'adminpanel:login'


class UpdateAboutUsView(LoginRequiredMixin, UpdateView):
    model = AboutUs
    template_name = 'update-aboutus.html'
    form_class = UpdateAboutUsForm
    success_url = reverse_lazy("adminpanel:static-content")
    login_url = 'adminpanel:login'


class ReportView(LoginRequiredMixin, ListView):
    model = Receipt
    template_name = 'reports-management.html'
    login_url = 'adminpanel:login'


class CreateCategory(LoginRequiredMixin, CreateView):
    model = Category
    template_name = 'category.html'
    login_url = 'adminpanel:login'
    form_class = CategoryForm
    success_url = reverse_lazy("adminpanel:category-list")


class CategoryList(LoginRequiredMixin, ListView):
    model = Category
    login_url = 'adminpanel:login'
    template_name = 'category-list.html'


class UserDelete(LoginRequiredMixin, DeleteView):
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        request_kwargs = kwargs
        object_id = request_kwargs['pk']
        UserObj = User.objects.get(id=object_id)
        UserObj.delete()
        messages.success(self.request, "User deleted successfully")
        return HttpResponseRedirect('/adminpanel/users-list/')


class MerchantDelete(LoginRequiredMixin, DeleteView):
    login_url = 'adminpanel:login'

    def get(self, request, *args, **kwargs):
        request_kwargs = kwargs
        object_id = request_kwargs['pk']
        merchant_obj = Merchant.objects.get(id=object_id)
        merchant_obj.blocked = True
        merchant_obj.save()
        # user = User.objects.get(email=merchant_obj.email)
        # logout(user)
        UserObj = User.objects.get(email=merchant_obj.email)
        UserObj.delete()
        # print(UserObj.email)
        messages.success(self.request, "Merchant deleted successfully")
        return HttpResponseRedirect('/adminpanel/merchant-list/')


class BannerList(LoginRequiredMixin, ListView):
    login_url = 'adminpanel:login'
    model = Banner
    template_name = 'banner-list.html'

    def get(self, request, *args, **kwargs):
        banner_obj = Banner.objects.all()
        return render(self.request, 'banner-list.html', {'banners': banner_obj})


class BannerView(LoginRequiredMixin, CreateView):
    login_url = 'adminpanel:login'
    model = Banner
    form_class = BannerForms
    template_name = 'banner.html'
    success_url = reverse_lazy('adminpanel:banner-list')

    # def post(self, request, *args, **kwargs):
    #     print(self.request.POST)
    #     return redirect('adminpanel:banner-list')


class BannerDetail(LoginRequiredMixin, DetailView):
    login_url = 'adminpanel:login'
    model = Banner
    template_name = 'banner-detail.html'


class UpdateBanner(LoginRequiredMixin, UpdateView):
    login_url = 'adminpanel:login'
    model = Banner
    form_class = BannerForms
    template_name = 'banner.html'
    success_url = reverse_lazy('adminpanel:banner-list')


class UpdateMerchant(LoginRequiredMixin, UpdateView):
    login_url = 'adminpanel:login'
    model = Merchant
    form_class = MerchantUpdateForm
    template_name = 'update-merchant.html'
    success_url = reverse_lazy('adminpanel:merchant-list')
    # def get_context_data(self, **kwargs):
    #     context = super().get_context_data(**kwargs)
    #     context['form'] = self.form_class(instance=self.request.user, initial={'email': self.request.user.email})
    #     return context


class DeleteBanner(LoginRequiredMixin, DeleteView):
    login_url = 'adminpanel:login'
    model = Banner
    template_name = 'banner_confirm_delete.html'
    success_url = reverse_lazy('adminpanel:banner-list')


class HideUser(LoginRequiredMixin, View):
    login_url = 'adminpanel:login'
    model = HiddenUsers

    def get(self, request, *args, **kwargs):
        print(self.request.user)
        print(kwargs)
        receipt_obj = Receipt.objects.get(id=kwargs['pk'])
        print(receipt_obj.merchant)
        print(receipt_obj.user)
        print(receipt_obj.merchant.email)
        HiddenUsers.objects.create(
            merchant=receipt_obj.merchant,
            user=receipt_obj.user
        )
        messages.success(self.request, 'User has been hidden successfully')
        return HttpResponseRedirect('/adminpanel/receipt-list/')
