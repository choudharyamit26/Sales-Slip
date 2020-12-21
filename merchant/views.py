from django.conf.global_settings import DEFAULT_FROM_EMAIL
import pyqrcode
import os
from django.core.files import File
from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View, ListView, DetailView, CreateView, FormView, TemplateView, UpdateView
from src.models import User, OrderItem, Receipt, Merchant, TermsAndCondition, UserNotification, Settings

from .forms import MerchantLoginForm, OrderForm, OrderFormSet, MerchantUpdateForm

user = get_user_model()

from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa


def render_to_pdf(template_src, context_dict={}):
    print('inside render to pdf ')
    print(template_src)
    print(context_dict)
    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type='application/pdf')
    return None


class MerchantLogin(View):
    model = User
    template_name = 'merchant-login.html'

    def get(self, request, *args, **kwargs):
        form = MerchantLoginForm()
        print('inside merchant login')
        try:
            return render(self.request, 'merchant-login.html',
                          {'form': form, 'cookie1': self.request.COOKIES.get('cid1'),
                           'cookie2': self.request.COOKIES.get('cid2'),
                           'cookie3': self.request.COOKIES.get('cid3')})
        except:
            return render(self.request, 'merchant-login.html', {'form': form})

    def post(self, request, *args, **kwargs):
        email = self.request.POST['email']
        password = self.request.POST['password']
        remember_me = self.request.POST.get('remember_me' or None)
        try:
            user_object = user.objects.get(email=email)
            if user_object.check_password(password):
                if user_object.is_merchant:
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
                    return redirect('merchant:dashboard')
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


class MerchantDashBoard(LoginRequiredMixin, ListView):
    model = User
    template_name = 'merchant-dashboard.html'
    login_url = 'merchant:login'

    def get(self, request, *args, **kwargs):
        users_count = User.objects.all().exclude(is_superuser=True).exclude(is_merchant=True).count()
        merchant = Merchant.objects.get(email=self.request.user.email)
        receipts_count = Receipt.objects.filter(merchant=merchant).count()

        context = {
            'users_count': users_count,
            'receipts_count': receipts_count,
        }
        return render(self.request, "merchant-dashboard.html", context)


class MerchantLogout(View):
    model = User

    def get(self, request, *args, **kwargs):
        logout(self.request)
        return redirect("merchant:login")


class PasswordResetConfirmView(View):
    template_name = 'merchant/password_reset_confirm.html'
    success_url = reverse_lazy('/merchant/password_reset_complete')

    def get(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if token_generator.check_token(user_object, token):
            return render(request, 'merchant/password_reset_confirm.html')
        else:
            messages.error(request, "Link is Invalid")
            return render(request, 'merchant/password_reset_confirm.html')

    def post(self, request, *args, **kwargs):

        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if not token_generator.check_token(user_object, token):
            messages.error(self.request, "Link is Invalid")
            return render(request, 'merchant/password_reset_confirm.html')

        password1 = self.request.POST.get('new_password1')
        password2 = self.request.POST.get('new_password2')

        if password1 != password2:
            messages.error(self.request, "Passwords do not match")
            return render(request, 'merchant/password_reset_confirm.html')
        elif len(password1) < 8:
            messages.error(
                self.request, "Password must be atleast 8 characters long")
            return render(request, 'merchant/password_reset_confirm.html')
        elif password1.isdigit() or password2.isdigit() or password1.isalpha() or password2.isalpha():
            messages.error(
                self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'merchant/password_reset_confirm.html')
        else:
            token = kwargs['token']
            user_id_b64 = kwargs['uidb64']
            uid = urlsafe_base64_decode(user_id_b64).decode()
            user_object = user.objects.get(id=uid)
            user_object.set_password(password1)
            user_object.save()
            return HttpResponseRedirect('/merchant/password-reset-complete/')


class PasswordResetView(View):
    template_name = 'merchant/password_reset.html'

    def get(self, request, *args, **kwargs):
        return render(request, 'merchant/password_reset.html')

    def post(self, request, *args, **kwargs):
        user = get_user_model()
        email = request.POST.get('email')
        email_template = "merchant/password_reset_email.html"
        user_qs = user.objects.filter(email=email)
        if len(user_qs) == 0:
            messages.error(request, 'Email does not exists')
            return render(request, 'merchant/password_reset.html')

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
            return redirect('/merchant/password-reset-done/')
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
            return redirect('/merchant/password-reset-done/')


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('merchant:dashboard')

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


class CreateOrder(LoginRequiredMixin, CreateView):
    model = OrderItem
    template_name = 'order-new.html'
    form_class = OrderForm

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['formset'] = OrderFormSet(queryset=OrderItem.objects.none())
        return context

    def form_valid(self, form):
        formset = OrderFormSet(self.request.POST)
        user = form.cleaned_data['user']
        order_id = get_random_string(16)
        instances = formset.save(commit=False)
        user_obj = User.objects.get(id=user.id)
        order_total = 0
        for instance in instances:
            quantity = instance.quantity
            price = instance.price
            amount = quantity * price
            order_total += amount
            instance.user = user
            instance.order_id = order_id
            instance.save()
        if instance:
            order = instance.order_id
            ordered_items = OrderItem.objects.filter(order_id=order)
            x = []
            i = 1
            for item in ordered_items:
                item.total = order_total
                item.save()
                product_string = 'product_' + str(i) + ':' + item.product
                x.append(product_string)
                price_string = 'price_' + str(i) + ':' + str(item.price)
                x.append(price_string)
                quantity_string = 'quantity_' + str(i) + ':' + str(item.quantity)
                x.append(quantity_string)
                i += 1
            item_string = ','.join(x)
            total_string = ',Total : ' + str(order_total) + ', '
            item_string += total_string
            merchant_obj = Merchant.objects.get(email=self.request.user.email)
            user_string = 'User ID:{},Name of the user:{} {}, User Contact Number:{}'.format(user.id,
                                                                                             user_obj.first_name,
                                                                                             user_obj.last_name,
                                                                                             user_obj.phone_number)
            merchant_string = 'Merchant : ' + str(merchant_obj)
            item_string += merchant_string + ', '
            item_string += user_string
            receipt_id = 0
            try:
                receipt_obj = Receipt.objects.last()
                receipt_id = receipt_obj.id + 1
            except Exception as e:
                print(e)
                receipt_id += 1
            print(receipt_id)
            bill = Receipt.objects.create(
                merchant=merchant_obj,
                user=user_obj,
                # qr_code=f'{receipt_id}.png',
            )
            for x in ordered_items:
                print(x)
                bill.order.add(x)
            item_string += ', Order Id : ' + str(bill.id)
            url = pyqrcode.create(item_string, encoding='utf-8')
            url.png(f'media/{receipt_id}.png', scale=6)
            qr = os.path.basename(f'{receipt_id}.png'), File(open(f'media/{receipt_id}.png', 'rb'))
            bill.qr_code = qr[1]
            bill.save(update_fields=['qr_code'])
            return HttpResponseRedirect(reverse('merchant:order-detail', args=(bill.id,)))

    def form_invalid(self, form):
        print('Form Invalid ---->>> ', self.request)
        messages.error(self.request, 'Some error occurred please check.')
        return self.render_to_response(self.get_context_data(form=form))


class OrderDetail(LoginRequiredMixin, DetailView):
    model = Receipt
    template_name = 'order-detail.html'
    login_url = 'merchant:login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        receipt = Receipt.objects.get(id=self.kwargs.get('pk'))
        print(receipt.order.all()[0].total)
        try:
            context['total_amount'] = receipt.order.all()[0].total
        except Exception as e:
            print(e)
        return context


class OrderList(LoginRequiredMixin, ListView):
    model = Receipt
    template_name = 'order-list.html'
    paginate_by = 5
    login_url = 'merchant:login'

    def get(self, request, *args, **kwargs):
        merchant_obj = Merchant.objects.get(email=self.request.user.email)
        receipts = Receipt.objects.filter(merchant=merchant_obj)
        context = {
            'object_list': receipts,
        }
        return render(self.request, "order-list.html", context)


class ApiIntegrationTutorial(LoginRequiredMixin, View):
    model = Receipt
    template_name = 'api-tutorial.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'api-tutorial.html')


class StaticContent(LoginRequiredMixin, View):
    model = TermsAndCondition
    template_name = 'static-content-management.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'static-content-management.html')


class MyProfile(LoginRequiredMixin, View):
    model = User
    template_name = 'myprofile.html'

    def get(self, request, *args, **kwargs):
        user = self.request.user
        category = Merchant.objects.get(email=self.request.user.email)
        # print(user.profile_pic.url)
        if request.is_secure():
            protocol = "https"
        else:
            protocol = "http"
        domain = request.META['HTTP_HOST']
        profile_pic_url = protocol + '://' + domain + user.profile_pic.url
        print(profile_pic_url)

        context = {
            'object': user,
            'category': category,
            'profile_pic_url': profile_pic_url
        }
        return render(self.request, 'myprofile.html', context)


class NotificationView(LoginRequiredMixin, ListView):
    model = UserNotification
    template_name = 'merchant-notification.html'
    login_url = 'merchant:login'


class NotificationCount(LoginRequiredMixin, ListView):
    login_url = 'merchant:login'

    def get(self, request, *args, **kwargs):
        user = User.objects.get(email=self.request.user.email)
        count = UserNotification.objects.filter(
            to=user.id).filter(read=False).count()
        return HttpResponse(count)


class ReadNotifications(LoginRequiredMixin, ListView):
    login_url = 'merchant:login'

    def get(self, request, *args, **kwargs):
        user = User.objects.get(email=self.request.user.email)
        notifications = UserNotification.objects.filter(
            to=user.id).filter(read=False)
        for obj in notifications:
            obj.read = True
            obj.save()
        return HttpResponse('Read all notifications')


class SetAdminNotificationSetting(LoginRequiredMixin, View):
    model = Settings
    login_url = 'merchnat:login'

    def get(self, request, *args, **kwargs):
        user = self.request.user
        x = self.request.GET.get('notification' or None)
        print(x)
        try:
            if x == 'true':
                settingObj = Settings.objects.get(user=user)
                settingObj.notification = True
                settingObj.save()
                return HttpResponseRedirect('merchant/change-password/')
            else:
                settingObj = Settings.objects.get(user=user)
                settingObj.notification = False
                settingObj.save()
                return HttpResponseRedirect('merchant/change-password/')
        except Exception as e:
            print(e)


class GetAdminNotificationSetting(LoginRequiredMixin, View):
    model = Settings
    login_url = 'merchant:login'

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


class PrintQRCode(LoginRequiredMixin, View):
    model = Receipt
    login_url = 'merchant:login'

    def get(self, request, *args, **kwargs):
        template = get_template('qr.html')
        bill = Receipt.objects.get(pk=self.kwargs.get('pk'))
        context = {
            'qr_url': bill.qr_code.url
        }
        pdf = render_to_pdf('qr.html', context)
        return HttpResponse(pdf, content_type='application/pdf')
        # if pdf:
        #     response = HttpResponse(pdf, content_type='application/pdf')
        #     content = "attachment;filename=RECEIPT%s.pdf" % (bill.id)
        #     response['Content-Disposition'] = content
        #     return response
        # return HttpResponse("Not found")


class UpdateProfilePicView(LoginRequiredMixin, UpdateView):
    model = Merchant
    form_class = MerchantUpdateForm
    template_name = 'update-profile.html'
    login_url = 'merchant:login'
    success_url = reverse_lazy('merchant:profile')

    def form_valid(self, form):
        try:
            profile_pic = self.request.FILES['profile_pic']
            merchant_obj = Merchant.objects.get(id=self.request.user.id)
            merchant_obj.profile_pic = profile_pic
            merchant_obj.save()
            user = User.objects.get(id=self.request.user.id)
            user.profile_pic = profile_pic
            user.save()
            messages.info(self.request, 'Profile pic updated successfully')
            return redirect('merchant:profile')
        except:
            messages.error(self.request, "Please select an image")
            return redirect(self.request.path_info)

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))
