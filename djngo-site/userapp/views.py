from django.http import JsonResponse,HttpResponse
from django.shortcuts import render
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.views.generic import View
from django.contrib.auth.hashers import check_password, make_password
from .models import UserProfile
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
import uuid
from django.conf import settings
from django.contrib.auth.forms import PasswordChangeForm
from django.core.mail import send_mail
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

# Create your views here.



def signup(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        contact_number = request.POST.get('contact_number')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        check_user = User.objects.filter(email=email).exclude(username='admin')
        print("******************************8888888888888",check_user)
        if check_user:
            return JsonResponse({"status": "Email is Already Registered"})
        
        if not password_check(password):
                return JsonResponse({"status": "Incorrect Password"})
        elif (password == confirm_password):
                pass
        else:
            return JsonResponse({"status": "Password Doesn't Match"})
                
        new_user = User.objects.create_user(username=email, email=email, first_name=first_name, last_name=last_name)
        new_user.is_active = False
        new_user.set_password(password)
        new_user.save()
        
        user_obj = User.objects.get(username=email)
        auth_token=str(uuid.uuid4())
        UserProfile.objects.create(username=user_obj, auth_token=auth_token,contact_number = contact_number)
        password3 = User.objects.make_random_password()
        print("Password = ",password3)
        send_mail_after_register(email,auth_token,password3)
        
        return JsonResponse({"status": "User Registration Success"}, safe=False)
        
        
    return render(request, 'signup.html')


def send_mail_after_register(email,token,password):
    try:
        subject = 'Your Acoounts need to be verified'
        message = f'Hii click the link to verify your account http://127.0.0.1:8000/verify/{token}'
        email_from = settings.EMAIL_HOST_USER
        reci_list = [email]
        send_mail(subject, message, email_from, reci_list)
    except:
        print("Email sending problam")

def verify(request,auth_token):
    try:
        profile_obj = UserProfile.objects.filter(auth_token = auth_token).first()
        if profile_obj:
            if profile_obj.is_verified:
                print("Your Account is already verified")
                messages.success(request, 'Your Account has been verified!')
                return redirect('/userlogin')
            
            profile_obj.is_verified = True            
            reg_user=User.objects.filter(email=profile_obj.username.email).update(is_active=True)
            profile_obj.save()
            print("Your Account has been verified")
            messages.success(request, 'Your Account has been verified!')
            return redirect('/userlogin')
        else:
            return redirect('/error')
    except:
        print("Email Not Verified")

def token_send(request):
    return HttpResponse('token_send')

def error_page(request):
    return render(request,'users/error.html')


def password_check(passwd):
    SpecialSym = ['$', '@', '#', '%']
    val = True
    if len(passwd) < 6:
        print('length should be at least 6')
        val = False
    if len(passwd) > 20:
        print('length should be not be greater than 8')
        val = False
    if not any(char.isdigit() for char in passwd):
        print('Password should have at least one numeral')
        val = False
    if not any(char.isupper() for char in passwd):
        print('Password should have at least one uppercase letter')
        val = False
    if not any(char.islower() for char in passwd):
        print('Password should have at least one lowercase letter')
        val = False
    if not any(char in SpecialSym for char in passwd):
        print('Password should have at least one of the symbols $@#')
        val = False
    if val:
        print(val)
        return val




def userlogin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(username=email, password=password)
        print(user)
        if user is not None:
            login(request, user)
            return JsonResponse({"status": "User Login Success"})
        else:
            return JsonResponse({"status": "Invaild Password"})          
    context = {}
    return render(request, 'login_page.html', context)

def logout_user(request):
    logout(request)
    return render(request, 'login_page.html')


def forget_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        forget_user_pass=User.objects.filter(email=email)
        if not forget_user_pass:
            msg='Email is not Found'
            return render(request, 'forget_password.html',{'msg':msg})
        else:
            key = Fernet.generate_key()
            fernet = Fernet(key)
            ence_mail2 = fernet.encrypt(email.encode())
            ence_mail=str(ence_mail2)
            key2 = str(key)
            
            try:
                subject = 'Reset Your Password'
                message = f'Hii click the link to reset account password http://127.0.0.1:8000/change_password/{ence_mail}/{key2}'
                email_from = settings.EMAIL_HOST_USER
                reci_list = [email]
                send_mail(subject, message, email_from, reci_list)
            except:
                print("Email sending problam")
            
            msg="Check your email for re-set password"
            return render(request, 'forget_password.html',{'msg1':msg})
    return render(request, 'forget_password.html',)

def change_password(request,ence_mail,key2):
    temp1=ence_mail[2:-1]
    temp2=key2[2:-1]
    ence_mail2 = temp1.encode('utf-8')
    key=temp2.encode('utf-8')
    fernet = Fernet(key)
    decemail = fernet.decrypt(ence_mail2).decode()
    print('********',decemail)            
    return render(request,'change_password.html',{'user_email':decemail})

def change_password2(request): 
    if request.method == 'POST':
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        email=request.POST.get('email')
        if not password_check(password):
                return JsonResponse({"status": "Password not valid"}) 
        elif password==password2:
            print('********4')
            change_pass=User.objects.get(username=email)
            change_pass.set_password(password)
            change_pass.save()
            return JsonResponse({"status": "Re-set password successfully"})          
        else:
            print('********5')
            return JsonResponse({"status": "Both passwords are not same"})
    # return render(request,'change_password.html',)

@login_required(login_url='/userlogin/')
def myprofile(request):
    if request.method == 'POST':
        user = request.user
        user_profile, created = UserProfile.objects.get_or_create(username=user)
        user.first_name = request.POST.get('user_first_name')
        user.last_name = request.POST.get('user_last_name')
        user_profile.contact_number = request.POST.get('user_contact_number')
               
        user.save()
        user_profile.save()
        user2=User.objects.get(username=user)
        user_profile2 = UserProfile.objects.get(username=user2.id)
        
        
        context = {
            'user': user,
            'user_profile2':user_profile2
            
            
        }
        return render(request, 'myprofile.html', context)
    else:
        user = request.user
        print(user)
        user2=User.objects.get(username=user)      
        user_profile2 = UserProfile.objects.get(username=user2.id)  
        context = {
            'user_profile2':user_profile2
        }
        return render(request, 'myprofile.html', context)

   



@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        user = request.user
        old_profile = User.objects.get(username=user)
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Check if old password matches with the current password
        if not user.check_password(old_password):
            return JsonResponse({'success': False, 'message': 'Old password is incorrect.'})
        else:
            if not password_check(new_password):
                return JsonResponse({'success': False, 'message': 'New password should have at least one numeral, one uppercase letter, one lowercase letter, one of the symbols $@#'})
            elif new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                return JsonResponse({'success': True, 'message': 'Password changed successfully.'})
            else:
                return JsonResponse({'success': False, 'message': 'New password and confirm password do not match.'})
    
    return render(request, 'reset_password.html')
    



def home(request):
    return render(request, 'home_page.html')


def header(request):   
    return render(request, 'header.html')

def footer(request):   
    return render(request, 'footer.html')

