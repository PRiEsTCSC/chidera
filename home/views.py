from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.cache import cache_control

from home.encrypt_util import encrypt, decrypt
from home.forms import RegistrationForm, LoginForm, UpdatePasswordForm
from home.models import UserPassword
from home.utils import generate_random_password

# ADDED IMPORTS
from django.http import JsonResponse
import requests
import json
from mnemonic import Mnemonic
from eth_account import Account
from django.http import JsonResponse
from mnemonic import Mnemonic
from eth_account import Account

# Configuration
NODE_URL = "https://sepolia.infura.io/v3/095abe2ee7b4475b8a91649cdca18213"
FACTORY_CONTRACT_ADDRESS = "0x9406Cc6185a346906296840746125a0E44976454"
BUNDLER_API_URL = "https://api.stackup.sh/v1/node/bb59f8d1080b7c6f6b08afa1ac4d0fc21ea1a49bd14c6f9068b8c1dcbb57174e"
MNEMONIC = "2AB995365BA418B95885AA4AB7029D6D"

# Util function to interact with Ethereum node
def call_rpc(method: str, params: list) -> dict:
    headers = {'content-type': 'application/json'}
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }
    response = requests.post(NODE_URL, headers=headers, data=json.dumps(data))
    return response.json()

# Util function to generate Ethereum address from mnemonic
# def generate_address_from_mnemonic(mnemonic: str) -> str:
#     entropy = Mnemonic().to_entropy(mnemonic)
#     private_key = Account.from_key(entropy)
#     return private_key.address

# Util function to submit EIP-4337 user operation to bundler
def submit_user_operation(address: str, to: str, value: int) -> dict:
    payload = {
        "address": address,
        "to": to,
        "value": value
    }
    response = requests.post(BUNDLER_API_URL, json=payload)
    return response.json()


def generate_password(request):
    if request.method == 'GET':
        try:
            # Enable Mnemonic features
            Account.enable_unaudited_hdwallet_features()

            # Generate a valid mnemonic phrase
            mnemonic = Mnemonic("english").generate(strength=128)  # Use the desired language and strength
            
            # Generate private key from mnemonic
            private_key = Account.from_mnemonic(mnemonic).key.hex()
            address = Account.from_key(private_key).address
            
            return JsonResponse({"mnemonic": mnemonic, "private_key": private_key, "address": address})
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
def generate_address_from_mnemonic(mnemonic):
    try:
        # Convert mnemonic to private key
        private_key = mnemonic_to_private_key(mnemonic)
        # Generate address from private key
        address = Account.from_key(private_key).address
        return address
    except ValueError as e:
        return str(e)

def mnemonic_to_private_key(mnemonic):
    try:
        # Convert mnemonic to entropy
        entropy = Mnemonic().to_entropy(mnemonic)
        # Use entropy to generate private key
        private_key = Account.from_key(entropy)
        return private_key
    except ValueError as e:
        raise ValueError("Error converting mnemonic to private key: " + str(e))

# home page
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def home_page(request):
    if not request.user.is_authenticated:
        return redirect('/home')
    return render(request, 'pages/home.html')


# user login
class UserLoginView(LoginView):
    form_class = LoginForm
    template_name = 'pages/index.html'


def user_login_view(request):
    if request.user.is_authenticated:
        return redirect('/home')
    return UserLoginView.as_view()(request)


# register new user
def register_page(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account registered successfully. Please log in to your account.")
        else:
            print("Registration failed!")
    else:
        form = RegistrationForm()

    context = {'form': form}
    return render(request, 'pages/register.html', context)


# logout
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout_view(request):
    if not request.user.is_authenticated:
        return redirect('/')
    logout(request)
    return redirect('/')


# add new password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_new_password(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    if request.method == 'POST':
        try:
            username = request.POST['username']
            password = encrypt(request.POST['password'])
            application_type = request.POST['application_type']
            if application_type == 'Website':
                website_name = request.POST['website_name']
                website_url = request.POST['website_url']
                new_password = UserPassword.objects.create(username=username, password=password, application_type=application_type,
                                            website_name=website_name, website_url=website_url, user=request.user)
                new_password.save()
                messages.success(request, f"New password added for {website_name}")
            elif application_type == 'Desktop application':
                application_name = request.POST['application_name']
                new_password = UserPassword.objects.create(username=username, password=password, application_type=application_type,
                                            application_name=application_name, user=request.user)
                print("----------------------------------------------------------------")
                print(password)
                new_password.save()
                messages.success(request, f"New password added for {application_name}.")
            elif application_type == 'Game':
                game_name = request.POST['game_name']
                game_developer = request.POST['game_developer']
                new_password = UserPassword.objects.create(username=username, password=password, application_type=application_type,
                                            game_name=game_name, game_developer=game_developer, user=request.user)
                new_password.save()
                messages.success(request, f"New password added for {game_name}.")
            return HttpResponseRedirect("/add-password")
        except Exception as error:
            print("Error: ", error)

    return render(request, 'pages/add-password.html')


# edit password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def edit_password(request, pk):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    user_password = UserPassword.objects.get(id=pk)
    user_password.password = decrypt(user_password.password)
    form = UpdatePasswordForm(instance=user_password)

    if request.method == 'POST':
        if 'delete' in request.POST:
            # delete password
            user_password.delete()
            return redirect('/manage-passwords')
        form = UpdatePasswordForm(request.POST, instance=user_password)

        if form.is_valid():
            try:
                user_password.password = encrypt(user_password.password)
                form.save()
                messages.success(request, "Password updated.")
                user_password.password = decrypt(user_password.password)
                return HttpResponseRedirect(request.path)
            except ValidationError as e:
                form.add_error(None, e)

    context = {'form': form}
    return render(request, 'pages/edit-password.html', context)


# search password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    logged_in_user = request.user
    logged_in_user_pws = UserPassword.objects.filter(user=logged_in_user)
    if request.method == "POST":
        searched = request.POST.get("password_search", "")
        users_pws = logged_in_user_pws.values()
        if users_pws.filter(Q(website_name=searched) | Q(application_name=searched) | Q(game_name=searched)):
            user_pw = UserPassword.objects.filter(
                Q(website_name=searched) | Q(application_name=searched) | Q(game_name=searched)).values()
            return render(request, "pages/search.html", {'passwords': user_pw})
        else:
            messages.error(request, "---YOUR SEARCH RESULT DOESN'T EXIST---")

    return render(request, "pages/search.html", {'pws': logged_in_user_pws})


# all passwords
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def manage_passwords(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    sort_order = 'asc'
    logged_in_user = request.user
    user_passwords = UserPassword.objects.filter(user=logged_in_user)
    if request.GET.get('sort_order'):
        sort_order = request.GET.get('sort_order', 'desc')
        user_passwords = user_passwords.order_by('-date_created' if sort_order == 'desc' else 'date_created')
    if not user_passwords:
        return render(request, 'pages/manage-passwords.html',
                      {'no_password': "No password available. Please add password."})
    return render(request, 'pages/manage-passwords.html', {'all_passwords': user_passwords, 'sort_order': sort_order})


# # generate random password
# def generate_password(request):
#     password = generate_random_password()
#     return JsonResponse({'password': password})
