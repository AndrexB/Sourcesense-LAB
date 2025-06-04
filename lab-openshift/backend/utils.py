import requests

def verify_recaptcha(token, secret):
    if not token:
        return False
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {'secret': secret, 'response': token}
    try:
        r = requests.post(url, data=data, timeout=5)
        return r.json().get("success", False)
    except Exception:
        return False