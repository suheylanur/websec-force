import requests
from urllib.parse import urlparse

DEFAULT_TIMEOUT= 10
#10 saniyeyik zaman asimi

def validate_url(url:str)-> str:
    #URL i dogrula
    if not isinstance(url,str)or not url.strip():
        raise ValueError("URL can not be empty.")
    #url bos veya sadece bosluklardan mi olusuyor
    url = url.strip()
    parsed_url = urlparse(url)
    
    if any(char.isspace() for char in url):
            raise ValueError("URL can not contain whitespace.")
        #URL in herhangi bir yerinde bosluk var mi
    
    if parsed_url.scheme not in ("http","https"):
        raise ValueError("URL must be HTTP or HTTPS.")
    
    if not parsed_url.hostname:
        raise ValueError("URL must contain a valid hostname")
    
    return url
  
def fetch_url(url:str)-> requests.Response:
    #http get request gonderir ve server responsu dondurur.
    url = validate_url(url)
    try:
        response = requests.get(url,timeout=DEFAULT_TIMEOUT)
        return response
    except requests.exceptions.Timeout as error:
        #eger istek zaman asiminia ugrarsa
        raise RuntimeError(f"Request timed out after {DEFAULT_TIMEOUT} seconds")from error
    except requests.exceptions.ConnectionError:
        #eger DNS cozumleme veya baglanti kurmada hata varsa
        raise RuntimeError("Could not connect to the target server.")
    except requests.exceptions.RequestException as error:
        #diger request kaynakli hatalar
        raise RuntimeError(f"HTTP request failed: {error}")
    #exceptions ile request kutuphanesindeki hatalara erisim saglariz