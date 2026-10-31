""" HTTP header analyze model
bu modul request.Response nesnesi alir ve olasi guvenlik 
sorunlarinda Finding olarak dondurur.
1 (Yokluk Otomatik Zafiyet Değildir): Bir güvenlik başlığının sunucu yanıtında hiç bulunmaması kesin bir açık olduğu anlamına gelmez. Bu durum "gözden geçirilmeli" tonunda, düşük veya orta önem derecesiyle (severity) raporlanır.
2 (Değer Kontrolü Şarttır): Başlığın sadece var olup olmadığına bakılmaz; içindeki değere de bakılır. Örneğin; HSTS başlığı var ama max-age=0 yapılmışsa ya da CSP içinde unsafe-inline kullanılmışsa bu güvenlik zafiyeti olarak yakalanır.
3 (Bağlam ve Gürültü Azaltma): Yanıtsal bağlama dikkat edilir:
    HTML olmayan yanıtlarda (örneğin bir resim veya JSON verisi) CSP veya X-Frame-Options gibi başlıklar aranmaz.
    Zaten CSP içinde frame-ancestors direktifi varsa, eski bir başlık olan X-Frame-Options ayrıca aranmaz (çünkü CSP bunu zaten kapsar).
    Şifrelenmemiş (HTTP) bağlantılarda HSTS aranmaz.
4 (Hassas Veri Güvenliği): Raporlama sırasında hata veya kanıt (evidence) alanlarına asla hassas veriler (örneğin cookie değerleri, şifreler vb.) yazılmaz.
"""
import re
#yerlesik regex modulu.supeli kaliplari bulur.
from typing import Optional
from urllib.parse import urlparse
import requests
from requests import Response
from websecforge.models.finding import Finding

SEVERITY_ORDER = {"info":0,"low":1,"medium":2,"high":3}
MAX_EVIDENCE_LENGTH = 300
HSTS_MIN_REECOMMENDED = 15_552_000
HSTS_PRELOAD_MIN = 31_536_000

def _truncate(text:str)-> str:
    return text if len(text) <= MAX_EVIDENCE_LENGTH else text[:MAX_EVIDENCE_LENGTH]+ "..."

def _get(response: Response,name:str)-> Optional [str]:
    """ header dondurur. eger yoksa None."""
    value =response.headers.get(name)
    return value.strip() if value is not None else None

def _schema(url:str)-> str:
    return urlparse(url).schema.lower()

def _is_html(response:Response)-> bool:
    """HTMl sayfasi mi? yanit boolean deger dondurur."""
    content_type = (_get(response,"Content0-Type") or "").lower()
    return content_type == "" or "html" in content_type
    
MISSING_HEADER_CHECKS = {
    #tarayicilara her zaman HTTPS uzerinden baglanmalarini soyler
     "Strict-Transport-Security":{
         "severity":"medium",
         "html_only":False,
         "recommendation":(
             "Review the HSTS policy and configure an appropriate "
            "max-age value (e.g. 31536000) when the site is HTTPS-only."
         ),
     },
     #web sayfasina hangi kaynaklarin yukleneblecegini belirler(css,png vs.)
     "Content-Security-Policy": {
        "severity": "medium",
        "html_only": True,
        "recommendation": (
            "Define an appropriate Content Security Policy (CSP) "
            "to help mitigate content injection attacks."
        ),
    },
     #sitenin baska bir sitenin icine gomulumunu kontrol eder.
    "X-Frame-Options": {
        "severity": "low",
        "html_only": True,
        "recommendation": (
            "Review clickjacking protection. Consider X-Frame-Options "
            "or the CSP frame-ancestors directive."
        ),
    },"Content-Security-Policy": {
        "severity": "medium",
        "html_only": True,
        "recommendation": (
            "Define an appropriate Content Security Policy (CSP) "
            "to help mitigate content injection attacks."
        ),
    },
    "X-Frame-Options": {
        "severity": "low",
        "html_only": True,
        "recommendation": (
            "Review clickjacking protection. Consider X-Frame-Options "
            "or the CSP frame-ancestors directive."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "html_only": False,
        "recommendation": "Consider setting X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "html_only": True,
        "recommendation": (
            "Configure an appropriate Referrer-Policy "
            "(e.g. strict-origin-when-cross-origin) to control referrer information."
        ),
    },
    "Permissions-Policy": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether browser features should be restricted "
            "using Permissions-Policy."
        ),
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether Cross-Origin-Opener-Policy is appropriate "
            "for the application's cross-origin isolation requirements."
        ),
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether Cross-Origin-Embedder-Policy is required "
            "for the application's cross-origin isolation requirements."
        ),
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "info",
        "html_only": False,
        "recommendation": (
            "Review whether Cross-Origin-Resource-Policy is appropriate "
            "for controlling cross-origin resource access."
        ),
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "info",
        "html_only": False,
        "recommendation": (
            "Review whether cross-domain policy files should be restricted."
        ),
    },
    "Origin-Agent-Cluster": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether Origin-Agent-Cluster is appropriate "
            "for the application's isolation requirements."
        ),
    },
    #sunucunun bildirdigi content type goz ardi edilip tahmin edilmesi engellenir.
    "X-Content-Type-Options": {
        "severity": "low",
        "html_only": False,
        "recommendation": "Consider setting X-Content-Type-Options to nosniff.",
    },
    #kullanici mevcut siteden baska siteye gittiginde hedef siteye gonderecegi Referer(geldigi sayfa adresi) 
    # bilgisinin ne kadar detayli olacagini kontrol eder.
    "Referrer-Policy": {
        "severity": "low",
        "html_only": True,
        "recommendation": (
            "Configure an appropriate Referrer-Policy "
            "(e.g. strict-origin-when-cross-origin) to control referrer information."
        ),
    },
    #web sitesinin tarayici ozelliklerine ve donanimlarina erisimi kisitlar veya kapatir.(konum vs.)
    "Permissions-Policy": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether browser features should be restricted "
            "using Permissions-Policy."
        ),
    },
    #acilan pencere ile ana pencere farkli kokenlerdeyse aralarindaki baglar koparilir
    "Cross-Origin-Opener-Policy": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether Cross-Origin-Opener-Policy is appropriate "
            "for the application's cross-origin isolation requirements."
        ),
    },
    #bir belgenin acikca yukleme izni vermeyen cross-origin kaynaklari yuklemesini engeller
    "Cross-Origin-Embedder-Policy": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether Cross-Origin-Embedder-Policy is required "
            "for the application's cross-origin isolation requirements."
        ),
    },
    #farkli domaninlerin sizin sunucnuzdaki kaynaklari kendi sayfasina yukleyip yuklemeyecegi kontrol edilir.
    "Cross-Origin-Resource-Policy": {
        "severity": "info",
        "html_only": False,
        "recommendation": (
            "Review whether Cross-Origin-Resource-Policy is appropriate "
            "for controlling cross-origin resource access."
        ),
    },
    #Adobe Flash veya PDF gibi eski teknolojilerin cross-domain politika dosyalarını (crossdomain.xml) nasıl okuyacağını kısıtlar.
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "info",
        "html_only": False,
        "recommendation": (
            "Review whether cross-domain policy files should be restricted."
        ),
    },
    #bellek tabanli izolasyonu arttirir.
    "Origin-Agent-Cluster": {
        "severity": "info",
        "html_only": True,
        "recommendation": (
            "Review whether Origin-Agent-Cluster is appropriate "
            "for the application's isolation requirements."
        ),
    },
 }  
#FINGERPRINT bilgi sizdirilabilir headerlar
#varliklari tek basinda zaafiyet degildir.surumu vs ifsa ederler.

DISCLOSURE_HEADER_CHECKS= {
    #yanit donduren web sunucusunun adini bazen surumunu soyler.o surumde tespit
    #edilen acik olup olmadigi bulunabilir.
    "Server": {
        "severity": "info",
        "version_severity": "low",
        "version_sensitive": True,
        "recommendation": (
            "Review whether the Server header reveals unnecessary "
            "server technology or version information."
        ),
    },
    #arkada calisan web catisini framework veya dili gosterir.
    #X-Powered-By: PHP/8.1.2 veya Express . tamamen kaldirilmalidir.
    "X-Powered-By": {
        "severity": "low",
        "version_sensitive": False,
        "recommendation": (
            "Consider removing unnecessary technology information "
            "from the X-Powered-By header."
        ),
    },
    #Microsoft tabanli projelerde kullanilan ASP.NET ve ASP.NET MVC altyapısının tam sürüm numarasını ifşa eder.
    "X-AspNet-Version": {
        "severity": "low",
        "version_sensitive": False,
        "recommendation": (
            "Review whether ASP.NET version information needs to be exposed."
        ),
    },
    #sitenin hangi CMS veya aracla uretildigini gosterir.(wordpress,drupal vb.)
    "X-Generator": {
        "severity": "info",
        "version_sensitive": False,
        "recommendation": (
            "Review whether the X-Generator header exposes unnecessary "
            "application or CMS information."
        ),
    },
    #sunucunun istegi islemek icin kac milisnaiye harcadigini gosterir
    "X-Runtime": {
        "severity": "info",
        "version_sensitive": False,
        "recommendation": "Review whether runtime information should be disclosed.",
    },
    #backend server ifsa edilebilir.
    "X-Backend-Server": {
        "severity": "info",
        "version_sensitive": False,
        "recommendation": (
            "Review whether internal backend server details should be exposed."
        ),
    },
    #istegein istemciye ulasana kadar hangi proxy sunucularindan
    #ag gecitlerinden veya CDN lerden gectigini gosterir
    "Via": {
        "severity": "info",
        "version_sensitive": False,
        "recommendation": (
            "Review whether the Via header reveals unnecessary "
            "proxy or intermediary information."
        ),
    },
    
}
VERSION_PATTERN = re.compile(r"\d+\.\d+")
#1.23.435 gibi surum numaralarini yakalar

#eski headerlar
DDEPRECATED_HEADER_CHECKS = {
    #eski tarayicilarda XSS filtresini devreye sokmak icin kullanilirdi.
    "X-XSS-Protection": {
        "severity": "info",
        "recommendation": (
            "Review this legacy header. Prefer setting it to 0 (or removing it) "
            "and rely on an appropriate CSP and secure coding practices instead."
        ),
    },
    #tarayiciya stenin SSL/TLS sertifikasini kontrol ederdi.
    "Expect-CT": {
        "severity": "info",
        "recommendation": (
            "Review this obsolete header and remove it if it is no longer needed."
        ),
    },
    #tarayiciya o web sitesi icin sadece SSL sertifikasi veya anahtara guvemesini soylerdi.
    #eger bu baslik kaybedilirse bu siteye asla erisilemez.
    "Public-Key-Pins": {
        "severity": "medium",
        "recommendation": (
            "Review this obsolete HTTP Public Key Pinning configuration "
            "and remove it if it is no longer needed."
        ),
    },
    #web sitesinin kamera,mikrofon,konum gibi donanimlara ersisimini kisitlar.
    "Feature-Policy": {
        "severity": "info",
        "recommendation": (
            "Review migration from the legacy Feature-Policy header "
            "to Permissions-Policy."
        ),
    },
}
def check_missing_headers(response:Response)-> list [Finding]:
    #eksik veya bos guvenlik basliklarini bulur.
    findings: list[Finding] = []
    is_https = _schema(response.url) == "https"
    is_html = _is_html(response)
    #CSP content security policy,guvenlik headeri , amaci XSS i onlemek eger
    #CSP varsa X-Frame-Options yoklugu onemli degildir.
    csp = (_get(response, "Content-Security-Policy") or "").lower()
    has_frame_ancestors = "frame-ancestors" in csp
    #Content-Security-Policy: frame-ancestors 'none'
    for header_name, details in MISSING_HEADER_CHECKS.items():
        if header_name == "Strict-Transport-Security" and not is_https:
            continue
        if header_name == "X-Frame-Options" and has_frame_ancestors:
            continue
        if details["html_only"] and has_frame_ancestors:
            continue
        value = _get(response,header_name)
        if value is None:
            findings.append(
                Finding(
                    title=f"Missing {header_name} header",
                    severity=details["severity"],
                    description=(f"The {header_name} header was not found in the HTTP "
                                 "response. Its absence may warrant a configuration review."),
                    evidence=f"{header_name} header is absent.",
                    recommendation=details["recommendation"],
                )
            )
        elif value == "":
            findings.append(
                Finding(
                    title=f"Empty {header_name} header",
                    severity=details["severity"],
                    description=(
                        f"The {header_name} header is present but has an empty."
                        "value, so it provides no protection"
                    ),
                    evidence=f"{header_name}: (empty)",
                    recommendation=details["recommendation"],
                )
            )
        return findings    
#Bilgi ifsasina neden olabilecek headerlar 
def check_disclosure_headers(response:Response)-> list[Finding]:
    #Docstring yani surum/teknoloji bilgisinin ifsa edebilecek basliklari bulma
    findings : list[Finding]=[]
    #burada bos liste olusturulur (Findingden alinan veirlerle)
    for header_name,details in DISCLOSURE_HEADER_CHECKS.items():
        #items() sozlukten keylerle beraber headerlari dondurur
        value = _get(response,header_name)
        if not value:
            continue
        severity = details["severity"]  
        if details["version_sensitive"] and VERSION_PATTERN.search(value):
            severity=details["version_severity"]
        findings.append(
            Finding(
                title=f"Information disclosure: {header_name}",
                severity=severity,
                description=(
                    f"The response contains the {header_name} header. It may"
                    "disclose infirmation about the server,application, or infrastructure."
                ),
                evidence=_truncate(f"{header_name}: {value}"),
                recommendation=details["recommendation"],
            )
        )        
    return findings

#Kullanimdan kaldirilmis headerlari kontol etme
def check_deprecated_headers(response:Response)-> list[Finding]:
    findings: list[Finding]=[]
    for header_name, details in DDEPRECATED_HEADER_CHECKS.items():
        value = _get(response,header_name)
        if not value:
            continue
        if header_name == "X-XSS-Protection" and value == "0":
            continue
        findings.append(
            Finding(
                title=f"Legacy header detected: {header_name}",
                severity=details["severty"],
                description=(
                    f"The response contains the legacy header {header_name}."
                    "This header may reveal information about the server, application, or infrastructure."
                ),
                evidence=_truncate(f"{header_name}: {value}"),
                recommendation=details["recommendation"],
            )
        )  
    return findings

#Header mevcut fakat yanlis/zayif yapilandirilmis olabilir.

def check_hsts_value(response:Response)-> list[Finding]:
    #HSTS degerini inceler (HTTP Strict Transport Security)
    #Strict-Transport-Security: max-age=31536000 hsts in 365 gun uygulanmasini ifade eder.
    findings: list[Finding] = []
    
    if _schema(response.url) != "https":
        return findings
    value = _get(response, "Strict-Transport-Security")
    if not value:
        return findings
    #eger yoksa check_missing_headersta raporlanir.
    
    #Directifler (guvenlilk headrinin icindeki belirli bir kural) ayristirir.
    #"max-age=31536000; includeSubDomains; preload"
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, val =part.partition("0")
        directives[name.strip().lover()] = val.strip().strip('"')
    evidence = _truncate(f"Strict-Transprot-Security: {value}")
    
    try:
        max_age = int(directives["max_age"])
    except(KeyError, ValueError):
        findings.append(
            Finding(
                title="Invalid HSTS max_age",
                severity="medium",
                description="The HSTS header has a missing or unparsable max-age directive.",
                evidence=evidence,
                recommendation="Set a valid max-age, e.g. 'max-age=31536000'.",  
            )
        )    
        return findings
    
    #HSTS de max-age tarayicinin bu politikayi kac saniye uygulayacagini belirtir.

    if max_age == 0:
        findings.append(
            Finding(
                title="HSTS is disabled (max-age=0)",
                severity="medium",
                description="max-age=0 instructs browser to remove the HSTS policy.",
                evidence=evidence,
                recommendation="Use a meaningful max-age value when the site is HTTPS-only.",
            )
        )
    elif max_age < HSTS_MIN_REECOMMENDED:
        findings.append(
            Finding(
                title="Short HSTS max-age",
                severity="low",
                description=(
                    f"HSTS max-age is {max_age} seconds,which is shorter than"
                    "the commonly recommended duration (-6 months or more)."
                ),
                evidence=evidence,
                recommendation="Consider increasing max-age to at least 31536000 ( 1 year).",
                
            )
        )
    if "includesubdomains" not in directives and max_age >0:
        
    #directifde includesubdomains varsa alt alan adlarina da HSTS politikasi uygulanir
        findings.append(
            Finding(
                title="HSTS does not cover subdomains.",
                severity="info",
                description="The HSTS policy lacks the includeSubDomains directive.",
                evidence=evidence,
                recommendation=(
                    "Review whether includeSubDomains is appropriate"
                    "(only if all subdomains support HTTPS)." 
                ),
            )
        )   
        #tarayici bir siteye ilk kez girerken henuz HSTS politikasini ogrenmemis olabilir.
        #burada preload listesi devreye girer            
        #bu listeye dahil olan siteler icin tarayici HTTPS kullanimi zorunlu tutabilir.
                 
    if "preload" in directives and (
        max_age < HSTS_PRELOAD_MIN or "includesubdomains" not in directives
    ):
        findings.append(
            Finding(
                title="HSTS preload requirements not met",
                severity="low",
                description=(
                    "The preload directive is set, but the policy does not meet."
                    "preload list requirements."
                ),
                evidence=evidence,
                recommendation=(
                     "Preload requires max-age >= 31536000 and includeSubDomains."
            ),
        )  
    )  
    return findings
def _parse_csp(csp: str) -> dict[str,list[str]]:
    #csp yi sozluge cevirir.
    #content security policy tarayiciya hangi kaynaklarin yuklenebilecegini bildirir.
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives.setdefault(name,[t.lower() for t in  tokens[1:]])
    return directives 

def check_csp_value(response:Response)-> list[Finding]:
    findings: list[Finding] = []
    value = _get(response, "Content-Security-Policy")
    if not value:
        return findings
    
    directives = _parse_csp(value)
    evidence=_truncate(f"Content-Security-Policy: {value} ")
    #eger script-src yoksa tarayiuci default-src doner(fallback)
    source_name ="script-src" if "script-src" in directives else "default-src" 
    script_sources = directives.get(source_name)
    
    if script_sources is None:
        findings.append(
            Finding(
                title = "CSP does not restrict scripts",
                severity="low",
                description="The CSP defines neither scrpit-src nor default-src.",
                evidence=evidence,
                recommendation="Define script-src (or default-src) to restrict script soureces."
            )
        )
    else:
        #eger nonce/hash varsa modern tarayicilar unsafe-inline i yok sayar
        has_nonce_or_hash = any(
        s.startswith(("'nonce-","'sha256-","'sha384-","'sha512-"))     
        for s in script_sources )      
               
        if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
            findings.append(
                Finding(
                    title="CSP allows unsafe-inline script ",
                    severity="medium",
                    description=(
                        f"{source_name} contains 'unsafe-inline', which weakens "
                         "protection against script injection."
                    ),
                    evidence=evidence,
                    recommendation="Prefer nonces or hashes instead of unasfe-inline .",
                    
                )
            )
            
        if "'unsafe-eval'" in script_sources:
            findings.append(
                Finding(
                    title="CSP allows unsafe-eval.",
                    severity="low",
                    description=f"{source_name} contains unsafe-eval (eval-like execution) .",
                    evidence=evidence,
                    recommendation="Avoid unsafe-eval and refactor code that depends on eval().",
                    
                )
            )       
        #her siteden script yuklenmesine izin verilir.
        
        broad = [s for s in script_sources if s in ("*","http:","https","data")]   
        if broad:
            findings.append(
                Finding(
                    title = "CPS script source is overly broad.",
                    severity= "medium",
                    description= (
                    f"{source_name} allows broad sources ({', '.join(broad)}),"
                    "which may defeat the purpose of the policy."
                ),
                evidence = evidence,
                recommendation = "Restrict script soruces to spesifci trusted origings.",
            ) 
        )
           #default-src	Belirli kaynak direktifleri için varsayılan kuralı belirler.
           # base-uri	HTML belgesindeki <base> elementinin hangi URL'leri kullanabileceğini sınırlar.
           #object-src	<object> ve <embed> gibi elementlerle yüklenen içeriklerin kaynaklarını sınırlar.



    missing = []
    if "base-uri" not in directives:
        missing.append("base-uri")
    if "object-src" not in directives and "default-src" not in directives:
        missing.append("object-src")
    if missing:
        findings.append(
            Finding(
                title = "CSP lacks hardening directives.",
                severity="info",
                descrpition =f"The CSP does not define: {', '.join(missing)}",
                recommendation="Conside adding base-uri 'self' and object-src 'none'"
            )
        )       
        return findings
def check_simple_header_values(response : Response)-> list[Finding]:
    #X-Frame-Options, X-Content-Type-Options ve Referrer-Policy değerleri.
    findings: list[Finding] = []
    # DENY ve SOMEOEIGIN degerlerini kontrol eder
    xfo =_get(response , "X-Frame-Options")
    if xfo and xfo.upper() not in ("DENY","SAMEORIGIN"):
        findings.append(
            Finding(
                title="Unrecognized X-Frame-Options value",
                severity ="low",
                description=(
                    "X-Frame-Options only supports DENY and SAMEORIGIN."
                    "Other values (including ALLOW-FROM) are ignoredby modern browsers."
                ),
                evidence=_truncate(f"X-Frame-Options: {xfo}"),
                recommendation="Use DENY/SAMEORIGIN or the CSP frame-ancestors directive.",
                
            )
        ) 
        #X-Content-Type-Options: tek geçerli değer nosniff
        #tarayıcının sunucunun belirttiği içerik türünü kendi tahminiyle 
        # değiştirmesini engelleyen bir HTTP güvenlik başlığıdır
    xcto = _get(response, "X-Content-Type-Options")
    if xcto and xcto.lower() != "nosniff":
        findings.append(
            Finding(
                title="Unrecognized X-Content-Type-Options value",
                                severity="low",
                                description="The only valid value for this header is nosniff.",
                                evidence=_truncate(f"X-Content-Type-Options: {xcto}"),
                                recommendation="Set X-Content-Type-Options to nosniff.",
                 
            )
        )
        #Referrer-Policy
        #URL bilgilerini gereğinden fazla paylaşabilecek politikaları tespit ediyor
    referrer = _get(response, "Referrer-Policy")
    if referrer:
        effective = referrer.split(",")[-1].strip().lower() 
        if effective in ("unsafe-url","no-referrer-when-downgrade"):
            findings.append(
                Finding(
                    title ="Permissive Referrer-Policy",
                    severity="low",
                description=(
                f"Refferer-Policy '{effective}'may leak full URLs."
                "(including paths and query strings) to other origins."
                ),
                evidence=_truncate(f"Referrer-Policy: {referrer}"),
                recommendation="Consider strict-origin-when-cross-origin or a stricter policy."
            )   
        )
    return findings
#CORS Cross origin resource sources : farklı origin'lerde
# bulunan web uygulamalarının birbirlerinin kaynaklarına tarayıcı 
# üzerinden erişmesine izin verilmesini düzenleyen bir mekanizmadır.
def check_cors_configuration(response: Response)-> list[Finding]:
            
        """ 
        Pasif CORS kontrolu:sadece  mevcut responsa bakar,yeni istek gondermez.
        '*' tek başına bulgu değildir (public API'lerde normaldir). Ancak '*' ile
            credentials=true birleşimi tutarsızdır; tarayıcılar bunu reddeder.
        """
        findings: list[Finding] = []
        allow_origin = _get(response, "Access-Control-Allow-Origin")
        allow_credentials =_get(response,"Access-Control-Allow-Credentials")
        
        if allow_origin == "*" and (allow_credentials or "").lower() == "true":
            findings.append(
                Finding(
                    title="Inconsistent CORS configuration",
                    severity ="info",
                    description=(
                        "The response combines a wildcard (*) allowed origin with"
                        "credentialed CORS.Browsers do not accept this combination."
                    ),
                    evidence=(
                        "Access-Control-Allow-Origin: *; "
                        "Access-Control-Allow-Credentials: true"
                    ),
                    recommendation=(
                        "If credentialed cross-origin access is required, return an "
                        "explicitly validated origin instead of a wildcard."
                    ),
                )
            )
        return findings
def check_cors_reflection(
    url:str,
    timeout: float=10,
    verify: bool = True,
) -> list[Finding]:
       #AKTİF CORS kontrolü: sahte Origin başlığıyla ek istekler gönderir. 
       # Gerçek CORS zafiyetleri genelde sunucunun gelen Origin'i körü körüne
       # yansıtmasıdır. Bu, normal (Origin'siz) istekte görünmez. Bu yüzden sadece
       # yetkili olduğun hedeflerde ve probe_cors=True ile çalıştır.     
    findings:list [Finding] = []
    test_origins = ["https://example.ex",None ]
    for origin in test_origins:
        try:
            probe= requests.get(
                url,
                headers={"Origin": origin},
                timeout=timeout,
                verify=verify,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue #test basarisiz diger origini dene 
        
        allow_origin =_get(probe , "Access-Control-Allow-Origin")
        allow_credentials =(_get(probe, "Access-Control-Allow-Credenetials")or "").lower()
        
        if allow_credentials != origin:
            continue 
        with_creds = allow_credentials == "true"
        
        findings.append(
            Finding(
                title=f"CORS reflects arbitrary Origin ({origin})",
                #eger credentials ile birlestirilse baska bir site kullancii oturumuyla veri okuyabilir
                severity="high" if with_creds else "medium",
                description=(
                    "The server echoed the supplied Origin in"
                    "Access-Control-Allow-Origin"
                    + (" and allows credentials." if with_creds else ".")
                ),
                evidence=_truncate(
                    f"Origin: {origin} -> Access-Control-Allow-Origin: {allow_origin}; "
                    f"Access-Control-Allow-Credentials: {allow_credentials or '(absent)'}"
                    
                ),
                recommendation=(
                    "Validate Origin against a strict allow-list and never "
                    "reflect untrusted values, especially with credentials."
                    
                ),
            )
        ) 
    return findings
#COOKIE GUVENLIGI
def get_set_cookie_headers(response: Response)-> list[str]:
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
            values = raw_headers.getlist("Set-Cookie")
            if values:
                return values
        
    """
        Her Set-Cookie başlığını ayrı string olarak döndürür.
    
        `response.headers.get("Set-Cookie")` birden fazla cookie'yi virgülle
        BİRLEŞTİRİR ve bu, Expires tarihindeki virgülle karışır. Bu yüzden
        urllib3'ün ham başlık nesnesindeki getlist() tercih edilir.
        """
    # Yedek: ham başlıklar yoksa (ör. mock yanıt). Birden fazla cookie varsa
    # ayrıştırma güvenilir olmayabilir.  
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


""" Cookie ozniteliklerini kontrol ediyoruz
  
    - Yönlendirme zincirindeki ara yanıtların cookie'leri de kontrol edilir
      (response.history), çünkü requests sadece son yanıtı döndürür.
    - Her cookie için TEK bulgu üretilir (en yüksek severity ile) ki rapor
      şişmesin.
    - Cookie DEĞERİ kanıtta gösterilmez (oturum anahtarı olabilir).
    """ 
    
def check_cookie_security(response: Response) -> list[Finding]:
    findings: list[Finding] = []
    responses = list(response.history) + [response]
    #sunucu yonlendirme sirasinda da cookie gonderebilir.kacirmamak icin ikisinide ekliyoruz.
    for resp in responses:
        is_https = _schema(resp.url) == "https"
        
        for cookie_header in get_set_cookie_headers(resp):
            parts = [p.strip() for p in cookie_header.split(";")]
            
            cookie_name = parts[0].split("=",1)[0].strip()
            #set-cookie basliginin ilk kismi cookie nin adini ve degerini icerir
            attributes = {}
            #sozluk olusturuyoruz.dict key-value seklinde verileri saklar
            for part in parts[1:]:
                if not part:
                    continue
                attr_name, _, attr_value = part.partition("=")
                attributes[attr_name.strip().lower()] = attr_value.strip()
            #0.indeximiz cookienin degeri 1.indexten baslayarak sirasiyla digerlerini aliyoruz
            #cookie ozellikelrini incelemek icin
            issues: list[tuple[str, str]] = []
            
            if is_https and "secure" not in attributes:
                issues.append(("medium","missing Secure attribute"))
                
            if "httponly" not in attributes:
                issues.append(("low", "missing HttpOnly attribute"))
            
            samesite = attributes.get("samesite")
            if samesite is None :
                issues.append(("low", "missing SameSite attribute" ))
            elif samesite.lower() == "none" and "Secure" not in attributes:
                #samesite = none secure olamdan modern tarayicilarda reddedilir.
                issues.append(("medium", "SameSite=None without Secure"))
            #cookie adının başına yazmak tek başına yeterli değildir. Cookie'nin ilgili kurallara da uyması gerekir.
                _#_Host-  kuralları
                # Bir cookie __Host- ile başlıyorsa:
                # 1. Secure özelliği bulunmalıdır.
                # 2. Path=/ olmalıdır.
                # 3. Domain özelliği bulunmamalıdır.    
            if cookie_name.startswith("_Host_") and (
                "secure" not in attributes or attributes.get("path") != "/"
                or "domain" in attributes
            ):
                issues.append(("medium", "__Host- prefix rules not satisfied"))
            if not issues:
                continue
            top_severity = max((sev for sev, _ in issues), key= SEVERITY_ORDER.get)
            findings.append(
                Finding(
                    title=f"Cookie security attributes:{cookie_name}",
                    severity=top_severity,
                    description=(
                        "The cookie has the following issues: "
                        + ", ".join(text for _, text in issues)
                        + "."
                    ),
                    #deger gizlenir sadece isim ve oznitelikler gosterilir.
                    evidence=_truncate(
                        f"Set-Cookie: {cookie_name} =<redacted>; "
                        + "; ".join(parts[1:])
                    ),
                    recommendation=(
                        "Set Secure on HTTPS cookies, HttpOnly for cookies not "
                        "needed by JavaScript, and an explicit SameSite value "
                        "(Lax/Strict, or None with Secure)."
                    ),
                )
            )    
            return findings
#web sitesinin https kulanip kullanmadigini ve guvenlik sorunlari olup olmadiigni konrol ediyorum.
def   check_transport(response: Response) -> list[Finding]:
    #iki adet amacimiz var:
    # Web sitesinin HTTPS kullanıp kullanmadığını kontrol etmek.
    # Yönlendirme zincirinde HTTPS bağlantısından
    # HTTP bağlantısına geçiş olup olmadığını belirlemek.
    findings: list [Finding] = []
    
    if _schema(response.url) != "https":
        findings.append(
            Finding(
                title="Response served over HTTP ",
                severity="medium",
                description=(
                    "The final response was delivered without TLS, so "
                    "transport-level protections (including HSTS) do not apply."    
                ),
                evidence=f"Final URL: {_truncate(response.url)}",
                recommendation="Serve the site over HTTPS and redirect HTTP to HTTPS. ",
            )
        )   
        
    #HTTPS -> HTTP gecisi (downgrade) yonlendirme zincirinde var mi?
    chain = [r.url for r in response.history] + [response.url]
    for current, nxt in zip(chain, chain[1:]):
        if _schema(current) == "https" and _schema(nxt) == "http":
            findings.append(
                Finding(
                    title="HTTPS to HTTP redirect downgrade",
                    severity="medium",
                    description="A redirect moves the user from HTTPS to plain HTTP.",
                    evidence=_truncate(f"{current} -> {nxt}"),
                    recommendation="Keep redirects on HTTPS end-to-end."
                )
            )
            return findings
 
 
 #ana analiz fonksiyonu
def analyze_security_headers(
    response: Response,
    probe_cors: bool = False,
    timeout: float = 10,
    verify: bool = True,
)-> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_transport(response))
    findings.extend(check_missing_headers(response))
    findings.extend(check_hsts_value(response))
    findings.extend(check_csp_value(response))  
    findings.extend(check_simple_header_values(response))
    findings.extend(check_disclosure_headers(response))
    findings.extend(check_deprecated_headers(response))
    findings.extend(check_cors_configuration(response))
    findings.extend(check_cookie_security(response))
    
    if probe_cors:
        findings.extend(check_cors_reflection(response.url,timeout=timeout, verify=verify))
        
        #en kritik bilgiler en ustte
         
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
        
    return findings
    
    
 

      

                    
                                

    