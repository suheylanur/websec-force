#Bir web sitesini taradığımızda elde ettiğimiz bütün sonuçları saklamak için kullaniyorum. 

from dataclasses import asdict, dataclass, field
from typing import Optional
from websecforge.models.finding import SEVERITIES, SEVERITY_ORDER, Finding

@dataclass 
class ScanResult:
    target: str
    final_url: str = ""
    status_code: Optional[int] = None
    elapsed_ms: Optional[int] = None
    redirects: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None
    
    """ 
    Tek bir hedefin tarama çıktısı.

    Tarama başarısız olursa (bağlantı hatası, geçersiz URL vb.) istisna
    fırlatmak yerine `error` doldurulur. Böylece 100 URL'lik bir toplu
    taramada tek bir hatalı hedef tüm işi durdurmaz.
    """
    
    @property
    def ok(self) -> bool:
        return self.error is None
    

    def count_by_severity(self) -> dict[str,int]:
        """{"info": n, "low": n, "medium": n, "high": n}"""
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
    
    def highest_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=SEVERITY_ORDER.get)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["ok"] = self.ok
        data["counts"] = self.count_by_severity()
        return data

            
        



