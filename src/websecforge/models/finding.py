"""Güvenlik kontrolleri sonucunda tespit edilen bulguları tanımlar."""
from dataclasses import dataclass,asdict
#asdict sozluge cevirir
SEVERITIES = ("info","low","medium","high")
SEVERITY_ORDER ={name: rank for rank , name in enumerate(SEVERITIES)}

@dataclass(frozen=True)
#olusturulan nesnenin degistirilmesini engeller 
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    url: str = ""
    
def __post_init__(self) -> None:
    #yazim hatalarini yakalar
    if self.severity not in SEVERITY_ORDER:
        raise ValueError(f"Invalid severity {self.severity!r}; expected one of {SEVERITIES}")
    
    if not self.title.strip():
        raise ValueError("Finding title cannot be empty.")

def to_dict(self) -> dict:
    return asdict(self) 
      
    