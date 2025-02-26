"""
Detection engine for Pterodactyl Guardian SDK.

This module provides the core detection engine that orchestrates all detection
modules, manages detection patterns, and coordinates analysis.
"""

import logging
import time
import threading
import re
from typing import Dict, List, Any, Optional, Union, Set, Tuple, Pattern
from dataclasses import dataclass, field
import json

from ..exceptions import DetectionError
from ..enums import DetectionModules, AnalysisLevel
from ..core.utils import hash_content, create_file_fingerprint
from ..core.signals import get_signal, CommonSignals


@dataclass
class DetectionPattern:
    """Detection pattern definition."""
    
    id: str
    module: str
    name: str
    pattern: str
    score: float
    enabled: bool = True
    compiled_pattern: Optional[Pattern] = None
    
    def __post_init__(self):
        """Compile the pattern after initialization."""
        if self.enabled and self.pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                logging.getLogger(__name__).error(f"Invalid regex pattern: {self.pattern}")
                self.enabled = False
    
    def match(self, content: str) -> List[Dict[str, Any]]:
        """
        Find all matches of this pattern in content.
        
        Args:
            content: Content to search
            
        Returns:
            List of match information
        """
        if not self.enabled or not self.compiled_pattern:
            return []
        
        matches = []
        
        for match in self.compiled_pattern.finditer(content):
            matches.append({
                "pattern_id": self.id,
                "pattern_name": self.name,
                "match": match.group(0),
                "position": match.start(),
                "score": self.score
            })
        
        return matches


@dataclass
class DetectionResult:
    """Result of a detection scan."""
    
    is_suspicious: bool = False
    score: float = 0.0
    threshold: float = 0.7
    module: str = ""
    matches: List[Dict[str, Any]] = field(default_factory=list)
    patterns_checked: int = 0
    patterns_matched: int = 0
    scan_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_suspicious": self.is_suspicious,
            "score": self.score,
            "threshold": self.threshold,
            "module": self.module,
            "matches": self.matches,
            "patterns_checked": self.patterns_checked,
            "patterns_matched": self.patterns_matched,
            "scan_time": self.scan_time
        }


class DetectionEngine:
    """
    Core detection engine that orchestrates all detection modules.
    """
    
    def __init__(
        self,
        storage=None,
        config=None,
        analysis=None,
        intelligence=None,
        logger: Optional[logging.Logger] = None,
        enabled_modules: Optional[List[str]] = None,
        thresholds: Optional[Dict[str, float]] = None
    ):
        """
        Initialize the detection engine.
        
        Args:
            storage: Storage manager
            config: Configuration manager
            analysis: Analysis manager
            intelligence: Intelligence manager
            logger: Logger instance
            enabled_modules: List of enabled detection modules
            thresholds: Detection thresholds by module
        """
        self.storage = storage
        self.config = config
        self.analysis = analysis
        self.intelligence = intelligence
        self.logger = logger or logging.getLogger(__name__)
        
       
        self.enabled_modules = enabled_modules or DetectionModules.all()
        self.logger.debug(f"Enabled detection modules: {', '.join(self.enabled_modules)}")
        
        
        self.thresholds = thresholds or {}
        for module in DetectionModules.all():
            if module not in self.thresholds:
                self.thresholds[module] = 0.7
        
        
        self._patterns: Dict[str, List[DetectionPattern]] = {}
        self._patterns_lock = threading.RLock()
        self._patterns_loaded = False
        
        
        self.detection_signal = get_signal(CommonSignals.DETECTION_FOUND)
        self.feedback_signal = get_signal(CommonSignals.LEARNING_FEEDBACK)
    
    def _load_patterns(self, module: Optional[str] = None) -> None:
        """
        Load detection patterns from storage.
        
        Args:
            module: Specific module to load patterns for
        """
        with self._patterns_lock:
           
            if not self.storage:
                self._load_default_patterns(module)
                return
            
            
            try:
                modules_to_load = [module] if module else self.enabled_modules
                
                for m in modules_to_load:
                    patterns = self.storage.get_patterns(m, enabled_only=True)
                    self._patterns[m] = [
                        DetectionPattern(
                            id=p["id"],
                            module=p["module"],
                            name=p["name"],
                            pattern=p["pattern"],
                            score=p["score"],
                            enabled=bool(p["enabled"])
                        )
                        for p in patterns
                    ]
                
                
                for m in modules_to_load:
                    if m not in self._patterns or not self._patterns[m]:
                        self._load_default_patterns(m)
                
                self._patterns_loaded = True
                
            except Exception as e:
                self.logger.error(f"Failed to load patterns: {e}")
                self._load_default_patterns(module)
    
    def _load_default_patterns(self, module: Optional[str] = None) -> None:
        """
        Load default detection patterns.
        
        Args:
            module: Specific module to load patterns for
        """
        default_patterns = self._get_default_patterns()
        
        if module:
            self._patterns[module] = default_patterns.get(module, [])
        else:
            self._patterns = default_patterns
    
    def _get_default_patterns(self) -> Dict[str, List[DetectionPattern]]:
        """
        Get default detection patterns.
        
        Returns:
            Dictionary of default patterns by module
        """
        
        patterns: Dict[str, List[DetectionPattern]] = {}
        
    
        patterns[DetectionModules.AUTOMATION.value] = [
            DetectionPattern(id="auto1", module=DetectionModules.AUTOMATION.value, name="Telegram Bot", 
                            pattern=r'(TelegramBot|pyTelegramBotAPI|python-telegram-bot|TelegramClient)', score=0.6),
            DetectionPattern(id="auto2", module=DetectionModules.AUTOMATION.value, name="Discord Bot", 
                            pattern=r'(discord\.py|discord\.js|DiscordClient|Client\s*\(\s*intents\s*\)|bot\.run\s*\(\s*token\s*\))', score=0.6),
            DetectionPattern(id="auto3", module=DetectionModules.AUTOMATION.value, name="WhatsApp Bot", 
                            pattern=r'(whatsapp-web\.js|Twilio|WhatsApp\s+API)', score=0.6),
            DetectionPattern(id="auto4", module=DetectionModules.AUTOMATION.value, name="Twitter Bot", 
                            pattern=r'(tweepy|TwitterClient|Twitter\s+API)', score=0.6),
            DetectionPattern(id="auto5", module=DetectionModules.AUTOMATION.value, name="Reddit Bot", 
                            pattern=r'(PRAW|RedditAPI|Reddit\s+API)', score=0.6),
            DetectionPattern(id="auto6", module=DetectionModules.AUTOMATION.value, name="Facebook Bot", 
                            pattern=r'(facebook-sdk|Selenium.*Facebook)', score=0.6),
            DetectionPattern(id="auto7", module=DetectionModules.AUTOMATION.value, name="Instagram Bot", 
                            pattern=r'(instapy|instaloader|Instagram\s+API)', score=0.6),
            DetectionPattern(id="auto8", module=DetectionModules.AUTOMATION.value, name="Slack Bot", 
                            pattern=r'(slack-sdk|SlackClient)', score=0.6),
            DetectionPattern(id="auto9", module=DetectionModules.AUTOMATION.value, name="Automated Browser", 
                            pattern=r'(Selenium|Puppeteer|Playwright|WebDriver)', score=0.5),
            DetectionPattern(id="auto10", module=DetectionModules.AUTOMATION.value, name="Bot Framework", 
                            pattern=r'(botkit|botpress|botbuilder)', score=0.6),
        ]
        
       
        patterns[DetectionModules.NETWORK.value] = [
            DetectionPattern(id="net1", module=DetectionModules.NETWORK.value, name="Port Scanning", 
                            pattern=r'(nmap|socket\s*\(\s*\)|range\s*\(\s*\d+\s*,\s*\d+\s*\).*\.connect\s*\(|for.*in.*range.*\d+.*\d+.*socket\.connect)', score=0.7),
            DetectionPattern(id="net2", module=DetectionModules.NETWORK.value, name="IP Enumeration", 
                            pattern=r'(subnet\s+scan|for\s+ip\s+in\s+network|ipaddress\.ip_network)', score=0.7),
            DetectionPattern(id="net3", module=DetectionModules.NETWORK.value, name="Request Flooding", 
                            pattern=r'(while\s+True.*requests\.get|for\s+i\s+in\s+range\s*\(\s*\d{3,}\s*\).*requests)', score=0.8),
            DetectionPattern(id="net4", module=DetectionModules.NETWORK.value, name="DDoS Tools", 
                            pattern=r'(LOIC|Slowloris|hping|xerxes)', score=0.9),
            DetectionPattern(id="net5", module=DetectionModules.NETWORK.value, name="Packet Manipulation", 
                            pattern=r'(scapy|raw\s+socket|struct\.pack)', score=0.7),
            DetectionPattern(id="net6", module=DetectionModules.NETWORK.value, name="Network Stress", 
                            pattern=r'(stress\s+test|benchmark\s+network|flood\s+packets)', score=0.7),
            DetectionPattern(id="net7", module=DetectionModules.NETWORK.value, name="DNS Amplification", 
                            pattern=r'(DNS\s+amplification|amplification\s+attack)', score=0.8),
            DetectionPattern(id="net8", module=DetectionModules.NETWORK.value, name="TCP/UDP Flood", 
                            pattern=r'(TCP\s+flood|UDP\s+flood|SYN\s+flood)', score=0.8),
            DetectionPattern(id="net9", module=DetectionModules.NETWORK.value, name="Proxy/VPN Exit", 
                            pattern=r'(proxy\s+server|VPN\s+provider|exit\s+node)', score=0.6),
            DetectionPattern(id="net10", module=DetectionModules.NETWORK.value, name="Connection Spoofing", 
                            pattern=r'(spoofing|spoof\s+connection|spoof\s+ip)', score=0.7),
        ]
        
        
        patterns[DetectionModules.RESOURCE.value] = [
            DetectionPattern(id="res1", module=DetectionModules.RESOURCE.value, name="Crypto Miner", 
                            pattern=r'(miner|mining|coin\s*hive|monero|stratum\+tcp|cryptonight)', score=0.8),
            DetectionPattern(id="res2", module=DetectionModules.RESOURCE.value, name="CPU/RAM Exhaustion", 
                            pattern=r'(while\s+True.*alloc|fork\s+bomb|:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*\&\s*\}|\[\s*\]\s*\{\s*\}\s*\(\s*\))', score=0.9),
            DetectionPattern(id="res3", module=DetectionModules.RESOURCE.value, name="Disk Space Filler", 
                            pattern=r'(while\s+True.*write\s*\(|dd\s+if=/dev/zero|fallocate\s+-l)', score=0.8),
            DetectionPattern(id="res4", module=DetectionModules.RESOURCE.value, name="Process Spawning", 
                            pattern=r'(while\s+True.*exec|os\.fork\s*\(\s*\)|Process\s*\(\s*\))', score=0.7),
            DetectionPattern(id="res5", module=DetectionModules.RESOURCE.value, name="Kernel Exploit", 
                            pattern=r'(kernel\s+exploit|privilege\s+escalation|CVE-\d)', score=0.8),
            DetectionPattern(id="res6", module=DetectionModules.RESOURCE.value, name="I/O Saturation", 
                            pattern=r'(I/O\s+saturation|disk\s+stress|fio)', score=0.7),
            DetectionPattern(id="res7", module=DetectionModules.RESOURCE.value, name="Background Service", 
                            pattern=r'(while\s+True.*sleep|daemon|nohup)', score=0.6),
            DetectionPattern(id="res8", module=DetectionModules.RESOURCE.value, name="Scheduling Abuse", 
                            pattern=r'(cron\s+job|at\s+command|schedule\s+task)', score=0.6),
            DetectionPattern(id="res9", module=DetectionModules.RESOURCE.value, name="Container Escape", 
                            pattern=r'(container\s+escape|docker\s+socket|mount\s+/proc)', score=0.8),
            DetectionPattern(id="res10", module=DetectionModules.RESOURCE.value, name="Filesystem Abuse", 
                            pattern=r'(while\s+True.*open\s*\(|for\s+i\s+in\s+range\s*\(\s*\d{3,}\s*\).*open)', score=0.7),
        ]
        
        
        patterns[DetectionModules.SPAM.value] = [
            DetectionPattern(id="spam1", module=DetectionModules.SPAM.value, name="Email Mass Sender", 
                            pattern=r'(mass\s+email|send_mail\s*\(\s*\)|smtplib|while.*send\s*\()', score=0.7),
            DetectionPattern(id="spam2", module=DetectionModules.SPAM.value, name="SMTP Libraries", 
                            pattern=r'(smtplib\.SMTP|nodemailer|PHPMailer)', score=0.5),
            DetectionPattern(id="spam3", module=DetectionModules.SPAM.value, name="SMS Bombardment", 
                            pattern=r'(SMS\s+bomb|text\s+message\s+flood|Twilio\.send)', score=0.7),
            DetectionPattern(id="spam4", module=DetectionModules.SPAM.value, name="Contact Form", 
                            pattern=r'(contact\s+form\s+submission|for.*in.*range.*POST.*contact)', score=0.6),
            DetectionPattern(id="spam5", module=DetectionModules.SPAM.value, name="Comment Spam", 
                            pattern=r'(comment\s+bot|review\s+generator|lorem\s+ipsum)', score=0.6),
            DetectionPattern(id="spam6", module=DetectionModules.SPAM.value, name="Forum Flooding", 
                            pattern=r'(forum\s+flood|message\s+board\s+spam)', score=0.7),
            DetectionPattern(id="spam7", module=DetectionModules.SPAM.value, name="Advertisement Injector", 
                            pattern=r'(ad\s+injector|advertisement\s+insertion)', score=0.7),
            DetectionPattern(id="spam8", module=DetectionModules.SPAM.value, name="Social Media Mass", 
                            pattern=r'(mass\s+message|bulk\s+messaging)', score=0.7),
            DetectionPattern(id="spam9", module=DetectionModules.SPAM.value, name="Direct Message Spam", 
                            pattern=r'(DM\s+spam|message\s+all\s+users)', score=0.7),
            DetectionPattern(id="spam10", module=DetectionModules.SPAM.value, name="API Abuse", 
                            pattern=r'(while\s+True.*api\.send|for\s+i\s+in\s+range\s*\(\s*\d{3,}\s*\).*api)', score=0.7),
        ]
        
       
        patterns[DetectionModules.DATA_HARVESTING.value] = [
            DetectionPattern(id="data1", module=DetectionModules.DATA_HARVESTING.value, name="Web Scraper", 
                            pattern=r'(BeautifulSoup|cheerio|scrapy|selenium.*scrape)', score=0.6),
            DetectionPattern(id="data2", module=DetectionModules.DATA_HARVESTING.value, name="Personal Info", 
                            pattern=r'(email\s+extraction|phone\s+number\s+collection|address\s+harvesting)', score=0.7),
            DetectionPattern(id="data3", module=DetectionModules.DATA_HARVESTING.value, name="Cookie Stealing", 
                            pattern=r'(document\.cookie|steal\s+cookie|session\s+hijacking)', score=0.8),
            DetectionPattern(id="data4", module=DetectionModules.DATA_HARVESTING.value, name="Credential Harvesting", 
                            pattern=r'(password\s+grabber|credential\s+harvester|phishing)', score=0.8),
            DetectionPattern(id="data5", module=DetectionModules.DATA_HARVESTING.value, name="Database Dumping", 
                            pattern=r'(database\s+dump|SELECT.*FROM.*WHERE|db\.query\s*\(\s*SELECT)', score=0.7),
            DetectionPattern(id="data6", module=DetectionModules.DATA_HARVESTING.value, name="User Data", 
                            pattern=r'(user\s+data\s+extraction|profile\s+scraper)', score=0.7),
            DetectionPattern(id="data7", module=DetectionModules.DATA_HARVESTING.value, name="Session Hijacking", 
                            pattern=r'(session\s+hijacking|cookie\s+theft)', score=0.8),
            DetectionPattern(id="data8", module=DetectionModules.DATA_HARVESTING.value, name="Auth Bypass", 
                            pattern=r'(authentication\s+bypass|login\s+bypass)', score=0.8),
            DetectionPattern(id="data9", module=DetectionModules.DATA_HARVESTING.value, name="Password Cracking", 
                            pattern=r'(password\s+cracking|brute\s+force|dictionary\s+attack)', score=0.8),
            DetectionPattern(id="data10", module=DetectionModules.DATA_HARVESTING.value, name="Sensitive File", 
                            pattern=r'(/etc/passwd|\.env|config\.php|database\.yml)', score=0.7),
        ]
        
        
        patterns[DetectionModules.GAME_SERVER.value] = [
            DetectionPattern(id="game1", module=DetectionModules.GAME_SERVER.value, name="Server Crasher", 
                            pattern=r'(server\s+crash|DoS\s+attack|memory\s+corruption)', score=0.8),
            DetectionPattern(id="game2", module=DetectionModules.GAME_SERVER.value, name="Resource Exploitation", 
                            pattern=r'(resource\s+exploit|CPU\s+spike|memory\s+leak)', score=0.7),
            DetectionPattern(id="game3", module=DetectionModules.GAME_SERVER.value, name="Container/VM Escape", 
                            pattern=r'(container\s+escape|vm\s+escape|namespace\s+escalation)', score=0.8),
            DetectionPattern(id="game4", module=DetectionModules.GAME_SERVER.value, name="Neighbor Targeting", 
                            pattern=r'(adjacent\s+server|neighbor\s+targeting)', score=0.7),
            DetectionPattern(id="game5", module=DetectionModules.GAME_SERVER.value, name="Network Flood", 
                            pattern=r'(network\s+flood|packet\s+storm)', score=0.7),
            DetectionPattern(id="game6", module=DetectionModules.GAME_SERVER.value, name="Malicious Plugin", 
                            pattern=r'(malicious\s+plugin|backdoor\s+plugin)', score=0.8),
            DetectionPattern(id="game7", module=DetectionModules.GAME_SERVER.value, name="Lateral Movement", 
                            pattern=r'(lateral\s+movement|pivot\s+to|network\s+scanning)', score=0.8),
            DetectionPattern(id="game8", module=DetectionModules.GAME_SERVER.value, name="Backdoor Installation", 
                            pattern=r'(backdoor\s+installation|persistent\s+access)', score=0.8),
        ]
        
        
        patterns[DetectionModules.WEB_SERVER.value] = [
            DetectionPattern(id="web1", module=DetectionModules.WEB_SERVER.value, name="SQL Injection", 
                            pattern=r'(\'.*OR.*--|\';.*--|UNION.*SELECT|SELECT.*FROM.*WHERE)', score=0.8),
            DetectionPattern(id="web2", module=DetectionModules.WEB_SERVER.value, name="XSS Payload", 
                            pattern=r'(<script>|javascript:|onload=|onerror=|onclick=)', score=0.7),
            DetectionPattern(id="web3", module=DetectionModules.WEB_SERVER.value, name="CSRF Exploit", 
                            pattern=r'(csrf\s+token|cross\s+site\s+request\s+forgery)', score=0.7),
            DetectionPattern(id="web4", module=DetectionModules.WEB_SERVER.value, name="File Inclusion", 
                            pattern=r'(include\s*\(\s*\$_GET|require\s*\(\s*\$_POST|../../../)', score=0.8),
            DetectionPattern(id="web5", module=DetectionModules.WEB_SERVER.value, name="Remote Code Execution", 
                            pattern=r'(eval\s*\(\s*\$_|exec\s*\(\s*\$_|system\s*\(\s*\$_)', score=0.9),
            DetectionPattern(id="web6", module=DetectionModules.WEB_SERVER.value, name="Web Shell", 
                            pattern=r'(web\s+shell|backdoor\s+shell|c99shell|r57shell)', score=0.9),
            DetectionPattern(id="web7", module=DetectionModules.WEB_SERVER.value, name="CMS Exploit", 
                            pattern=r'(WordPress\s+exploit|Drupal\s+CVE|Joomla\s+vulnerability)', score=0.7),
            DetectionPattern(id="web8", module=DetectionModules.WEB_SERVER.value, name="API Abuse", 
                            pattern=r'(API\s+abuse|API\s+rate\s+limit)', score=0.6),
            DetectionPattern(id="web9", module=DetectionModules.WEB_SERVER.value, name="Session Manipulation", 
                            pattern=r'(session\s+manipulation|session\s+fixation)', score=0.7),
            DetectionPattern(id="web10", module=DetectionModules.WEB_SERVER.value, name="Auth Brute Force", 
                            pattern=r'(login\s+brute\s+force|password\s+cracking)', score=0.7),
        ]
        
       
        patterns[DetectionModules.INFRASTRUCTURE.value] = [
            DetectionPattern(id="infra1", module=DetectionModules.INFRASTRUCTURE.value, name="Container Escape", 
                            pattern=r'(container\s+escape|docker\s+socket|docker\.sock)', score=0.9),
            DetectionPattern(id="infra2", module=DetectionModules.INFRASTRUCTURE.value, name="VM Breakout", 
                            pattern=r'(VM\s+breakout|hypervisor\s+escape)', score=0.9),
            DetectionPattern(id="infra3", module=DetectionModules.INFRASTRUCTURE.value, name="Privilege Escalation", 
                            pattern=r'(privilege\s+escalation|sudo|setuid)', score=0.8),
            DetectionPattern(id="infra4", module=DetectionModules.INFRASTRUCTURE.value, name="Docker Socket", 
                            pattern=r'(docker\.sock|/var/run/docker\.sock)', score=0.8),
            DetectionPattern(id="infra5", module=DetectionModules.INFRASTRUCTURE.value, name="Kubernetes API", 
                            pattern=r'(kubernetes\s+API|k8s\s+API|kube-apiserver)', score=0.8),
            DetectionPattern(id="infra6", module=DetectionModules.INFRASTRUCTURE.value, name="Service Discovery", 
                            pattern=r'(service\s+discovery\s+abuse|etcd\s+discovery)', score=0.7),
            DetectionPattern(id="infra7", module=DetectionModules.INFRASTRUCTURE.value, name="Cloud Credential", 
                            pattern=r'(AWS\s+key|Azure\s+credential|GCP\s+credential)', score=0.8),
            DetectionPattern(id="infra8", module=DetectionModules.INFRASTRUCTURE.value, name="Infra Scanning", 
                            pattern=r'(infrastructure\s+scan|network\s+discovery)', score=0.7),
            DetectionPattern(id="infra9", module=DetectionModules.INFRASTRUCTURE.value, name="Config Exposure", 
                            pattern=r'(config\s+exposure|terraform\s+state|kubeconfig)', score=0.7),
            DetectionPattern(id="infra10", module=DetectionModules.INFRASTRUCTURE.value, name="Internal Pivot", 
                            pattern=r'(internal\s+pivot|lateral\s+movement)', score=0.8),
        ]
        
       
        patterns[DetectionModules.SECURITY.value] = [
            DetectionPattern(id="sec1", module=DetectionModules.SECURITY.value, name="Malware Signature", 
                            pattern=r'(malware\s+signature|virus\s+pattern|trojan\s+horse)', score=0.8),
            DetectionPattern(id="sec2", module=DetectionModules.SECURITY.value, name="Reverse Shell", 
                            pattern=r'(reverse\s+shell|bash\s+-i|nc\s+-e|python\s+-c\s+.*socket)', score=0.9),
            DetectionPattern(id="sec3", module=DetectionModules.SECURITY.value, name="Command & Control", 
                            pattern=r'(command\s+and\s+control|C2\s+server|beacon)', score=0.8),
            DetectionPattern(id="sec4", module=DetectionModules.SECURITY.value, name="Data Exfiltration", 
                            pattern=r'(data\s+exfiltration|data\s+theft|information\s+stealing)', score=0.8),
            DetectionPattern(id="sec5", module=DetectionModules.SECURITY.value, name="Encoded/Obfuscated", 
                            pattern=r'(base64_decode|rot13|chr\s*\(\s*\d+\s*\)|String\.fromCharCode)', score=0.7),
            DetectionPattern(id="sec6", module=DetectionModules.SECURITY.value, name="Script Kiddie", 
                            pattern=r'(script\s+kiddie|metasploit|exploit\s+framework)', score=0.7),
            DetectionPattern(id="sec7", module=DetectionModules.SECURITY.value, name="Cross-Container", 
                            pattern=r'(cross-container\s+communication|container\s+to\s+container)', score=0.8),
            DetectionPattern(id="sec8", module=DetectionModules.SECURITY.value, name="Suspicious Curl", 
                            pattern=r'(curl\s+.*\|\s*bash|wget\s+.*\|\s*sh)', score=0.8),
            DetectionPattern(id="sec9", module=DetectionModules.SECURITY.value, name="Outbound Connection", 
                            pattern=r'(outbound\s+connection|connect\s+to\s+external)', score=0.7),
            DetectionPattern(id="sec10", module=DetectionModules.SECURITY.value, name="Encrypted Payload", 
                            pattern=r'(encrypted\s+payload|obfuscated\s+code)', score=0.7),
        ]
        
        
        patterns[DetectionModules.OBFUSCATION.value] = [
            DetectionPattern(id="obf1", module=DetectionModules.OBFUSCATION.value, name="Base64 Encoded", 
                            pattern=r'(base64_decode\s*\(|atob\s*\(|\s*=[A-Za-z0-9+/]{20,}=*\s*;)', score=0.7),
            DetectionPattern(id="obf2", module=DetectionModules.OBFUSCATION.value, name="Hex Encoded", 
                            pattern=r'(\\x[0-9a-f]{2}|0x[0-9a-f]{2}|\$\\x)', score=0.6),
            DetectionPattern(id="obf3", module=DetectionModules.OBFUSCATION.value, name="JS Obfuscation", 
                            pattern=r'(_0x[a-f0-9]{4}|[a-zA-Z0-9]{30,}|String\.fromCharCode)', score=0.7),
            DetectionPattern(id="obf4", module=DetectionModules.OBFUSCATION.value, name="Python Obfuscator", 
                            pattern=r'(PyArmor|PyMinifier)', score=0.6),
            DetectionPattern(id="obf5", module=DetectionModules.OBFUSCATION.value, name="Char Code", 
                            pattern=r'(chr\s*\(\s*\d+\s*\)|String\.fromCharCode\s*\(\s*\d+\s*\))', score=0.7),
            DetectionPattern(id="obf6", module=DetectionModules.OBFUSCATION.value, name="Unicode Escape", 
                            pattern=r'(\\u[0-9a-f]{4}|&#x[0-9a-f]{2,4};)', score=0.6),
            DetectionPattern(id="obf7", module=DetectionModules.OBFUSCATION.value, name="String Concatenation", 
                            pattern=r'("[^"]{1,2}"\s*\+\s*"[^"]{1,2}"\s*\+|\'[^\']{1,2}\'\s*\+\s*\'[^\']{1,2}\'\s*\+)', score=0.6),
            DetectionPattern(id="obf8", module=DetectionModules.OBFUSCATION.value, name="Control Flow", 
                            pattern=r'(eval\s*\(\s*function\s*\([^)]*\)\s*\{|setTimeout\s*\(\s*function\s*\(\s*\)\s*\{)', score=0.7),
            DetectionPattern(id="obf9", module=DetectionModules.OBFUSCATION.value, name="Packer Tools", 
                            pattern=r'(eval\s*\(\s*function\s*\(p,a,c,k,e,d\)|_1598142966)', score=0.8),
            DetectionPattern(id="obf10", module=DetectionModules.OBFUSCATION.value, name="Multi-Layer", 
                            pattern=r'(base64_decode\s*\(\s*gzinflate\s*\(|atob\s*\(\s*unescape\s*\()', score=0.8),
            DetectionPattern(id="obf11", module=DetectionModules.OBFUSCATION.value, name="Steganography", 
                            pattern=r'(\$\w+\s*=\s*\$\w+\[[\'"]data[\'"]\]\[[\'"]image[\'"])', score=0.7),
            DetectionPattern(id="obf12", module=DetectionModules.OBFUSCATION.value, name="Variable Substitution", 
                            pattern=r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=.*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\()', score=0.6),
            DetectionPattern(id="obf13", module=DetectionModules.OBFUSCATION.value, name="Uncommon Encoding", 
                            pattern=r'(str_rot13|convert_uudecode)', score=0.7),
            DetectionPattern(id="obf14", module=DetectionModules.OBFUSCATION.value, name="Logic Obfuscation", 
                            pattern=r'(\(\~[0-9]+\)|\!\+\[\]|\+\!\+\[\])', score=0.7),
            DetectionPattern(id="obf15", module=DetectionModules.OBFUSCATION.value, name="Binary Data", 
                            pattern=r'(\\x[0-9a-f]{2}\\x[0-9a-f]{2}|0x[0-9a-f]{2},0x[0-9a-f]{2})', score=0.7),
            DetectionPattern(id="obf16", module=DetectionModules.OBFUSCATION.value, name="Array Indexes", 
                            pattern=r'(\[\d+\]\[\d+\]\[\d+\]|\[[\'"]\\x[0-9a-f]{2}[\'"]\])', score=0.6),
            DetectionPattern(id="obf17", module=DetectionModules.OBFUSCATION.value, name="Function Scrambling", 
                            pattern=r'(function\s*\w+\s*\(\)\s*\{\s*return\s*([\'"]).*\2\.split\s*\()', score=0.7),
            DetectionPattern(id="obf18", module=DetectionModules.OBFUSCATION.value, name="Dead Code", 
                            pattern=r'(if\s*\(\s*false\s*\)\s*\{.*\}|if\s*\(\s*0\s*\)\s*\{.*\})', score=0.6),
            DetectionPattern(id="obf19", module=DetectionModules.OBFUSCATION.value, name="Self-Modifying", 
                            pattern=r'(function\s*\(\s*\)\s*\{\s*[^{]*=\s*arguments\.callee\.toString\s*\(\s*\))', score=0.8),
            DetectionPattern(id="obf20", module=DetectionModules.OBFUSCATION.value, name="Comment Embedded", 
                            pattern=r'(\/\*[^\*]*\*\/\s*\)|\*\/\s*\))', score=0.6),
        ]
        
        return patterns
    
    def detect(
        self,
        content: str,
        module: str,
        file_type: str = "text",
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect pattern matches in content.
        
        Args:
            content: Content to analyze
            module: Detection module to use
            file_type: Type of file/content
            context: Additional context for detection
            
        Returns:
            Detection result
        
        Raises:
            DetectionError: If detection fails
        """
        if module not in self.enabled_modules:
            raise DetectionError(f"Module {module} is not enabled")
        
      
        if not self._patterns_loaded or module not in self._patterns:
            self._load_patterns(module)
        
        
        threshold = self.thresholds.get(module, 0.7)
        
       
        result = DetectionResult(module=module, threshold=threshold)
        
        start_time = time.time()
        
        try:
            
            patterns = self._patterns.get(module, [])
            result.patterns_checked = len(patterns)
            
            
            all_matches = []
            for pattern in patterns:
                if not pattern.enabled:
                    continue
                
                matches = pattern.match(content)
                if matches:
                    all_matches.extend(matches)
            
            
            all_matches.sort(key=lambda m: m["position"])
            
            
            result.matches = all_matches
            result.patterns_matched = len(set(m["pattern_id"] for m in all_matches))
            
            
            max_score = 0.0
            for match in all_matches:
                max_score = max(max_score, match["score"])
            
            
            if result.patterns_matched > 1:
                max_score = min(max_score * 1.2, 1.0)
            
            result.score = max_score
            result.is_suspicious = max_score >= threshold
            
            
            if self.analysis and result.is_suspicious:
                if hasattr(self.analysis, "analyze"):
                    self.analysis.analyze(result, content, file_type, context)
            
            
            if self.intelligence and result.is_suspicious:
                if hasattr(self.intelligence, "process"):
                    self.intelligence.process(result, content, file_type, context)
            
            
            result.scan_time = time.time() - start_time
            
            
            if result.is_suspicious and self.detection_signal:
                self.detection_signal.send(
                    sender=self,
                    module=module,
                    result=result.to_dict(),
                    content_hash=hash_content(content),
                    file_type=file_type,
                    context=context
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Detection error in module {module}: {e}")
            raise DetectionError(f"Detection failed in module {module}: {e}")
    
    def detect_all(
        self,
        content: str,
        file_type: str = "text",
        modules: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, DetectionResult]:
        """
        Run all detection modules on content.
        
        Args:
            content: Content to analyze
            file_type: Type of file/content
            modules: List of modules to use (defaults to all enabled modules)
            context: Additional context for detection
            
        Returns:
            Dictionary of module names to detection results
        """
        
        modules_to_use = modules or self.enabled_modules
        modules_to_use = [m for m in modules_to_use if m in self.enabled_modules]
        
        
        results = {}
        for module in modules_to_use:
            try:
                results[module] = self.detect(content, module, file_type, context)
            except Exception as e:
                self.logger.error(f"Error in detect_all for module {module}: {e}")
                results[module] = DetectionResult(module=module, threshold=self.thresholds.get(module, 0.7))
        
        return results
    
    def check_suspicious(
        self,
        content: str,
        file_type: str = "text",
        modules: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        analysis_level: str = AnalysisLevel.STANDARD.value
    ) -> Dict[str, Any]:
        """
        Check if content is suspicious.
        
        Args:
            content: Content to analyze
            file_type: Type of file/content
            modules: List of modules to use (defaults to all enabled modules)
            context: Additional context for detection
            analysis_level: Level of analysis to perform
            
        Returns:
            Dictionary with results
        """
        
        results = self.detect_all(content, file_type, modules, context)
        
        
        suspicious_modules = []
        max_score = 0.0
        all_matches = []
        
        for module, result in results.items():
            if result.is_suspicious:
                suspicious_modules.append(module)
                max_score = max(max_score, result.score)
                all_matches.extend(result.matches)
        
        
        all_matches.sort(key=lambda m: (m["score"], m["position"]), reverse=True)
        
        
        if len(all_matches) > 10:
            all_matches = all_matches[:10]
        
        
        fingerprint = create_file_fingerprint(content)
        
        return {
            "is_suspicious": len(suspicious_modules) > 0,
            "suspicious_score": max_score,
            "suspicious_modules": suspicious_modules,
            "top_matches": all_matches,
            "fingerprint": fingerprint,
            "modules_checked": len(results),
            "analysis_level": analysis_level
        }
    
    def process_feedback(
        self,
        module: str,
        detection_id: Optional[str] = None,
        pattern_id: Optional[str] = None,
        false_positive: bool = False,
        notes: Optional[str] = None
    ) -> bool:
        """
        Process feedback for a detection.
        
        Args:
            module: Detection module
            detection_id: Detection ID (optional)
            pattern_id: Pattern ID (optional)
            false_positive: Whether the detection is a false positive
            notes: Feedback notes (optional)
            
        Returns:
            True if feedback was processed, False otherwise
        """
        
        if self.storage:
            try:
                feedback_id = self.storage.add_learning_feedback(
                    module=module,
                    detection_id=detection_id,
                    pattern_id=pattern_id,
                    false_positive=false_positive,
                    notes=notes
                )
                
                if not feedback_id:
                    self.logger.error("Failed to store feedback")
                    return False
                
            except Exception as e:
                self.logger.error(f"Error storing feedback: {e}")
                return False
        
        
        if self.intelligence and hasattr(self.intelligence, "process_feedback"):
            try:
                self.intelligence.process_feedback(
                    module=module,
                    detection_id=detection_id,
                    pattern_id=pattern_id,
                    false_positive=false_positive,
                    notes=notes
                )
            except Exception as e:
                self.logger.error(f"Error processing feedback in intelligence: {e}")
        
        
        if self.feedback_signal:
            self.feedback_signal.send(
                sender=self,
                module=module,
                detection_id=detection_id,
                pattern_id=pattern_id,
                false_positive=false_positive,
                notes=notes
            )
        
        return True
    
    def add_custom_pattern(
        self,
        module: str,
        name: str,
        pattern: str,
        score: float = 0.7
    ) -> Optional[str]:
        """
        Add a custom detection pattern.
        
        Args:
            module: Detection module
            name: Pattern name
            pattern: Regex pattern
            score: Pattern score (0.0 to 1.0)
            
        Returns:
            Pattern ID if successful, None otherwise
        """
        if module not in DetectionModules.all():
            raise DetectionError(f"Invalid module: {module}")
        
        try:
            
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            raise DetectionError(f"Invalid regex pattern: {e}")
        
        
        pattern_id = None
        if self.storage:
            try:
                pattern_id = self.storage.add_pattern(
                    module=module,
                    name=name,
                    pattern=pattern,
                    score=score,
                    enabled=True
                )
            except Exception as e:
                self.logger.error(f"Error storing pattern: {e}")
        
        
        if not pattern_id:
            import uuid
            pattern_id = str(uuid.uuid4())
        
        
        with self._patterns_lock:
            if module not in self._patterns:
                self._patterns[module] = []
            
            self._patterns[module].append(
                DetectionPattern(
                    id=pattern_id,
                    module=module,
                    name=name,
                    pattern=pattern,
                    score=score,
                    enabled=True
                )
            )
        
        return pattern_id
