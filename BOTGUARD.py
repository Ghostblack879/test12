import time
import statistics
import hashlib
import re
import json
import ipaddress
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

# إعداد نظام التسجيل
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[

    logging.FileHandler("ddos_protection.log", encoding="utf-8"),  # تعيين التشفير إلى UTF-8
    logging.StreamHandler()
    ]
)
logger = logging.getLogger("DDoSProtectionBot")


class UserProfile:
    """
    فئة لتخزين ملف تعريف المستخدم وتحليل سلوكه
    """
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.user_agent = None
        self.geolocation = None
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.request_paths = []
        self.session_duration = []
        self.login_attempts = 0
        self.failed_login_attempts = 0
        self.suspicious_activities = []
        self.is_authenticated = False
        self.request_intervals = []
        self.cookies = {}
        self.threat_score = 0
        self.browser_fingerprint = None
        self.previous_requests = deque(maxlen=20)

    def update_profile(self, request_data, timestamp):
        """
        تحديث ملف تعريف المستخدم بناءً على طلب جديد
        """
        self.last_seen = timestamp
        # استخراج مسار الطلب إذا كان متاحًا
        path = self._extract_path_from_request(request_data)
        if path:
            self.request_paths.append(path)
        # تحديث فواصل الطلبات
        if self.previous_requests:
            last_request_time = self.previous_requests[-1][0]
            interval = timestamp - last_request_time
            self.request_intervals.append(interval)
        # إضافة الطلب الحالي إلى قائمة الطلبات السابقة
        self.previous_requests.append((timestamp, request_data))
        # تحديث User-Agent إذا كان موجودًا في الطلب
        if "User-Agent:" in request_data:
            self.user_agent = re.search(r"User-Agent: (.*?)(?:\r\n|\n|$)", request_data).group(1)
        # حساب البصمة الرقمية للمتصفح إذا كانت متاحة
        if self.user_agent:
            self.browser_fingerprint = self._compute_browser_fingerprint(request_data)
        # تحديث حالة تسجيل الدخول
        if "/login" in request_data.lower() or "/signin" in request_data.lower():
            if "POST" in request_data:
                self.login_attempts += 1
                if "error" in request_data.lower() or "invalid" in request_data.lower():
                    self.failed_login_attempts += 1
        # تحديث الكوكيز
        self._extract_cookies(request_data)
        # تحديث درجة التهديد
        self._calculate_threat_score()

    def _extract_path_from_request(self, request_data):
        """
        استخراج مسار الطلب من بيانات الطلب HTTP
        """
        match = re.search(r"(GET|POST|PUT|DELETE|HEAD) ([^ ]+)", request_data)
        if match:
            return match.group(2)
        return None

    def _compute_browser_fingerprint(self, request_data):
        """
        حساب بصمة المتصفح للتعرف على المستخدم
        """
        fingerprint_data = [
            self.user_agent or "",
            self._extract_accept_headers(request_data),
            self._extract_language(request_data),
            self._extract_screen_resolution(request_data)
        ]
        return hashlib.sha256("".join(fingerprint_data).encode()).hexdigest()

    def _extract_accept_headers(self, request_data):
        """
        استخراج رؤوس Accept من الطلب
        """
        headers = []
        for header_type in ["Accept:", "Accept-Language:", "Accept-Encoding:"]:
            match = re.search(f"{header_type} (.*?)(?:\r\n|\n|$)", request_data)
            if match:
                headers.append(match.group(1))
        return "".join(headers)

    def _extract_language(self, request_data):
        """
        استخراج لغة المتصفح
        """
        match = re.search(r"Accept-Language: (.*?)(?:\r\n|\n|$)", request_data)
        return match.group(1) if match else ""

    def _extract_screen_resolution(self, request_data):
        """
        استخراج دقة الشاشة إذا كانت متاحة في الطلب
        """
        # قد تكون متوفرة في معلمات URL أو ملفات تعريف الارتباط
        return ""

    def _extract_cookies(self, request_data):
        """
        استخراج ملفات تعريف الارتباط من الطلب
        """
        match = re.search(r"Cookie: (.*?)(?:\r\n|\n|$)", request_data)
        if match:
            cookie_str = match.group(1)
            cookie_pairs = cookie_str.split("; ")
            for pair in cookie_pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    self.cookies[key] = value

    def _calculate_threat_score(self):
        """
        حساب درجة التهديد لهذا المستخدم بناءً على سلوكه
        """
        score = 0
        # عوامل زيادة درجة التهديد
        if self.failed_login_attempts > 3:
            score += self.failed_login_attempts * 10
        if len(self.request_intervals) > 5:
            avg_interval = sum(self.request_intervals) / len(self.request_intervals)
            if avg_interval < 0.5:  # أقل من نصف ثانية
                score += 50
            elif avg_interval < 1:  # أقل من ثانية واحدة
                score += 20
        # تحقق من الطلبات المتكررة للمسار نفسه
        path_counter = defaultdict(int)
        for path in self.request_paths[-20:]:  # آخر 20 طلب فقط
            path_counter[path] += 1
        max_path_count = max(path_counter.values()) if path_counter else 0
        if max_path_count > 10:
            score += 30
        # تحقق من الوصول إلى مسارات حساسة
        sensitive_paths = [
            "/admin",
            "/wp-login",
            "/config",
            "/.env",
            "/phpMyAdmin"
        ]
        for path in self.request_paths:
            if any(sensitive in path for sensitive in sensitive_paths):
                score += 15
        # أنماط الاستعلام المشبوهة
        suspicious_patterns = [
            "union select",
            "exec(",
            "<script>",
            "../../../",
            "etc/passwd"
        ]
        for request in self.previous_requests:
            request_data = request[1]
            if any(pattern in request_data.lower() for pattern in suspicious_patterns):
                score += 25
        self.threat_score = score

    def get_summary(self):
        """
        الحصول على ملخص لملف تعريف المستخدم
        """
        return {
            "ip": self.ip_address,
            "user_agent": self.user_agent,
            "first_seen": datetime.fromtimestamp(self.first_seen).strftime('%Y-%m-%d %H:%M:%S'),
            "last_seen": datetime.fromtimestamp(self.last_seen).strftime('%Y-%m-%d %H:%M:%S'),
            "request_count": len(self.request_paths),
            "avg_request_interval": sum(self.request_intervals) / len(
                self.request_intervals) if self.request_intervals else None,
            "login_attempts": self.login_attempts,
            "failed_login_attempts": self.failed_login_attempts,
            "is_authenticated": self.is_authenticated,
            "threat_score": self.threat_score,
            "fingerprint": self.browser_fingerprint,
            "recent_paths": self.request_paths[-5:] if self.request_paths else []
        }


class GeoIPDatabase:
    """
    فئة وهمية لقاعدة بيانات الموقع الجغرافي للـ IP
    في التنفيذ الحقيقي، يمكنك استخدام مكتبة مثل MaxMind GeoIP
    """
    def lookup(self, ip_address):
        """
        البحث عن معلومات الموقع الجغرافي لعنوان IP
        """
        # هذا محاكاة - في الإنتاج، استخدم قاعدة بيانات GeoIP حقيقية
        return {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 0,
            "longitude": 0,
            "isp": "Unknown"
        }


class DDoSProtectionBot:
    def __init__(self, config=None):
        """
        تهيئة بوت الحماية من هجمات DDoS مع إعدادات إضافية
        :param config: قاموس التكوين للبوت
        """
        self.config = config or {
            "window_size": 60,  # حجم نافذة التحليل بالثواني
            "threshold_multiplier": 3,  # مُضاعف العتبة للكشف عن الشذوذ
            "rate_limit": 100,  # الحد الأقصى لعدد الطلبات المسموح بها لكل IP في الدقيقة
            "max_threat_score": 70,  # درجة التهديد القصوى قبل الحظر
            "block_duration": 3600,  # مدة الحظر بالثواني (ساعة واحدة)
            "whitelist": [],  # قائمة عناوين IP المسموح بها دائمًا
            "blacklist": [],  # قائمة عناوين IP المحظورة دائمًا
            "country_blacklist": [],  # قائمة البلدان المحظورة
            "log_level": "INFO",  # مستوى التسجيل
            "challenge_threshold": 40,  # العتبة لتقديم تحدي للمستخدم
            "auto_ban_enabled": True,  # تمكين الحظر التلقائي
            "proxy_detection": True,  # تمكين اكتشاف البروكسي/VPN
        }
        # قواميس وهياكل البيانات للتتبع
        self.ip_request_count = defaultdict(int)  # عدد الطلبات لكل IP
        self.ip_timestamps = defaultdict(list)  # طوابع زمنية للطلبات لكل IP
        self.blocked_ips = {}  # قاموس عناوين IP المحظورة مع وقت انتهاء الحظر
        self.traffic_history = deque(maxlen=100)  # سجل حركة المرور الإجمالية
        self.user_profiles = {}  # ملفات تعريف المستخدمين حسب IP
        self.session_store = {}  # مخزن الجلسات
        self.last_cleanup = time.time()  # وقت آخر تنظيف للبيانات
        self.geo_db = GeoIPDatabase()  # قاعدة بيانات الموقع الجغرافي
        self.challenge_sessions = {}  # مخزن تحديات CAPTCHA
        self.periodic_tasks_thread = None  # مؤشر مهمة دورية
        self.rules_engine = self._initialize_rules_engine()  # محرك القواعد
        # تعيين مستوى التسجيل
        logger.setLevel(getattr(logging, self.config["log_level"]))
        # بدء المهام الدورية
        self._start_periodic_tasks()

    def _initialize_rules_engine(self):
        """
        تهيئة محرك القواعد للكشف عن الهجمات
        """
        return [
            {
                "name": "rate_limiting",
                "description": "فحص تجاوز معدل الطلبات",
                "enabled": True,
                "threshold": self.config["rate_limit"],
                "action": "block",
                "priority": 1
            },
            {
                "name": "threat_score",
                "description": "فحص درجة التهديد",
                "enabled": True,
                "threshold": self.config["max_threat_score"],
                "action": "block",
                "priority": 2
            },
            {
                "name": "geographic_restriction",
                "description": "تقييد حسب الموقع الجغرافي",
                "enabled": len(self.config["country_blacklist"]) > 0,
                "countries": self.config["country_blacklist"],
                "action": "block",
                "priority": 3
            },
            {
                "name": "suspicious_patterns",
                "description": "فحص أنماط الطلبات المشبوهة",
                "enabled": True,
                "patterns": [
                    r"(?i)union\s+select",
                    r"(?i)exec\s*\(",
                    r"(?i)eval\s*\(",
                    r"(?i)document\.cookie",
                    r"(?:.*)etc/passwd",
                    r"(?:.*)wp-login",
                    r"(?:.*)\.\.\.\."
                ],
                "action": "block",
                "priority": 4
            },
            {
                "name": "brute_force_detection",
                "description": "اكتشاف محاولات اختراق القوة الغاشمة",
                "enabled": True,
                "threshold": 5,  # عدد محاولات تسجيل الدخول الفاشلة
                "action": "challenge",
                "priority": 5
            }
        ]

    def _start_periodic_tasks(self):
        """
        بدء المهام الدورية في خيط منفصل
        """
        self.periodic_tasks_thread = threading.Thread(target=self._run_periodic_tasks)
        self.periodic_tasks_thread.daemon = True
        self.periodic_tasks_thread.start()

    def _run_periodic_tasks(self):
        """
        تنفيذ المهام الدورية مثل تنظيف البيانات والتقارير
        """
        while True:
            try:
                current_time = time.time()
                # تنظيف البيانات القديمة
                self._cleanup_old_data(current_time)
                # تحديث إحصائيات وتقارير
                self._generate_traffic_report()
                # إزالة الحظر عن عناوين IP التي انتهت صلاحية حظرها
                self._cleanup_expired_blocks(current_time)
                # انتظار دقيقة واحدة قبل التشغيل التالي
                time.sleep(60)
            except Exception as e:
                logger.error(f"خطأ في المهام الدورية: {str(e)}")
                time.sleep(60)  # انتظر قبل المحاولة مرة أخرى

    def process_request(self, ip_address, request_data, timestamp=None):
        """
        معالجة طلب وارد وتحديد ما إذا كان يجب السماح به أو حظره
        :param ip_address: عنوان IP لمصدر الطلب
        :param request_data: بيانات الطلب (يمكن أن تكون نص HTTP أو بيانات الحزمة)
        :param timestamp: الطابع الزمني للطلب (إذا كان None، سيتم استخدام الوقت الحالي)
        :return: قاموس يحتوي على نتائج المعالجة وأي معلومات إضافية
        """
        if timestamp is None:
            timestamp = time.time()
        # تحقق من القائمة البيضاء أولاً
        if ip_address in self.config["whitelist"]:
            return {"allowed": True, "reason": "IP في القائمة البيضاء"}
        # تحقق من القائمة السوداء
        if ip_address in self.config["blacklist"]:
            return {"allowed": False, "reason": "IP في القائمة السوداء"}
        # تحقق من قائمة الحظر
        if ip_address in self.blocked_ips:
            block_expiry = self.blocked_ips[ip_address]
            if timestamp < block_expiry:
                remaining = int(block_expiry - timestamp)
                return {"allowed": False, "reason": "IP محظور", "remaining_seconds": remaining}
            else:
                # إزالة من قائمة الحظر إذا انتهت المدة
                del self.blocked_ips[ip_address]
        # تحديث ملف تعريف المستخدم أو إنشاؤه إذا لم يكن موجودًا
        if ip_address not in self.user_profiles:
            self.user_profiles[ip_address] = UserProfile(ip_address)
            # البحث عن معلومات الموقع الجغرافي (في خلفية منفصلة لتجنب التأخير)
            threading.Thread(target=self._enrich_user_profile, args=(ip_address,)).start()
        # تحديث ملف تعريف المستخدم
        self.user_profiles[ip_address].update_profile(request_data, timestamp)
        # تحديث إحصائيات الطلب
        self.ip_request_count[ip_address] += 1
        self.ip_timestamps[ip_address].append(timestamp)
        # تحديث سجل حركة المرور الإجمالية
        current_traffic = len(self.traffic_history)
        self.traffic_history.append(timestamp)
        # تطبيق آليات الكشف والحماية
        result = self._apply_protection_mechanisms(ip_address, request_data, timestamp, current_traffic)
        # تسجيل النتيجة
        if result["allowed"]:
            logger.debug(f"تم قبول الطلب من {ip_address}: {request_data[:50]}...")
        else:
            logger.warning(f"تم رفض الطلب من {ip_address}: {result['reason']}")
        return result

    def _enrich_user_profile(self, ip_address):
        """
        إثراء ملف تعريف المستخدم بمعلومات إضافية
        """
        try:
            if ip_address in self.user_profiles:
                profile = self.user_profiles[ip_address]
                # إضافة معلومات الموقع الجغرافي
                profile.geolocation = self.geo_db.lookup(ip_address)
                # تحقق من استخدام VPN/Proxy (تنفيذ وهمي)
                profile.is_proxy = self._check_if_proxy(ip_address)
                logger.debug(f"تم إثراء ملف تعريف المستخدم لـ {ip_address}")
        except Exception as e:
            logger.error(f"خطأ في إثراء ملف تعريف المستخدم لـ {ip_address}: {str(e)}")

    def _check_if_proxy(self, ip_address):
        """
        تحقق مما إذا كان عنوان IP من بروكسي أو VPN
        في التنفيذ الحقيقي، استخدم قاعدة بيانات خارجية أو API للتحقق
        """
        # تنفيذ وهمي - في الإنتاج، استخدم خدمة تحقق من البروكسي/VPN
        return False

    def _apply_protection_mechanisms(self, ip_address, request_data, timestamp, current_traffic):
        """
        تطبيق آليات الحماية المختلفة للكشف عن هجمات DDoS المحتملة والسلوك المشبوه
        :return: قاموس يحتوي على معلومات حول القرار والسبب
        """
        result = {"allowed": True, "reason": "مقبول", "actions": []}
        # التحقق من وجود رمز تحدي CAPTCHA في الطلب
        captcha_result = self._check_captcha_challenge(ip_address, request_data)
        if captcha_result is not None:
            return captcha_result
        # تطبيق قواعد الحماية من محرك القواعد
        for rule in sorted(self.rules_engine, key=lambda r: r["priority"]):
            if not rule["enabled"]:
                continue
            rule_result = self._apply_rule(rule, ip_address, request_data, timestamp)
            if rule_result and not rule_result["allowed"]:
                result["allowed"] = False
                result["reason"] = rule_result["reason"]
                result["actions"].extend(rule_result.get("actions", []))
                # تنفيذ الإجراء المرتبط بالقاعدة
                if rule["action"] == "block" and self.config["auto_ban_enabled"]:
                    self._block_ip(ip_address, reason=result["reason"])
                elif rule["action"] == "challenge":
                    self._issue_challenge(ip_address)
                    result["challenge"] = True
                # إرجاع النتيجة مبكرًا إذا كانت القاعدة ذات أولوية عالية
                if rule["priority"] <= 2:
                    return result
        # الكشف عن الشذوذ في حركة المرور الإجمالية
        if self._detect_traffic_anomaly(current_traffic):
            logger.warning(f"تم اكتشاف شذوذ في حركة المرور الإجمالية: {current_traffic} طلب")
            # عند اكتشاف شذوذ، نطبق قواعد أكثر صرامة على عناوين IP المشبوهة
            user_profile = self.user_profiles.get(ip_address)
            if user_profile and user_profile.threat_score > self.config["challenge_threshold"]:
                if user_profile.threat_score > self.config["max_threat_score"]:
                    result["allowed"] = False
                    result["reason"] = "درجة تهديد عالية أثناء زيادة حركة المرور"
                    self._block_ip(ip_address, reason=result["reason"])
                else:
                    # إصدار تحدي CAPTCHA
                    self._issue_challenge(ip_address)
                    result["challenge"] = True
                    result["allowed"] = False
                    result["reason"] = "تم إصدار تحدي للتحقق من هوية المستخدم"
        return result

    def _apply_rule(self, rule, ip_address, request_data, timestamp):
        """
        تطبيق قاعدة محددة من محرك القواعد
        :return: قاموس يحتوي على نتيجة تطبيق القاعدة أو None إذا لم تنطبق
        """
        if rule["name"] == "rate_limiting":
            # فحص تجاوز معدل الطلبات
            if self._check_rate_limit(ip_address, timestamp, rule["threshold"]):
                return {
                    "allowed": False,
                    "reason": f"تجاوز معدل الطلبات ({rule['threshold']} طلب/دقيقة)",
                    "actions": ["log", "block"]
                }
        elif rule["name"] == "threat_score":
            # فحص درجة التهديد
            user_profile = self.user_profiles.get(ip_address)
            if user_profile and user_profile.threat_score > rule["threshold"]:
                return {
                    "allowed": False,
                    "reason": f"درجة تهديد عالية: {user_profile.threat_score}",
                    "actions": ["log", "block"]
                }
        elif rule["name"] == "geographic_restriction":
            # تقييد حسب الموقع الجغرافي
            user_profile = self.user_profiles.get(ip_address)
            if user_profile and user_profile.geolocation:
                country = user_profile.geolocation.get("country")
                if country in rule["countries"]:
                    return {
                        "allowed": False,
                        "reason": f"الدولة محظورة: {country}",
                        "actions": ["log", "block"]
                    }
        elif rule["name"] == "suspicious_patterns":
            # فحص أنماط الطلبات المشبوهة
            for pattern in rule["patterns"]:
                if re.search(pattern, request_data, re.IGNORECASE):
                    return {
                        "allowed": False,
                        "reason": "تم اكتشاف نمط مشبوه في الطلب",
                        "actions": ["log", "block"]
                    }
        elif rule["name"] == "brute_force_detection":
            # اكتشاف محاولات اختراق القوة الغاشمة
            user_profile = self.user_profiles.get(ip_address)
            if user_profile and user_profile.failed_login_attempts > rule["threshold"]:
                return {
                    "allowed": False,
                    "reason": f"محاولات تسجيل دخول فاشلة متعددة: {user_profile.failed_login_attempts}",
                    "actions": ["log", "challenge"]
                }
        return None

    def _check_captcha_challenge(self, ip_address, request_data):
        """
        التحقق من استجابة تحدي CAPTCHA في الطلب
        :param ip_address: عنوان IP للمستخدم
        :param request_data: بيانات الطلب الوارد
        :return: نتيجة التحقق من CAPTCHA أو None إذا لم تكن ذات صلة
        """
        # تحقق مما إذا كان المستخدم لديه جلسة تحدي نشطة
        if ip_address in self.challenge_sessions:
            # استخراج رمز CAPTCHA من الطلب
            captcha_code = self._extract_captcha_response(request_data)

            if captcha_code:
                # مقارنة الرمز المستخرج مع الرمز المتوقع
                expected_code = self.challenge_sessions[ip_address]["code"]
                if captcha_code == expected_code:
                    # CAPTCHA صحيح، إزالة الجلسة وتخفيض درجة التهديد
                    del self.challenge_sessions[ip_address]

                    # تخفيض درجة التهديد لملف تعريف المستخدم
                    if ip_address in self.user_profiles:
                        self.user_profiles[ip_address].threat_score -= 20
                        if self.user_profiles[ip_address].threat_score < 0:
                            self.user_profiles[ip_address].threat_score = 0

                    return {"allowed": True, "reason": "تم التحقق بنجاح من خلال CAPTCHA"}
                else:
                    # CAPTCHA غير صحيح، زيادة عدد المحاولات الفاشلة
                    self.challenge_sessions[ip_address]["attempts"] += 1

                    if self.challenge_sessions[ip_address]["attempts"] > 3:
                        # عدد كبير من المحاولات الفاشلة، حظر IP
                        self._block_ip(ip_address, reason="محاولات كثيرة فاشلة لحل CAPTCHA")
                        del self.challenge_sessions[ip_address]
                        return {"allowed": False, "reason": "محاولات كثيرة فاشلة لحل CAPTCHA"}

                    return {"allowed": False, "reason": "رمز CAPTCHA غير صحيح", "challenge": True}

            # إذا لم يتم العثور على رمز CAPTCHA، تحقق من صلاحية التحدي
            current_time = time.time()
            if self.challenge_sessions[ip_address]["expiry"] < current_time:
                # انتهت صلاحية التحدي، إصدار تحدي جديد
                self._issue_challenge(ip_address)

            return {"allowed": False, "reason": "يجب إكمال CAPTCHA", "challenge": True}

        # إذا لم يكن هناك جلسة تحدي نشطة، لا حاجة للتحقق
        return None

    def _extract_captcha_response(self, request_data):
        """
        استخراج استجابة CAPTCHA من بيانات الطلب
        """
        match = re.search(r"captcha_response=([a-zA-Z0-9]+)", request_data)
        if match:
            return match.group(1)
        return None

    def _issue_challenge(self, ip_address):
        """
        إصدار تحدي CAPTCHA لعنوان IP
        """
        # إنشاء رمز عشوائي
        code = hashlib.md5(f"{ip_address}-{time.time()}".encode()).hexdigest()[:6]
        # تخزين معلومات التحدي
        self.challenge_sessions[ip_address] = {
            "code": code,
            "issued_at": time.time(),
            "expiry": time.time() + 600,  # 10 دقائق
            "attempts": 0
        }
        logger.info(f"تم إصدار تحدي CAPTCHA لـ {ip_address}")

    def _check_rate_limit(self, ip_address, timestamp, threshold):
        """
        التحقق من تجاوز عنوان IP لمعدل الطلبات المسموح به
        :return: True إذا تم تجاوز المعدل
        """
        # احسب عدد الطلبات في الدقيقة الأخيرة
        recent_timestamps = [ts for ts in self.ip_timestamps[ip_address] if timestamp - ts <= 60]
        request_count = len(recent_timestamps)
        return request_count > threshold

    def _detect_traffic_anomaly(self, current_traffic):
        """
        اكتشاف الشذوذ في حركة المرور الإجمالية
        :return: True إذا تم اكتشاف شذوذ
        """
        if len(self.traffic_history) < 10:
            # البيانات غير كافية للكشف
            return False
        # حساب معدل الطلبات الحالي (طلبات/ثانية)
        window_size = self.config["window_size"]
        current_time = time.time()
        recent_timestamps = [ts for ts in self.traffic_history if current_time - ts <= window_size]
        if not recent_timestamps:
            return False
        current_rate = len(recent_timestamps) / window_size
        # حساب المعدل التاريخي
        historical_rates = []
        for i in range(1, 6):  # استخدام 5 نوافذ سابقة للمقارنة
            start_time = current_time - (i + 1) * window_size
            end_time = current_time - i * window_size
            window_timestamps = [ts for ts in self.traffic_history
                                 if start_time <= ts <= end_time]
            if window_timestamps:
                historical_rates.append(len(window_timestamps) / window_size)
        if not historical_rates:
            return False
        # حساب المتوسط والانحراف المعياري
        mean_rate = statistics.mean(historical_rates)
        # تجنب القسمة على صفر إذا كان المتوسط صفراً
        if mean_rate == 0:
            return current_rate > 0
        # حساب نسبة الزيادة
        increase_ratio = current_rate / mean_rate
        # اكتشاف الشذوذ: هل الزيادة تتجاوز العتبة؟
        threshold = self.config["threshold_multiplier"]
        if increase_ratio > threshold:
            logger.warning(
                f"تم اكتشاف شذوذ في حركة المرور: {current_rate:.2f} طلب/ثانية (زيادة بنسبة {increase_ratio:.2f}x)")
            return True
        return False

    def _block_ip(self, ip_address, duration=None, reason="سلوك مشبوه"):
        """
        حظر عنوان IP لفترة زمنية محددة
        :param ip_address: عنوان IP المراد حظره
        :param duration: مدة الحظر بالثواني (إذا كان None، يتم استخدام المدة الافتراضية)
        :param reason: سبب الحظر
        """
        if duration is None:
            duration = self.config["block_duration"]
        expiry = time.time() + duration
        self.blocked_ips[ip_address] = expiry
        logger.warning(
            f"تم حظر {ip_address} حتى {datetime.fromtimestamp(expiry).strftime('%Y-%m-%d %H:%M:%S')} - السبب: {reason}")

    def _cleanup_old_data(self, current_time):
        """
        تنظيف البيانات القديمة لتوفير الذاكرة
        :param current_time: الوقت الحالي
        """
        # تنظيف بيانات الطلبات القديمة
        cleanup_threshold = current_time - 3600  # ساعة واحدة
        for ip in list(self.ip_timestamps.keys()):
            self.ip_timestamps[ip] = [ts for ts in self.ip_timestamps[ip] if ts > cleanup_threshold]
            # إزالة الإدخالات الفارغة
            if not self.ip_timestamps[ip]:
                del self.ip_timestamps[ip]
                if ip in self.ip_request_count:
                    del self.ip_request_count[ip]
        # تنظيف جلسات CAPTCHA منتهية الصلاحية
        for ip in list(self.challenge_sessions.keys()):
            if self.challenge_sessions[ip]["expiry"] < current_time:
                del self.challenge_sessions[ip]
        # تنظيف ملفات تعريف المستخدمين غير النشطة
        inactive_threshold = current_time - 86400  # يوم واحد
        for ip in list(self.user_profiles.keys()):
            if self.user_profiles[ip].last_seen < inactive_threshold:
                del self.user_profiles[ip]
        logger.debug("تم تنظيف البيانات القديمة")

    def _cleanup_expired_blocks(self, current_time):
        """
        إزالة عناوين IP التي انتهت مدة حظرها من قائمة الحظر
        :param current_time: الوقت الحالي
        """
        for ip in list(self.blocked_ips.keys()):
            if self.blocked_ips[ip] < current_time:
                del self.blocked_ips[ip]
                logger.info(f"تم إلغاء حظر {ip} بعد انتهاء المدة")

    def _generate_traffic_report(self):
        """
        إنشاء تقرير عن حركة المرور
        """
        current_time = time.time()
        window_time = 300  # 5 دقائق
        # حساب إجمالي الطلبات في النافذة الزمنية
        recent_requests = [ts for ts in self.traffic_history if current_time - ts <= window_time]
        request_count = len(recent_requests)
        # حساب معدل الطلبات
        rate = request_count / window_time if window_time > 0 else 0
        # عدد عناوين IP الفريدة
        unique_ips = len([ip for ip in self.ip_timestamps if
                          any(current_time - ts <= window_time for ts in self.ip_timestamps[ip])])
        # عدد عناوين IP المحظورة
        blocked_count = len(self.blocked_ips)
        logger.info(
            f"تقرير حركة المرور: {request_count} طلب في {window_time / 60:.1f} دقيقة ({rate:.2f} طلب/ثانية), "
            f"{unique_ips} IP فريد, {blocked_count} IP محظور")

    def get_status(self):
        """
        الحصول على حالة البوت الحالية
        :return: قاموس يحتوي على معلومات الحالة
        """
        current_time = time.time()
        # حساب حركة المرور الحالية
        recent_timestamps = [ts for ts in self.traffic_history if current_time - ts <= 60]
        current_rate = len(recent_timestamps) / 60 if recent_timestamps else 0
        # جمع معلومات عن المستخدمين النشطين
        active_profiles = [profile for profile in self.user_profiles.values()
                           if current_time - profile.last_seen <= 300]  # نشط في آخر 5 دقائق
        # حساب متوسط درجة التهديد
        avg_threat = sum(profile.threat_score for profile in active_profiles) / len(
            active_profiles) if active_profiles else 0
        # جمع الـ IP ذات درجة التهديد الأعلى
        high_threat_ips = [(profile.ip_address, profile.threat_score)
                           for profile in active_profiles
                           if profile.threat_score > self.config["challenge_threshold"]]
        high_threat_ips.sort(key=lambda x: x[1], reverse=True)
        return {
            "time": datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S'),
            "traffic_rate": f"{current_rate:.2f} req/s",
            "active_users": len(active_profiles),
            "blocked_ips": len(self.blocked_ips),
            "avg_threat_score": f"{avg_threat:.2f}",
            "high_threat_ips": high_threat_ips[:5],  # أعلى 5 عناوين IP تهديدًا
            "challenge_active": len(self.challenge_sessions)
        }

    def update_config(self, new_config):
        """
        تحديث إعدادات البوت
        :param new_config: قاموس التكوين الجديد
        :return: True إذا تم التحديث بنجاح
        """
        # تحديث الإعدادات المتوفرة فقط
        for key, value in new_config.items():
            if key in self.config:
                self.config[key] = value
        # تحديث إعدادات محرك القواعد إذا لزم الأمر
        if "rate_limit" in new_config:
            for rule in self.rules_engine:
                if rule["name"] == "rate_limiting":
                    rule["threshold"] = new_config["rate_limit"]
                    break
        if "max_threat_score" in new_config:
            for rule in self.rules_engine:
                if rule["name"] == "threat_score":
                    rule["threshold"] = new_config["max_threat_score"]
                    break
        # تحديث مستوى التسجيل
        if "log_level" in new_config:
            logger.setLevel(getattr(logging, new_config["log_level"]))
        logger.info(f"تم تحديث التكوين: {new_config}")
        return True

    def add_to_whitelist(self, ip_address):
        """
        إضافة عنوان IP إلى القائمة البيضاء
        :param ip_address: عنوان IP المراد إضافته
        :return: True إذا تمت الإضافة بنجاح
        """
        if ip_address not in self.config["whitelist"]:
            self.config["whitelist"].append(ip_address)
            logger.info(f"تمت إضافة {ip_address} إلى القائمة البيضاء")
            # إزالة من القائمة السوداء أو قائمة الحظر إذا كان موجودًا
            if ip_address in self.config["blacklist"]:
                self.config["blacklist"].remove(ip_address)
            if ip_address in self.blocked_ips:
                del self.blocked_ips[ip_address]
            return True
        return False

    def add_to_blacklist(self, ip_address, reason="تمت الإضافة يدويًا"):
        """
        إضافة عنوان IP إلى القائمة السوداء
        :param ip_address: عنوان IP المراد إضافته
        :param reason: سبب الإضافة
        :return: True إذا تمت الإضافة بنجاح
        """
        if ip_address not in self.config["blacklist"]:
            self.config["blacklist"].append(ip_address)
            logger.info(f"تمت إضافة {ip_address} إلى القائمة السوداء - السبب: {reason}")
            # إزالة من القائمة البيضاء إذا كان موجودًا
            if ip_address in self.config["whitelist"]:
                self.config["whitelist"].remove(ip_address)
            # حظر فوري
            self.blocked_ips[ip_address] = time.time() + 365 * 86400  #
    def _block_ip(self, ip_address, duration=None, reason="سلوك مشبوه"):
        """
        حظر عنوان IP لفترة زمنية محددة
        :param ip_address: عنوان IP المراد حظره
        :param duration: مدة الحظر بالثواني (إذا كان None، يتم استخدام المدة الافتراضية)
        :param reason: سبب الحظر
        """
        if duration is None:
            duration = self.config["block_duration"]
        expiry = time.time() + duration
        self.blocked_ips[ip_address] = expiry
        logger.warning(
            f"تم حظر {ip_address} حتى {datetime.fromtimestamp(expiry).strftime('%Y-%m-%d %H:%M:%S')} - السبب: {reason}")

    def _cleanup_old_data(self, current_time):
        """
        تنظيف البيانات القديمة لتوفير الذاكرة
        :param current_time: الوقت الحالي
        """
        # تنظيف بيانات الطلبات القديمة
        cleanup_threshold = current_time - 3600  # ساعة واحدة
        for ip in list(self.ip_timestamps.keys()):
            self.ip_timestamps[ip] = [ts for ts in self.ip_timestamps[ip] if ts > cleanup_threshold]
            # إزالة الإدخالات الفارغة
            if not self.ip_timestamps[ip]:
                del self.ip_timestamps[ip]
                if ip in self.ip_request_count:
                    del self.ip_request_count[ip]
        # تنظيف جلسات CAPTCHA منتهية الصلاحية
        for ip in list(self.challenge_sessions.keys()):
            if self.challenge_sessions[ip]["expiry"] < current_time:
                del self.challenge_sessions[ip]
        # تنظيف ملفات تعريف المستخدمين غير النشطة
        inactive_threshold = current_time - 86400  # يوم واحد
        for ip in list(self.user_profiles.keys()):
            if self.user_profiles[ip].last_seen < inactive_threshold:
                del self.user_profiles[ip]
        logger.debug("تم تنظيف البيانات القديمة")

    def _cleanup_expired_blocks(self, current_time):
        """
        إزالة عناوين IP التي انتهت مدة حظرها من قائمة الحظر
        :param current_time: الوقت الحالي
        """
        for ip in list(self.blocked_ips.keys()):
            if self.blocked_ips[ip] < current_time:
                del self.blocked_ips[ip]
                logger.info(f"تم إلغاء حظر {ip} بعد انتهاء المدة")

    def _generate_traffic_report(self):
        """
        إنشاء تقرير عن حركة المرور
        """
        current_time = time.time()
        window_time = 300  # 5 دقائق
        # حساب إجمالي الطلبات في النافذة الزمنية
        recent_requests = [ts for ts in self.traffic_history if current_time - ts <= window_time]
        request_count = len(recent_requests)
        # حساب معدل الطلبات
        rate = request_count / window_time if window_time > 0 else 0
        # عدد عناوين IP الفريدة
        unique_ips = len([ip for ip in self.ip_timestamps if
                          any(current_time - ts <= window_time for ts in self.ip_timestamps[ip])])
        # عدد عناوين IP المحظورة
        blocked_count = len(self.blocked_ips)
        logger.info(
            f"تقرير حركة المرور: {request_count} طلب في {window_time / 60:.1f} دقيقة ({rate:.2f} طلب/ثانية), "
            f"{unique_ips} IP فريد, {blocked_count} IP محظور")

    def get_status(self):
        """
        الحصول على حالة البوت الحالية
        :return: قاموس يحتوي على معلومات الحالة
        """
        current_time = time.time()
        # حساب حركة المرور الحالية
        recent_timestamps = [ts for ts in self.traffic_history if current_time - ts <= 60]
        current_rate = len(recent_timestamps) / 60 if recent_timestamps else 0
        # جمع معلومات عن المستخدمين النشطين
        active_profiles = [profile for profile in self.user_profiles.values()
                           if current_time - profile.last_seen <= 300]  # نشط في آخر 5 دقائق
        # حساب متوسط درجة التهديد
        avg_threat = sum(profile.threat_score for profile in active_profiles) / len(
            active_profiles) if active_profiles else 0
        # جمع الـ IP ذات درجة التهديد الأعلى
        high_threat_ips = [(profile.ip_address, profile.threat_score)
                           for profile in active_profiles
                           if profile.threat_score > self.config["challenge_threshold"]]
        high_threat_ips.sort(key=lambda x: x[1], reverse=True)
        return {
            "time": datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S'),
            "traffic_rate": f"{current_rate:.2f} req/s",
            "active_users": len(active_profiles),
            "blocked_ips": len(self.blocked_ips),
            "avg_threat_score": f"{avg_threat:.2f}",
            "high_threat_ips": high_threat_ips[:5],  # أعلى 5 عناوين IP تهديدًا
            "challenge_active": len(self.challenge_sessions)
        }

    def update_config(self, new_config):
        """
        تحديث إعدادات البوت
        :param new_config: قاموس التكوين الجديد
        :return: True إذا تم التحديث بنجاح
        """
        # تحديث الإعدادات المتوفرة فقط
        for key, value in new_config.items():
            if key in self.config:
                self.config[key] = value
        # تحديث إعدادات محرك القواعد إذا لزم الأمر
        if "rate_limit" in new_config:
            for rule in self.rules_engine:
                if rule["name"] == "rate_limiting":
                    rule["threshold"] = new_config["rate_limit"]
                    break
        if "max_threat_score" in new_config:
            for rule in self.rules_engine:
                if rule["name"] == "threat_score":
                    rule["threshold"] = new_config["max_threat_score"]
                    break
        # تحديث مستوى التسجيل
        if "log_level" in new_config:
            logger.setLevel(getattr(logging, new_config["log_level"]))
        logger.info(f"تم تحديث التكوين: {new_config}")
        return True

    def add_to_whitelist(self, ip_address):
        """
        إضافة عنوان IP إلى القائمة البيضاء
        :param ip_address: عنوان IP المراد إضافته
        :return: True إذا تمت الإضافة بنجاح
        """
        if ip_address not in self.config["whitelist"]:
            self.config["whitelist"].append(ip_address)
            logger.info(f"تمت إضافة {ip_address} إلى القائمة البيضاء")
            # إزالة من القائمة السوداء أو قائمة الحظر إذا كان موجودًا
            if ip_address in self.config["blacklist"]:
                self.config["blacklist"].remove(ip_address)
            if ip_address in self.blocked_ips:
                del self.blocked_ips[ip_address]
            return True
        return False

    def add_to_blacklist(self, ip_address, reason="تمت الإضافة يدويًا"):
        """
        إضافة عنوان IP إلى القائمة السوداء
        :param ip_address: عنوان IP المراد إضافته
        :param reason: سبب الإضافة
        :return: True إذا تمت الإضافة بنجاح
        """
        if ip_address not in self.config["blacklist"]:
            self.config["blacklist"].append(ip_address)
            logger.info(f"تمت إضافة {ip_address} إلى القائمة السوداء - السبب: {reason}")
            # إزالة من القائمة البيضاء إذا كان موجودًا
            if ip_address in self.config["whitelist"]:
                self.config["whitelist"].remove(ip_address)
            # حظر فوري
            self.blocked_ips[ip_address] = time.time() + 365 * 86400  # حظر لمدة سنة
            return True
        return False

    def remove_from_blacklist(self, ip_address):
        """
        إزالة عنوان IP من القائمة السوداء
        :param ip_address: عنوان IP المراد إزالته
        :return: True إذا تمت الإزالة بنجاح
        """
        if ip_address in self.config["blacklist"]:
            self.config["blacklist"].remove(ip_address)
            # إزالة من قائمة الحظر أيضًا
            if ip_address in self.blocked_ips:
                del self.blocked_ips[ip_address]
            logger.info(f"تمت إزالة {ip_address} من القائمة السوداء")
            return True
        return False

    def get_user_profile(self, ip_address):
        """
        الحصول على ملف تعريف المستخدم
        :param ip_address: عنوان IP للمستخدم
        :return: ملخص ملف تعريف المستخدم أو None إذا لم يكن موجودًا
        """
        if ip_address in self.user_profiles:
            return self.user_profiles[ip_address].get_summary()
        return None

    def add_custom_rule(self, rule):
        """
        إضافة قاعدة مخصصة لمحرك القواعد
        :param rule: قاموس يمثل القاعدة الجديدة
        :return: True إذا تمت الإضافة بنجاح
        """
        # التحقق من وجود الحقول المطلوبة
        required_fields = ["name", "description", "enabled", "action", "priority"]
        if not all(field in rule for field in required_fields):
            logger.error(f"فشلت إضافة القاعدة: الحقول المطلوبة مفقودة")
            return False
        # التحقق من عدم وجود قاعدة بنفس الاسم
        if any(r["name"] == rule["name"] for r in self.rules_engine):
            logger.error(f"فشلت إضافة القاعدة: قاعدة بنفس الاسم موجودة بالفعل")
            return False
        # إضافة القاعدة
        self.rules_engine.append(rule)
        logger.info(f"تمت إضافة قاعدة جديدة: {rule['name']}")
        return True

    def stop(self):
        """
        إيقاف البوت وتنظيف الموارد
        """
        logger.info("جاري إيقاف بوت الحماية...")
        # إيقاف المهام الدورية إذا كانت قيد التشغيل
        if self.periodic_tasks_thread and self.periodic_tasks_thread.is_alive():
            # لا يمكن إيقاف الخيط مباشرةً في Python، ولكن يمكننا استخدام علم
            self._should_stop = True
            self.periodic_tasks_thread.join(timeout=2)
        # حفظ البيانات إذا لزم الأمر
        self._save_data()
        logger.info("تم إيقاف بوت الحماية بنجاح")

    def _save_data(self):
        """
        حفظ بيانات البوت للاستخدام في المستقبل
        """
        data = {
            "config": self.config,
            "blocked_ips": self.blocked_ips,
            "blacklist": self.config["blacklist"],
            "whitelist": self.config["whitelist"],
            "rules": self.rules_engine
        }
        try:
            with open("ddos_protection_data.json", "w") as f:
                json.dump(data, f)
            logger.info("تم حفظ بيانات البوت بنجاح")
        except Exception as e:
            logger.error(f"فشل حفظ البيانات: {str(e)}")

    @classmethod
    def load(cls, filename="ddos_protection_data.json"):
        """
        تحميل بوت حماية من ملف
        :param filename: اسم ملف البيانات
        :return: كائن DDoSProtectionBot مع البيانات المحملة
        """
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            bot = cls(config=data.get("config", {}))
            bot.blocked_ips = data.get("blocked_ips", {})
            bot.config["blacklist"] = data.get("blacklist", [])
            bot.config["whitelist"] = data.get("whitelist", [])
            bot.rules_engine = data.get("rules", bot.rules_engine)
            logger.info(f"تم تحميل بوت الحماية من {filename}")
            return bot
        except FileNotFoundError:
            logger.warning(f"ملف البيانات {filename} غير موجود، جاري إنشاء بوت جديد")
            return cls()
        except Exception as e:
            logger.error(f"فشل تحميل البيانات: {str(e)}")
            return cls()
    if __name__ == "__main__":
        # إنشاء البوت مع تكوين مخصص
        config = {
            "window_size": 60,
            "threshold_multiplier": 3,
            "rate_limit": 100,
            "max_threat_score": 70,
            "block_duration": 3600,
            "whitelist": ["127.0.0.1"],
            "blacklist": [],
            "country_blacklist": ["CountryX", "CountryY"],
            "log_level": "INFO",
            "challenge_threshold": 40,
            "auto_ban_enabled": True,
            "proxy_detection": True,
            "alert_email_enabled": False
        }

bot = DDoSProtectionBot()

sample_request = (
    "GET /login HTTP/1.1\n"
    "Host: example.com\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"
    "Accept-Language: en-US,en;q=0.5\n"
    "Accept-Encoding: gzip, deflate, br\n"
    "Connection: keep-alive\n"
    "Cookie: session=abc123; user=guest"
)

result = bot.process_request("192.168.1.100", sample_request)
print(f"نتيجة معالجة الطلب: {result}")

# استخراج معلومات الحالة
status = bot.get_status()
print(f"حالة البوت: {status}")

# إيقاف البوت عند الانتهاء
bot.stop()