import hashlib
import json
import urllib.request
import urllib.error

class ModrinthVerifier:
    """Verifies Minecraft mod authenticity directly against the official Modrinth API."""

    def __init__(self, db=None):
        self.db = db
        self.user_agent = "ANSH9BOSS-CheatsAnalyzer/2.0 (security-audit@ansh9boss.app)"

    @staticmethod
    def calculate_sha1(filepath):
        try:
            sha1 = hashlib.sha1()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha1.update(chunk)
            return sha1.hexdigest().lower()
        except Exception:
            return ""

    @staticmethod
    def calculate_sha512(filepath):
        try:
            sha512 = hashlib.sha512()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha512.update(chunk)
            return sha512.hexdigest().lower()
        except Exception:
            return ""

    def verify_mod(self, filepath):
        """
        Queries Modrinth API to check if the mod hash matches an official, unmodified release.
        Returns: (is_verified_clean, mod_info_dict)
        """
        sha1 = self.calculate_sha1(filepath)
        if not sha1 or len(sha1) != 40:
            return False, {"source": "Invalid Hash", "clean": False}

        # Check local database cache first
        if self.db:
            cached_clean, cached_title = self.db.get_whitelist_cache(sha1)
            if cached_clean is not None:
                return cached_clean, {
                    "source": "Modrinth (Cached)",
                    "title": cached_title,
                    "clean": cached_clean,
                    "sha1": sha1
                }

        # Query Modrinth API v2
        url = f"https://api.modrinth.com/v2/version_file/{sha1}?algorithm=sha1"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": self.user_agent}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "id" in data and "project_id" in data:
                    project_id = data.get("project_id", "")
                    version_name = data.get("name", "Verified Mod")
                    loaders = ", ".join(data.get("loaders", []))
                    
                    info = {
                        "source": f"Modrinth Official ({project_id})",
                        "title": f"{version_name} [{loaders}]",
                        "clean": True,
                        "project_id": project_id,
                        "sha1": sha1
                    }
                    if self.db:
                        self.db.cache_whitelist(sha1, project_id, version_name, True)
                    return True, info
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Mod not found on Modrinth - either custom, third-party, or unverified
                return False, {"source": "Unverified on Modrinth", "clean": False, "sha1": sha1}
        except Exception as e:
            pass

        return False, {"source": "Offline / Unverified", "clean": False, "sha1": sha1}
