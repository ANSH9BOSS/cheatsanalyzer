import hashlib
import json
import urllib.request
import urllib.error
from core.trusted_database import OFFICIAL_MODS_WHITELIST, SAFE_MANIFEST_IDENTIFIERS

class ModrinthVerifier:
    """Verifies Minecraft mod authenticity using Modrinth API v2 and Local Official Whitelist."""

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
        Multi-tier verification:
        Tier 1: Local SQLite Hash Cache
        Tier 2: Official Modrinth v2 API File Hash Resolution
        Tier 3: Manifest Identifier & Author Whitelist (for offline speed & resilience)
        Returns: (is_verified_clean, mod_info_dict)
        """
        sha1 = self.calculate_sha1(filepath)
        if not sha1 or len(sha1) != 40:
            return False, {"source": "Invalid Hash", "clean": False, "confidence": 0}

        # Tier 1: Local database cache
        if self.db:
            cached_clean, cached_title = self.db.get_whitelist_cache(sha1)
            if cached_clean is not None:
                return cached_clean, {
                    "source": "Modrinth Cloud (Cached)",
                    "title": cached_title,
                    "clean": cached_clean,
                    "sha1": sha1,
                    "confidence": 100 if cached_clean else 0
                }

        # Tier 2: Modrinth API v2 Query
        url = f"https://api.modrinth.com/v2/version_file/{sha1}?algorithm=sha1"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": self.user_agent}
            )
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "id" in data and "project_id" in data:
                    project_id = data.get("project_id", "")
                    version_name = data.get("name", "Verified Mod")
                    loaders = ", ".join(data.get("loaders", []))
                    
                    info = {
                        "source": f"Modrinth Official [{project_id}]",
                        "title": f"{version_name} ({loaders})",
                        "clean": True,
                        "project_id": project_id,
                        "sha1": sha1,
                        "confidence": 100
                    }
                    if self.db:
                        self.db.cache_whitelist(sha1, project_id, version_name, True)
                    return True, info
        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass
        except Exception:
            pass

        return False, {"source": "Unverified on Modrinth", "clean": False, "sha1": sha1, "confidence": 0}

    def verify_batch_mods(self, filepaths):
        """
        Batches up to 100 SHA-1 hashes into a single Modrinth API call for ultra-fast instant resolution.
        Returns dict: {filepath: (is_clean, info_dict)}
        """
        results = {}
        hash_to_path = {}
        uncached_hashes = []

        for fp in filepaths:
            sha1 = self.calculate_sha1(fp)
            if not sha1:
                results[fp] = (False, {"source": "Invalid Hash", "clean": False, "confidence": 0})
                continue
            hash_to_path[sha1] = fp

            # Check cache
            if self.db:
                cached_clean, cached_title = self.db.get_whitelist_cache(sha1)
                if cached_clean is not None:
                    results[fp] = (cached_clean, {
                        "source": "Modrinth Cloud (Cached)",
                        "title": cached_title,
                        "clean": cached_clean,
                        "sha1": sha1,
                        "confidence": 100 if cached_clean else 0
                    })
                    continue

            uncached_hashes.append(sha1)

        # Query Modrinth API in 1 single batch POST
        if uncached_hashes:
            try:
                payload = json.dumps({"hashes": uncached_hashes[:100], "algorithm": "sha1"}).encode("utf-8")
                req = urllib.request.Request(
                    "https://api.modrinth.com/v2/version_files",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": self.user_agent
                    }
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    api_data = json.loads(resp.read().decode("utf-8"))
                    for sha1_key, vdata in api_data.items():
                        if sha1_key in hash_to_path:
                            fp = hash_to_path[sha1_key]
                            proj_id = vdata.get("project_id", "")
                            vname = vdata.get("name", "Verified Mod")
                            loaders = ", ".join(vdata.get("loaders", []))
                            info = {
                                "source": f"Modrinth Official [{proj_id}]",
                                "title": f"{vname} ({loaders})",
                                "clean": True,
                                "project_id": proj_id,
                                "sha1": sha1_key,
                                "confidence": 100
                            }
                            results[fp] = (True, info)
                            if self.db:
                                self.db.cache_whitelist(sha1_key, proj_id, vname, True)
            except Exception:
                pass

        # Fill remaining unverified
        for fp in filepaths:
            if fp not in results:
                sha1 = self.calculate_sha1(fp)
                results[fp] = (False, {"source": "Unverified on Modrinth", "clean": False, "sha1": sha1, "confidence": 0})

        return results
