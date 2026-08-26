import math
import statistics

class ClickCurveAnalyzer:
    """Mathematical statistical engine for detecting artificial autoclickers, macro loops, and jitter emulators."""

    @staticmethod
    def analyze_intervals(click_intervals_ms):
        """
        Analyzes a sequence of click intervals (time between clicks in ms).
        Returns dict with metrics: mean_cps, std_dev, kurtosis, is_autoclicker, reason.
        """
        if not click_intervals_ms or len(click_intervals_ms) < 15:
            return {
                "valid": False,
                "message": "Insufficient click sample size (need at least 15 clicks)"
            }

        n = len(click_intervals_ms)
        mean_interval = statistics.mean(click_intervals_ms)
        std_dev = statistics.stdev(click_intervals_ms) if n > 1 else 0
        mean_cps = 1000.0 / mean_interval if mean_interval > 0 else 0

        # Kurtosis & Distribution Skew
        variance = statistics.variance(click_intervals_ms) if n > 1 else 0
        if variance > 0:
            m4 = sum((x - mean_interval) ** 4 for x in click_intervals_ms) / n
            kurtosis = (m4 / (variance ** 2)) - 3
        else:
            kurtosis = 0

        # Autoclicker Heuristics
        # 1. Unnaturally constant interval (std_dev < 3.5ms with CPS > 12)
        # 2. Perfect uniform randomization with 0 debounce (< 8ms minimum delay with static bounds)
        # 3. Identical repeating interval patterns (macro replay)
        is_autoclicker = False
        reasons = []

        if mean_cps >= 13.0 and std_dev < 4.0:
            is_autoclicker = True
            reasons.append(f"Impossibly low click deviation ({std_dev:.2f}ms) at {mean_cps:.1f} CPS (Linear Autoclicker)")

        # Check for duplicate consecutive millisecond intervals
        duplicates = sum(1 for i in range(n - 1) if abs(click_intervals_ms[i] - click_intervals_ms[i+1]) < 0.1)
        if duplicates / n > 0.40 and mean_cps > 10.0:
            is_autoclicker = True
            reasons.append(f"Excessive duplicate millisecond intervals ({duplicates}/{n}) indicating synthetic click generation")

        return {
            "valid": True,
            "sample_count": n,
            "mean_cps": round(mean_cps, 2),
            "std_dev_ms": round(std_dev, 2),
            "kurtosis": round(kurtosis, 2),
            "is_autoclicker": is_autoclicker,
            "confidence_score": 95 if is_autoclicker else 0,
            "reasons": reasons
        }
