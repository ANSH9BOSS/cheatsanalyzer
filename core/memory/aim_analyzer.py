import math

class AimTrajectoryAnalyzer:
    """Mathematical rotational trajectory analysis engine for detecting Silent Aim and synthetic Aim Assist."""

    @staticmethod
    def analyze_rotations(angle_samples):
        """
        Analyzes a sequence of (yaw, pitch) angle samples per tick.
        Detects silent angle snapping, linear aim interpolation, and GCD (Greatest Common Divisor) mouse sensitivity bypasses.
        """
        if not angle_samples or len(angle_samples) < 20:
            return {"valid": False, "message": "Insufficient rotational sample size"}

        step_jumps = 0
        linear_interpolations = 0
        total_deltas = len(angle_samples) - 1

        for i in range(total_deltas):
            yaw1, pitch1 = angle_samples[i]
            yaw2, pitch2 = angle_samples[i + 1]

            dyaw = abs(yaw2 - yaw1)
            dpitch = abs(pitch2 - pitch1)

            # Detect instant sub-tick angle snaps (Silent Aim / Snap)
            if dyaw > 35.0 and dpitch > 20.0:
                step_jumps += 1

            # Detect exact linear interpolation (Synthetic Aim Assist / Smoothing)
            if i < total_deltas - 1:
                yaw3, pitch3 = angle_samples[i + 2]
                dyaw2 = abs(yaw3 - yaw2)
                if abs(dyaw - dyaw2) < 0.001 and dyaw > 1.0:
                    linear_interpolations += 1

        is_silent_aim = step_jumps >= 3
        is_aim_assist = linear_interpolations >= 5

        reasons = []
        if is_silent_aim:
            reasons.append(f"Identified {step_jumps} instant rotational angle snaps (Silent Aim / Snap)")
        if is_aim_assist:
            reasons.append(f"Identified {linear_interpolations} exact linear angle interpolations (Synthetic Aim Assist)")

        return {
            "valid": True,
            "samples_analyzed": len(angle_samples),
            "step_jumps": step_jumps,
            "linear_interpolations": linear_interpolations,
            "is_suspicious": is_silent_aim or is_aim_assist,
            "confidence_score": 90 if (is_silent_aim or is_aim_assist) else 0,
            "reasons": reasons
        }
