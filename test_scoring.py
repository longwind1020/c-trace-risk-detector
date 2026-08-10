import unittest

from detector import SAMPLE_EN, SAMPLE_ZH, analyze_text
from scoring import calculate_risk, progress_percent


class ScoringTests(unittest.TestCase):
    def scores(self, a, b, c, d):
        return {"identity": a, "synthetic": b, "urgency": c, "financial": d}

    def test_risk_boundaries(self):
        self.assertEqual(calculate_risk(self.scores(0, 0, 0, 2)).level, "低风险")
        self.assertEqual(calculate_risk(self.scores(0, 0, 1, 2)).level, "中风险")
        self.assertEqual(calculate_risk(self.scores(0, 2, 2, 2)).level, "高风险")
        self.assertEqual(calculate_risk(self.scores(2, 2, 2, 2)).total, 8)

    def test_invalid_values_are_rejected(self):
        with self.assertRaises(ValueError):
            calculate_risk(self.scores(0, 1, 2, 3))
        with self.assertRaises(ValueError):
            calculate_risk({"identity": 0})

    def test_chinese_detection(self):
        result = analyze_text(SAMPLE_ZH)
        self.assertEqual(result.language, "zh")
        self.assertEqual(result.scores, {"identity": 2, "synthetic": 1, "urgency": 2, "financial": 2})
        self.assertTrue(any("企业高管" in item for item in result.scam_types))
        self.assertGreaterEqual(len(result.cross_border_hits), 2)

    def test_english_detection(self):
        result = analyze_text(SAMPLE_EN)
        self.assertEqual(result.language, "en")
        self.assertEqual(result.scores["identity"], 2)
        self.assertEqual(result.scores["urgency"], 2)
        self.assertEqual(result.scores["financial"], 2)
        self.assertEqual(result.scores["synthetic"], 1)

    def test_mixed_language_and_safe_text(self):
        mixed = analyze_text("请今天 review the official public report and contact the official office for verification.")
        self.assertIn(mixed.language, {"mixed", "en"})
        safe = analyze_text("会议改到周五下午三点，请通过公司通讯录确认参会人。")
        self.assertEqual(sum(safe.scores.values()), 0)

    def test_financial_and_ai_keywords(self):
        result = analyze_text("Use USDT now. This deepfake video is from an unknown source.")
        self.assertEqual(result.scores["financial"], 2)
        self.assertEqual(result.scores["synthetic"], 2)

    def test_progress(self):
        self.assertEqual(progress_percent(0), 0)
        self.assertEqual(progress_percent(8), 100)


if __name__ == "__main__":
    unittest.main()

