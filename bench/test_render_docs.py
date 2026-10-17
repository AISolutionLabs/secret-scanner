#!/usr/bin/env python3
"""Tests for bench/render_docs.py: the published-figures consistency check.

  python3 bench/test_render_docs.py
"""
import copy, json, os, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import render_docs as rd  # noqa: E402

LATEST = json.load(open(os.path.join(HERE, "results", "latest.json")))
RESULTS = open(os.path.join(rd.ROOT, LATEST["results_file"])).read()


class PublishedFigures(unittest.TestCase):
    def test_repository_is_consistent(self):
        p = subprocess.run([sys.executable, os.path.join(HERE, "render_docs.py"), "--check", "--release"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_changed_figure_makes_docs_stale(self):
        d = copy.deepcopy(LATEST)
        d["policy"]["balanced"]["recall"] = 60.0
        changed = rd.render(d)
        self.assertIn("README.md", changed)
        self.assertIn("docs/precision.md", changed)
        self.assertIn("cmd/secretscan/benchfigures.go", changed)

    def test_figure_not_in_results_file_fails(self):
        for path, value in ((("policy", "balanced", "recall"), 60.0), (("tools", "gitleaks", "precision"), 92.0),
                            (("triage", "standard", "true"), 1095), (("breakdown", "confidence", "low", "precision"), 90.0),
                            (("leaky_repo", "detect_secrets", "extra"), 1), (("disagreements", "changetoken_missed_lines"), 15)):
            d = copy.deepcopy(LATEST)
            cur = d
            for k in path[:-1]:
                cur = cur[k]
            cur[path[-1]] = value
            self.assertTrue(rd.check_sourced(d, RESULTS), f"{path} = {value} not caught")
        self.assertEqual(rd.check_sourced(LATEST, RESULTS), [])

    def test_unsourced_percentage_fails(self):
        orig = rd.published
        try:
            rd.published = lambda d: [("README.md", "<!-- bench:x -->\n42.0%\n<!-- /bench:x -->\nok\n"),
                                      ("README.md", "balanced blocks ~60% of labeled secrets at 92% precision\n"),
                                      ("README.md", "secrets are redacted by default (80% masked)\n")]
            errs = rd.check_unsourced(LATEST)
        finally:
            rd.published = orig
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("~60%", errs[0])

    def test_balanced_figures_name_their_setting(self):
        """Every published balanced figure says which testFixtures setting it is for."""
        p = LATEST["policy"]
        for rel, regs in rd.regions(LATEST).items():
            for name, body in regs.items():
                for key, setting in (("balanced", 'testFixtures = "block"'), ("balanced_review", 'testFixtures = "review"')):
                    if rd.pct(p[key]["recall"]) in body:
                        self.assertIn(setting, body, f"{rel} bench:{name} quotes {key} without {setting}")

    def test_detection_fingerprint_tracks_detection_code(self):
        tmp = tempfile.mkdtemp()
        try:
            for d in rd.DETECTION_DIRS:
                shutil.copytree(os.path.join(rd.ROOT, d), os.path.join(tmp, d))
            base = rd.fingerprint(tmp)
            self.assertEqual(base, rd.fingerprint())
            test = os.path.join(tmp, "internal", "detect", "zz_test.go")
            open(test, "w").write("package detect\n")
            self.assertEqual(rd.fingerprint(tmp), base, "tests must not change the fingerprint")
            ev = os.path.join(tmp, "internal", "detect", "evidence.go")
            with open(ev, "a") as f:
                f.write("\n// a comment is not a detection change\n")
            self.assertEqual(rd.fingerprint(tmp), base)
            src = open(ev).read()
            open(ev, "w").write(src.replace('Medium = "medium"', 'Medium = "med"', 1))
            self.assertNotEqual(rd.fingerprint(tmp), base)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
