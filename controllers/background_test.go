package controllers

import (
	"testing"

	"vshell/utils"
)

// TestBuildDefaultLicTime 校验 FUN_0194cd00 的默认授权值构造：种子
// "2jgg\xd9\x95ck" + 10 个增量字节置换后得到 "20990101"，即
// licTime=20990101、client limit=99（与黑盒观测一致）。
func TestBuildDefaultLicTime(t *testing.T) {
	licTime, clientNum := buildDefaultLicTime()
	if licTime != 20990101 {
		t.Fatalf("licTime = %d, want 20990101", licTime)
	}
	if clientNum != defaultClientLimit {
		t.Fatalf("clientNum = %d, want defaultClientLimit %d", clientNum, defaultClientLimit)
	}
	if defaultClientLimit != 99 {
		t.Fatalf("defaultClientLimit = %d, want 99", defaultClientLimit)
	}
}

// TestLicenseKeyLookup 校验 license 键读取路径（FUN_0194bd60 以 7 字节键在
// 设置单例里查 license）。
func TestLicenseKeyLookup(t *testing.T) {
	if licenseConfigKey != "license" || len(licenseConfigKey) != 7 {
		t.Fatalf("licenseConfigKey = %q (len %d), want 7-byte \"license\"",
			licenseConfigKey, len(licenseConfigKey))
	}

	prev := utils.GetFullSettings()
	utils.SetFullSettingsForTest(&utils.FullSettings{License: "test-license"})
	t.Cleanup(func() { utils.SetFullSettingsForTest(prev) })

	got, ok := getLicenseKey()
	if !ok || got != "test-license" {
		t.Fatalf("getLicenseKey() = (%q, %v), want (\"test-license\", true)", got, ok)
	}
}

// TestAppBackgroundNoLicense 校验无 license 时走 FUN_0194cd00 默认路径：
// 授权 20990101/99，master_type 与 web_basic_auth 写入启动状态。
func TestAppBackgroundNoLicense(t *testing.T) {
	prev := utils.GetFullSettings()
	utils.SetFullSettingsForTest(&utils.FullSettings{
		MasterType:   "web",
		WebBasicAuth: true,
		LogPath:      "/tmp/vshell-test.log",
	})
	t.Cleanup(func() { utils.SetFullSettingsForTest(prev) })

	AppBackground()

	got := backgroundStateSnapshot()
	if !got.Called {
		t.Fatal("AppBackground did not record a start")
	}
	if got.LicTime != 20990101 || got.ClientNum != 99 {
		t.Fatalf("licTime/clientNum = %d/%d, want 20990101/99", got.LicTime, got.ClientNum)
	}
	if got.LicenseVerified {
		t.Fatal("LicenseVerified = true without a license key")
	}
	if got.MasterType != "web" || !got.WebBasicAuth {
		t.Fatalf("master/basicAuth = %q/%v, want web/true", got.MasterType, got.WebBasicAuth)
	}
	if got.LogPath != "/tmp/vshell-test.log" {
		t.Fatalf("logPath = %q", got.LogPath)
	}
}

// TestAppBackgroundUnverifiableLicenseFallsBack 校验配置了 license 但无法离线
// 校验时的回落路径。
//
// 差异（deliberate divergence）：原版经 FUN_00e3ce40 联网校验，失败则
// FUN_005ecc00 panic【中止进程】；复刻端不中止，改用 utils.GetLicenseStatus 的
// 黑盒观测授权值继续启动。本测试断言的正是「复刻端回落」这一实际行为
// （licTime=20991201 —— 注意这与无 license 时 FUN_0194cd00 的 20990101 是
// 两个不同来源）；若将来改成与原版一致的中止行为，本用例必须随之改写。
func TestAppBackgroundUnverifiableLicenseFallsBack(t *testing.T) {
	prev := utils.GetFullSettings()
	utils.SetFullSettingsForTest(&utils.FullSettings{License: "not-a-real-license"})
	t.Cleanup(func() { utils.SetFullSettingsForTest(prev) })

	AppBackground()

	got := backgroundStateSnapshot()
	if !got.Called {
		t.Fatal("AppBackground did not record a start")
	}
	if got.LicTime != 20991201 {
		t.Fatalf("licTime = %d, want the observed license value 20991201", got.LicTime)
	}
	// utils.GetLicenseStatus 对无法解出的 license 返回黑盒观测值（valid），
	// 因此这条路径应记录为「已校验」。
	if !got.LicenseVerified {
		t.Fatal("LicenseVerified = false, want true (observed fallback values)")
	}
	if got.ClientNum != 99 {
		t.Fatalf("clientNum = %d, want 99", got.ClientNum)
	}
}
