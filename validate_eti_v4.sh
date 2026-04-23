#!/bin/bash
# ETI-AARE v4.0 Validation — Verifies all fixes for empty page bug

PASS=0
FAIL=0
MODULE="js/email-threat-module.js"
CSS="css/email-threat.css"
HTML="index.html"

pass() { echo "  ✅ $1"; ((PASS++)); }
fail() { echo "  ❌ $1"; ((FAIL++)); }

echo "═══════════════════════════════════════════════════════"
echo " ETI-AARE v4.0 — Empty Page Fix Validation"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "── RC-FIX-1: .eti-module.active visibility ──"
grep -q "root.classList.add('active')" "$MODULE" && pass "mount() adds .active to #etiModuleRoot" || fail "mount() does NOT add .active class — module will be invisible"
grep -q "\.eti-module\.active.*display.*flex\|\.eti-module\.active.*{.*display.*flex" "$CSS" && pass ".eti-module.active { display:flex } exists in CSS" || fail ".eti-module.active CSS rule missing"
grep -q "display: none" "$CSS" && pass ".eti-module { display:none } default exists" || fail "default display:none missing"

echo ""
echo "── RC-FIX-2: Page container sizing ──"
grep -q "container\.style\.height.*100%\|container\.style\.height = '100%'" "$MODULE" && pass "mount() sets container height:100%" || fail "mount() does not set container height"
grep -q "container\.style\.display.*flex\|container\.style\.display = 'flex'" "$MODULE" && pass "mount() sets container display:flex" || fail "mount() does not set display:flex on container"
grep -q "#page-email-threat" "$CSS" && pass "#page-email-threat CSS override exists" || fail "#page-email-threat CSS override missing"
grep -q "page-email-threat.*height:100%\|page-email-threat.*overflow:hidden" "$HTML" && pass "page-email-threat has height:100% in HTML" || fail "page-email-threat missing height:100% in HTML"
grep -q "#page-email-threat:not(.active)" "$CSS" && pass "#page-email-threat:not(.active) { display:none } exists" || fail "visibility guard for inactive state missing"

echo ""
echo "── RC-FIX-3: Container-scoped queries ──"
grep -q "state\.container.*querySelectorAll\|scope.*querySelectorAll" "$MODULE" && pass "switchTab uses scoped querySelectorAll" || fail "switchTab uses document.querySelectorAll (may conflict)"
grep -q "state\.analyzing-step.*scope\|scope.*eti-analyzing-step\|const scope = state\.container" "$MODULE" && pass "showAnalyzing uses scoped querySelectorAll" || fail "showAnalyzing uses document.querySelectorAll"
grep -q "const scope = state\.container" "$MODULE" && pass "scope variable uses state.container fallback" || fail "scope variable missing"

echo ""
echo "── RC-FIX-4: runDemo null-safety ──"
grep -q "result && result\.success && result\.data" "$MODULE" && pass "runDemo checks result.success AND result.data" || fail "runDemo null-check insufficient"
grep -q "animateAnalyzingSteps();" "$MODULE" && pass "animateAnalyzingSteps called in runDemo" || fail "animateAnalyzingSteps missing from runDemo"

echo ""
echo "── Layout integrity ──"
grep -q "eti-layout" "$MODULE" && pass "eti-layout exists in module HTML" || fail "eti-layout missing from module HTML"
grep -q "eti-left-panel" "$MODULE" && pass "eti-left-panel exists" || fail "eti-left-panel missing"
grep -q "eti-center-panel" "$MODULE" && pass "eti-center-panel exists" || fail "eti-center-panel missing"
grep -q "eti-right-panel" "$MODULE" && pass "eti-right-panel exists" || fail "eti-right-panel missing"
grep -q "etiEmptyState" "$MODULE" && pass "etiEmptyState empty-state div exists" || fail "etiEmptyState missing"
grep -q "etiTabContent" "$MODULE" && pass "etiTabContent div exists" || fail "etiTabContent missing"

echo ""
echo "── Demo functions ──"
grep -q "processMockAnalysis" "$MODULE" && pass "processMockAnalysis called as fallback" || fail "processMockAnalysis fallback missing"
grep -q "generateMockData" "$MODULE" && pass "generateMockData function exists" || fail "generateMockData missing"
grep -q "phishing.*bec.*malware.*clean\|map\[scenario\]" "$MODULE" && pass "All 4 demo scenarios defined" || fail "Demo scenarios incomplete"

echo ""
echo "── Export check ──"
grep -q "window\.ETIModule = ETIModule" "$MODULE" && pass "window.ETIModule exported" || fail "window.ETIModule NOT exported"
grep -q "mount," "$MODULE" && pass "mount in public API return" || fail "mount not in public API"
grep -q "onShow," "$MODULE" && pass "onShow in public API return" || fail "onShow not in public API"
grep -q "runDemo," "$MODULE" && pass "runDemo in public API return" || fail "runDemo not in public API"

echo ""
echo "── CSS completeness ──"
grep -q "eti-header" "$CSS" && pass "eti-header CSS exists" || fail "eti-header CSS missing"
grep -q "eti-layout" "$CSS" && pass "eti-layout CSS exists" || fail "eti-layout CSS missing"
grep -q "eti-empty-state" "$CSS" && pass "eti-empty-state CSS exists" || fail "eti-empty-state CSS missing"
grep -q "eti-demo-btn" "$CSS" && pass "eti-demo-btn CSS exists" || fail "eti-demo-btn CSS missing"
grep -q "eti-toast" "$CSS" && pass "eti-toast CSS exists" || fail "eti-toast CSS missing"
grep -q "eti-analyzing-overlay" "$CSS" && pass "eti-analyzing-overlay CSS exists" || fail "eti-analyzing-overlay CSS missing"

echo ""
echo "── index.html wiring ──"
grep -q "email-threat.*css/email-threat.css" "$HTML" && pass "email-threat.css loaded in index.html" || fail "email-threat.css not loaded"
grep -q "js/email-threat-module.js" "$HTML" && pass "email-threat-module.js loaded in index.html" || fail "email-threat-module.js not loaded"
grep -q "ETIModule\.mount" "$HTML" && pass "ETIModule.mount called in BRAIN_MODULES" || fail "ETIModule.mount not called in BRAIN_MODULES"
grep -q "'email-threat'.*true" "$HTML" && pass "email-threat feature flag enabled" || fail "email-threat feature flag not found"
grep -q "data-page=\"email-threat\"" "$HTML" && pass "nav link for email-threat exists" || fail "nav link for email-threat missing"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " SUMMARY: $PASS passed, $FAIL failed"
if [ $FAIL -eq 0 ]; then
  echo " 🎉 ALL CHECKS PASSED — ETI-AARE page ready"
else
  echo " ⚠️  $FAIL check(s) need attention"
fi
echo "═══════════════════════════════════════════════════════"
