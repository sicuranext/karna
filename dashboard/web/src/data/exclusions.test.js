import test from "node:test";
import assert from "node:assert/strict";

import {
  buildExclusionControls,
  exclusionBuilderFromFields,
  exclusionBuilderToFields,
  exclusionBuilderValid,
  exclusionFieldsFromControls,
  exclusionTargetFromMatchedAt,
  requestFieldFromTarget,
  requestFieldToTarget,
  exclusionInputValid,
  splitExclusionValues,
} from "./exclusions.js";

test("splits comma and newline values, trims and deduplicates", () => {
  assert.deepEqual(splitExclusionValues("934110, 942100\n934110"), ["934110", "942100"]);
});

test("builds all supported exclusion control forms", () => {
  const fields = {
    removeRuleIds: "934110, 942100-942199",
    removeTags: "attack-sqli\nattack-xss",
    targetRuleGroups: [{ selectors: "934110,942100", targets: "redirect_to\nrequest.header.value:x-client" }],
    targetTagGroups: [{ selectors: "attack-rce", targets: "request.arg.value:cmd, token" }],
  };
  const controls = buildExclusionControls(fields);
  assert.equal(controls.length, 10);
  assert.deepEqual(controls[0], { remove_rule: { rule_id: "934110" } });
  assert.deepEqual(controls[2], { remove_rules_by_tag: { tag: "attack-sqli" } });
  assert.ok(controls.some((control) => control.remove_target_from_rule_by_id?.target === "request.arg.value:redirect_to"));
  assert.ok(controls.some((control) => control.remove_target_rule_by_tag?.name === "request.arg.value:token"));
  assert.equal(exclusionInputValid(fields), true);
});

test("rejects partial variable mappings", () => {
  assert.equal(exclusionInputValid({ targetRuleGroups: [{ selectors: "934110", targets: "" }] }), false);
  assert.equal(exclusionInputValid({ removeTags: "attack-sqli", targetTagGroups: [{ selectors: "attack-xss", targets: "" }] }), false);
});

test("round-trips supported controls into guided fields", () => {
  const controls = [
    { remove_rule: { rule_id: "934110" } },
    { remove_rules_by_tag: { tag: "attack-sqli" } },
    { remove_target_from_rule_by_id: { rule_id: "942100", target: "request.arg.value:pwd" } },
    { remove_target_from_rule_by_id: { rule_id: "942100", target: "request.arg.value:user" } },
    { remove_target_rule_by_tag: { tag: "attack-xss", name: "request.header.value:x-client" } },
  ];
  const fields = exclusionFieldsFromControls(controls);
  assert.equal(fields.removeRuleIds, "934110");
  assert.equal(fields.removeTags, "attack-sqli");
  assert.deepEqual(fields.targetRuleGroups, [{ selectors: "942100", targets: "request.arg.value:pwd\nrequest.arg.value:user" }]);
  assert.deepEqual(buildExclusionControls(fields), controls);
});

test("does not claim unsupported controls are editable in guided mode", () => {
  assert.equal(exclusionFieldsFromControls([{ engine_off: true }]), null);
});

test("builds the All CRS rules request-header exclusion without exposing Karna targets", () => {
  const builder = {
    exclusionKind: "fields", allCrs: true, selectedRuleIds: [], selectedTags: [],
    advancedRuleIds: "", advancedTags: "", requestFields: [{ type: "header", name: "X-Pippo" }],
  };
  assert.equal(exclusionBuilderValid(builder), true);
  assert.deepEqual(buildExclusionControls(exclusionBuilderToFields(builder)), [{
    remove_target_rule_by_tag: { tag: "OWASP_CRS", name: "request.header.value:x-pippo" },
  }]);
});

test("combines complete detection messages, categories, and advanced selectors", () => {
  const builder = {
    exclusionKind: "detections", allCrs: false,
    selectedRuleIds: ["942100", "941100"], selectedTags: ["attack-rce"],
    advancedRuleIds: "920100-920199", advancedTags: "custom-policy", requestFields: [],
  };
  assert.deepEqual(buildExclusionControls(exclusionBuilderToFields(builder)), [
    { remove_rule: { rule_id: "942100" } },
    { remove_rule: { rule_id: "941100" } },
    { remove_rule: { rule_id: "920100-920199" } },
    { remove_rules_by_tag: { tag: "attack-rce" } },
    { remove_rules_by_tag: { tag: "custom-policy" } },
  ]);
});

test("round-trips friendly fields and rejects mappings that need the raw editor", () => {
  const fields = {
    removeRuleIds: "", removeTags: "",
    targetRuleGroups: [{ selectors: "942100\n941100", targets: "request.arg.value:q\nrequest.cookie.value:session" }],
    targetTagGroups: [{ selectors: "OWASP_CRS\nattack-xss", targets: "request.arg.value:q\nrequest.cookie.value:session" }],
  };
  const builder = exclusionBuilderFromFields(fields);
  assert.equal(builder.allCrs, true);
  assert.deepEqual(builder.requestFields, [{ type: "parameter", name: "q" }, { type: "cookie", name: "session" }]);
  assert.deepEqual(exclusionBuilderToFields(builder), fields);
  assert.equal(exclusionBuilderFromFields({
    ...fields,
    targetTagGroups: [{ selectors: "attack-xss", targets: "request.header.value:x-client" }],
  }), null);
});

test("translates observed event locations into friendly request fields", () => {
  assert.equal(exclusionTargetFromMatchedAt("request.headers.X-Pippo"), "request.header.value:x-pippo");
  assert.equal(exclusionTargetFromMatchedAt("request.args.redirect_to"), "request.arg.value:redirect_to");
  assert.equal(exclusionTargetFromMatchedAt("request.body.json.customer.address"), "request.body.json.value:customer.address");
  assert.deepEqual(requestFieldFromTarget("request.header.value:x-pippo"), { type: "header", name: "x-pippo" });
  assert.equal(requestFieldToTarget({ type: "json", name: "customer.address" }), "request.body.json.value:customer.address");
});
