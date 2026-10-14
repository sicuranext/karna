const MAX_DRAFT_TEXT = 240;
const MAX_REQUEST_PATH = 2048;

function clipped(value, max = MAX_DRAFT_TEXT) {
  return String(value || "").trim().slice(0, max);
}

export function exclusionTargetFromMatchedAt(matchedAt) {
  const target = clipped(matchedAt);
  const arg = target.match(/^request\.(?:query|arg|body\.urlencode|body\.multipart)\.(value|name):(.+)$/);
  if (arg) return `request.arg.${arg[1]}:${arg[2]}`;
  const observedArg = target.match(/^request\.args?\.(.+)$/);
  if (observedArg) return `request.arg.value:${observedArg[1]}`;
  const observedHeader = target.match(/^request\.headers?\.(.+)$/);
  if (observedHeader) return `request.header.value:${observedHeader[1].toLowerCase()}`;
  const observedCookie = target.match(/^request\.cookies?\.(.+)$/);
  if (observedCookie) return `request.cookie.value:${observedCookie[1]}`;
  const observedJson = target.match(/^request\.body\.json\.(?:value:)?(.+)$/);
  if (observedJson) return `request.body.json.value:${observedJson[1]}`;
  return target;
}

export function normalizeExclusionTarget(value) {
  const target = clipped(value);
  if (!target) return "";
  if (target.startsWith("request.")) return target;
  return `request.arg.value:${target}`;
}

export const EXCLUSION_FIELD_TYPES = [
  { id: "parameter", label: "Request parameter", placeholder: "redirect_to" },
  { id: "header", label: "Request header", placeholder: "X-Pippo" },
  { id: "cookie", label: "Cookie", placeholder: "wordpress_logged_in" },
  { id: "json", label: "JSON body field", placeholder: "customer.address" },
  { id: "body", label: "Entire request body", placeholder: "" },
];

export function requestFieldToTarget(field) {
  const type = String(field?.type || "");
  const name = clipped(field?.name);
  if (type === "body") return "request.body";
  if (!name) return "";
  if (type === "parameter") return `request.arg.value:${name}`;
  if (type === "header") return `request.header.value:${name.toLowerCase()}`;
  if (type === "cookie") return `request.cookie.value:${name}`;
  if (type === "json") return `request.body.json.value:${name}`;
  return "";
}

export function requestFieldFromTarget(value) {
  const target = clipped(value);
  if (target === "request.body") return { type: "body", name: "" };
  const mappings = [
    ["request.arg.value:", "parameter"],
    ["request.header.value:", "header"],
    ["request.cookie.value:", "cookie"],
    ["request.body.json.value:", "json"],
  ];
  for (const [prefix, type] of mappings) {
    if (target.startsWith(prefix) && target.length > prefix.length) {
      return { type, name: target.slice(prefix.length) };
    }
  }
  return null;
}

export function splitExclusionValues(value) {
  const seen = new Set();
  return String(value || "")
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter((item) => item && !seen.has(item) && seen.add(item));
}

function populatedGroups(groups) {
  return (Array.isArray(groups) ? groups : []).filter((group) =>
    String(group?.selectors || "").trim() || String(group?.targets || "").trim());
}

export function exclusionInputValid(exclusion) {
  const direct = splitExclusionValues(exclusion?.removeRuleIds).length
    + splitExclusionValues(exclusion?.removeTags).length;
  const ruleGroups = populatedGroups(exclusion?.targetRuleGroups);
  const tagGroups = populatedGroups(exclusion?.targetTagGroups);
  const complete = [...ruleGroups, ...tagGroups].every((group) =>
    splitExclusionValues(group.selectors).length && splitExclusionValues(group.targets).length);
  return complete && (direct > 0 || ruleGroups.length > 0 || tagGroups.length > 0);
}

export function buildExclusionControls(exclusion) {
  const controls = [];
  splitExclusionValues(exclusion?.removeRuleIds).forEach((ruleId) => {
    controls.push({ remove_rule: { rule_id: ruleId } });
  });
  splitExclusionValues(exclusion?.removeTags).forEach((tag) => {
    controls.push({ remove_rules_by_tag: { tag } });
  });
  populatedGroups(exclusion?.targetRuleGroups).forEach((group) => {
    splitExclusionValues(group.selectors).forEach((ruleId) => {
      splitExclusionValues(group.targets).forEach((target) => {
        controls.push({
          remove_target_from_rule_by_id: {
            rule_id: ruleId,
            target: normalizeExclusionTarget(target),
          },
        });
      });
    });
  });
  populatedGroups(exclusion?.targetTagGroups).forEach((group) => {
    splitExclusionValues(group.selectors).forEach((tag) => {
      splitExclusionValues(group.targets).forEach((target) => {
        controls.push({
          remove_target_rule_by_tag: {
            tag,
            name: normalizeExclusionTarget(target),
          },
        });
      });
    });
  });
  return controls;
}

function appendGrouped(groups, selector, target) {
  const found = groups.find((group) => group.selectors === selector);
  if (found) found.targets = `${found.targets}\n${target}`;
  else groups.push({ selectors: selector, targets: target });
}

export function exclusionFieldsFromControls(controls) {
  if (!Array.isArray(controls) || controls.length === 0) return null;
  const removeRuleIds = [];
  const removeTags = [];
  const targetRuleGroups = [];
  const targetTagGroups = [];

  for (const control of controls) {
    if (!control || typeof control !== "object" || Array.isArray(control) || Object.keys(control).length !== 1) return null;
    if (control.remove_rule?.rule_id) removeRuleIds.push(String(control.remove_rule.rule_id));
    else if (control.remove_rules_by_tag?.tag) removeTags.push(String(control.remove_rules_by_tag.tag));
    else if (control.remove_target_from_rule_by_id?.rule_id && control.remove_target_from_rule_by_id?.target) {
      appendGrouped(targetRuleGroups, String(control.remove_target_from_rule_by_id.rule_id), String(control.remove_target_from_rule_by_id.target));
    } else if (control.remove_target_rule_by_tag?.tag && control.remove_target_rule_by_tag?.name) {
      appendGrouped(targetTagGroups, String(control.remove_target_rule_by_tag.tag), String(control.remove_target_rule_by_tag.name));
    } else return null;
  }

  return {
    removeRuleIds: removeRuleIds.join("\n"),
    removeTags: removeTags.join("\n"),
    targetRuleGroups,
    targetTagGroups,
  };
}

function sameValues(left, right) {
  const a = [...new Set(left)].sort();
  const b = [...new Set(right)].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export function exclusionBuilderToFields(builder) {
  const selectedRuleIds = Array.isArray(builder?.selectedRuleIds) ? builder.selectedRuleIds : [];
  const selectedTags = Array.isArray(builder?.selectedTags) ? builder.selectedTags : [];
  const ruleIds = [...new Set([...selectedRuleIds, ...splitExclusionValues(builder?.advancedRuleIds)])];
  const tags = [...new Set([
    ...(builder?.allCrs ? ["OWASP_CRS"] : []),
    ...selectedTags,
    ...splitExclusionValues(builder?.advancedTags),
  ])];

  if (builder?.exclusionKind === "detections") {
    return {
      removeRuleIds: ruleIds.join("\n"), removeTags: tags.join("\n"),
      targetRuleGroups: [], targetTagGroups: [],
    };
  }

  const targets = (Array.isArray(builder?.requestFields) ? builder.requestFields : [])
    .map(requestFieldToTarget).filter(Boolean);
  const targetText = [...new Set(targets)].join("\n");
  return {
    removeRuleIds: "", removeTags: "",
    targetRuleGroups: ruleIds.length && targetText ? [{ selectors: ruleIds.join("\n"), targets: targetText }] : [],
    targetTagGroups: tags.length && targetText ? [{ selectors: tags.join("\n"), targets: targetText }] : [],
  };
}

export function exclusionBuilderValid(builder) {
  const fields = exclusionBuilderToFields(builder);
  if (!exclusionInputValid(fields)) return false;
  if (builder?.exclusionKind !== "fields") return true;
  const requestFields = Array.isArray(builder?.requestFields) ? builder.requestFields : [];
  return requestFields.length > 0 && requestFields.every((field) => requestFieldToTarget(field));
}

export function exclusionBuilderFromFields(fields) {
  const removeRuleIds = splitExclusionValues(fields?.removeRuleIds);
  const removeTags = splitExclusionValues(fields?.removeTags);
  const ruleGroups = populatedGroups(fields?.targetRuleGroups);
  const tagGroups = populatedGroups(fields?.targetTagGroups);
  const hasCompleteDetections = removeRuleIds.length || removeTags.length;
  const hasTargetMappings = ruleGroups.length || tagGroups.length;
  if (hasCompleteDetections && hasTargetMappings) return null;

  if (hasCompleteDetections) {
    return {
      exclusionKind: "detections",
      allCrs: removeTags.includes("OWASP_CRS"),
      selectedRuleIds: removeRuleIds,
      selectedTags: removeTags.filter((tag) => tag !== "OWASP_CRS"),
      advancedRuleIds: "", advancedTags: "", requestFields: [],
    };
  }

  const targetSets = [
    ...ruleGroups.map((group) => splitExclusionValues(group.targets)),
    ...tagGroups.map((group) => splitExclusionValues(group.targets)),
  ];
  if (!targetSets.length || targetSets.some((targets) => !sameValues(targetSets[0], targets))) return null;
  const requestFields = targetSets[0].map(requestFieldFromTarget);
  if (requestFields.some((field) => !field)) return null;
  const ruleIds = ruleGroups.flatMap((group) => splitExclusionValues(group.selectors));
  const tags = tagGroups.flatMap((group) => splitExclusionValues(group.selectors));
  return {
    exclusionKind: "fields",
    allCrs: tags.includes("OWASP_CRS"),
    selectedRuleIds: [...new Set(ruleIds)],
    selectedTags: [...new Set(tags.filter((tag) => tag !== "OWASP_CRS"))],
    advancedRuleIds: "", advancedTags: "", requestFields,
  };
}

export function exclusionTargetName(target) {
  const value = clipped(target);
  const colon = value.lastIndexOf(":");
  return colon >= 0 ? value.slice(colon + 1) : value;
}

export function exclusionRuleId(sourceRuleId, target) {
  const suffix = `${clipped(sourceRuleId)}_${exclusionTargetName(target)}`
    .replace(/[^a-zA-Z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80);
  return `exclude_${suffix || "false_positive"}`;
}

export function eventExclusionDraft(ev, match, pluginId) {
  const matchedAt = clipped(match?.matched_parts?.[0]?.on);
  const excludeTarget = exclusionTargetFromMatchedAt(matchedAt);
  const rawPath = clipped(String(ev?.request?.uri || "/").split("?", 1)[0], MAX_REQUEST_PATH) || "/";
  const sourceRuleId = clipped(match?.rule_id);

  return {
    pluginId: clipped(pluginId),
    serviceName: clipped(ev?.service?.name),
    id: exclusionRuleId(sourceRuleId, excludeTarget),
    phase: "access",
    message: `Exclude ${exclusionTargetName(excludeTarget) || "matched target"} from rule ${sourceRuleId} on ${rawPath}`.slice(0, MAX_DRAFT_TEXT),
    variable: "request.raw_path",
    op: "eq",
    value: rawPath,
    transforms: [],
    action: "exclusion",
    exclusionKind: "fields",
    allCrs: false,
    selectedRuleIds: sourceRuleId ? [sourceRuleId] : [],
    selectedTags: [],
    advancedRuleIds: "",
    advancedTags: "",
    requestFields: [requestFieldFromTarget(excludeTarget)].filter(Boolean),
    sourceRuleMessage: clipped(match?.message),
    matchedAt,
  };
}
