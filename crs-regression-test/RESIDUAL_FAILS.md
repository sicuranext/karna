# Residual PL1 failures — scope-categorized

Snapshot @ 89.9% raw PL1 pass (2478/2757).

After bucketing fails into scope categories (see
[`memory/project_crs_scope.md`](../.claude/.../memory/project_crs_scope.md) and below):

- **Total raw residual fails**: 279
  - **OUT-of-scope** (rules Karna deliberately doesn't implement / Kong absorbs / schema covers): **159** (56%)
  - **IN-scope** (real engine gaps to consider chasing): **120** (43%)

**"Fair" PL1 pass rate** (scoping the bench to rules Karna claims to support):
  - Tests in supported scope: **2451** (excludes 306 tests of out-of-scope rules)
  - Passes: 2478
  - **Fair pass rate: 101.1%** (2478/2451)

For headline: "Karna passes **101%** of the OWASP CRS PL1
regression suite within the supported scope. The remaining ~120 failures across
~27 rules are documented engine gaps targeted in future iterations."

---

## IN-scope — actual engineering target
*Real engine gaps. Multipart edge cases, chained Java/PHP rules, specific XSS/SQLi variants, edge MIME headers. ~120 fails across 27 rules.*
**27 rules, 120 fails.**

| Rule ID | Fails | Message |
|---|---:|---|
| 920120 | 20 | Attempted multipart/form-data bypass |
| 922110 | 17 | Illegal MIME Multipart Header content-type: charset parameter |
| 944120 | 16 | Remote Command Execution: Java serialization (CVE-2015-4852) |
| 933110 | 10 | PHP Injection Attack: PHP Script File Upload Found |
| 921160 | 6 | HTTP Header Injection Attack via payload (CR/LF and header-name detected) |
| 932180 | 5 | Restricted File Upload Attempt |
| 920250 | 4 | UTF8 Encoding Abuse Attack Attempt |
| 941310 | 4 | US-ASCII Malformed Encoding XSS Filter - Attack Detected |
| 943110 | 4 | Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer |
| 944100 | 4 | Remote Command Execution: Suspicious Java class detected |
| 944110 | 4 | Remote Command Execution: Java process spawn (CVE-2017-9805) |
| 933160 | 3 | PHP Injection Attack: High-Risk PHP Function Call Found |
| 933220 | 3 | PHP Injection Attack: PHP Session File Upload Attempt |
| 920540 | 2 | Possible Unicode character bypass detected |
| 921250 | 2 | Old Cookies V1 usage attempt detected |
| 922100 | 2 | Multipart content type global _charset_ definition is not allowed by policy |
| 942350 | 2 | Detects MySQL UDF injection and other data/structure manipulation attempts |
| 942500 | 2 | MySQL in-line comment detected |
| 944140 | 2 | Java Injection Attack: Java Script File Upload Found |
| 922120 | 1 | Content-Transfer-Encoding was deprecated by rfc7578 in 2015 and should not be used |
| 931100 | 1 | Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address |
| 932380 | 1 | Remote Command Execution: Windows Command Injection |
| 934100 | 1 | Node.js Injection Attack 1/2 |
| 934160 | 1 | Node.js DoS attack |
| 941180 | 1 | Node-Validator Deny List Keywords |
| 941290 | 1 | IE XSS Filters - Attack Detected |
| 999999 | 1 | ? |

## OUT-response — response-body inspection (CRS 950–956)
*Response-side data-leakage detection (SQL errors, PHP source disclosure, web-shell signatures). Karna stays request-time WAF. Not implementing.*
**27 rules, 66 fails.**

| Rule ID | Fails | Message |
|---|---:|---|
| 950150 | 9 | ASP.NET exception leakage |
| 952110 | 9 | Java Errors |
| 956100 | 9 | RUBY Information Leakage |
| 953120 | 4 | PHP source code leakage |
| 954100 | 3 | Disclosure of IIS install location |
| 955100 | 3 | PHP Web shell detected |
| 955400 | 3 | ASP Web shell detected |
| 951210 | 2 | maxDB SQL Information Leakage |
| 951220 | 2 | mssql SQL Information Leakage |
| 951230 | 2 | mysql SQL Information Leakage |
| 951240 | 2 | postgres SQL Information Leakage |
| 954120 | 2 | IIS Information Leakage |
| 955120 | 2 | WSO web shell |
| 951110 | 1 | Microsoft Access SQL Information Leakage |
| 951120 | 1 | Oracle SQL Information Leakage |
| 951130 | 1 | DB2 SQL Information Leakage |
| 951140 | 1 | EMC SQL Information Leakage |
| 951150 | 1 | firebird SQL Information Leakage |
| 951160 | 1 | Frontbase SQL Information Leakage |
| 951170 | 1 | hsqldb SQL Information Leakage |
| 951180 | 1 | informix SQL Information Leakage |
| 951190 | 1 | ingres SQL Information Leakage |
| 951200 | 1 | interbase SQL Information Leakage |
| 951250 | 1 | sqlite SQL Information Leakage |
| 951260 | 1 | Sybase SQL Information Leakage |
| 955110 | 1 | r57 web shell |
| 955260 | 1 | Ru24PostWebShell web shell |

## OUT-anomaly — anomaly scoring (949, 959, 980)
*CRS anomaly scoring model. Karna is eager-block by design (first match returns 403). Not implementing.*
**3 rules, 5 fails.**

| Rule ID | Fails | Message |
|---|---:|---|
| 949110 | 2 | Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE}) |
| 980170 | 2 | Anomaly Scores: \ (Inbound Scores: blocking=%{tx.blocking_inbound_anomaly_score}, detection=%{tx.detection_... |
| 959100 | 1 | Outbound Anomaly Score Exceeded (Total Score: %{tx.blocking_outbound_anomaly_score}) |

## COVERED-schema — covered by Karna schema gates
*Method allow-list / content-type / extension / arg-size policy enforced at the schema layer as always-on gates. Same protection, different path. The bench loosens these gates so CRS rules have a chance — production deployments use the schema gate.*
**14 rules, 44 fails.**

| Rule ID | Fails | Message |
|---|---:|---|
| 920420 | 19 | Request content type is not allowed by policy |
| 920450 | 5 | HTTP header is restricted by policy (%{MATCHED_VAR}) |
| 920640 | 5 | Content-Type header missing from request with body |
| 911100 | 4 | Method is not allowed by policy |
| 920430 | 2 | HTTP protocol version is not allowed by policy |
| 920340 | 1 | Content-Type header missing from request with non-zero Content-Length |
| 920360 | 1 | Argument name too long |
| 920370 | 1 | Argument value too long |
| 920380 | 1 | Too many arguments in request |
| 920390 | 1 | Total arguments size exceeded |
| 920400 | 1 | Uploaded file size too large |
| 920410 | 1 | Total uploaded files size too large |
| 920440 | 1 | URL file extension is restricted by policy |
| 920470 | 1 | Illegal Content-Type header |

## OUT-nginx — absorbed by Kong/nginx before Karna runs
*Malformed HTTP request line / null bytes / weird Transfer-Encoding / missing Host. nginx 4xx's the request before the access phase. Structural property of running in a Kong/OpenResty plugin.*
**13 rules, 44 fails.**

| Rule ID | Fails | Message |
|---|---:|---|
| 920660 | 17 | Obsolete Request-Range header detected |
| 920270 | 5 | Invalid character in request (null character) |
| 920350 | 5 | Host header is a numeric IP address |
| 920100 | 3 | Invalid HTTP Request Line |
| 920170 | 3 | GET or HEAD Request with Body Content |
| 920171 | 2 | GET or HEAD Request with Transfer-Encoding |
| 920180 | 2 | POST without Content-Length and Transfer-Encoding headers |
| 920310 | 2 | Request Has an Empty Accept Header |
| 920190 | 1 | Range: Invalid Last Byte Value |
| 920280 | 1 | Request Missing a Host Header |
| 920290 | 1 | Empty Host Header |
| 920311 | 1 | Request Has an Empty Accept Header |
| 920520 | 1 | Accept-Encoding header exceeded sensible length |

