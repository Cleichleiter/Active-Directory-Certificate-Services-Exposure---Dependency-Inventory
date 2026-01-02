Limitations



This document outlines the intentional limitations of this project and the boundaries within which its outputs should be used.



These limitations are by design. They reflect a deliberate tradeoff in favor of safety, correctness, and interpretability.



Read-Only Visibility



This project performs inspection only.



It does not:



Modify AD CS configuration



Interact with authentication workflows



Trigger enrollment or renewal



Validate trust paths through live authentication



As a result, some dependencies may exist that cannot be observed without active interaction.



Dependency Discovery Is Best-Effort



Certificate-based dependencies are often implicit.



This project can only identify dependencies that are:



Discoverable through configuration and metadata



Observable without authentication attempts



Derivable without inference or speculation



If a dependency is undocumented and not externally visible, it may not appear in results.



Absence of a finding does not imply absence of reliance.



No Exploit or Abuse Context



The project intentionally avoids:



Mapping exploit paths



Identifying abuse scenarios



Assigning vulnerability classifications



Evaluating attack feasibility



As a result, outputs should not be used as evidence of security posture or exploit risk.



This tool answers “what depends on trust,” not “how trust can be broken.”



No Severity or Risk Scoring



Findings are not scored, ranked, or labeled as high or low risk.



Severity is context-dependent and must consider:



Business criticality



Availability requirements



Operational maturity



Ownership and documentation quality



Automated severity labeling would obscure nuance and create false confidence.



Environment-Specific Interpretation Required



Results are valid only for the environment in which they are collected.



They do not account for:



Organizational processes



Incident response capability



Vendor support contracts



Change management maturity



Interpretation without local context may lead to incorrect conclusions.



AD CS Scope Only



This project focuses exclusively on Active Directory Certificate Services.



It does not inventory:



Third-party PKI platforms



Cloud-native certificate services



Application-managed trust stores



Non-domain-integrated identity systems



Organizations with hybrid or multi-PKI environments must supplement this inventory.



Not a Replacement for Other Assessments



This project does not replace:



Red team assessments



AD CS hardening guides



Compliance audits



Formal threat modeling



Cryptographic migration planning



It is intended to precede and inform those efforts.



Intentional Conservatism



Some potentially interesting data points are intentionally excluded because:



They require elevated risk to collect



They depend on assumptions



They cannot be validated safely



The project favors reliable partial visibility over speculative completeness.



Expected Use Pattern



This tool is most effective when used as:



A baseline inventory



A documentation accelerator



A discussion catalyst



A planning aid



It is not intended for continuous monitoring or real-time detection.



Summary



These limitations are not deficiencies.



They are design decisions aligned with the project’s purpose:

to make certificate-based trust visible without introducing risk, noise, or false authority.



Understanding these boundaries is essential to using the project responsibly.

