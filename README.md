Active Directory Certificate Services Exposure \& Dependency Inventory



This project provides a read-only inventory and dependency analysis of Active Directory Certificate Services (AD CS) in enterprise environments.



Its purpose is to help organizations understand where certificate-based trust exists, what depends on it, and what breaks if it fails—before attempting enforcement, migration, or security controls.



Most environments operate AD CS as critical infrastructure without a clear understanding of its trust boundaries or blast radius. This project exists to make those dependencies visible.



What This Project Does



Inventories AD CS infrastructure and certificate authorities



Enumerates enabled certificate templates and their intended usage



Identifies certificate-based trust dependencies across services



Surfaces implicit and undocumented trust relationships



Produces machine-readable and human-readable inventory outputs



Supports risk, availability, and migration planning discussions



What This Project Does Not Do



Perform exploitation or privilege escalation



Map ESC attack paths



Simulate adversary behavior



Modify certificate services or templates



Enforce cryptographic or identity controls



This is not a red-team tool. It is an engineering and architecture visibility tool.



Intended Use Cases



Understanding certificate trust as a dependency, not just a security control



Identifying single points of failure in identity infrastructure



Preparing for certificate lifecycle changes or migrations



Supporting audits, risk assessments, and documentation efforts



Informing modernization or cryptographic transition planning



Project Philosophy



Certificate services create implicit trust.



Implicit trust is often undocumented, widely relied upon, and poorly understood until it fails.

This project treats AD CS as infrastructure, not as an attack surface.



Inventory comes before enforcement.

Understanding comes before controls.



Project Status



This project is active but intentionally scoped.



The current goal is to establish a reliable baseline for AD CS exposure and dependency visibility. Future enhancements may be added incrementally based on real-world needs, with an emphasis on safety, correctness, and clarity over feature expansion.



There is no fixed roadmap or release schedule.



Audience



Systems and identity engineers



Infrastructure and enterprise architects



Security and risk professionals



Technical leaders responsible for availability and trust



Familiarity with Active Directory concepts is assumed.



License



This project is licensed under the terms of the included LICENSE file.

