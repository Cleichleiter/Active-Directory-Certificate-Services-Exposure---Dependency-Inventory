README.md text to add

Execution Context and Requirements



This toolkit supports two execution modes depending on where it is run.



Local-only mode (works on any Windows workstation)



Collects local certificate store inventory and local certificate usage signals



Produces valid adcs\_inventory.json and adcs\_inventory.csv outputs



Does not require domain membership or access to Active Directory



Directory-backed mode (requires domain access)



Enumerates AD CS Certificate Templates and Enterprise CAs from Active Directory



Summarizes template permissions (Enroll/AutoEnroll and high-impact rights) when enabled



Requires:



A domain-joined host



Network reachability to a domain controller



Sufficient read access to the Configuration naming context and PKI containers



Graceful skip behavior



When the script detects that directory-backed inventory is not available (for example, on a non-domain workstation), it will:



Log an informational message



Skip CA/template/permission modules safely



Continue producing local-only inventory outputs without throwing exceptions



Recommended run locations for full coverage



Domain Controller (DC)



Certificate Authority (CA) server



Domain-joined management host with RSAT and directory read access

