Execution Modes



This project supports two execution modes depending on where it is run. The output files are always produced, but the scope of collected artifacts varies based on Active Directory availability.



Mode 1: LocalOnly



LocalOnly mode occurs when the script is run on a host that cannot access Active Directory PKI objects. This is most common on:



Non-domain-joined workstations



Domain-joined hosts without LDAP/Configuration NC access



Restricted environments where directory bind fails



In LocalOnly mode, the script collects:



Local certificate usage (machine store)



Local certificate usage (current user store) when enabled



In LocalOnly mode, the script skips:



Enterprise CA discovery



Certificate Template inventory



Template permission summarization



The output still includes:



reports\\adcs\_inventory.json



reports\\adcs\_inventory.csv



The JSON metadata (meta) will include:



executionMode: LocalOnly



skippedModules: list of skipped modules



skipReason: NotDomainJoined or DirectoryBindUnavailable



Mode 2: DirectoryBacked



DirectoryBacked mode occurs when the script can bind to Active Directory and read AD CS PKI objects from the Configuration naming context. This is most common on:



Domain Controllers



AD CS CA servers



Domain-joined administrative workstations with directory read access



In DirectoryBacked mode, the script can collect:



Enterprise CA objects



Certificate Template objects



Template permission summaries (when enabled)



Local certificate usage (optional)



The output includes:



reports\\adcs\_inventory.json



reports\\adcs\_inventory.csv



reports\\template\_permissions.json (only when permission rows are produced)



The JSON metadata (meta) will include:



executionMode: DirectoryBacked



skippedModules: \[]



skipReason: None



Recommended Run Locations for Full Coverage



If you want CA/template/permissions output, run on one of the following:



AD CS CA server



Domain Controller



Domain-joined management host with RSAT and directory read access



Notes



All collection is read-only.



The tool is designed to produce valid output even when only partial visibility is available.



Skipped modules are not treated as errors; they are explicitly recorded in the output metadata.

