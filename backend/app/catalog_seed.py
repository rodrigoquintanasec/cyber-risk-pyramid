"""Initial technology catalogue (seed data). It is loaded into SQLite once; from then on the DATABASE is the source of truth and new
technologies are added through the API/UI, not by editing this file.

Rules: CPE ids are only those that exist in the NVD CPE dictionary (verified with scripts/verify_cpe.py against the official API; the result
is stored in the `verified` marker of each entry). KEV matchers use the vendor/product strings CISA actually publishes. News patterns are
explicit product names only (never a bare vendor word or an ambiguous common word). A technology with no CPE (cloud services) never gets a
Threat Signal Score.
cpes: "part:vendor:product" tokens. kind: product | family | platform | cloud.
"""
from __future__ import annotations

# Verified against the NVD CPE dictionary (official API) on 2026-11-17: every "part:vendor:product" token below returned >= 1 dictionary entry.
# Candidates that returned none were REMOVED, not guessed (nutanix acropolis_operating_system, redhat podman, ixsystems truenas, crowdstrike falcon_sensor).
# id, name, vendor, product, category, kind, description, aliases, cpes, kev [(vendor_regex, product_regex)], news [regex]
OS, NS, NW, VIRT, CON, WEB, DB, CLOUD, IAM, MAIL, DEV, MON, ENT, STOR, REM = (
    "Operating Systems", "Network Security", "Networking", "Virtualization", "Containers & Orchestration", "Web Servers", "Databases", "Cloud Platforms",
    "Identity & Access Management", "Email & Collaboration", "DevOps & Development", "Monitoring & Security", "Enterprise Applications", "Storage & Backup", "Remote Access")
CATEGORIES = (OS, NS, NW, VIRT, CON, WEB, DB, CLOUD, IAM, MAIL, DEV, MON, ENT, STOR, REM)

NEW: list[tuple] = [
    # ------------------------------------------------------------------ Operating Systems
    ("windows-10", "Windows 10", "Microsoft", "Windows 10", OS, "family", "Microsoft desktop operating system (feature releases).", ["Win10"], "o:microsoft:windows_10_1507 o:microsoft:windows_10_1607 o:microsoft:windows_10_1809 o:microsoft:windows_10_21h2 o:microsoft:windows_10_22h2", [], [r"\bwindows 10\b"]),
    ("windows-11", "Windows 11", "Microsoft", "Windows 11", OS, "family", "Microsoft desktop operating system (feature releases).", ["Win11"], "o:microsoft:windows_11_21h2 o:microsoft:windows_11_22h2 o:microsoft:windows_11_23h2 o:microsoft:windows_11_24h2", [], [r"\bwindows 11\b"]),
    ("ubuntu", "Ubuntu Linux", "Canonical", "Ubuntu Linux", OS, "product", "Debian-based Linux distribution by Canonical.", ["Ubuntu"], "o:canonical:ubuntu_linux", [], [r"\bubuntu\b"]),
    ("debian", "Debian Linux", "Debian", "Debian Linux", OS, "product", "Community Linux distribution.", ["Debian GNU/Linux"], "o:debian:debian_linux", [], [r"\bdebian\b"]),
    ("rhel", "Red Hat Enterprise Linux", "Red Hat", "Enterprise Linux", OS, "product", "Commercial enterprise Linux distribution.", ["RHEL"], "o:redhat:enterprise_linux", [], [r"red hat enterprise linux", r"\brhel\b"]),
    ("centos", "CentOS", "CentOS", "CentOS", OS, "product", "Community RHEL-compatible Linux distribution.", [], "o:centos:centos", [], [r"\bcentos\b"]),
    ("suse-linux-enterprise", "SUSE Linux Enterprise Server", "SUSE", "Linux Enterprise Server", OS, "product", "Enterprise Linux distribution by SUSE.", ["SLES"], "o:suse:linux_enterprise_server", [], [r"suse linux enterprise", r"\bsles\b"]),
    ("macos", "macOS", "Apple", "macOS", OS, "product", "Apple desktop operating system.", ["Mac OS X"], "o:apple:macos", [], [r"\bmacos\b"]),
    ("android-os", "Android", "Google", "Android", OS, "product", "Google mobile operating system.", [], "o:google:android", [("android", r".*")], [r"\bandroid\b"]),
    ("freebsd", "FreeBSD", "FreeBSD", "FreeBSD", OS, "product", "BSD operating system.", [], "o:freebsd:freebsd", [], [r"\bfreebsd\b"]),
    ("oracle-linux", "Oracle Linux", "Oracle", "Linux", OS, "product", "Enterprise Linux distribution by Oracle.", [], "o:oracle:linux", [], [r"oracle linux"]),
    ("ibm-aix", "IBM AIX", "IBM", "AIX", OS, "product", "IBM UNIX operating system.", ["AIX"], "o:ibm:aix", [], [r"\bibm aix\b"]),
    ("oracle-solaris", "Oracle Solaris", "Oracle", "Solaris", OS, "product", "Oracle UNIX operating system.", ["Solaris"], "o:oracle:solaris", [], [r"\bsolaris\b"]),
    # ------------------------------------------------------------------ Network Security
    ("palo-alto-pan-os", "Palo Alto PAN-OS", "Palo Alto Networks", "PAN-OS", NS, "product", "Operating system of Palo Alto Networks firewalls.", ["PAN-OS"], "o:paloaltonetworks:pan-os", [("palo alto networks", r"pan-os")], [r"\bpan-os\b"]),
    ("palo-alto-globalprotect", "Palo Alto GlobalProtect", "Palo Alto Networks", "GlobalProtect", NS, "product", "Palo Alto Networks VPN gateway/client.", ["GlobalProtect"], "a:paloaltonetworks:globalprotect", [], [r"\bglobalprotect\b"]),
    ("cisco-asa-ftd", "Cisco ASA / Firepower Threat Defense", "Cisco", "Adaptive Security Appliance / FTD", NS, "family", "Cisco firewall software family.", ["Cisco ASA", "FTD"], "o:cisco:adaptive_security_appliance_software a:cisco:firepower_threat_defense", [("cisco", r"adaptive security appliance.*|.*firepower threat defense.*|secure firewall adaptive.*")], [r"cisco asa\b", r"firepower threat defense", r"adaptive security appliance"]),
    ("cisco-ise", "Cisco Identity Services Engine", "Cisco", "Identity Services Engine", NS, "product", "Cisco network access control platform.", ["Cisco ISE"], "a:cisco:identity_services_engine", [("cisco", r"identity services engine")], [r"identity services engine", r"\bcisco ise\b"]),
    ("sonicwall-sonicos", "SonicWall SonicOS", "SonicWall", "SonicOS", NS, "product", "SonicWall firewall operating system.", ["SonicOS"], "o:sonicwall:sonicos", [("sonicwall", r"sonicos")], [r"\bsonicos\b"]),
    ("sophos-firewall", "Sophos Firewall", "Sophos", "Firewall (SFOS)", NS, "product", "Sophos firewall operating system.", ["SFOS", "XG Firewall"], "o:sophos:sfos", [("sophos", r"firewall")], [r"sophos firewall", r"\bsfos\b"]),
    ("watchguard-fireware", "WatchGuard Fireware", "WatchGuard", "Fireware", NS, "product", "WatchGuard Firebox firewall operating system.", ["Firebox"], "o:watchguard:fireware", [("watchguard", r"firebox")], [r"watchguard firebox", r"\bfireware\b"]),
    ("juniper-junos", "Juniper Junos OS", "Juniper", "Junos", NS, "product", "Juniper network operating system.", ["Junos"], "o:juniper:junos", [("juniper", r"junos.*")], [r"\bjunos\b"]),
    ("f5-big-ip", "F5 BIG-IP", "F5", "BIG-IP", NS, "family", "F5 application delivery and security platform.", ["BIG-IP"], "a:f5:big-ip_local_traffic_manager a:f5:big-ip_access_policy_manager a:f5:big-ip_application_security_manager", [("f5", r"big-ip.*")], [r"\bbig-ip\b"]),
    ("citrix-netscaler", "Citrix NetScaler", "Citrix", "NetScaler ADC / Gateway", NS, "family", "Citrix application delivery controller and gateway.", ["NetScaler", "Citrix ADC"], "a:citrix:netscaler_application_delivery_controller a:citrix:netscaler_gateway", [("citrix", r"netscaler.*|application delivery controller.*")], [r"\bnetscaler\b"]),
    ("ivanti-connect-secure", "Ivanti Connect Secure", "Ivanti", "Connect Secure", NS, "product", "Ivanti (formerly Pulse Secure) SSL VPN.", ["Pulse Connect Secure"], "a:ivanti:connect_secure a:pulsesecure:pulse_connect_secure", [("ivanti", r"connect secure.*|pulse connect secure|policy secure.*"), ("pulse secure", r".*")], [r"ivanti connect secure", r"pulse (?:connect )?secure"]),
    ("openssl", "OpenSSL", "OpenSSL", "OpenSSL", NS, "product", "Cryptography and TLS library.", [], "a:openssl:openssl", [], [r"\bopenssl\b"]),
    ("check-point", "Check Point Gateways", "Check Point", "Security Gateway", NS, "family", "Check Point firewall and gateway software.", ["Quantum", "Gaia"], "o:checkpoint:gaia_os a:checkpoint:security_gateway", [], [r"check point (?:quantum|gaia|security gateway)"]),
    # ------------------------------------------------------------------ Networking
    ("cisco-ios-xe", "Cisco IOS XE", "Cisco", "IOS XE", NW, "product", "Cisco network operating system for enterprise switches and routers.", ["IOS XE"], "o:cisco:ios_xe", [("cisco", r"ios and ios xe.*|ios xe.*|ios software and cisco ios xe.*|ios, xr, and xe.*")], [r"\bios xe\b"]),
    ("cisco-ios", "Cisco IOS", "Cisco", "IOS", NW, "product", "Classic Cisco network operating system.", ["Cisco IOS"], "o:cisco:ios", [("cisco", r"ios software|ios")], []),
    ("cisco-nx-os", "Cisco NX-OS", "Cisco", "NX-OS", NW, "product", "Cisco data-centre switch operating system.", ["NX-OS"], "o:cisco:nx-os", [], [r"\bnx-os\b"]),
    ("arista-eos", "Arista EOS", "Arista", "EOS", NW, "product", "Arista switch operating system.", ["EOS"], "o:arista:eos", [], [r"arista eos"]),
    ("mikrotik-routeros", "MikroTik RouterOS", "MikroTik", "RouterOS", NW, "product", "MikroTik router operating system.", ["RouterOS"], "o:mikrotik:routeros", [("mikrotik", r"routeros")], [r"\brouteros\b"]),
    ("aruba-arubaos", "Aruba ArubaOS", "HPE Aruba", "ArubaOS", NW, "product", "HPE Aruba wireless/controller operating system.", ["ArubaOS"], "o:arubanetworks:arubaos", [], [r"\barubaos\b"]),
    ("ubiquiti-unifi-os", "Ubiquiti UniFi OS", "Ubiquiti", "UniFi OS", NW, "product", "Ubiquiti UniFi console operating system.", ["UniFi"], "o:ui:unifi_os", [("ubiquiti", r"unifi os")], [r"\bunifi\b"]),
    # ------------------------------------------------------------------ Virtualization
    ("proxmox-ve", "Proxmox VE", "Proxmox", "Virtual Environment", VIRT, "product", "Open-source virtualization management platform.", ["Proxmox"], "a:proxmox:virtual_environment", [], [r"\bproxmox\b"]),
    ("citrix-hypervisor", "Citrix Hypervisor", "Citrix", "Hypervisor", VIRT, "product", "Citrix (XenServer) hypervisor.", ["XenServer"], "o:citrix:hypervisor a:citrix:xenserver", [], [r"citrix hypervisor", r"\bxenserver\b"]),
    ("xen", "Xen Hypervisor", "Xen Project", "Xen", VIRT, "product", "Open-source type-1 hypervisor.", ["Xen"], "o:xen:xen", [], [r"xen hypervisor", r"xen project"]),
    ("qemu", "QEMU", "QEMU", "QEMU", VIRT, "product", "Open-source machine emulator and virtualizer.", [], "a:qemu:qemu", [], [r"\bqemu\b"]),
    ("virtualbox", "Oracle VM VirtualBox", "Oracle", "VM VirtualBox", VIRT, "product", "Desktop virtualization by Oracle.", ["VirtualBox"], "a:oracle:vm_virtualbox", [], [r"\bvirtualbox\b"]),
    # ------------------------------------------------------------------ Containers & Orchestration
    ("containerd", "containerd", "Linux Foundation", "containerd", CON, "product", "Container runtime.", [], "a:linuxfoundation:containerd", [], [r"\bcontainerd\b"]),
    ("runc", "runc", "Open Container Initiative", "runc", CON, "product", "Low-level container runtime.", [], "a:linuxfoundation:runc", [], [r"\brunc\b"]),
    ("openshift", "Red Hat OpenShift", "Red Hat", "OpenShift Container Platform", CON, "product", "Kubernetes-based application platform.", ["OpenShift"], "a:redhat:openshift_container_platform", [], [r"\bopenshift\b"]),
    ("rancher", "SUSE Rancher", "SUSE", "Rancher", CON, "product", "Kubernetes management platform.", ["Rancher"], "a:suse:rancher", [], [r"\brancher\b"]),
    ("harbor", "Harbor", "Harbor", "Harbor", CON, "product", "Open-source container registry.", [], "a:goharbor:harbor", [], [r"harbor registry", r"\bgoharbor\b"]),
    ("argo-cd", "Argo CD", "Argo Project", "Argo CD", CON, "product", "GitOps continuous delivery for Kubernetes.", ["ArgoCD"], "a:argoproj:argo_cd", [], [r"\bargo ?cd\b"]),
    ("istio", "Istio", "Istio", "Istio", CON, "product", "Service mesh.", [], "a:istio:istio", [], [r"\bistio\b"]),
    ("etcd", "etcd", "etcd", "etcd", CON, "product", "Distributed key-value store used by Kubernetes.", [], "a:etcd:etcd", [], [r"\betcd\b"]),
    ("helm", "Helm", "Helm", "Helm", CON, "product", "Kubernetes package manager.", [], "a:helm:helm", [], [r"helm chart"]),
    # ------------------------------------------------------------------ Web Servers
    ("apache-http-server", "Apache HTTP Server", "Apache", "HTTP Server", WEB, "product", "Apache web server.", ["httpd"], "a:apache:http_server", [("apache", r"http server")], [r"apache http server", r"apache httpd", r"\bhttpd\b"]),
    ("nginx", "NGINX", "F5", "NGINX", WEB, "product", "Web server and reverse proxy.", ["nginx"], "a:f5:nginx a:nginx:nginx", [], [r"\bnginx\b"]),
    ("microsoft-iis", "Microsoft IIS", "Microsoft", "Internet Information Services", WEB, "product", "Windows web server.", ["IIS"], "a:microsoft:internet_information_services", [], [r"internet information services", r"microsoft iis"]),
    ("apache-tomcat", "Apache Tomcat", "Apache", "Tomcat", WEB, "product", "Java servlet container.", ["Tomcat"], "a:apache:tomcat", [("apache", r"tomcat")], [r"apache tomcat", r"\btomcat\b"]),
    ("haproxy", "HAProxy", "HAProxy", "HAProxy", WEB, "product", "Load balancer and reverse proxy.", [], "a:haproxy:haproxy", [], [r"\bhaproxy\b"]),
    ("lighttpd", "lighttpd", "lighttpd", "lighttpd", WEB, "product", "Lightweight web server.", [], "a:lighttpd:lighttpd", [], [r"\blighttpd\b"]),
    ("php", "PHP", "PHP Group", "PHP", WEB, "product", "Server-side scripting language.", [], "a:php:php", [("php group", r"php")], [r"\bphp\b"]),
    ("nodejs", "Node.js", "OpenJS Foundation", "Node.js", WEB, "product", "JavaScript runtime.", ["NodeJS"], "a:nodejs:node.js", [], [r"node\.js", r"\bnodejs\b"]),
    # ------------------------------------------------------------------ Databases
    ("postgresql", "PostgreSQL", "PostgreSQL", "PostgreSQL", DB, "product", "Open-source relational database.", ["Postgres"], "a:postgresql:postgresql", [], [r"\bpostgresql\b", r"\bpostgres\b"]),
    ("mysql", "MySQL", "Oracle", "MySQL", DB, "product", "Open-source relational database.", [], "a:oracle:mysql", [], [r"\bmysql\b"]),
    ("mariadb", "MariaDB", "MariaDB", "MariaDB", DB, "product", "MySQL-compatible relational database.", [], "a:mariadb:mariadb", [], [r"\bmariadb\b"]),
    ("mongodb", "MongoDB", "MongoDB", "MongoDB", DB, "product", "Document database.", [], "a:mongodb:mongodb", [], [r"\bmongodb\b"]),
    ("redis", "Redis", "Redis", "Redis", DB, "product", "In-memory data store.", [], "a:redis:redis", [], [r"\bredis\b"]),
    ("oracle-database", "Oracle Database", "Oracle", "Database Server", DB, "product", "Oracle relational database.", ["Oracle DB"], "a:oracle:database_server", [], [r"oracle database"]),
    ("microsoft-sql-server", "Microsoft SQL Server", "Microsoft", "SQL Server", DB, "product", "Microsoft relational database.", ["MSSQL"], "a:microsoft:sql_server", [("microsoft", r"sql server")], [r"microsoft sql server", r"\bmssql\b"]),
    ("elasticsearch", "Elasticsearch", "Elastic", "Elasticsearch", DB, "product", "Search and analytics engine.", [], "a:elastic:elasticsearch", [("elastic", r"elasticsearch")], [r"\belasticsearch\b"]),
    ("sqlite", "SQLite", "SQLite", "SQLite", DB, "product", "Embedded SQL database.", [], "a:sqlite:sqlite", [], [r"\bsqlite\b"]),
    ("apache-cassandra", "Apache Cassandra", "Apache", "Cassandra", DB, "product", "Distributed NoSQL database.", ["Cassandra"], "a:apache:cassandra", [], [r"apache cassandra"]),
    # ------------------------------------------------------------------ Cloud Platforms (services without CPE: no product identifiers, no score)
    ("aws", "Amazon Web Services", "Amazon", "AWS", CLOUD, "cloud", "Amazon cloud platform (service, not a versioned product).", ["AWS"], "", [], [r"\baws\b", r"amazon web services"]),
    ("microsoft-azure", "Microsoft Azure", "Microsoft", "Azure", CLOUD, "cloud", "Microsoft cloud platform.", ["Azure"], "", [], [r"\bazure\b"]),
    ("google-cloud", "Google Cloud Platform", "Google", "Google Cloud", CLOUD, "cloud", "Google cloud platform.", ["GCP"], "", [], [r"google cloud", r"\bgcp\b"]),
    ("oracle-cloud", "Oracle Cloud Infrastructure", "Oracle", "Oracle Cloud", CLOUD, "cloud", "Oracle cloud platform.", ["OCI"], "", [], [r"oracle cloud"]),
    ("cloudflare", "Cloudflare", "Cloudflare", "Cloudflare", CLOUD, "cloud", "CDN, DNS and edge security service.", [], "", [], [r"\bcloudflare\b"]),
    ("servicenow", "ServiceNow", "ServiceNow", "Now Platform", CLOUD, "cloud", "Cloud workflow platform.", ["Now Platform"], "", [("servicenow", r".*")], [r"\bservicenow\b"]),
    ("salesforce", "Salesforce", "Salesforce", "Salesforce Platform", CLOUD, "cloud", "Cloud CRM platform.", [], "", [], [r"\bsalesforce\b"]),
    # ------------------------------------------------------------------ Identity & Access Management
    ("microsoft-entra-id", "Microsoft Entra ID", "Microsoft", "Entra ID", IAM, "cloud", "Microsoft cloud identity service (formerly Azure AD).", ["Azure AD", "Azure Active Directory"], "", [], [r"entra id", r"azure active directory", r"\bazure ad\b"]),
    ("microsoft-active-directory", "Microsoft Active Directory", "Microsoft", "Active Directory", IAM, "family", "Windows directory services.", ["AD FS", "AD DS"], "a:microsoft:active_directory_federation_services", [("microsoft", r"active directory")], [r"active directory"]),
    ("okta", "Okta", "Okta", "Okta", IAM, "cloud", "Cloud identity service.", [], "", [], [r"\bokta\b"]),
    ("keycloak", "Keycloak", "Red Hat", "Keycloak", IAM, "product", "Open-source identity and access management.", [], "a:redhat:keycloak", [], [r"\bkeycloak\b"]),
    ("pingfederate", "PingFederate", "Ping Identity", "PingFederate", IAM, "product", "Federation server.", [], "a:pingidentity:pingfederate", [], [r"\bpingfederate\b"]),
    ("cyberark", "CyberArk Privileged Access", "CyberArk", "Privileged Access Manager", IAM, "product", "Privileged access management.", [], "a:cyberark:privileged_access_manager", [], [r"\bcyberark\b"]),
    ("openldap", "OpenLDAP", "OpenLDAP", "OpenLDAP", IAM, "product", "Open-source LDAP directory.", [], "a:openldap:openldap", [], [r"\bopenldap\b"]),
    # ------------------------------------------------------------------ Email & Collaboration
    ("microsoft-exchange", "Microsoft Exchange Server", "Microsoft", "Exchange Server", MAIL, "product", "Microsoft mail server.", ["Exchange"], "a:microsoft:exchange_server", [("microsoft", r"exchange server")], [r"exchange server", r"\bproxylogon\b", r"\bproxyshell\b"]),
    ("microsoft-sharepoint", "Microsoft SharePoint Server", "Microsoft", "SharePoint Server", MAIL, "product", "Microsoft collaboration server.", ["SharePoint"], "a:microsoft:sharepoint_server", [("microsoft", r"sharepoint( server)?")], [r"\bsharepoint\b"]),
    ("microsoft-office", "Microsoft Office", "Microsoft", "Office", MAIL, "family", "Microsoft Office desktop suite.", ["Word", "Excel", "Outlook"], "a:microsoft:office", [("microsoft", r"office|word|excel|powerpoint|outlook")], [r"microsoft office"]),
    ("microsoft-365", "Microsoft 365", "Microsoft", "Microsoft 365", MAIL, "cloud", "Microsoft cloud productivity suite.", ["Office 365", "M365"], "", [], [r"microsoft 365", r"office 365", r"\bm365\b"]),
    ("google-workspace", "Google Workspace", "Google", "Workspace", MAIL, "cloud", "Google cloud productivity suite.", ["G Suite"], "", [], [r"google workspace", r"\bg suite\b"]),
    ("zimbra", "Zimbra Collaboration", "Zimbra", "Collaboration Suite", MAIL, "product", "Email and collaboration server.", ["ZCS"], "a:zimbra:collaboration a:synacor:zimbra_collaboration_suite", [("synacor", r"zimbra.*"), ("zimbra", r".*")], [r"\bzimbra\b"]),
    ("roundcube", "Roundcube Webmail", "Roundcube", "Webmail", MAIL, "product", "Open-source webmail client.", [], "a:roundcube:webmail", [("roundcube", r".*")], [r"\broundcube\b"]),
    ("exim", "Exim", "Exim", "Exim", MAIL, "product", "Mail transfer agent.", [], "a:exim:exim", [("exim", r"exim")], [r"\bexim\b"]),
    ("postfix", "Postfix", "Postfix", "Postfix", MAIL, "product", "Mail transfer agent.", [], "a:postfix:postfix", [], []),
    ("atlassian-confluence", "Atlassian Confluence", "Atlassian", "Confluence", MAIL, "family", "Team wiki and collaboration.", ["Confluence"], "a:atlassian:confluence_data_center a:atlassian:confluence_server", [("atlassian", r"confluence.*")], [r"\bconfluence\b"]),
    ("atlassian-jira", "Atlassian Jira", "Atlassian", "Jira", MAIL, "family", "Issue and project tracking.", ["Jira"], "a:atlassian:jira_data_center a:atlassian:jira_server", [("atlassian", r"jira.*")], [r"\bjira\b"]),
    # ------------------------------------------------------------------ DevOps & Development
    ("gitlab", "GitLab", "GitLab", "GitLab", DEV, "product", "DevOps platform and Git hosting.", [], "a:gitlab:gitlab", [("gitlab", r".*")], [r"\bgitlab\b"]),
    ("jenkins", "Jenkins", "Jenkins", "Jenkins", DEV, "product", "Automation server for CI/CD.", [], "a:jenkins:jenkins", [("jenkins", r".*")], [r"\bjenkins\b"]),
    ("github-enterprise-server", "GitHub Enterprise Server", "GitHub", "Enterprise Server", DEV, "product", "Self-hosted GitHub.", ["GHES"], "a:github:enterprise_server", [], [r"github enterprise"]),
    ("teamcity", "JetBrains TeamCity", "JetBrains", "TeamCity", DEV, "product", "CI/CD server.", ["TeamCity"], "a:jetbrains:teamcity", [("jetbrains", r"teamcity")], [r"\bteamcity\b"]),
    ("bitbucket", "Atlassian Bitbucket", "Atlassian", "Bitbucket", DEV, "family", "Git repository management.", ["Bitbucket"], "a:atlassian:bitbucket_data_center a:atlassian:bitbucket_server", [], [r"\bbitbucket\b"]),
    ("ansible", "Red Hat Ansible", "Red Hat", "Ansible", DEV, "family", "IT automation.", ["Ansible"], "a:redhat:ansible_automation_platform a:redhat:ansible_engine", [], [r"\bansible\b"]),
    ("terraform", "HashiCorp Terraform", "HashiCorp", "Terraform", DEV, "product", "Infrastructure as code.", [], "a:hashicorp:terraform", [], [r"\bterraform\b"]),
    ("hashicorp-vault", "HashiCorp Vault", "HashiCorp", "Vault", DEV, "product", "Secrets management.", ["Vault"], "a:hashicorp:vault", [], [r"hashicorp vault"]),
    ("sonarqube", "SonarQube", "SonarSource", "SonarQube", DEV, "product", "Code quality and security analysis.", [], "a:sonarsource:sonarqube", [], [r"\bsonarqube\b"]),
    ("nexus-repository", "Sonatype Nexus Repository", "Sonatype", "Nexus Repository Manager", DEV, "product", "Artifact repository.", ["Nexus"], "a:sonatype:nexus_repository_manager", [], [r"nexus repository"]),
    ("jfrog-artifactory", "JFrog Artifactory", "JFrog", "Artifactory", DEV, "product", "Artifact repository.", ["Artifactory"], "a:jfrog:artifactory", [("jfrog", r"artifactory")], [r"\bartifactory\b"]),
    ("spring-framework", "Spring Framework", "VMware", "Spring Framework", DEV, "product", "Java application framework.", ["Spring4Shell"], "a:vmware:spring_framework a:pivotal_software:spring_framework", [], [r"spring framework", r"spring4shell"]),
    ("apache-log4j", "Apache Log4j", "Apache", "Log4j", DEV, "product", "Java logging library.", ["Log4Shell"], "a:apache:log4j", [("apache", r"log4j.*")], [r"\blog4j\b", r"\blog4shell\b"]),
    ("apache-struts", "Apache Struts", "Apache", "Struts", DEV, "product", "Java web application framework.", ["Struts"], "a:apache:struts", [("apache", r"struts.*")], [r"apache struts", r"\bstruts\b"]),
    ("oracle-java", "Oracle Java SE", "Oracle", "Java SE (JDK/JRE)", DEV, "family", "Java runtime and development kit.", ["JDK", "JRE"], "a:oracle:jdk a:oracle:jre", [("oracle", r"java se|java runtime environment.*")], [r"oracle java", r"java se\b"]),
    # ------------------------------------------------------------------ Monitoring & Security
    ("splunk", "Splunk Enterprise", "Splunk", "Splunk Enterprise", MON, "product", "Log analytics and SIEM platform.", [], "a:splunk:splunk", [], [r"\bsplunk\b"]),
    ("grafana", "Grafana", "Grafana Labs", "Grafana", MON, "product", "Observability dashboards.", [], "a:grafana:grafana", [("grafana labs", r"grafana")], [r"\bgrafana\b"]),
    ("zabbix", "Zabbix", "Zabbix", "Zabbix", MON, "product", "Infrastructure monitoring.", [], "a:zabbix:zabbix", [("zabbix", r".*")], [r"\bzabbix\b"]),
    ("nagios-xi", "Nagios XI", "Nagios", "Nagios XI", MON, "product", "Infrastructure monitoring.", ["Nagios"], "a:nagios:nagios_xi", [("nagios", r"nagios xi")], [r"\bnagios\b"]),
    ("kibana", "Kibana", "Elastic", "Kibana", MON, "product", "Elastic visualization.", [], "a:elastic:kibana", [], [r"\bkibana\b"]),
    ("wazuh", "Wazuh", "Wazuh", "Wazuh", MON, "product", "Open-source XDR/SIEM.", [], "a:wazuh:wazuh", [], [r"\bwazuh\b"]),
    ("solarwinds-orion", "SolarWinds Orion Platform", "SolarWinds", "Orion Platform", MON, "product", "IT monitoring platform.", ["Orion"], "a:solarwinds:orion_platform", [("solarwinds", r"orion.*")], [r"solarwinds orion", r"\borion platform\b"]),
    ("solarwinds-web-help-desk", "SolarWinds Web Help Desk", "SolarWinds", "Web Help Desk", MON, "product", "IT service desk.", ["WHD"], "a:solarwinds:web_help_desk", [("solarwinds", r"web help desk")], [r"web help desk"]),
    ("wireshark", "Wireshark", "Wireshark", "Wireshark", MON, "product", "Network protocol analyser.", [], "a:wireshark:wireshark", [], [r"\bwireshark\b"]),
    ("clamav", "ClamAV", "ClamAV", "ClamAV", MON, "product", "Open-source antivirus engine.", [], "a:clamav:clamav", [], [r"\bclamav\b"]),
    ("paessler-prtg", "Paessler PRTG", "Paessler", "PRTG Network Monitor", MON, "product", "Network monitoring.", ["PRTG"], "a:paessler:prtg_network_monitor", [("paessler", r"prtg.*")], [r"\bprtg\b"]),
    ("trend-micro-apex-one", "Trend Micro Apex One", "Trend Micro", "Apex One", MON, "product", "Endpoint security.", ["Apex One"], "a:trendmicro:apex_one", [("trend micro", r"apex one.*")], [r"apex one"]),
    # ------------------------------------------------------------------ Enterprise Applications
    ("sap-netweaver", "SAP NetWeaver", "SAP", "NetWeaver", ENT, "family", "SAP application server platform.", ["NetWeaver"], "a:sap:netweaver_application_server_abap a:sap:netweaver_application_server_java", [("sap", r"netweaver.*")], [r"sap netweaver"]),
    ("oracle-weblogic", "Oracle WebLogic Server", "Oracle", "WebLogic Server", ENT, "product", "Java application server.", ["WebLogic"], "a:oracle:weblogic_server", [("oracle", r"weblogic server")], [r"\bweblogic\b"]),
    ("oracle-ebs", "Oracle E-Business Suite", "Oracle", "E-Business Suite", ENT, "product", "Oracle ERP suite.", ["EBS"], "a:oracle:e-business_suite", [("oracle", r"e-business suite")], [r"e-business suite"]),
    ("ibm-websphere", "IBM WebSphere Application Server", "IBM", "WebSphere Application Server", ENT, "product", "Java application server.", ["WebSphere"], "a:ibm:websphere_application_server", [], [r"\bwebsphere\b"]),
    ("moveit-transfer", "Progress MOVEit Transfer", "Progress", "MOVEit Transfer", ENT, "product", "Managed file transfer.", ["MOVEit"], "a:progress:moveit_transfer a:ipswitch:moveit_transfer", [("progress", r"moveit.*")], [r"\bmoveit\b"]),
    ("fortra-goanywhere", "Fortra GoAnywhere MFT", "Fortra", "GoAnywhere MFT", ENT, "product", "Managed file transfer.", ["GoAnywhere"], "a:fortra:goanywhere_managed_file_transfer", [("fortra", r"goanywhere.*")], [r"\bgoanywhere\b"]),
    ("adobe-coldfusion", "Adobe ColdFusion", "Adobe", "ColdFusion", ENT, "product", "Web application platform.", ["ColdFusion"], "a:adobe:coldfusion", [("adobe", r"coldfusion")], [r"\bcoldfusion\b"]),
    ("adobe-acrobat-reader", "Adobe Acrobat / Reader", "Adobe", "Acrobat Reader", ENT, "family", "PDF software.", ["Acrobat"], "a:adobe:acrobat_reader a:adobe:acrobat", [("adobe", r"acrobat.*|reader.*")], [r"acrobat reader", r"adobe reader"]),
    ("adobe-commerce-magento", "Adobe Commerce / Magento", "Adobe", "Commerce", ENT, "family", "E-commerce platform.", ["Magento"], "a:adobe:commerce a:magento:magento", [("adobe", r"commerce.*|magento.*")], [r"\bmagento\b", r"adobe commerce"]),
    ("wordpress", "WordPress", "WordPress", "WordPress", ENT, "product", "Content management system.", [], "a:wordpress:wordpress", [("wordpress", r".*")], [r"\bwordpress\b"]),
    ("drupal", "Drupal", "Drupal", "Drupal", ENT, "product", "Content management system.", [], "a:drupal:drupal", [("drupal", r".*")], [r"\bdrupal\b"]),
    ("google-chrome", "Google Chrome / Chromium", "Google", "Chrome", ENT, "family", "Web browser.", ["Chromium"], "a:google:chrome", [("google", r"chromium.*")], [r"google chrome", r"\bchromium\b"]),
    ("mozilla-firefox", "Mozilla Firefox", "Mozilla", "Firefox", ENT, "product", "Web browser.", ["Firefox"], "a:mozilla:firefox", [("mozilla", r"firefox.*")], [r"\bfirefox\b"]),
    # ------------------------------------------------------------------ Storage & Backup
    ("veeam-backup-replication", "Veeam Backup & Replication", "Veeam", "Backup & Replication", STOR, "product", "Backup and recovery software.", ["VBR"], "a:veeam:backup_\\&_replication", [("veeam", r"backup (?:&|and) replication")], [r"\bveeam\b"]),
    ("netapp-ontap", "NetApp ONTAP", "NetApp", "ONTAP", STOR, "product", "Storage operating system.", ["ONTAP"], "a:netapp:ontap", [], [r"\bontap\b"]),
    ("synology-dsm", "Synology DiskStation Manager", "Synology", "DiskStation Manager", STOR, "product", "NAS operating system.", ["DSM"], "o:synology:diskstation_manager", [], [r"diskstation manager", r"synology dsm"]),
    ("qnap-qts", "QNAP QTS", "QNAP", "QTS", STOR, "product", "NAS operating system.", ["QTS"], "o:qnap:qts", [("qnap", r"network attached storage.*|photo station|.*qts.*")], [r"qnap (?:qts|nas)", r"\bqts\b"]),
    ("veritas-backup-exec", "Veritas Backup Exec", "Veritas", "Backup Exec", STOR, "product", "Backup software.", [], "a:veritas:backup_exec", [("veritas", r"backup exec.*")], [r"backup exec"]),
    ("commvault", "Commvault", "Commvault", "Commvault", STOR, "product", "Data protection platform.", [], "a:commvault:commvault", [], [r"\bcommvault\b"]),
    ("minio", "MinIO", "MinIO", "MinIO", STOR, "product", "S3-compatible object storage.", [], "a:minio:minio", [("minio", r"minio")], [r"\bminio\b"]),
    ("ceph", "Ceph", "Ceph", "Ceph", STOR, "product", "Distributed storage.", [], "a:ceph:ceph", [], [r"\bceph\b"]),
    # ------------------------------------------------------------------ Remote Access
    ("openssh", "OpenSSH", "OpenBSD", "OpenSSH", REM, "product", "SSH implementation.", [], "a:openbsd:openssh", [], [r"\bopenssh\b"]),
    ("citrix-virtual-apps", "Citrix Virtual Apps and Desktops", "Citrix", "Virtual Apps and Desktops", REM, "family", "Application and desktop virtualization.", ["XenApp", "Citrix Workspace"], "a:citrix:virtual_apps_and_desktops a:citrix:xenapp", [("citrix", r"virtual apps.*|session recording")], [r"citrix virtual apps", r"\bxenapp\b"]),
    ("anydesk", "AnyDesk", "AnyDesk", "AnyDesk", REM, "product", "Remote desktop software.", [], "a:anydesk:anydesk", [], [r"\banydesk\b"]),
    ("teamviewer", "TeamViewer", "TeamViewer", "TeamViewer", REM, "product", "Remote access software.", [], "a:teamviewer:teamviewer", [], [r"\bteamviewer\b"]),
    ("connectwise-screenconnect", "ConnectWise ScreenConnect", "ConnectWise", "ScreenConnect", REM, "product", "Remote support software.", ["ScreenConnect"], "a:connectwise:screenconnect", [("connectwise", r"screenconnect")], [r"\bscreenconnect\b"]),
    ("openvpn", "OpenVPN", "OpenVPN", "OpenVPN", REM, "product", "Open-source VPN.", [], "a:openvpn:openvpn", [], [r"\bopenvpn\b"]),
    ("apache-guacamole", "Apache Guacamole", "Apache", "Guacamole", REM, "product", "Clientless remote desktop gateway.", ["Guacamole"], "a:apache:guacamole", [], [r"\bguacamole\b"]),
    ("beyondtrust-remote-support", "BeyondTrust Remote Support / PRA", "BeyondTrust", "Remote Support", REM, "family", "Remote support and privileged remote access.", ["PRA"], "a:beyondtrust:remote_support a:beyondtrust:privileged_remote_access", [("beyondtrust", r".*")], [r"\bbeyondtrust\b"]),
    ("simplehelp", "SimpleHelp", "SimpleHelp", "SimpleHelp", REM, "product", "Remote support software.", [], "a:simple-help:simplehelp", [("simplehelp", r"simplehelp")], [r"\bsimplehelp\b"]),
]

# Metadata for the six technologies that already existed (matchers stay in catalog.py exactly as before).
LEGACY_META = {
    "windows-server": ("Microsoft", "Windows Server", OS, "family", "Microsoft server operating system (2012–2025)."),
    "linux": ("Linux", "Linux Kernel", OS, "product", "The Linux kernel."),
    "docker": ("Docker", "Docker Engine / Desktop", CON, "family", "Container platform (Docker Engine, Desktop, Moby)."),
    "kubernetes": ("Kubernetes", "Kubernetes", CON, "family", "Container orchestration platform."),
    "vmware": ("VMware", "vSphere / ESXi / vCenter", VIRT, "family", "VMware virtualization products."),
    "fortinet": ("Fortinet", "FortiOS and related products", NS, "family", "Fortinet security products (FortiOS, FortiProxy, FortiManager…)."),
}
