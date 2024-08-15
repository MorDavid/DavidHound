using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using DavidHound.RPC;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;

namespace DavidHound
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool WaitNamedPipeA(string lpNamedPipeName, uint nTimeOut);
        public static IPAddress[] ResolveHostname(string hostname)
        {
            IPAddress[] addresses = new IPAddress[0];
            try
            {
                addresses = Dns.GetHostAddresses(hostname);
                if (addresses.Length > 0)
                {
                    return addresses;
                }
                else
                {
                    return new IPAddress[0];
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error resolving hostname: {ex.Message}");
                return new IPAddress[0];
            }
        }
        public static string ip2json(IPAddress[] addresses)
        {

            if (addresses == null || addresses.Length == 0)
            {
                return "[]"; // Return an empty JSON array
            }
            else
            {
                string ip_str = "[";
                foreach (IPAddress ip in addresses)
                {
                    ip_str += "\"" + ip.ToString() + "\",";
                }
                ip_str = ip_str.Substring(0, ip_str.Length - 1);
                ip_str += "]";
                return ip_str;
            }
        }
        static string WebDAVScan(string singleTarget)
        {
            string pipename = @"\\" + singleTarget + @"\pipe\DAV RPC SERVICE";
            bool davActive = WaitNamedPipeA(pipename, 5000);

            // Output to the console
            if (davActive)
            {
                return "true";
            }
            else
            {
                return "false";
            }
        }
        static string SpoolerScan(string singleTarget)
        {
            IntPtr hHandle = IntPtr.Zero;
            var test = new rprn();

            var devmodeContainer = new DavidHound.RPC.rprn.DEVMODE_CONTAINER();
            try
            {
                var ret = test.RpcOpenPrinter("\\\\" + singleTarget, out hHandle, null, ref devmodeContainer, 0);
                if (ret == 0)
                {
                    return "true";
                }
            }
            finally
            {
                if (hHandle != IntPtr.Zero)
                    test.RpcClosePrinter(ref hHandle);
            }
            return "false";
        }
        static void CreateJsonFile(string jsonString, string filePath)
        {
            try
            {
                // Write the JSON string to the specified file path
                File.WriteAllText(filePath, jsonString);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
        private static List<string> LoadHostsFromFile(string fileName)
        {
            List<string> hosts = new List<string>();

            try
            {
                // Check if the file exists
                if (!File.Exists(fileName))
                {
                    Console.WriteLine("[X] Error: The specified file does not exist.");
                    return hosts;
                }

                // Read all lines from the file and add them to the hosts list
                string[] lines = File.ReadAllLines(fileName);

                foreach (string line in lines)
                {
                    // Add each line (host) to the hosts list after trimming whitespace
                    string trimmedLine = line.Trim();
                    if (!string.IsNullOrEmpty(trimmedLine))
                    {
                        hosts.Add(trimmedLine);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error reading file: " + ex.Message);
            }

            return hosts;
        }
        private static List<string> GetComputersInDomain(string domainName)
        {
            List<string> computers = new List<string>();
            try
            {
                using (DirectoryEntry rootEntry = new DirectoryEntry("LDAP://" + domainName))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
                    {
                        searcher.Filter = "(objectClass=computer)";
                        searcher.PageSize = 1000;
                        foreach (object obj in searcher.FindAll())
                        {
                            string computerName = ((SearchResult)obj).GetDirectoryEntry().Name;
                            computers.Add(computerName.Split(new char[] { '=' })[1]);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error, GetComputersInDomain: " + ex.Message);
            }
            return computers;
        }
        private static List<string> GetDomainControllers(string domainName)
        {
            List<string> DomainControllers = new List<string>();
            try
            {
                Domain domain = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domainName));
                DomainControllerCollection controllers = domain.DomainControllers;
                foreach (DomainController controller in controllers)
                {
                    DomainControllers.Add(controller.ToString().Replace('.'+domain.ToString(),""));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error, GetDomainControllers: " + ex.Message);
            }
            return DomainControllers;
        }
        static bool CheckLDAPSigning(string protocol,string dc_fqdn)
        {
            bool protocolBool = false;
            if (protocol == "LDAP")
            {
                try
                {
                    using (LdapConnection connection = new LdapConnection($"{dc_fqdn}:389"))
                    {
                        connection.SessionOptions.ProtocolVersion = 3;
                        connection.SessionOptions.SecureSocketLayer = false;
                        connection.Bind();
                        protocolBool = true;
                    }
                }
                catch
                {
                    protocolBool = false;
                }
            }

            if (protocol == "LDAPS")
            {
                try
                {
                    using (LdapConnection connection = new LdapConnection($"{dc_fqdn}:636"))
                    {
                        connection.SessionOptions.ProtocolVersion = 3;
                        connection.SessionOptions.SecureSocketLayer = true;
                        connection.Bind();
                        protocolBool = true;
                    }
                }
                catch
                {
                    protocolBool = false;
                }
            }
            return protocolBool;
        }
        static Dictionary<string, string> AVReference = new Dictionary<string, string>{
            {"avast! Antivirus", "Avast"},
            {"aswBcc", "Avast"},
            {"Avast Business Console Client Antivirus Service", "Avast"},

            {"epag", "Bitdefender Endpoint Agent"},
            {"EPIntegrationService", "Bitdefender Endpoint Integration Service"},
            {"EPProtectedService", "Bitdefender Endpoint Protected Service"},
            {"epredline", "Bitdefender Endpoint Redline Services"},
            {"EPSecurityService", "Bitdefender Endpoint Security Service"},
            {"EPUpdateService", "Bitdefender Endpoint Update Service"},

            {"CiscoAMP", "Cisco Secure endpoint"},

            {"CSFalconService", "CrowdStrike Falcon Sensor Service"},

            {"CylanceSvc", "Cylance"},
            {"ekm", "ESET"},
            {"epfw", "ESET"},
            {"epfwlwf", "ESET"},
            {"epfwwfp" , "ESET"},
            {"EraAgentSvc", "ESET"},

            {"xagt" , "FireEye Endpoint Agent"},

            {"fgprocsvc" , "ForeScout Remote Inspection Service"},
            {"SecureConnector" , "ForeScout SecureConnector Service"},

            {"fsdevcon", "F-Secure"},
            {"FSDFWD", "F-Secure"},
            {"F-Secure Network Request Broker", "F-Secure"},
            {"FSMA", "F-Secure"},
            {"FSORSPClient", "F-Secure"},

            {"klif", "Kasperksky"},
            {"klim", "Kasperksky"},
            {"kltdi", "Kasperksky"},
            {"kavfsslp", "Kasperksky"},
            {"KAVFSGT", "Kasperksky"},
            {"KAVFS", "Kasperksky"},

            {"enterceptagent", "MacAfee"},
            {"macmnsvc", "MacAfee Agent Common Services"},
            {"masvc", "MacAfee Agent Service"},
            {"McAfeeFramework", "MacAfee Agent Backwards Compatiblity Service"},
            {"McAfeeEngineService", "MacAfee"},
            {"mfefire", "MacAfee Firewall Core Service"},
            {"mfemms", "MacAfee Service Controller"},
            {"mfevtp", "MacAfee Validation Trust Protection Service"},
            {"mfewc", "MacAfee Endpoint Security Web Control Service"},

            {"cyverak", "PaloAlto Traps KernelDriver"},
            {"cyvrmtgn", "PaloAlto Traps KernelDriver"},
            {"cyvrfsfd", "PaloAlto Traps FileSystemDriver"},
            {"cyserver", "PaloAlto Traps Reporting Service"},
            {"CyveraService", "PaloAlto Traps"},
            {"tlaservice", "PaloAlto Traps Local Analysis Service"},
            {"twdservice", "PaloAlto Traps Watchdog Service"},

            {"SentinelAgent", "SentinelOne"},
            {"SentinelHelperService", "SentinelOne"},
            {"SentinelStaticEngine ", "SentinelIbe Static Service"},
            {"LogProcessorService ", "SentinelOne Agent Log Processing Service"},

            {"sophosssp", "Sophos"},
            {"Sophos Agent", "Sophos"},
            {"Sophos AutoUpdate Service", "Sophos"},
            {"Sophos Clean Service", "Sophos"},
            {"Sophos Device Control Service", "Sophos"},
            {"Sophos File Scanner Service", "Sophos"},
            {"Sophos Health Service", "Sophos"},
            {"Sophos MCS Agent", "Sophos"},
            {"Sophos MCS Client", "Sophos"},
            {"Sophos Message Router", "Sophos"},
            {"Sophos Safestore Service", "Sophos"},
            {"Sophos System Protection Service", "Sophos"},
            {"Sophos Web Control Service", "Sophos"},
            {"sophossps", "Sophos"},

            {"SepMasterService" , "Symantec Endpoint Protection"},
            {"SNAC" , "Symantec Network Access Control"},
            {"Symantec System Recovery" , "Symantec System Recovery"},
            {"Smcinst", "Symantec Connect"},
            {"SmcService", "Symantec Connect"},

            {"Sysmon", "Sysmon"},

            {"AMSP", "Trend"},
            {"tmcomm", "Trend"},
            {"tmactmon", "Trend"},
            {"tmevtmgr", "Trend"},
            {"ntrtscan", "Trend Micro Worry Free Business"},

            {"WRSVC", "Webroot"},

            {"WinDefend", "Windows Defender Antivirus Service"},
            {"Sense ", "Windows Defender Advanced Threat Protection Service"},
            {"WdNisSvc ", "Windows Defender Antivirus Network Inspection Service"}
        };
        static List<string> customService = new List<string>();
        public static void MarshalUnmananagedArray2Struct<T>(IntPtr unmanagedArray, int length, out T[] mangagedArray)
        {
            var size = Marshal.SizeOf(typeof(T));
            mangagedArray = new T[length];

            for (int i = 0; i < length; i++)
            {
                IntPtr ins = new IntPtr(unmanagedArray.ToInt64() + i * size);
                mangagedArray[i] = (T)Marshal.PtrToStructure(ins, typeof(T));
            }
        }
        private static List<string> GetAntiVirus(string computer)
        {
            List<string> AntiVirusList = new List<string>();
            NativeMethods.UNICODE_STRING us = new NativeMethods.UNICODE_STRING();
            NativeMethods.LSA_OBJECT_ATTRIBUTES loa = new NativeMethods.LSA_OBJECT_ATTRIBUTES();
            us.Initialize(computer);
            IntPtr PolicyHandle = IntPtr.Zero;
            uint ret = NativeMethods.LsaOpenPolicy(ref us, ref loa, 0x00000800, out PolicyHandle);
            us.Dispose();
            if (ret != 0)
            {
                return AntiVirusList;
            }
            var names = new NativeMethods.UNICODE_STRING[AVReference.Count + customService.Count];
            try
            {
                int i = 0;
                foreach (var entry in AVReference)
                {
                    names[i] = new NativeMethods.UNICODE_STRING();
                    names[i].Initialize("NT Service\\" + entry.Key);
                    i++;
                }
                foreach (var entry in customService)
                {
                    names[i] = new NativeMethods.UNICODE_STRING();
                    names[i].Initialize("NT Service\\" + entry);
                    i++;
                }
                IntPtr ReferencedDomains, Sids;
                ret = NativeMethods.LsaLookupNames(PolicyHandle, names.Length, names, out ReferencedDomains, out Sids);
                if (ret == 0xC0000073)
                {
                    //AntiVirusList.Add("No known service found");
                    return AntiVirusList;
                }
                if (ret != 0 && ret != 0x00000107)
                {
                    //AntiVirusList.Add("Unable to lookup");
                    return AntiVirusList;
                }
                try
                {
                    var domainList = (NativeMethods.LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure(ReferencedDomains, typeof(NativeMethods.LSA_REFERENCED_DOMAIN_LIST));
                    if (domainList.Entries > 0)
                    {
                        var trustInfo = (NativeMethods.LSA_TRUST_INFORMATION)Marshal.PtrToStructure(domainList.Domains, typeof(NativeMethods.LSA_TRUST_INFORMATION));
                    }
                    NativeMethods.LSA_TRANSLATED_SID[] translated;
                    MarshalUnmananagedArray2Struct<NativeMethods.LSA_TRANSLATED_SID>(Sids, names.Length, out translated);

                    i = 0;
                    foreach (var entry in AVReference)
                    {
                        if (translated[i].DomainIndex >= 0)
                        {
                            AntiVirusList.Add(entry.Value);
                        }
                        i++;
                    }
                    foreach (var entry in customService)
                    {
                        AntiVirusList.Add(entry);
                        i++;
                    }
                }
                finally
                {
                    NativeMethods.LsaFreeMemory(ReferencedDomains);
                    NativeMethods.LsaFreeMemory(Sids);
                }
            }
            finally
            {
                NativeMethods.LsaClose(PolicyHandle);
                for (int k = 0; k < names.Length; k++)
                {
                    names[k].Dispose();
                }
            }
            return AntiVirusList;
        }
        public static string list2json(List<string> list)
        {
            if (list == null || list.Count == 0)
            {
                return "[]"; // Return an empty JSON array
            }
            else
            {
                string str = "[";
                foreach (string parameter in list)
                {
                    str += "\"" + parameter.ToString() + "\",";
                }
                str = str.Substring(0, str.Length - 1);
                str += "]";
                return str;
            }
        }
        static void Main(string[] args)
        {
            List<string> targetHosts;
            List<string> DomainControllers = new List<string>();
            string domainName = null;
            string fileName = null;
            string outputFileName = "DavidHound.json";
            Console.WriteLine(@"
  █▀▄ █▀█ █ █ ▀█▀ █▀▄   █ █ █▀█ █ █ █▀█ █▀▄
  █ █ █▀█ ▀▄▀  █  █ █   █▀█ █ █ █ █ █ █ █ █
  ▀▀  ▀ ▀  ▀  ▀▀▀ ▀▀    ▀ ▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ 
                               By Mor David");
            Console.WriteLine("");
            string json = "[";
            int threadCount = 10;
            bool smb_signing_enabled = false; // TODO
            bool webdav_enabled = false;
            bool spooler_enabled = false;
            bool ipaddress_enabled = false;
            bool antivirus_enabled = false;
            bool ldap_signing_enabled = false;
            bool session_enabled = false; // TODO
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-h":
                    case "--help":
                        Console.WriteLine("Usage: [options]");
                        Console.WriteLine("Options:");
                        Console.WriteLine("  -h, --help              Show this help message and exit.");
                        Console.WriteLine("  -d, --domain [name]     Specify the domain name.");
                        Console.WriteLine("  -f, --file [file]       Specify the input file name.");
                        Console.WriteLine("  -o, --output [file]     Specify the output file name.");
                        Console.WriteLine("  -t, --threads [number]  Set the number of threads.");
                        //Console.WriteLine("  -s, --sessions          Enable Sessions check.");
                        Console.WriteLine("  -wd, --webdav           Enable WebDAV check.");
                        Console.WriteLine("  -sp, --spooler          Enable Print Spooler check.");
                        Console.WriteLine("  -ip, --ips              Enable IP address check.");
                        Console.WriteLine("  -av, --antivirus        Enable antivirus check.");
                        //Console.WriteLine("  -sb, --smbsigning       Enable SMB signing check.");
                        Console.WriteLine("  -ls, --ldapsigning      Enable LDAP signing check.");
                        return;
                        break;
                    case "-d":
                    case "--domain":
                        domainName = args[++i];
                        break;
                    case "-f":
                    case "--file":
                        fileName = args[++i];
                        break;
                    case "-o":
                    case "--output":
                        outputFileName = args[++i];
                        break;
                    case "-t":
                    case "--threads":
                        threadCount = int.Parse(args[++i]);
                        break;
                    case "-sb":
                    case "--smbsigning":
                        webdav_enabled = true;
                        break;
                    case "-wd":
                    case "--webdav":
                        webdav_enabled = true;
                        break;
                    case "-sp":
                    case "--spooler":
                        spooler_enabled = true;
                        break;
                    case "-ip":
                    case "--ips":
                        ipaddress_enabled = true;
                        break;
                    case "-av":
                    case "--antivirus":
                        antivirus_enabled = true;
                        break;
                    case "-ls":
                    case "--ldapsigning":
                        ldap_signing_enabled = true;
                        break;
                }
            }
            
            if (args.Length == 0)
            {
                Console.WriteLine("[X] Error: Provide target domain on the command line, use flag --domain or --file and --output.");
                return;
            }
            try
            {
                if (fileName != null) // File Actions
                {
                    targetHosts = LoadHostsFromFile(fileName);
                }
                else // Domain Actions
                {
                    DomainControllers = GetDomainControllers(domainName);
                    targetHosts = GetComputersInDomain(domainName);
                }
                int tcIndex = Array.FindIndex(args, x => x.StartsWith("--tc", StringComparison.OrdinalIgnoreCase));
                if (tcIndex >= 0)
                {
                    threadCount = Int32.Parse(args[tcIndex + 1]);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error parsing the arguments, please check and try again.");
                Console.WriteLine(e.ToString());
                return;
            }

            
            // Set up StreamWriter for writing to the output file
            using (StreamWriter writer = outputFileName != null ? new StreamWriter(outputFileName) : null)
            {
                
                Parallel.ForEach(targetHosts, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, singleTarget =>
                {
                    string json_line = "";
                    json_line += "{";
                    json_line += $"\"Name\":\"{singleTarget}\",";
                    Console.WriteLine("[+] Checking " + singleTarget);

                    // SMB Signing
                    if (smb_signing_enabled == true)
                    {
                        //TODO
                    }

                    // Sessions
                    if (session_enabled == true)
                    {
                        //TODO
                    }

                    // Web DAV Client Status
                    if (webdav_enabled == true)
                    {
                        string WebDAVStatus = WebDAVScan(singleTarget);
                        if (WebDAVStatus == "true")
                        {
                            json_line += $"\"webdav\":{WebDAVStatus},";
                        }
                    }

                    // Spooler Status
                    if (spooler_enabled == true)
                    {
                        string SpoolerStatus = SpoolerScan(singleTarget);
                        if (SpoolerStatus == "true")
                        {
                            json_line += $"\"spooler\":{SpoolerStatus},";
                        }
                    }

                    // IP Addresses
                    if (ipaddress_enabled == true)
                    {
                        IPAddress[] DNSResolve = ResolveHostname(singleTarget);
                        if (DNSResolve.Length > 0)
                        {
                            json_line += $"\"ip\":{ip2json(DNSResolve)},";
                        }
                    }

                    // Anti Virus Checker
                    if (antivirus_enabled == true)
                    {
                        List<string> AntiVirusList = GetAntiVirus(singleTarget);
                        if (AntiVirusList.Count != 0)
                        {
                            json_line += $"\"antivirus\":" + list2json(AntiVirusList) + ",";
                        }
                    }

                    // LDAP Signing Checker
                    if (ldap_signing_enabled == true) { 
                        foreach (string dc in DomainControllers)
                        {
                            if (singleTarget == dc)
                            {
                                if (CheckLDAPSigning("LDAP", dc + "." + domainName))
                                {
                                    json_line += $"\"ldapsigning389\":true,";
                                }
                                else
                                {
                                    json_line += $"\"ldapsigning389\":false,";
                                }
                                if (CheckLDAPSigning("LDAPS", dc + "." + domainName))
                                {
                                    json_line += $"\"ldapsigning636\":true,";
                                }
                                else
                                {
                                    json_line += $"\"ldapsigning636\":false,";
                                }
                            }
                        }
                    }
                    json_line = json_line.TrimEnd(',');
                    json_line += "}";
                    json += json_line + ",";
                });
                
                json = json.TrimEnd(',') + "]";
            }
            CreateJsonFile(json, outputFileName);
        }
    }
}