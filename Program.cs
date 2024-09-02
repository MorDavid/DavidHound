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
using System.Text;
using System.Threading;
using System.Linq;

namespace DavidHound
{
    class Program
    {
        //Pre2K
        const int LOGON32_LOGON_NETWORK = 3;
        const int LOGON32_PROVIDER_DEFAULT = 0;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken
        );

        // Sessions
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("Wtsapi32.dll", CharSet = CharSet.Auto)]
        private static extern bool WTSEnumerateSessions(
                IntPtr hServer,
                int reserved,
                int version,
                out IntPtr ppSessionInfo,
                out int count
            );

        [DllImport("Wtsapi32.dll", CharSet = CharSet.Auto)]
        private static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("Wtsapi32.dll", CharSet = CharSet.Auto)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int sessionId,
            WTSInfoClass wtsInfoClass,
            out IntPtr ppBuffer,
            out int bytesReturned
        );

        [DllImport("Wtsapi32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr WTSOpenServer(string serverName);

        [DllImport("Wtsapi32.dll", CharSet = CharSet.Auto)]
        private static extern bool WTSCloseServer(IntPtr hServer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct WTS_SESSION_INFO
        {
            public int SessionID;
            public int State;
            public IntPtr pWinStationName;
        }

        private enum WTSInfoClass
        {
            WTSUserName = 5
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetSessionEnum(
            string servername,
            string UncClientName,
            string username,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetWkstaUserEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SESSION_INFO_10
        {
            public string sesi10_cname;
            public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

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
                Console.WriteLine($"[IP ADDRESS] Error resolving hostname ({hostname}): {ex.Message}");
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
        static async Task Main(string[] args)
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
            bool session_enabled = false;
            bool pre2k_enabled = false;
            string outputFilePath = "SessionCollector.json";
            // Args
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
                        Console.WriteLine("  -s, --sessions          Enable Sessions check.");
                        Console.WriteLine("  -wd, --webdav           Enable WebDAV check.");
                        Console.WriteLine("  -sp, --spooler          Enable Print Spooler check.");
                        Console.WriteLine("  -ip, --ips              Enable IP address check.");
                        Console.WriteLine("  -av, --antivirus        Enable antivirus check.");
                        Console.WriteLine("  -p2, --pre2k            Enable Pre2K check.");
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
                    case "-s":
                    case "--sessions":
                        session_enabled = true;
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
                        smb_signing_enabled = true;
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
                    case "-p2":
                    case "--pre2k":
                        pre2k_enabled = true;
                        break;
                    case "king":
                        session_enabled = true;
                        smb_signing_enabled = true;
                        webdav_enabled = true;
                        spooler_enabled = true;
                        ipaddress_enabled = true;
                        antivirus_enabled = true;
                        ldap_signing_enabled = true;
                        pre2k_enabled = true;
                        break;
                }
            }

            // Pre2K Functions
            static string Pre2k_UserFixer(string username)
            {
                if (username.Length <= 15)
                {
                    return username;
                }
                else
                {
                    return username.Substring(0, 15);
                }
            }
            static string Pre2k_PasswordFixer(string password)
            {
                if (password.Length <= 14)
                {
                    return password;
                }
                else
                {
                    return password.Substring(0, 14);
                }
            }
            static bool Pre2k_AuthenticateMachineAccount(string username, string password, string domain)
            {
                IntPtr tokenHandle;
                bool isAuthenticated = LogonUser(username, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out tokenHandle);

                if (isAuthenticated)
                {
                    CloseHandle(tokenHandle);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            static bool Pre2k_Auth(string host, string domain)
            {
                try
                {
                    return Pre2k_AuthenticateMachineAccount(Pre2k_UserFixer(host) + "$", Pre2k_PasswordFixer(host.ToLower()), domain);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PRE2K] An error occurred: {ex.Message}");
                    return false;
                }
            }
            static async Task DelayWithJitterAsync(int milliseconds)
            {
                var random = new Random();
                var jitter = random.Next(-milliseconds / 2, milliseconds / 2);
                var totalDelay = milliseconds + jitter;
                if (totalDelay < 0)
                    totalDelay = 0;
                await Task.Delay(totalDelay);
            }
            static List<string> GetPre2KComputerDomain(string domainName)
            {
                List<string> computers = new List<string>();
                using (DirectorySearcher searcher = new DirectorySearcher("(userAccountControl=4128)"))
                {
                    searcher.SearchRoot = new DirectoryEntry($"LDAP://{domainName}");
                    searcher.PropertiesToLoad.Add("name");
                    SearchResultCollection results = searcher.FindAll();
                    for (int i = 0; i < results.Count; i++)
                    {
                        string computerName = results[i].Properties["name"][0].ToString();
                        computers.Add(computerName);
                    }
                }
                return computers;
            }
            // END Pre2K Functions

            // Get Computers
            if (args.Length != 0)
            {
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
            } else {
                Console.WriteLine("[X] Error: Provide target domain on the command line, use flag --domain or --file and --output.");
                return;
            }

            // Session Functions
            static async Task<string> CallWinStationEnumerateW(int num, string serverName)
            {
                StringBuilder sb = new StringBuilder();
                IntPtr hServer = IntPtr.Zero;
                IntPtr pSessionInfo = IntPtr.Zero;
                int sessionCount = 0;

                try
                {
                    hServer = WTSOpenServer(serverName);
                    if (hServer == IntPtr.Zero)
                    {
                        throw new Exception($"Failed to connect to server: {serverName}");
                    }

                    // Enumerate sessions
                    if (WTSEnumerateSessions(hServer, 0, 1, out pSessionInfo, out sessionCount))
                    {
                        IntPtr current = pSessionInfo;
                        int dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));

                        for (int i = 0; i < sessionCount; i++)
                        {
                            WTS_SESSION_INFO sessionInfo = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);

                            // Retrieve and print username
                            IntPtr pBuffer = IntPtr.Zero;
                            int bytesReturned = 0;

                            if (WTSQuerySessionInformation(hServer, sessionInfo.SessionID, WTSInfoClass.WTSUserName, out pBuffer, out bytesReturned))
                            {
                                string userName = Marshal.PtrToStringAuto(pBuffer).ToUpper();
                                if (!string.IsNullOrWhiteSpace(userName))
                                {
                                    sb.Append($"{{\"Host\":\"{serverName}\",\"User\":\"{userName}\",\"Type\":\"WinStationEnumerateW\"}},");
                                    Console.WriteLine($"[SESSIONS] [{num}] WinStationEnumerateW\t{serverName}\t{userName}");
                                }
                                WTSFreeMemory(pBuffer);
                            }
                            else
                            {
                                Console.WriteLine($"[SESSIONS] [{num}] WinStationEnumerateW\t{serverName}\tSessionID: {sessionInfo.SessionID}\tState: {sessionInfo.State}\tUser: Failed to retrieve username.");
                            }

                            current = IntPtr.Add(current, dataSize);
                        }

                        WTSFreeMemory(pSessionInfo);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
                finally
                {
                    if (hServer != IntPtr.Zero)
                    {
                        WTSCloseServer(hServer);
                    }
                }

                return sb.ToString();
            }
            static async Task<string> CallNetSessionEnum(int num, string serverName)
            {
                StringBuilder sb = new StringBuilder();
                IntPtr bufPtr = IntPtr.Zero;
                int entriesRead, totalEntries, resumeHandle = 0;
                HashSet<string> uniqueSessions = new HashSet<string>();

                int result = NetSessionEnum(serverName, null, null, 10, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);
                
                if (result == 0)
                {
                    var iterPtr = bufPtr;
                    for (int i = 0; i < entriesRead; i++)
                    {
                        var sessionInfo = Marshal.PtrToStructure<SESSION_INFO_10>(iterPtr);
                        string sessionUser = sessionInfo.sesi10_username.ToUpper();

                        if (!uniqueSessions.Contains(sessionUser))
                        {
                            uniqueSessions.Add(sessionUser);
                            sb.Append($"{{\"Host\":\"{serverName}\",\"User\":\"{sessionUser}\",\"Type\":\"NetSessionEnum\"}},");
                            Console.WriteLine($"[SESSIONS] [{num}] NetSessionEnum\t{serverName}\t{sessionUser}");
                        }
                        iterPtr = (IntPtr)(iterPtr.ToInt64() + Marshal.SizeOf<SESSION_INFO_10>());
                    }
                }

                if (bufPtr != IntPtr.Zero)
                {
                    NetApiBufferFree(bufPtr);
                }

                return sb.ToString();
            }
            static async Task<string> CallNetWkstaUserEnum(int num, string serverName)
            {
                StringBuilder sb = new StringBuilder();
                IntPtr bufPtr = IntPtr.Zero;
                int entriesRead, totalEntries, resumeHandle = 0;
                HashSet<string> uniqueUsers = new HashSet<string>();

                int result = NetWkstaUserEnum(serverName, 1, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);

                if (result == 0)
                {
                    var iterPtr = bufPtr;
                    for (int i = 0; i < entriesRead; i++)
                    {
                        var userInfo = Marshal.PtrToStructure<WKSTA_USER_INFO_1>(iterPtr);
                        string username = userInfo.wkui1_username.ToUpper();
                        string domainOrComputer = userInfo.wkui1_logon_domain.ToUpper();

                        string userKey = $"{username}@{domainOrComputer}";

                        if (!uniqueUsers.Contains(userKey))
                        {
                            uniqueUsers.Add(userKey);

                            bool endsWithDollarSign = username.EndsWith("$");
                            bool isLocal = domainOrComputer.EndsWith(serverName);
                            if (!endsWithDollarSign && !isLocal)
                            {
                                sb.Append($"{{\"Host\":\"{serverName}\",\"User\":\"{username}@{domainOrComputer}\",\"Type\":\"NetWkstaUserEnum\"}},");
                                Console.WriteLine($"[SESSIONS] [{num}] NetWkstaUserEnum\t{serverName}\t{domainOrComputer}\\{username}");
                            }
                        }
                        iterPtr = (IntPtr)(iterPtr.ToInt64() + Marshal.SizeOf<WKSTA_USER_INFO_1>());
                    }
                }

                if (bufPtr != IntPtr.Zero)
                {
                    NetApiBufferFree(bufPtr);
                }

                return sb.ToString();
            }
            static async Task<string> ProcessServer(int num, string serverName, bool useWkstaUserEnum, bool useNetSessionEnum, bool useWinStationEnumerateW)
            {
                string result = "";

                if (useWkstaUserEnum)
                {
                    result += await CallNetWkstaUserEnum(num, serverName);
                }

                if (useNetSessionEnum)
                {
                    result += await CallNetSessionEnum(num, serverName);
                }

                if (useWinStationEnumerateW)
                {
                    result += await CallWinStationEnumerateW(num, serverName);
                }

                return result;
            }
            // END Session Functions

            if (!string.IsNullOrEmpty(domainName) || !string.IsNullOrEmpty(fileName))
            {
                //Pre2k Computer List
                List<string> Pre2k;
                if (!string.IsNullOrEmpty(domainName))
                {
                    Pre2k = GetPre2KComputerDomain(domainName);
                }
                else
                {
                    Pre2k = LoadHostsFromFile(fileName);
                }
                // END Pre2k Computer List

                // Sessions
                if (session_enabled == true)
                {
                    List<Task<string>> tasks = new List<Task<string>>();
                    Console.WriteLine("[SESSIONS] Start sessions");
                    bool useNetSessionEnum = true;
                    bool useWkstaUserEnum = true;
                    bool useWinStationEnumerateW = true;
                    for (int i = 0; i < args.Length; i++)
                    {
                        switch (args[i])
                        {
                            case "--no-netSessionEnum":
                                useNetSessionEnum = false;
                                break;
                            case "--no-wkstaUserEnum":
                                useWkstaUserEnum = false;
                                break;
                            case "--no-winStationEnumerateW":
                                useWinStationEnumerateW = false;
                                break;
                        }
                    }
                    SemaphoreSlim semaphore = new SemaphoreSlim(threadCount);
                    int num = 0;
                    var startTime = DateTime.Now;
                    foreach (string line in targetHosts)
                    {
                        await semaphore.WaitAsync();

                        tasks.Add(Task.Run(async () =>
                        {
                            num = num + 1;
                            try
                            {
                                Console.WriteLine($"[SESSIONS] {num}\tStart processing\t{line}");
                                var result = await ProcessServer(num, line, useWkstaUserEnum, useNetSessionEnum, useWinStationEnumerateW);
                                return result;
                            }
                            finally
                            {
                                semaphore.Release();
                            }
                        }));
                    }
                    var results = await Task.WhenAll(tasks);
                    var combinedResults = string.Join(Environment.NewLine, results);
                    var lines = combinedResults.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                    var uniqueLines = new List<string>();
                    foreach (var line in lines)
                    {
                        if (!uniqueLines.Contains(line))
                        {
                            uniqueLines.Add(line);
                        }
                    }

                    var modifiedLines = uniqueLines
                        .Select(line => line.Length > 0 ? line.Substring(0, line.Length - 1) : line)
                        .ToList();
                    var jsonArray = "[" + string.Join(",", modifiedLines) + "]";
                    if (jsonArray != "[]")
                    {
                        File.WriteAllText(outputFilePath, jsonArray);
                    }
                    var endTime = DateTime.Now;
                    var duration = endTime - startTime;
                    Console.WriteLine($"[DAVIDHOUND] Sessions enumeration activity done. Total time taken: {duration.TotalSeconds} seconds.");
                }
                // END Sessions

                // Set up StreamWriter for writing to the output file
                using (StreamWriter writer = outputFileName != null ? new StreamWriter(outputFileName) : null)
                {
                    Parallel.ForEach(targetHosts, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, singleTarget =>
                    {
                        string json_line = "";
                        json_line += "{";
                        json_line += $"\"Name\":\"{singleTarget}\",";
                        Console.WriteLine("[DAVIDHOUND] Checking " + singleTarget);

                    // SMB Signing
                    if (smb_signing_enabled == true)
                        {
                        //TODO
                    }
                    // Pre2K
                    if (pre2k_enabled == true)
                    {
                        if (Pre2k.Count == 0)
                        {
                            Console.WriteLine("[PRE2K] Not found some 2K Machine Account.");
                        }
                        if (Pre2k.Contains(singleTarget))
                        {
                            if(Pre2k_Auth(singleTarget, domainName))
                            {
                                json_line += $"\"pre2k\":true,\"owned\":true,";
                            } else {
                                json_line += $"\"pre2k\":false,";
                            }
                        }
                            
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
                    if (ldap_signing_enabled == true)
                        {
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
            } else
            {
                Console.WriteLine("[DAVIDHOUND] Domain or File is missing.");
                return;

            }
        }
    }
}