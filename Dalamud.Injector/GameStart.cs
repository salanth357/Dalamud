using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

using PeNet;
using PeNet.Header.Pe;

using Serilog;

// ReSharper disable InconsistentNaming

namespace Dalamud.Injector
{
    /// <summary>
    /// Class responsible for starting the game and stripping ACL protections from processes.
    /// </summary>
    public static class GameStart
    {
        /// <summary>
        /// Start a process without ACL protections.
        /// </summary>
        /// <param name="workingDir">The working directory.</param>
        /// <param name="exePath">The path to the executable file.</param>
        /// <param name="arguments">Arguments to pass to the executable file.</param>
        /// <param name="dontFixAcl">Don't actually fix the ACL.</param>
        /// <param name="beforeResume">Action to execute before the process is started.</param>
        /// <param name="waitForGameWindow">Wait for the game window to be ready before proceeding.</param>
        /// <returns>The started process.</returns>
        /// <exception cref="Win32Exception">Thrown when a win32 error occurs.</exception>
        /// <exception cref="GameStartException">Thrown when the process did not start correctly.</exception>
        public static Process LaunchGame(string workingDir, string exePath, string arguments, bool dontFixAcl, Action<Process> beforeResume, bool waitForGameWindow = true, bool disableAslr = false)
        {
            Process process = null;

            var psecDesc = IntPtr.Zero;
            if (!dontFixAcl)
            {
                var userName = Environment.UserName;

                var pExplicitAccess = default(PInvoke.EXPLICIT_ACCESS);
                PInvoke.BuildExplicitAccessWithName(
                    ref pExplicitAccess,
                    userName,
                    PInvoke.STANDARD_RIGHTS_ALL | PInvoke.SPECIFIC_RIGHTS_ALL & ~PInvoke.PROCESS_VM_WRITE,
                    PInvoke.GRANT_ACCESS,
                    0);

                if (PInvoke.SetEntriesInAcl(1, ref pExplicitAccess, IntPtr.Zero, out var newAcl) != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!PInvoke.InitializeSecurityDescriptor(out var secDesc, PInvoke.SECURITY_DESCRIPTOR_REVISION))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!PInvoke.SetSecurityDescriptorDacl(ref secDesc, true, newAcl, false))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                psecDesc = Marshal.AllocHGlobal(Marshal.SizeOf<PInvoke.SECURITY_DESCRIPTOR>());
                Marshal.StructureToPtr(secDesc, psecDesc, true);
            }

            var lpProcessInformation = default(PInvoke.PROCESS_INFORMATION);
            try
            {
                var lpProcessAttributes = new PInvoke.SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf<PInvoke.SECURITY_ATTRIBUTES>(),
                    lpSecurityDescriptor = psecDesc,
                    bInheritHandle = false,
                };

                var lpStartupInfo = new PInvoke.STARTUPINFO
                {
                    cb = Marshal.SizeOf<PInvoke.STARTUPINFO>(),
                };

                var compatLayerPrev = Environment.GetEnvironmentVariable("__COMPAT_LAYER");

                if (!string.IsNullOrEmpty(compatLayerPrev) && !compatLayerPrev.Contains("RunAsInvoker"))
                {
                    Environment.SetEnvironmentVariable("__COMPAT_LAYER", $"RunAsInvoker {compatLayerPrev}");
                }
                else if (string.IsNullOrEmpty(compatLayerPrev))
                {
                    Environment.SetEnvironmentVariable("__COMPAT_LAYER", "RunAsInvoker");
                }

                try
                {
                    if (disableAslr)
                    {
                        NtCreateProcessEx(
                            workingDir,
                            exePath,
                            arguments,
                            psecDesc,
                            out lpProcessInformation.hProcess,
                            out lpProcessInformation.hThread);
                    }
                    else
                    {

                        Log.Information("Launching old style");
                        if (!PInvoke.CreateProcess(
                                null,
                                $"\"{exePath}\" {arguments}",
                                ref lpProcessAttributes,
                                IntPtr.Zero,
                                false,
                                PInvoke.CREATE_SUSPENDED,
                                IntPtr.Zero,
                                workingDir,
                                ref lpStartupInfo,
                                out lpProcessInformation))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                }
                finally
                {
                    Environment.SetEnvironmentVariable("__COMPAT_LAYER", compatLayerPrev);
                }

                if (!dontFixAcl)
                    DisableSeDebug(lpProcessInformation.hProcess);

                process = new ExistingProcess(lpProcessInformation.hProcess);

                beforeResume?.Invoke(process);

                PInvoke.ResumeThread(lpProcessInformation.hThread);

                // Ensure that the game main window is prepared
                if (waitForGameWindow)
                {
                    try
                    {
                        var tries = 0;
                        const int maxTries = 1200;
                        const int timeout = 50;

                        do
                        {
                            Thread.Sleep(timeout);

                            if (process.HasExited)
                                throw new GameStartException();

                            if (tries > maxTries)
                                throw new GameStartException($"Couldn't find game window after {maxTries * timeout}ms");

                            tries++;
                        }
                        while (TryFindGameWindow(process) == IntPtr.Zero);
                    }
                    catch (InvalidOperationException)
                    {
                        throw new GameStartException("Could not read process information.");
                    }
                }

                if (!dontFixAcl)
                    CopyAclFromSelfToTargetProcess(lpProcessInformation.hProcess);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[GameStart] Uncaught error during initialization, trying to kill process");

                try
                {
                    process?.Kill();
                }
                catch (Exception killEx)
                {
                    Log.Error(killEx, "[GameStart] Could not kill process");
                }

                throw;
            }
            finally
            {
                if (psecDesc != IntPtr.Zero)
                    Marshal.FreeHGlobal(psecDesc);
                PInvoke.CloseHandle(lpProcessInformation.hThread);
            }

            return process;
        }

        public static FileStream? CloneAndModifyForASLR(string exePath, out string newPath)
        {
            var pe = new PeFile(exePath);
            if (pe.ImageNtHeaders == null)
            {
                newPath = exePath;
                return null;
            }

            pe.ImageNtHeaders.OptionalHeader.DllCharacteristics &= ~DllCharacteristicsType.DynamicBase;
            pe.ImageNtHeaders.FileHeader.Characteristics &= ~FileCharacteristicsType.RelocsStripped;
            var peSpan = pe.RawFile.AsSpan(0, pe.RawFile.Length);

            var tempPath = Path.Join(Path.GetTempPath(), "ffxiv_dx11.exe");
            using var wf = File.Open(tempPath, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);

            wf.Write(peSpan);
            newPath = tempPath;
            return wf;
        }

        public static void NtCreateProcessEx(
            string workingDir, string exePath, string arguments, IntPtr pSecDesc, out nint hProcess, out nint hThread)
        {

            // Make sure we hold the handle to this long enough to
            using var exeFile = CloneAndModifyForASLR(exePath, out var tempFilename);
            // This uses an NT-style path, which starts with \??\
            using var sourceFilename = PInvoke.UNICODE_STRING.Create(@"\??\" + tempFilename);
            using var attr = new AllocPtr<PInvoke.OBJECT_ATTRIBUTES>();
            unsafe
            {
                attr.Value->Length = 48;
                attr.Value->ObjectName = sourceFilename.Ptr;
            }

            int status;
            var iosb = default(PInvoke.IO_STATUS_BLOCK);
            IntPtr hFile;
            // // TODO: const
            // status = PInvoke.NtOpenFile(
            //     out hFile,
            //     0x00100001,
            //     attr.Ptr,
            //     ref iosb,
            //     1,
            //     0x20);
            // if (status != 0) throw new Win32Exception(status);
            hFile = exeFile.SafeFileHandle.DangerousGetHandle();

            // TODO: const
            status = PInvoke.NtCreateSection(
                out var hSection,
                PInvoke.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                IntPtr.Zero,
                2,
                0x01000000,
                hFile);
            if (status != 0) throw new Win32Exception(status);

            using var procAttr = new AllocPtr<PInvoke.OBJECT_ATTRIBUTES>();
            unsafe
            {
                procAttr.Value->Length = 48;
                procAttr.Value->SecurityDescriptor = pSecDesc;
            }

            status = PInvoke.NtCreateProcessEx(
                out hProcess,
                0x1FFFFFU,
                procAttr.Ptr,
                -1, // Current Process
                0,
                hSection,
                0,
                0,
                0);
            if (status != 0) throw new Win32Exception(status);

            PInvoke.CloseHandle(hSection);

            PInvoke.PROCESS_BASIC_INFORMATION processInfo = default;
            status = PInvoke.NtQueryInformationProcess(
                hProcess,
                0, // TODO: const
                out processInfo,
                (uint)Marshal.SizeOf<PInvoke.PROCESS_BASIC_INFORMATION>(),
                IntPtr.Zero
            );
            if (status != 0) throw new Win32Exception(status);

            using var imageName = PInvoke.UNICODE_STRING.Create(exePath);
            using var workingDirUS = PInvoke.UNICODE_STRING.Create(workingDir);
            using var cmdLine = PInvoke.UNICODE_STRING.Create($"\"{exePath}\" {arguments}");
            using var windowTitle = PInvoke.UNICODE_STRING.Create("ffxiv_dx11.exe");
            // TODO: What's up with this value- is this always right?
            using var desktopInfo = PInvoke.UNICODE_STRING.Create("Winsta0\\Default");
            using var shellInfo = PInvoke.UNICODE_STRING.Create("\0");

            status = PInvoke.RtlCreateProcessParametersEx(
                out var procParamsPtr,
                imageName,
                workingDirUS,
                workingDirUS,
                cmdLine,
                0, // this loads the current env
                windowTitle,
                desktopInfo,
                shellInfo,
                IntPtr.Zero,
                1); // TODO: Const
            if (status != 0) throw new Win32Exception(status);

            unsafe
            {
                var procParams = (PInvoke.RTL_USER_PROCESS_PARAMETERS*)procParamsPtr;
                var paramsSize = (uint)(procParams->MaximumLength + procParams->EnvironmentSize);
                var paramsRemote = IntPtr.Zero;

                PInvoke.RtlDeNormalizeProcessParams(procParamsPtr);

                status = PInvoke.NtAllocateVirtualMemory(
                    hProcess,
                    ref paramsRemote,
                    0,
                    ref paramsSize,
                    0x3000, // TODO: Const
                    0x4 // TODO: Const
                );
                if (status != 0) throw new Win32Exception(status);

                procParams->Environment += paramsRemote - procParamsPtr;

                status = PInvoke.NtWriteVirtualMemory(
                    hProcess,
                    paramsRemote,
                    procParamsPtr,
                    paramsSize,
                    IntPtr.Zero
                );
                if (status != 0) throw new Win32Exception(status);

                status = PInvoke.RtlDestroyProcessParameters(procParamsPtr);
                if (status != 0) throw new Win32Exception(status);

                status = PInvoke.NtWriteVirtualMemory(
                    hProcess,
                    processInfo.PebBaseAddress + Marshal.OffsetOf<PInvoke.PEB>("ProcessParameters"),
                    (IntPtr)(&paramsRemote),
                    (ulong)Marshal.SizeOf<IntPtr>(),
                    IntPtr.Zero
                );
                if (status != 0) throw new Win32Exception(status);
            }

            status = PInvoke.NtQueryInformationProcess(
                hProcess,
                37, // TODO: Const
                out PInvoke.SECTION_IMAGE_INFORMATION imageInfo,
                (uint)Marshal.SizeOf<PInvoke.SECTION_IMAGE_INFORMATION>(),
                IntPtr.Zero);
            if (status != 0) throw new Win32Exception(status);

            status = PInvoke.NtCreateThreadEx(
                out hThread,
                2097151U,
                IntPtr.Zero,
                hProcess,
                imageInfo.TransferAddress,
                IntPtr.Zero,
                1, // TODO: Const
                imageInfo.ZeroBits,
                imageInfo.CommittedStackSize,
                imageInfo.MaximumStackSize,
                IntPtr.Zero);
            if (status != 0) throw new Win32Exception(status);
        }

        /// <summary>
        /// Copies ACL of current process to the target process.
        /// </summary>
        /// <param name="hProcess">Native handle to the target process.</param>
        /// <exception cref="Win32Exception">Thrown when a win32 error occurs.</exception>
        public static void CopyAclFromSelfToTargetProcess(IntPtr hProcess)
        {
            if (PInvoke.GetSecurityInfo(
                    PInvoke.GetCurrentProcess(),
                    PInvoke.SE_OBJECT_TYPE.SE_KERNEL_OBJECT,
                    PInvoke.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out var pACL,
                    IntPtr.Zero,
                    IntPtr.Zero) != 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (PInvoke.SetSecurityInfo(
                    hProcess,
                    PInvoke.SE_OBJECT_TYPE.SE_KERNEL_OBJECT,
                    PInvoke.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | PInvoke.SECURITY_INFORMATION.UNPROTECTED_DACL_SECURITY_INFORMATION,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    pACL,
                    IntPtr.Zero) != 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        /// <summary>
        /// Claim a SE Debug Privilege.
        /// </summary>
        public static void ClaimSeDebug()
        {
            var hToken = PInvoke.INVALID_HANDLE_VALUE;
            try
            {
                if (!PInvoke.OpenThreadToken(PInvoke.GetCurrentThread(), PInvoke.TOKEN_QUERY | PInvoke.TOKEN_ADJUST_PRIVILEGES, false, out hToken))
                {
                    if (Marshal.GetLastWin32Error() != PInvoke.ERROR_NO_TOKEN)
                        throw new Exception("ClaimSeDebug.OpenProcessToken#1", new Win32Exception(Marshal.GetLastWin32Error()));

                    if (!PInvoke.ImpersonateSelf(PInvoke.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation))
                        throw new Exception("ClaimSeDebug.ImpersonateSelf", new Win32Exception(Marshal.GetLastWin32Error()));

                    if (!PInvoke.OpenThreadToken(PInvoke.GetCurrentThread(), PInvoke.TOKEN_QUERY | PInvoke.TOKEN_ADJUST_PRIVILEGES, false, out hToken))
                        throw new Exception("ClaimSeDebug.OpenProcessToken#2", new Win32Exception(Marshal.GetLastWin32Error()));
                }

                var luidDebugPrivilege = default(PInvoke.LUID);
                if (!PInvoke.LookupPrivilegeValue(null, PInvoke.SE_DEBUG_NAME, ref luidDebugPrivilege))
                    throw new Exception("ClaimSeDebug.LookupPrivilegeValue", new Win32Exception(Marshal.GetLastWin32Error()));

                var tpLookup = new PInvoke.TOKEN_PRIVILEGES()
                {
                    PrivilegeCount = 1,
                    Privileges = new PInvoke.LUID_AND_ATTRIBUTES[1]
                    {
                        new PInvoke.LUID_AND_ATTRIBUTES()
                        {
                            Luid = luidDebugPrivilege,
                            Attributes = PInvoke.SE_PRIVILEGE_ENABLED,
                        },
                    },
                };

                if (!PInvoke.AdjustTokenPrivileges(hToken, false, ref tpLookup, 0, IntPtr.Zero, IntPtr.Zero))
                    throw new Exception("ClaimSeDebug.AdjustTokenPrivileges", new Win32Exception(Marshal.GetLastWin32Error()));
            }
            finally
            {
                if (hToken != PInvoke.INVALID_HANDLE_VALUE && hToken != IntPtr.Zero)
                    PInvoke.CloseHandle(hToken);
            }
        }

        private static void DisableSeDebug(IntPtr processHandle)
        {
            if (!PInvoke.OpenProcessToken(processHandle, PInvoke.TOKEN_QUERY | PInvoke.TOKEN_ADJUST_PRIVILEGES, out var tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var luidDebugPrivilege = default(PInvoke.LUID);
            if (!PInvoke.LookupPrivilegeValue(null, PInvoke.SE_DEBUG_NAME, ref luidDebugPrivilege))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var requiredPrivileges = new PInvoke.PRIVILEGE_SET
            {
                PrivilegeCount = 1,
                Control = PInvoke.PRIVILEGE_SET_ALL_NECESSARY,
                Privilege = new PInvoke.LUID_AND_ATTRIBUTES[1],
            };

            requiredPrivileges.Privilege[0].Luid = luidDebugPrivilege;
            requiredPrivileges.Privilege[0].Attributes = PInvoke.SE_PRIVILEGE_ENABLED;

            if (!PInvoke.PrivilegeCheck(tokenHandle, ref requiredPrivileges, out bool bResult))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // SeDebugPrivilege is enabled; try disabling it
            if (bResult)
            {
                var tokenPrivileges = new PInvoke.TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new PInvoke.LUID_AND_ATTRIBUTES[1],
                };

                tokenPrivileges.Privileges[0].Luid = luidDebugPrivilege;
                tokenPrivileges.Privileges[0].Attributes = PInvoke.SE_PRIVILEGE_REMOVED;

                if (!PInvoke.AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            PInvoke.CloseHandle(tokenHandle);
        }

        private static IntPtr TryFindGameWindow(Process process)
        {
            IntPtr hwnd = IntPtr.Zero;
            while ((hwnd = PInvoke.FindWindowEx(IntPtr.Zero, hwnd, "FFXIVGAME", IntPtr.Zero)) != IntPtr.Zero)
            {
                PInvoke.GetWindowThreadProcessId(hwnd, out uint pid);

                if (pid == process.Id && PInvoke.IsWindowVisible(hwnd))
                {
                    break;
                }
            }

            return hwnd;
        }

        /// <summary>
        /// Exception thrown when the process has exited before a window could be found.
        /// </summary>
        public class GameStartException : Exception
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="GameStartException"/> class.
            /// </summary>
            /// <param name="message">The message to pass on.</param>
            public GameStartException(string? message = null)
                : base(message ?? "Game exited prematurely.")
            {
            }
        }

        // Definitions taken from PInvoke.net (with some changes)
        [SuppressMessage("StyleCop.CSharp.NamingRules", "SA1307:Accessible fields should begin with upper-case letter", Justification = "WINAPI conventions")]
        [SuppressMessage("StyleCop.CSharp.ReadabilityRules", "SA1121:Use built-in type alias", Justification = "WINAPI conventions")]
        [SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1400:Access modifier should be declared", Justification = "WINAPI conventions")]
        [SuppressMessage("StyleCop.CSharp.NamingRules", "SA1306:Field names should begin with lower-case letter", Justification = "WINAPI conventions")]
        [SuppressMessage("StyleCop.CSharp.NamingRules", "SA1310:Field names should not contain underscore", Justification = "WINAPI conventions")]
        [SuppressMessage("StyleCop.CSharp.ReadabilityRules", "SA1124:Do not use regions", Justification = "WINAPI conventions")]
        private static class PInvoke
        {
            #region Constants
            public const string SE_DEBUG_NAME = "SeDebugPrivilege";

            public const UInt32 STANDARD_RIGHTS_ALL = 0x001F0000;
            public const UInt32 SPECIFIC_RIGHTS_ALL = 0x0000FFFF;
            public const UInt32 PROCESS_VM_WRITE = 0x0020;

            public const UInt32 GRANT_ACCESS = 1;

            public const UInt32 SECURITY_DESCRIPTOR_REVISION = 1;

            public const UInt32 CREATE_SUSPENDED = 0x00000004;

            public const UInt32 TOKEN_QUERY = 0x0008;
            public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;

            public const UInt32 PRIVILEGE_SET_ALL_NECESSARY = 1;

            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;

            public const UInt32 ERROR_NO_TOKEN = 0x000003F0;

            public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

            public enum MULTIPLE_TRUSTEE_OPERATION
            {
                NO_MULTIPLE_TRUSTEE,
                TRUSTEE_IS_IMPERSONATE,
            }

            public enum TRUSTEE_FORM
            {
                TRUSTEE_IS_SID,
                TRUSTEE_IS_NAME,
                TRUSTEE_BAD_FORM,
                TRUSTEE_IS_OBJECTS_AND_SID,
                TRUSTEE_IS_OBJECTS_AND_NAME,
            }

            public enum TRUSTEE_TYPE
            {
                TRUSTEE_IS_UNKNOWN,
                TRUSTEE_IS_USER,
                TRUSTEE_IS_GROUP,
                TRUSTEE_IS_DOMAIN,
                TRUSTEE_IS_ALIAS,
                TRUSTEE_IS_WELL_KNOWN_GROUP,
                TRUSTEE_IS_DELETED,
                TRUSTEE_IS_INVALID,
                TRUSTEE_IS_COMPUTER,
            }

            public enum SE_OBJECT_TYPE
            {
                SE_UNKNOWN_OBJECT_TYPE,
                SE_FILE_OBJECT,
                SE_SERVICE,
                SE_PRINTER,
                SE_REGISTRY_KEY,
                SE_LMSHARE,
                SE_KERNEL_OBJECT,
                SE_WINDOW_OBJECT,
                SE_DS_OBJECT,
                SE_DS_OBJECT_ALL,
                SE_PROVIDER_DEFINED_OBJECT,
                SE_WMIGUID_OBJECT,
                SE_REGISTRY_WOW64_32KEY,
            }

            [Flags]
            public enum SECURITY_INFORMATION
            {
                OWNER_SECURITY_INFORMATION = 1,
                GROUP_SECURITY_INFORMATION = 2,
                DACL_SECURITY_INFORMATION = 4,
                SACL_SECURITY_INFORMATION = 8,
                UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
                UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
                PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            }

            public enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation,
            }

            [Flags]
            public enum SECTION_ACCESS_RIGHTS : uint
            {
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            }

            public const SECTION_ACCESS_RIGHTS SECTION_ALL_ACCESS = SECTION_ACCESS_RIGHTS.STANDARD_RIGHTS_REQUIRED |
                                                                    SECTION_ACCESS_RIGHTS.SECTION_QUERY |
                                                                    SECTION_ACCESS_RIGHTS.SECTION_MAP_WRITE |
                                                                    SECTION_ACCESS_RIGHTS.SECTION_MAP_READ |
                                                                    SECTION_ACCESS_RIGHTS.SECTION_MAP_EXECUTE |
                                                                    SECTION_ACCESS_RIGHTS.SECTION_EXTEND_SIZE;
            #endregion

            #region Methods

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern void BuildExplicitAccessWithName(
                ref EXPLICIT_ACCESS pExplicitAccess,
                string pTrusteeName,
                uint accessPermissions,
                uint accessMode,
                uint inheritance);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern int SetEntriesInAcl(
                int cCountOfExplicitEntries,
                ref EXPLICIT_ACCESS pListOfExplicitEntries,
                IntPtr oldAcl,
                out IntPtr newAcl);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool InitializeSecurityDescriptor(
                out SECURITY_DESCRIPTOR pSecurityDescriptor,
                uint dwRevision);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool SetSecurityDescriptorDacl(
                ref SECURITY_DESCRIPTOR pSecurityDescriptor,
                bool bDaclPresent,
                IntPtr pDacl,
                bool bDaclDefaulted);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CreateProcess(
               string lpApplicationName,
               string lpCommandLine,
               ref SECURITY_ATTRIBUTES lpProcessAttributes,
               IntPtr lpThreadAttributes,
               bool bInheritHandles,
               UInt32 dwCreationFlags,
               IntPtr lpEnvironment,
               string lpCurrentDirectory,
               [In] ref STARTUPINFO lpStartupInfo,
               out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("ntdll.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
            public static extern int NtOpenFile(
                out IntPtr handle,
                uint access,
                IntPtr objectAttributes,
                ref IO_STATUS_BLOCK ioStatus,
                uint share,
                uint openOptions);

            [DllImport("ntdll.dll")]
            public static extern int NtCreateSection(
                out IntPtr hSection,
                SECTION_ACCESS_RIGHTS DesiredAccess,
                IntPtr objectAttributes, // left as IntPtr because we don't use
                IntPtr MaximumSize, // left as IntPtr because we don't use
                UInt32 sectionPageProtection,
                UInt32 allocationAttributes,
                IntPtr fileHandle
            );

            [DllImport("ntdll.dll")]
            public static extern int NtCreateProcessEx(
                out IntPtr hProcess,
                uint DesiredAccess,
                IntPtr objectAttributes, // IntPtr because we don't need it
                IntPtr parentProcess,
                uint flags,
                IntPtr sectionHandle,
                IntPtr debugPort,
                IntPtr tokenHandle,
                uint reserved
            );

            [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern int NtQueryInformationProcess(
                IntPtr hProcess,
                int ProcessInformationClass,
                out PROCESS_BASIC_INFORMATION processInformation,
                uint ProcessInformationLength,
                IntPtr returnLength
            );

            [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern int NtQueryInformationProcess(
                IntPtr hProcess,
                int ProcessInformationClass,
                out SECTION_IMAGE_INFORMATION processInformation,
                uint ProcessInformationLength,
                IntPtr returnLength
            );

            [DllImport("ntdll.dll")]
            public static extern int RtlCreateProcessParametersEx(
                out IntPtr pProcessParameters, // outputs a RTL_USER_PROCESS_PARAMETERS*
                IntPtr ImagePathName,
                IntPtr DllPath,
                IntPtr CurrentDirectory,
                IntPtr CommandLine,
                IntPtr Environment,
                IntPtr WindowTitle,
                IntPtr DesktopInfo,
                IntPtr ShellInfo,
                IntPtr RuntimeData,
                uint Flags
            );

            [DllImport("ntdll.dll")]
            public static extern IntPtr RtlDeNormalizeProcessParams(IntPtr ProcessParameters);

            [DllImport("ntdll.dll")]
            public static extern int RtlDestroyProcessParameters(IntPtr ProcessParameters);

            [DllImport("ntdll.dll")]
            public static extern int NtAllocateVirtualMemory(
                IntPtr hProcess,
                ref IntPtr BaseAddress,
                uint ZeroBits,
                ref uint RegionSize,
                uint AllocationType,
                uint Protect
            );

            [DllImport("ntdll.dll")]
            public static extern int NtWriteVirtualMemory(
                IntPtr hProcess,
                IntPtr BaseAddress,
                IntPtr Buffer,
                ulong BufferSize,
                IntPtr NumberOfBytesWritten // we don't care
            );

            [DllImport("ntdll.dll")]
            public static extern int NtCreateThreadEx(
                    out IntPtr threadHandle,
                    uint desiredAccess,
                    IntPtr objectAttributes,
                    IntPtr processHandle,
                    IntPtr startRoutine,
                    IntPtr argument,
                    uint createFlags,
                    nuint zeroBits,
                    nuint stackSize,
                    nuint maximumStackSize,
                    IntPtr attributeList
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint ResumeThread(IntPtr hThread);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ImpersonateSelf(
                SECURITY_IMPERSONATION_LEVEL impersonationLevel);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenProcessToken(
                IntPtr processHandle,
                UInt32 desiredAccess,
                out IntPtr tokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenThreadToken(
                IntPtr threadHandle,
                uint desiredAccess,
                bool openAsSelf,
                out IntPtr tokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool PrivilegeCheck(
                IntPtr clientToken,
                ref PRIVILEGE_SET requiredPrivileges,
                out bool pfResult);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool AdjustTokenPrivileges(
                IntPtr tokenHandle,
                bool disableAllPrivileges,
                ref TOKEN_PRIVILEGES newState,
                int cbPreviousState,
                IntPtr previousState,
                IntPtr cbOutPreviousState);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern uint GetSecurityInfo(
                IntPtr handle,
                SE_OBJECT_TYPE objectType,
                SECURITY_INFORMATION securityInfo,
                IntPtr pSidOwner,
                IntPtr pSidGroup,
                out IntPtr pDacl,
                IntPtr pSacl,
                IntPtr pSecurityDescriptor);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern uint SetSecurityInfo(
                IntPtr handle,
                SE_OBJECT_TYPE objectType,
                SECURITY_INFORMATION securityInfo,
                IntPtr psidOwner,
                IntPtr psidGroup,
                IntPtr pDacl,
                IntPtr pSacl);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentThread();

            [DllImport("user32.dll", SetLastError = true)]
            public static extern IntPtr FindWindowEx(IntPtr parentHandle, IntPtr hWndChildAfter, string className, IntPtr windowTitle);

            [DllImport("user32.dll", SetLastError = true)]
            public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsWindowVisible(IntPtr hWnd);

            #endregion

            #region Structures

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 0)]
            public struct TRUSTEE : IDisposable
            {
                public IntPtr pMultipleTrustee;
                public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
                public TRUSTEE_FORM TrusteeForm;
                public TRUSTEE_TYPE TrusteeType;
                private IntPtr ptstrName;

                public string Name => Marshal.PtrToStringAuto(this.ptstrName) ?? string.Empty;

#pragma warning disable CA1416

                void IDisposable.Dispose()
                {
                    if (this.ptstrName != IntPtr.Zero) Marshal.Release(this.ptstrName);
                }

#pragma warning restore CA1416
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 0)]
            public struct EXPLICIT_ACCESS
            {
                uint grfAccessPermissions;
                uint grfAccessMode;
                uint grfInheritance;
                TRUSTEE Trustee;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_DESCRIPTOR
            {
                public byte Revision;
                public byte Sbz1;
                public UInt16 Control;
                public IntPtr Owner;
                public IntPtr Group;
                public IntPtr Sacl;
                public IntPtr Dacl;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFO
            {
                public Int32 cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public Int32 dwX;
                public Int32 dwY;
                public Int32 dwXSize;
                public Int32 dwYSize;
                public Int32 dwXCountChars;
                public Int32 dwYCountChars;
                public Int32 dwFillAttribute;
                public Int32 dwFlags;
                public Int16 wShowWindow;
                public Int16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public UInt32 dwThreadId;
            }

            [StructLayout(LayoutKind.Explicit, Size = 48)]
            public struct PROCESS_BASIC_INFORMATION
            {
                [FieldOffset(0)]
                public int ExitStatus;
                [FieldOffset(8)]
                public IntPtr PebBaseAddress; // PEB*
                [FieldOffset(0x10)]
                public nuint AffinityMask;
                [FieldOffset(0x18)]
                public int BasePriority;
                [FieldOffset(0x20)]
                public IntPtr UniqueProcessId;
                [FieldOffset(0x28)]
                public IntPtr InheritedFromUniqueProcessId;
            }

            // We don't need everything on this
            [StructLayout(LayoutKind.Explicit, Size = 64)]
            public struct SECTION_IMAGE_INFORMATION
            {
                [FieldOffset(0)]
                public IntPtr TransferAddress;

                [FieldOffset(8)]
                public UInt32 ZeroBits;

                [FieldOffset(0x10)]
                public UIntPtr MaximumStackSize;

                [FieldOffset(0x18)]
                public UIntPtr CommittedStackSize;
            }

            // This struct is huge, but we're only going to add the fields we care about
            [StructLayout(LayoutKind.Explicit, Size = 1992)]
            public struct PEB
            {
                [FieldOffset(32)]
                public IntPtr ProcessParameters; // RTL_USER_PROCESS_PARAMETERS
            }

            // This struct is huge, but we're only going to add the fields we care about
            [StructLayout(LayoutKind.Explicit, Size = 1088)]
            public struct RTL_USER_PROCESS_PARAMETERS
            {
                [FieldOffset(0)]
                public uint MaximumLength;
                [FieldOffset(4)]
                public uint Length;
                [FieldOffset(128)]
                public IntPtr Environment;
                [FieldOffset(1008)]
                public IntPtr EnvironmentSize;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public bool bInheritHandle;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID
            {
                public UInt32 LowPart;
                public Int32 HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PRIVILEGE_SET
            {
                public UInt32 PrivilegeCount;
                public UInt32 Control;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public LUID_AND_ATTRIBUTES[] Privilege;
            }

            public struct LUID_AND_ATTRIBUTES
            {
                public LUID Luid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_PRIVILEGES
            {
                public UInt32 PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public LUID_AND_ATTRIBUTES[] Privileges;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8, Size=16)]
            public struct UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;

                public static unsafe AllocPtr<UNICODE_STRING> Create(string source)
                {
                    var strBufLen = source.Length * 2;
                    var str = (UNICODE_STRING*)Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>() + strBufLen);
                    str->Buffer = (IntPtr)str + Marshal.SizeOf<UNICODE_STRING>();
                    str->Length = str->MaximumLength = (ushort)strBufLen;
                    Encoding.Unicode.GetBytes(source, new Span<byte>((void*)str->Buffer, strBufLen));
                    return str!;
                }
            }

            [StructLayout(LayoutKind.Explicit, Size = 16)]
            public struct IO_STATUS_BLOCK
            {
                [FieldOffset(0)]
                public uint Status;
                [FieldOffset(8)]
                public IntPtr information;
            }

            [StructLayout(LayoutKind.Explicit, Size = 48)]
            public struct OBJECT_ATTRIBUTES()
            {
                [FieldOffset(0)]
                public Int32 Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
                [FieldOffset(8)]
                public IntPtr RootDirectory;
                [FieldOffset(0x10)]
                public IntPtr ObjectName;
                [FieldOffset(0x18)]
                public uint Attributes;
                [FieldOffset(0x20)]
                public IntPtr SecurityDescriptor;
                [FieldOffset(0x28)]
                public IntPtr SecurityQualityOfService;
            }

            #endregion
        }

        public class AllocPtr<T> : IDisposable
            where T : unmanaged
        {
            public readonly IntPtr Ptr;

            private readonly bool owned = true;
            private bool disposed;

            public unsafe T* Value => (T*)this.Ptr;

            public unsafe AllocPtr()
            {
                this.Ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
                *this.Value = default;
            }

            public unsafe AllocPtr(T* ptr, bool takeOwnership = true)
                : this((IntPtr)ptr, takeOwnership)
            {
            }

            public AllocPtr(IntPtr ptr, bool takeOwnership = true)
            {
                this.Ptr = ptr;
                this.owned = takeOwnership;
            }

            public static unsafe implicit operator AllocPtr<T>(T* ptr) => new(ptr);

            public static unsafe implicit operator T*(AllocPtr<T> ptr) => (T*)ptr.Ptr;

            public static implicit operator IntPtr(AllocPtr<T> ptr) => ptr.Ptr;

            /// <inheritdoc/>
            public void Dispose()
            {
                if (this.disposed) return;
                this.disposed = true;
                if (this.owned)
                {
                    Marshal.FreeHGlobal(this.Ptr);
                }
            }
        }
    }
}
