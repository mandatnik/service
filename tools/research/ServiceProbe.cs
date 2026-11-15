// Temporary SCM service and read-only certificate reader for the research stand.
using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Threading;
using Microsoft.Win32;

public sealed class CertView {
    public string SHA256, Thumbprint, Serial, Subject, Issuer, NotBeforeUTC, NotAfterUTC;
}
public sealed class StoreView {
    public bool Exists;
    public CertView[] Certificates;
}
public static class NativeProbe {
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct TP { public uint Count; public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct CERT_CONTEXT { public uint Encoding; public IntPtr Data; public uint Length; public IntPtr Info, Store; }
    [DllImport("advapi32", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out LUID value);
    [DllImport("advapi32", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool all, ref TP state, uint len, IntPtr prev, IntPtr needed);
    [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
    [DllImport("crypt32", SetLastError=true)] static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr crypt, uint flags, IntPtr key);
    [DllImport("crypt32", SetLastError=true)] static extern IntPtr CertOpenSystemStore(IntPtr crypt, string store);
    [DllImport("crypt32", SetLastError=true)] static extern IntPtr CertEnumCertificatesInStore(IntPtr store, IntPtr prev);
    [DllImport("crypt32", SetLastError=true)] static extern bool CertCloseStore(IntPtr store, uint flags);
    [DllImport("crypt32", SetLastError=true)] static extern bool CertAddEncodedCertificateToStore(IntPtr store, uint encoding, byte[] data, uint length, uint mode, IntPtr result);
    static Exception Error(string op) { return new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), op); }
    public static void Enable(string name) {
        IntPtr token;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x28, out token)) throw Error("OpenProcessToken");
        try {
            LUID luid; if (!LookupPrivilegeValue(null, name, out luid)) throw Error("LookupPrivilegeValue");
            TP tp = new TP { Count=1, Luid=luid, Attributes=2 };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) throw Error("AdjustTokenPrivileges");
            int code=Marshal.GetLastWin32Error(); if (code!=0) throw new System.ComponentModel.Win32Exception(code, name);
        } finally { CloseHandle(token); }
    }
    static CertView[] Enumerate(IntPtr store) {
        List<CertView> result=new List<CertView>();
        IntPtr current=IntPtr.Zero;
        while ((current=CertEnumCertificatesInStore(store,current))!=IntPtr.Zero) {
            CERT_CONTEXT ctx=(CERT_CONTEXT)Marshal.PtrToStructure(current,typeof(CERT_CONTEXT));
            byte[] der=new byte[ctx.Length]; Marshal.Copy(ctx.Data,der,0,der.Length);
            using (X509Certificate2 c=new X509Certificate2(der)) using (SHA256 hash=SHA256.Create()) {
                result.Add(new CertView { SHA256=BitConverter.ToString(hash.ComputeHash(der)).Replace("-", "").ToLowerInvariant(), Thumbprint=c.Thumbprint,
                    Serial=c.SerialNumber, Subject=c.Subject, Issuer=c.Issuer,
                    NotBeforeUTC=c.NotBefore.ToUniversalTime().ToString("o"), NotAfterUTC=c.NotAfter.ToUniversalTime().ToString("o") });
            }
        }
        int error=Marshal.GetLastWin32Error();
        if (error!=unchecked((int)0x80092004) && error!=259 && error!=0) throw new System.ComponentModel.Win32Exception(error,"CertEnumCertificatesInStore");
        return result.ToArray();
    }
    public static StoreView Read(string path) {
        using (RegistryKey key=Registry.Users.OpenSubKey(path,false)) {
            if (key==null) return new StoreView { Exists=false, Certificates=new CertView[0] };
            IntPtr store=CertOpenStore(new IntPtr(4),0,IntPtr.Zero,0xC000,key.Handle.DangerousGetHandle());
            if (store==IntPtr.Zero) throw Error("CertOpenStore(REG, READONLY)");
            try { return new StoreView { Exists=true, Certificates=Enumerate(store) }; }
            finally { CertCloseStore(store,0); }
        }
    }
    public static CertView[] ReadOwnMy() {
        IntPtr store=CertOpenSystemStore(IntPtr.Zero,"MY");
        if (store==IntPtr.Zero) throw Error("CertOpenSystemStore(MY)");
        try { return Enumerate(store); } finally { CertCloseStore(store,0); }
    }
    public static void Seed(string path,string[] files) {
        using (RegistryKey key=Registry.Users.CreateSubKey(path)) {
            IntPtr store=CertOpenStore(new IntPtr(4),0,IntPtr.Zero,0,key.Handle.DangerousGetHandle());
            if (store==IntPtr.Zero) throw Error("CertOpenStore(REG, seed)");
            try { foreach(string file in files) { byte[] der=File.ReadAllBytes(file); if(!CertAddEncodedCertificateToStore(store,0x10001,der,(uint)der.Length,1,IntPtr.Zero)) throw Error("CertAddEncodedCertificateToStore(NEW)"); } }
            finally { CertCloseStore(store,0); }
        }
    }
}

public sealed class MandatnikResearchService : ServiceBase {
    readonly string directory;
    public MandatnikResearchService(string dir) { directory=dir; ServiceName="MandatnikResearchProbe"; AutoLog=false; }
    protected override void OnStart(string[] args) {
        ThreadPool.QueueUserWorkItem(delegate {
            try {
                ProcessStartInfo info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell\\v1.0\\powershell.exe"));
                info.Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+Path.Combine(directory,"probe.ps1")+"\" -Directory \""+directory+"\"";
                info.UseShellExecute=false; info.CreateNoWindow=true; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
                using(Process process=Process.Start(info)) {
                    string output=process.StandardOutput.ReadToEnd(), error=process.StandardError.ReadToEnd(); process.WaitForExit();
                    File.WriteAllText(Path.Combine(directory,"runner.stdout.txt"),output); File.WriteAllText(Path.Combine(directory,"runner.stderr.txt"),error);
                    File.WriteAllText(Path.Combine(directory,"runner.exit.txt"),process.ExitCode.ToString());
                }
            } catch(Exception e) { File.WriteAllText(Path.Combine(directory,"runner.failure.txt"),e.ToString()); }
            finally { Stop(); }
        });
    }
    public static void Main(string[] args) { if(args.Length!=1) throw new ArgumentException("directory required"); ServiceBase.Run(new MandatnikResearchService(args[0])); }
}
