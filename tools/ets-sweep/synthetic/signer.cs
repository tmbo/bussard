// Hash and sign a fabricated .knxprod with ETS's own signing library (test data only).
// Usage: signer.exe [--master <knx_master.xml>] <in.knxprod> <out.knxprod> <workdir>     hash, sign, zip
//        (--master replaces the archive's knx_master.xml, e.g. the stub <KNX/>, with that file)
//        signer.exe --dir-only <in> <out> <workdir>         only the directory signature, no hashes
//        signer.exe --verify <in.knxprod> <workdir>         report what the library thinks of a file
//        signer.exe --verify-dir <workdir>                  the same on an unpacked folder
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

class Signer {
  const string EtsDir = @"C:\Program Files (x86)\ETS6";
  const BindingFlags Any = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
  static Assembly Lib;
  static bool DirOnly;
  static string Master;

  static Type T(string name) {
    var t = Lib.GetType("Knx.Ets.XmlSigning." + name);
    if (t == null) throw new Exception("type not found: " + name);
    return t;
  }
  // The overload whose parameters accept `args` (null fits any reference or Nullable parameter).
  static bool Fits(ParameterInfo[] ps, object[] args) {
    return ps.Length == args.Length && ps.Select((p, i) => args[i] == null || p.ParameterType.IsInstanceOfType(args[i])).All(b => b);
  }
  static object New(string type, params object[] args) {
    return T(type).GetConstructors(Any).First(c => Fits(c.GetParameters(), args)).Invoke(args);
  }
  static object Call(object target, string name, params object[] args) {
    var t = target as Type ?? target.GetType();
    var m = t.GetMethods(Any).First(x => x.Name == name && Fits(x.GetParameters(), args));
    return m.Invoke(target is Type ? null : target, args);
  }
  static object Get(object target, string name) { return target.GetType().GetProperty(name, Any).GetValue(target); }

  static int Main(string[] a) {
    AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
      var p = Path.Combine(EtsDir, new AssemblyName(e.Name).Name + ".dll");
      return File.Exists(p) ? Assembly.LoadFrom(p) : null;
    };
    Lib = Assembly.LoadFrom(Path.Combine(EtsDir, "Knx.Ets.XmlSigning.dll"));
    if (a[0] == "--verify-dir") {
      Verify(Path.GetFullPath(a[1]));
      return 0;
    }
    if (a[0] == "--verify") {
      Unpack(a[1], Path.GetFullPath(a[2]));
      try { Verify(Path.GetFullPath(a[2])); } catch (TargetInvocationException e) { Console.Error.WriteLine("FAILED: " + e.InnerException); return 1; }
      return 0;
    }
    if (a[0] == "--master") {
      Master = a[1];
      a = a.Skip(2).ToArray();
    }
    if (a[0] == "--dir-only") {
      DirOnly = true;
      a = a.Skip(1).ToArray();
    }
    // Absolute: from a relative work path the library writes a directory
    // signature that neither its own check nor ETS 6.4 accepts (2026-10-30).
    string input = a[0], output = a[1], work = Path.GetFullPath(a[2]);
    Unpack(input, work);
    // ETS 6.4 reads the master data version from the archive's knx_master.xml
    // before anything else; the stub <KNX/> of a synthetic product fails that
    // with a FormatException (2026-10-30), so the signer puts ETS's own copy in.
    if (Master != null) {
      File.Copy(Master, Path.Combine(work, "knx_master.xml"), true);
      Console.WriteLine("master " + Master);
    }
    try { Sign(work); } catch (TargetInvocationException e) { Console.Error.WriteLine("FAILED: " + e.InnerException); return 1; }
    if (File.Exists(output)) File.Delete(output);
    using (var zip = ZipFile.Open(output, ZipArchiveMode.Create)) {
      foreach (var f in Directory.GetFiles(work, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal)) {
        var rel = f.Substring(work.Length).TrimStart('\\').Replace('\\', '/');
        zip.CreateEntryFromFile(f, rel, CompressionLevel.Optimal);
        Console.WriteLine("entry " + rel);
      }
    }
    return 0;
  }

  static void Unpack(string input, string work) {
    if (Directory.Exists(work)) Directory.Delete(work, true);
    ZipFile.ExtractToDirectory(input, work);
  }

  static void Verify(string work) {
    var master = Path.Combine(work, "knx_master.xml");
    if (File.Exists(master)) {
      var md = new System.Xml.XmlDocument();
      md.PreserveWhitespace = true;
      md.Load(master);
      var xs = T("XmlSigning").GetConstructor(Any, null, new[] { typeof(bool) }, null).Invoke(new object[] { false });
      Console.WriteLine("verify knx_master.xml " + Call(xs, "CheckMasterDataSignature", md));
    }
    foreach (var manu in Directory.GetDirectories(work, "M-*")) {
      var appHashes = new Dictionary<string, string>();
      var same = new Dictionary<string, string>();
      foreach (var app in Directory.GetFiles(manu, "*_A-*.xml")) {
        var doc = new System.Xml.XmlDocument();
        doc.Load(app);
        var prog = (System.Xml.XmlElement)doc.GetElementsByTagName("ApplicationProgram")[0];
        string id = prog.GetAttribute("Id");
        appHashes[id] = prog.GetAttribute("Hash");
        same[id] = id;
        var state = Call(New("Signer.ApplicationProgramHasher", new FileInfo(app), new Dictionary<string, string>(), false, null), "ValidateHash");
        Console.WriteLine("verify app " + id + " hash " + state);
      }
      var hw = New("Signer.HardwareSigner", new FileInfo(Path.Combine(manu, "Hardware.xml")), same, appHashes, false);
      foreach (System.Collections.DictionaryEntry kv in (System.Collections.IDictionary)Call(hw, "ValidateSignaturesAndHashes"))
        Console.WriteLine("verify hw " + kv.Key + " " + kv.Value);
      Console.WriteLine("verify directory " + Path.GetFileName(manu) + " " + Call(T("XmlSigning"), "CheckDirectorySignature", manu, null));
    }
  }

  // 4. Directory signature over the manufacturer folder, written next to it as
  // <folder>.signature. The path must be absolute: with a relative one the
  // library signs something else, and ETS 6.4 refuses the file ("Projektdatei
  // hat keine gültige Signatur").
  static void SignFolder(string manu) {
    Call(T("XmlSigning"), "SignDirectory", manu, false, null);
  }

  static void Sign(string work) {
    if (DirOnly) {
      foreach (var manu in Directory.GetDirectories(work, "M-*")) SignFolder(manu);
      return;
    }
    foreach (var manu in Directory.GetDirectories(work, "M-*")) {
      var appMap = new Dictionary<string, string>();
      var appHashes = new Dictionary<string, string>();
      var baggages = new Dictionary<string, string>();
      // 1. Application programs: hash, derive the fingerprint, patch the ids.
      foreach (var original in Directory.GetFiles(manu, "*_A-*.xml")) {
        // The hasher writes the program under its new name and deletes its input,
        // so it reads a renamed copy (else an unchanged id deletes the result).
        var app = original + ".unsigned";
        File.Move(original, app);
        var h = New("Signer.ApplicationProgramHasher", new FileInfo(app), baggages, true, null);
        Call(h, "HashFile");
        string oldId = (string)Get(h, "OldApplProgId"), newId = (string)Get(h, "NewApplProgId");
        var renamed = (FileInfo)Get(h, "NewNameWithNewFingerprint");
        appMap[oldId] = newId;
        appHashes[newId] = (string)Get(h, "GeneratedHashString");
        Console.WriteLine("app " + oldId + " -> " + newId + " hash " + appHashes[newId] + " file " + (renamed == null ? "-" : renamed.Name));
        if (File.Exists(app)) File.Delete(app);
        if (renamed == null || !File.Exists(renamed.FullName)) throw new Exception("hasher wrote no program for " + oldId);
      }
      // 2. Hardware: Hash of Product and Hardware2Program, ids patched to the new application ids.
      var hw = New("Signer.HardwareSigner", new FileInfo(Path.Combine(manu, "Hardware.xml")), appMap, appHashes, true);
      Call(hw, "SignFile");
      var hwMap = (IDictionary<string, string>)Get(hw, "OldNewIdMappings");
      foreach (var kv in hwMap) Console.WriteLine("hw " + kv.Key + " -> " + kv.Value);
      // 3. Catalog: CatalogItem / Hardware2Program references follow the new ids.
      var cat = New("Signer.CatalogIdPatcher", new FileInfo(Path.Combine(manu, "Catalog.xml")), hwMap, null);
      Call(cat, "Patch");
      SignFolder(manu);
    }
  }
}
