using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using eazdevirt.Types;

namespace eazdevirt
{
	/// <summary>
	/// Module that contains methods virtualized by Eazfuscator.NET.
	/// </summary>
	public class EazModule
	{
		public ModuleDefMD Module { get; private set; }

		public VirtualMachineType VType { get; private set; }

		public IList<VirtualOpCode> VirtualInstructions { get; private set; }

		/// <summary>
		/// Dictionary containing all identified instruction types (opcodes).
		/// Maps virtual opcode (int) to virtual instruction containing the actual opcode.
		/// </summary>
		public Dictionary<Int32, VirtualOpCode> IdentifiedOpCodes;

		/// <summary>
		/// Embedded resource string identifier.
		/// </summary>
		public String ResourceStringId { get; private set; }

		/// <summary>
		/// Embedded resource crypto key.
		/// </summary>
		public Int32 ResourceCryptoKey { get; private set; }

		/// <summary>
		/// Position translator.
		/// </summary>
		public IPositionTranslator PositionTranslator { get; private set; }

		/// <summary>
		/// Serialization version to use for readers/resolvers.
		/// </summary>
		public SerializationVersion Version { get; private set; }

		public ILogger Logger { get; private set; }

		private Byte[] _transformedResourceBytes;

		/// <summary>
		/// Construct an EazModule from a filepath.
		/// </summary>
		/// <param name="filepath">Filepath of assembly</param>
		public EazModule(String filepath)
			: this(ModuleDefMD.Load(filepath))
		{
		}

		public EazModule(String filepath, ILogger logger)
			: this(ModuleDefMD.Load(filepath), logger)
		{
		}

		/// <summary>
		/// Construct an EazModule from a loaded ModuleDefMD.
		/// </summary>
		/// <param name="module">Loaded module</param>
		public EazModule(ModuleDefMD module)
			: this(module, null)
		{
		}

		public EazModule(ModuleDefMD module, ILogger logger)
		{
			this.Module = module;
			this.Logger = logger ?? DummyLogger.NoThrowInstance;
			this.Initialize();
		}

		private void Initialize()
		{
			// Try to locate the crypto stream. Modern Eazfuscator versions
			// (2021+) redesigned this type so the V1/V2 detectors may not
			// match. We don't fail hard — VType discovery and opcode-handler
			// identification do not actually need the crypt method, only
			// stub-position decoding and final body reading do. If the
			// caller tries to use PositionTranslator and it's null, that
			// specific step will fail with a more precise error.
			var cryptoStreamDef = this.FindCryptoStreamType();
			if (cryptoStreamDef != null)
			{
				this.PositionTranslator = new PositionTranslator(cryptoStreamDef);
				this.Version = cryptoStreamDef is CryptoStreamDefV2 || cryptoStreamDef is CryptoStreamDefModern
					? SerializationVersion.V2
					: SerializationVersion.V1;
			}
			else
			{
				// Default to V2 — newer Eazfuscators are more likely to be V2-ish.
				this.Version = SerializationVersion.V2;
				this.Logger.Warning(this, "Crypto stream TypeDef not recognized; continuing with detect-only capabilities.");
			}

			this.VType = new VirtualMachineType(this);
			this.InitializeIdentifiedOpCodes();
		}

		public void Write(String filepath, Boolean noThrow = false)
		{
			var options = new ModuleWriterOptions(this.Module);
			options.MetadataOptions.Flags |= MetadataFlags.PreserveAll;

			if (noThrow)
				options.Logger = DummyLogger.NoThrowInstance;

			this.Module.Write(filepath, options);
		}

        /// <summary>
        /// Get the resource with virtualized method data as a Stream.
        /// </summary>
        /// <param name="rawStream">
        /// Whether or not to return a raw stream that doesn't automatically handle crypto
        /// </param>
        /// <returns>Stream</returns>
        public Stream GetResourceStream(Boolean rawStream = false)
		{
			var streamType = this.FindCryptoStreamType();
			if (streamType == null)
				throw new Exception("Unable to find crypto stream type");

			if (this.ResourceStringId == null)
			{
				var vmethod = this.FindFirstVirtualizedMethod();
				if (vmethod != null)
				{
					this.ResourceStringId = vmethod.ResourceStringId;
					this.ResourceCryptoKey = vmethod.ResourceCryptoKey;
				}
				else
					throw new Exception("Unable to find any virtualized methods");
			}

			var resource = this.Module.Resources.FindEmbeddedResource(this.ResourceStringId);
			if (resource == null)
				throw new Exception("Unable to find resource");

			if (rawStream)
				return resource.CreateReader().AsStream();

			var baseStream = this.GetTransformedResourceBaseStream() ?? resource.CreateReader().AsStream();
			return streamType.CreateStream(baseStream, this.ResourceCryptoKey);
		}

		private Stream GetTransformedResourceBaseStream()
		{
		    if (_transformedResourceBytes != null)
		        return new MemoryStream(_transformedResourceBytes, false);

		    MethodStub vmethod;
		    try { vmethod = this.FindFirstVirtualizedMethod(); }
		    catch { return null; }
		    if (vmethod?.CreateStreamMethod == null)
		        return null;
		    if (!CreateStreamMethodAppliesResourceTransform(vmethod.CreateStreamMethod))
		        return null;

		    try
		    {
		        _transformedResourceBytes = ExtractResourceViaSanitizedAssembly(vmethod.CreateStreamMethod);
		        return _transformedResourceBytes != null
		            ? new MemoryStream(_transformedResourceBytes, false)
		            : null;
		    }
		    catch (Exception ex)
		    {
		        this.Logger.Warning(this, "Unable to materialize transformed VM resource: {0}", ex.Message);
		        return null;
		    }
		}

		private static Boolean CreateStreamMethodAppliesResourceTransform(MethodDef method)
		{
		    if (!method.HasBody || !method.Body.HasInstructions)
		        return false;

		    return method.Body.Instructions.Any(instr =>
		        instr.OpCode.Code == Code.Call
		        && instr.Operand is IMethod called
		        && called.MethodSig != null
		        && called.MethodSig.RetType.FullName.Equals("System.IO.Stream")
		        && called.MethodSig.Params.Count == 3
		        && called.MethodSig.Params[0].FullName.Equals("System.IO.Stream")
		        && called.MethodSig.Params[1].FullName.Equals("System.Byte[]")
		        && called.MethodSig.Params[2].FullName.Equals("System.String"));
		}

		private Byte[] ExtractResourceViaSanitizedAssembly(MethodDef createStreamMethod)
		{
		    var location = this.Module.Location;
		    if (String.IsNullOrWhiteSpace(location) || !File.Exists(location))
		        return null;

		    var tempPath = Path.Combine(
		        Path.GetTempPath(),
		        "eazfix-resource-" + Guid.NewGuid().ToString("N") + Path.GetExtension(location));

		    try
		    {
		        var tempModule = ModuleDefMD.Load(location);
		        var cctor = tempModule.GlobalType?.FindStaticConstructor();
		        if (cctor != null)
		        {
		            cctor.Body.Instructions.Clear();
		            cctor.Body.ExceptionHandlers.Clear();
		            cctor.Body.Variables.Clear();
		            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
		        }
		        tempModule.Write(tempPath, new ModuleWriterOptions(tempModule)
		        {
		            MetadataOptions = new MetadataOptions(MetadataFlags.PreserveAll)
		        });

		        var asm = Assembly.LoadFile(tempPath);
		        var method = asm.ManifestModule.ResolveMethod(unchecked((Int32)createStreamMethod.MDToken.Raw));
		        using (var stream = (Stream)method.Invoke(null, new Object[0]))
		        using (var ms = new MemoryStream())
		        {
		            stream.CopyTo(ms);
		            return ms.ToArray();
		        }
		    }
		    finally
		    {
		        try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
		    }
		}

		/// <summary>
		/// Try and find the type used for crypto streams.
		/// </summary>
		/// <returns>Crypto stream TypeDef, or null if none found</returns>
		public CryptoStreamDef FindCryptoStreamType()
		{
		    // Eazfuscator 2025.x nests the crypto stream type and no longer always
		    // derives directly from System.IO.Stream; walk all types and check the
		    // stream-like signature first. Several helper streams can share the
		    // same shape, so prefer the one actually constructed by the VM stream
		    // setup method.
		    var modernCandidates = this.Module.GetTypes()
		        .Where(CryptoStreamDefModern.Is)
		        .ToList();
		    foreach (var typeDef in modernCandidates) {
		        if (IsConstructedByVmResourceReader(typeDef))
		            return new CryptoStreamDefModern(typeDef);
		    }
		    if (modernCandidates.Count > 0)
		        return new CryptoStreamDefModern(modernCandidates[0]);

		    foreach (var typeDef in this.Module.GetTypes().Where(type =>
		            type.BaseType != null
		            && type.BaseType.FullName.Equals(typeof(System.IO.Stream).FullName))) {
		        if (CryptoStreamDefV2.Is(typeDef))
		            return new CryptoStreamDefV2(typeDef);
		        else if (CryptoStreamDef.Is(typeDef))
		            return new CryptoStreamDef(typeDef);
		    }

		    return null;
		}

		private Boolean IsConstructedByVmResourceReader(TypeDef streamType)
		{
		    foreach (var type in this.Module.GetTypes())
		    foreach (var method in type.Methods)
		    {
		        if (!method.HasBody || !method.Body.HasInstructions)
		            continue;
		        if (!method.ReturnType.FullName.Equals("System.Void"))
		            continue;
		        if (method.Parameters.Count != 4)
		            continue;
		        if (!method.Parameters[1].Type.FullName.Equals("System.IO.Stream"))
		            continue;
		        if (!method.Parameters[2].Type.FullName.Equals("System.Int64"))
		            continue;
		        if (!method.Parameters[3].Type.FullName.Equals("System.String"))
		            continue;

		        foreach (var instr in method.Body.Instructions)
		        {
		            if (instr.OpCode.Code != dnlib.DotNet.Emit.Code.Newobj)
		                continue;
		            if (!(instr.Operand is MethodDef ctor) || !ctor.IsConstructor)
		                continue;
		            if (ctor.DeclaringType == streamType)
		                return true;
		        }
		    }

		    return false;
		}

		/// <summary>
		/// Look for virtualized methods and return the first found. Useful because
		/// all virtualized methods seem to use the same manifest resource and crypto
		/// key.
		/// </summary>
		/// <returns>First virtualized method if found, null if none found</returns>
		public MethodStub FindFirstVirtualizedMethod()
		{
			var types = this.Module.GetTypes();
			foreach (var type in types)
			{
				MethodStub[] methods = this.FindMethodStubs(type);
				if (methods.Length > 0)
					return methods[0];
			}

			return null;
		}

		/// <summary>
		/// Look for virtualized methods throughout the module.
		/// </summary>
		/// <returns>Found virtualized methods</returns>
		public MethodStub[] FindMethodStubs()
		{
			List<MethodStub> list = new List<MethodStub>();

			var types = this.Module.GetTypes();
			foreach(var type in types)
			{
				MethodStub[] methods = this.FindMethodStubs(type);
				list.AddRange(methods);
			}

			return list.ToArray();
		}

		/// <summary>
		/// Look for virtualized methods of a specific type.
		/// </summary>
		/// <param name="type">Type to look in</param>
		/// <returns>Found virtualized methods</returns>
		public MethodStub[] FindMethodStubs(TypeDef type)
		{
			List<MethodStub> list = new List<MethodStub>();

			var methods = type.Methods;
			foreach (var method in methods)
			{
				if (this.IsMethodStub(method))
					list.Add(new MethodStub(this, method));
			}

			return list.ToArray();
		}

		/// <summary>
		/// Makes an estimated guess as to whether or not the given method
		/// is a virtualized method.
		/// </summary>
		/// <param name="method">Method to inspect</param>
		/// <returns>true if virtualized, false if not</returns>
		/// <remarks>
		/// Performs two checks:
		/// First, it checks for a `ldstr` instruction that loads a length-10 string.
		/// Second, it checks for a call to a method: (Stream, String, Object[]): ???
		/// </remarks>
		public Boolean IsMethodStub(MethodDef method)
		{
			if (method == null || !method.HasBody || !method.Body.HasInstructions)
				return false;

			Boolean hasMethodCall = false, hasLdstr = false;

			var instrs = method.Body.Instructions;
			foreach(var instr in instrs)
			{
				if(instr.OpCode.Code == dnlib.DotNet.Emit.Code.Ldstr)
				{
					String operand = (String)instr.Operand;
					if (operand != null && operand.Length == 10)
						hasLdstr = true;
				}

				if (instr.OpCode.Code == dnlib.DotNet.Emit.Code.Call)
				{
					MethodDef calledMethod;
					if (instr.Operand is MethodDef && (calledMethod = ((MethodDef)instr.Operand)) != null)
					{
						ParameterList p = calledMethod.Parameters;

						TypeSig[] types = null;
						if(p.Count == 3 || p.Count == 6)
						{
							types = new TypeSig[] { p[0].Type, p[1].Type, p[2].Type };
						}
						else if (p.Count == 4 || p.Count == 7)
						{
							types = new TypeSig[] { p[1].Type, p[2].Type, p[3].Type };
						}

						if (types != null
						&& types[0].FullName.Equals("System.IO.Stream")
						&& types[1].FullName.Equals("System.String")
						&& types[2].FullName.Equals("System.Object[]"))
						{
							hasMethodCall = true;
							break;
						}
					}
				}
			}

			return hasLdstr && hasMethodCall;
		}

		/// <summary>
		/// Find all virtual instructions and attempt to identify them.
		/// </summary>
		private void InitializeIdentifiedOpCodes()
		{
			this.IdentifiedOpCodes = new Dictionary<Int32, VirtualOpCode>();

			try
			{
				this.VirtualInstructions = VirtualOpCode.FindAllInstructions(this, this.VType.Type);
			}
			catch (Exception ex)
			{
				this.Logger.Warning(this, "Opcode enumeration failed: {0}", ex.Message);
				this.VirtualInstructions = new List<VirtualOpCode>();
				return;
			}

			var identified = this.VirtualInstructions.Where((instruction) => instruction.IsIdentified);

			Boolean warningOccurred = false;

			foreach (var instruction in identified)
			{
				Boolean containsVirtual = this.IdentifiedOpCodes.ContainsKey(instruction.VirtualCode);

				VirtualOpCode existing = this.IdentifiedOpCodes.Where((kvp, index) => kvp.Value.IdentityEquals(instruction)).FirstOrDefault().Value;
				Boolean containsActual = (existing != null);

				if (containsVirtual)
					this.Logger.Warning(this, "WARNING: Multiple instruction types with the same virtual opcode detected ({0})",
						instruction.VirtualCode);

				if (containsActual && !instruction.ExpectsMultiple) {
				    string opcodeName = instruction.HasCILOpCode 
                        ? instruction.OpCode.ToString() 
                        : instruction.SpecialOpCode.ToString();

				    this.Logger.Warning(this, "WARNING: Multiple virtual opcodes map to the same actual opcode ({0}, {1} => {2})",
						existing.VirtualCode, instruction.VirtualCode, opcodeName);
				}

				if (!warningOccurred)
					warningOccurred = (containsVirtual || containsActual);

				this.IdentifiedOpCodes.Add(instruction.VirtualCode, instruction);
			}

			if (warningOccurred)
				Console.WriteLine();
		}

		/// <summary>
		/// Write params to Console for debugging purposes.
		/// </summary>
		/// <param name="method">Method</param>
		public static void WriteMethodDefParams(MethodDef method)
		{
			ParameterList p = method.Parameters;

			Console.Write("(");
			foreach (var param in p) Console.Write(param.Type.FullName + " ");
			Console.WriteLine(")");
		}
	}
}
