using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace eazdevirt
{
	/// <summary>
	/// Represents a method stub of a method virtualized by Eazfuscator.NET.
	/// </summary>
	public class MethodStub
	{
		/// <summary>
		/// Parent.
		/// </summary>
		public EazModule Parent { get; private set; }

		/// <summary>
		/// Module.
		/// </summary>
		public ModuleDefMD Module { get { return this.Parent.Module; } }

		/// <summary>
		/// Underlying method.
		/// </summary>
		public MethodDef Method { get; private set; }

		/// <summary>
		/// The method that creates the raw resource stream. The method body
		/// contains a `ldstr` instruction with the resource name.
		/// </summary>
		public MethodDef CreateStreamMethod { get; private set; }

		/// <summary>
		/// The method that does the work.
		/// </summary>
		public MethodDef VirtualCallMethod { get; private set; }

		/// <summary>
		/// Instruction index at which the VirtualCallMethod was found.
		/// </summary>
		public Int32 VirtualCallIndex { get; private set; }

		/// <summary>
		/// The string used to specify the file position to read at.
		/// </summary>
		public String PositionString { get; private set; }

		public Int64 Position { get; private set; }

		/// <summary>
		/// String identifier of the embedded resource which contains encrypted
		/// virtualized method info.
		/// </summary>
		public String ResourceStringId { get; private set; }

		/// <summary>
		/// Crypto key integer used to decrypt the embedded resource.
		/// </summary>
		public Int32 ResourceCryptoKey { get; private set; }

	    /// <summary>
	    /// Crypto key integer used to decrypt the TODO.
	    /// </summary>
	    public Int32 ResourceCryptoKey2 { get; private set; }

        /// <summary>
        /// Construct a MethodStub from an existing method.
        /// </summary>
        /// <param name="module">Parent module</param>
        /// <param name="method">Stub method</param>
        public MethodStub(EazModule module, MethodDef method)
		{
			this.Parent = module;
			this.Method = method;
			this.Initialize();
		}

		/// <summary>
		/// Try to find all helpful information about the method stub and
		/// virtualized method.
		/// </summary>
		private void Initialize()
		{
			if (!this.Method.HasBody || !this.Method.Body.HasInstructions)
				return;

			var instrs = this.Method.Body.Instructions;
			this.VirtualCallIndex = -1;

			// Get info on virtual call method
			for(int i = 0; i < instrs.Count; i++)
			{
				var instr = instrs[i];

				MethodDef method = null;
				if(instr.OpCode.Code == dnlib.DotNet.Emit.Code.Call
				&& (method = Helpers.TryTransformCallOperand(instr.Operand)) != null
				&& IsVirtualCallMethod(method))
				{
					this.VirtualCallMethod = method;
					this.VirtualCallIndex = i;
					break;
				}
			}

			if (this.VirtualCallMethod == null)
				throw new Exception("Couldn't get VirtualCallMethod");

			// Get the position string (best-effort on modern Eazfuscator).
			// Primary: index-based lookup relative to the dispatch call.
			// Fallback: scan backwards from the dispatch call for any
			// length-10 ldstr, then forwards from method start.
			this.PositionString = TryGetPositionString(instrs, this.VirtualCallIndex, this.VirtualCallMethod.Parameters.Count);

			// Get the create stream method
			for (int i = (this.VirtualCallIndex - 3); i >= 0; i--)
			{
				var instr = instrs[i];
				MethodDef method = null;

				if (instr.OpCode.Code == dnlib.DotNet.Emit.Code.Call
				&& (method = Helpers.TryTransformCallOperand(instr.Operand)) != null
				&& method.ReturnType.FullName.Equals("System.IO.Stream"))
				{
					this.CreateStreamMethod = method;
				}
			}

			// Get the resource string id (if we found CreateStreamMethod)
			if (this.CreateStreamMethod != null)
				this.ResourceStringId = FindResourceStringId(this.CreateStreamMethod);

			// Crypto key extraction depends on a specific IL "rabbit hole" chain
			// (FindResourceCryptoKey) that Eazfuscator 2025.x changed. Treat
			// missing keys + position as soft failures so callers can still get
			// VirtualCallMethod / PositionString / ResourceStringId — which is
			// enough to identify and report virtualized methods even when we
			// can't decrypt their bodies.
			try
			{
				this.ResourceCryptoKey = FindResourceCryptoKey(this.VirtualCallMethod);
				this.ResourceCryptoKey2 = FindResourceCryptoKey(this.VirtualCallMethod, true);

				if (this.Parent.PositionTranslator != null)
					this.Position = this.Parent.PositionTranslator.ToPosition(this.PositionString, this.ResourceCryptoKey2);
			}
			catch
			{
				// Leave keys/position defaulted to zero. This stub is still
				// identified; full devirt just won't be possible for it.
			}
		}

		/// <summary>
		/// Best-effort extraction of the 10-char position string from a stub's IL.
		/// Index-based lookup first (the historical eazdevirt pattern); on
		/// failure, scan backwards then forwards for any length-10 ldstr.
		/// Returns null if nothing matches.
		/// </summary>
		private static String TryGetPositionString(IList<Instruction> instrs, int virtualCallIndex, int paramCount)
		{
			int expected = virtualCallIndex - 2;
			if (paramCount >= 6) expected -= 3;

			if (expected >= 0 && expected < instrs.Count
				&& instrs[expected].OpCode.Code == dnlib.DotNet.Emit.Code.Ldstr
				&& instrs[expected].Operand is String s0 && s0.Length == 10)
				return s0;

			// Scan backwards from the dispatch call.
			for (int i = virtualCallIndex - 1; i >= 0; i--)
			{
				if (instrs[i].OpCode.Code == dnlib.DotNet.Emit.Code.Ldstr
					&& instrs[i].Operand is String s1 && s1.Length == 10)
					return s1;
			}

			// Scan forwards from start (catch unusual orderings).
			for (int i = 0; i < virtualCallIndex; i++)
			{
				if (instrs[i].OpCode.Code == dnlib.DotNet.Emit.Code.Ldstr
					&& instrs[i].Operand is String s2 && s2.Length == 10)
					return s2;
			}

			return null;
		}

		/// <summary>
		/// Find the crypto key for the resource associated with the given method
		/// used in virtualized methods.
		/// </summary>
		/// <param name="method">
		/// Method used in virtualized methods, following the pattern: (Stream, String, Object[]): Object
		/// </param>
		/// <returns>Crypto key</returns>
		public static Int32 FindResourceCryptoKey(MethodDef method, bool second = false)
		{
		    if (TryFindModernResourceCryptoKey(method, second, out var modernKey))
		        return modernKey;

		    MethodDef origMethod = method;
		    MethodDef prev = null;

		    for (int i = 0; i < 6 && method != null; i++)
		    {
		        if (method.ReturnType.FullName.Equals("System.Int32"))
		        {
		            if (second) {
		                //prev is void SetStream(long, Stream, string)
		                //find StringToPosition
		                MethodDef mdSTP = (MethodDef)prev.Body.Instructions
		                    .First(a => a.OpCode.Code == Code.Call
		                                && a.Operand is MethodDef
		                                && (a.Operand as MethodDef).ReturnType.FullName.Equals("System.Int64")).Operand;


                        //find get_XorKey2
                        method = (MethodDef)mdSTP.Body.Instructions
                            .First(a => a.OpCode.Code == Code.Call
                                        && a.Operand is MethodDef
                                        && (a.Operand as MethodDef).ReturnType.FullName.Equals("System.Int32")).Operand;
                    }
		            break;
		        }

		        prev = method;
		        method = Helpers.GetFirstCalledMethod(method);
		    }

            if (method == null)
				throw new Exception("Rabbit-Hole strategy of finding the resource crypto key failed");

			var instructions = method.Body.Instructions;
			var count = method.Body.Instructions.Count;

			if (!method.HasBody || !method.Body.HasInstructions || count < 2
			|| !method.ReturnType.FullName.Equals("System.Int32"))
				throw new Exception(String.Format(
					"Found method, but seems insufficient (token={0:X8})", method.MDToken.Raw
				));

			if (instructions[count - 2].OpCode.Code == dnlib.DotNet.Emit.Code.Ldc_I4
			&& instructions[count - 1].OpCode.Code == dnlib.DotNet.Emit.Code.Ret)
			{
				return (Int32)instructions[count - 2].Operand;
			}

			throw new Exception(String.Format(
				"Found bad method? (token={0:X8})", origMethod.MDToken.Raw
			));
		}

		private static bool TryFindModernResourceCryptoKey(MethodDef method, bool second, out Int32 key)
		{
		    key = 0;
		    var vmType = method?.DeclaringType;
		    if (vmType == null)
		        return false;

		    if (second)
		    {
		        foreach (var m in vmType.Methods)
		        {
		            if (!m.HasBody || !m.Body.HasInstructions) continue;
		            if (!m.ReturnType.FullName.Equals("System.Int64")) continue;
		            if (m.Parameters.Count != 2 || !m.Parameters[1].Type.FullName.Equals("System.String")) continue;

		            foreach (var ins in m.Body.Instructions)
		            {
		                if (ins.OpCode.Code != Code.Call || !(ins.Operand is MethodDef called)) continue;
		                if (!called.ReturnType.FullName.Equals("System.Int32")) continue;
		                if (TryReadConstantIntReturn(called, out key))
		                    return true;
		            }
		        }
		        return false;
		    }

		    foreach (var m in vmType.Methods)
		    {
		        if (!m.HasBody || !m.Body.HasInstructions) continue;
		        if (!m.ReturnType.FullName.Equals("System.Void")) continue;
		        if (m.Parameters.Count != 4) continue;
		        if (!m.Parameters[1].Type.FullName.Equals("System.IO.Stream")) continue;
		        if (!m.Parameters[2].Type.FullName.Equals("System.Int64")) continue;
		        if (!m.Parameters[3].Type.FullName.Equals("System.String")) continue;

		        foreach (var ins in m.Body.Instructions)
		        {
		            if (ins.OpCode.Code != Code.Call || !(ins.Operand is MethodDef called)) continue;
		            if (!called.ReturnType.FullName.Equals("System.Int32")) continue;
		            if (TryReadConstantIntReturn(called, out key))
		                return true;
		        }
		    }

		    for (int i = 0; i < 12 && method != null; i++)
		    {
		        if (method.HasBody && method.Body.HasInstructions)
		        {
		            foreach (var ins in method.Body.Instructions)
		            {
		                if (ins.OpCode.Code != Code.Call || !(ins.Operand is MethodDef called)) continue;
		                if (!called.ReturnType.FullName.Equals("System.Int32")) continue;
		                if (TryReadConstantIntReturn(called, out key))
		                    return true;
		            }
		        }
		        method = Helpers.GetFirstCalledMethod(method);
		    }

		    return false;
		}

		private static bool TryReadConstantIntReturn(MethodDef method, out Int32 value)
		{
		    value = 0;
		    if (method == null || !method.HasBody || !method.Body.HasInstructions)
		        return false;
		    var instructions = method.Body.Instructions;
		    if (!method.ReturnType.FullName.Equals("System.Int32") || instructions.Count < 2)
		        return false;
		    if (instructions[instructions.Count - 2].IsLdcI4()
		        && instructions[instructions.Count - 1].OpCode.Code == Code.Ret)
		    {
		        value = instructions[instructions.Count - 2].GetLdcI4Value();
		        return true;
		    }
		    return false;
		}
        
        /// <summary>
        /// Find the resource string Id, given the method that contains it.
        /// </summary>
        /// <param name="method">Method</param>
        /// <returns>Resource string Id if successful, or null if not successful</returns>
        /// <remarks>This extraction is very simple and just gets the operand of the first `ldstr`</remarks>
        public static String FindResourceStringId(MethodDef method)
		{
			if (method == null)
				throw new ArgumentNullException();

			if (!method.HasBody || !method.Body.HasInstructions)
				return null;

			foreach(var instr in method.Body.Instructions)
			{
				if (instr.OpCode.Code == dnlib.DotNet.Emit.Code.Ldstr)
					return (String)instr.Operand;
			}

			return null;
		}

		/// <summary>
		/// Whether or not a method appears to be the stream creation method.
		/// </summary>
		/// <param name="method">Method to check</param>
		/// <returns>true if stream creation method, false if not</returns>
		public static Boolean IsCreateStreamMethod(MethodDef method)
		{
			if (method == null)
				throw new ArgumentNullException();

			return method.Parameters.Count == 0
				&& method.ReturnType.FullName.Equals("System.IO.Stream");
		}

		/// <summary>
		/// Whether or not a method appears to be the virtual call method.
		/// </summary>
		/// <param name="method">Method to check</param>
		/// <returns>true if virtual call method, false if not</returns>
		public static Boolean IsVirtualCallMethod(MethodDef method)
		{
			if (method == null)
				throw new ArgumentNullException();

			ParameterList p = method.Parameters;

			TypeSig[] types = null;
			if (p.Count == 3 || p.Count == 6)
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
				return true;
			}

			return false;
		}
	}
}
