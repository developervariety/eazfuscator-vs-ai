using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace eazdevirt.Types
{
	public class CryptoStreamDef : BaseTypeDefProvider
	{
		public MethodDef CryptMethod { get; private set; }

		public CryptoStreamDef(TypeDef cryptoStream)
			: base(cryptoStream)
		{
			this.Initialize();
		}

		private void Initialize()
		{
			// Find/set crypt method
			this.CryptMethod = this.FindCryptMethod();
			if (this.CryptMethod == null)
				throw new Exception("Unable to find crypt method of CryptoStreamDef");
		}

		/// <summary>
		/// Find the crypt method.
		/// </summary>
		/// <returns>Crypt MethodDef, or null if none found</returns>
		protected MethodDef FindCryptMethod()
		{
			return this.TypeDef.Methods.FirstOrDefault(m =>
			{
				return !m.IsStatic
					&& m.ReturnType.FullName.Equals(typeof(Byte).FullName)
					&& m.Parameters.Count == 3
					&& m.Parameters[1].Type.FullName.Equals(typeof(Byte).FullName)
					&& (m.Parameters[2].Type.FullName.Equals(typeof(Int64).FullName)
					    || m.Parameters[2].Type.FullName.Equals(typeof(UInt32).FullName));
			});
		}

		public virtual CryptoStreamBase CreateStream(Stream baseStream, Int32 key)
		{
			return new V1.CryptoStreamV1(baseStream, key);
		}

		public static Boolean Is(TypeDef typeDef)
		{
			try
			{
				var cryptoStreamDef = new CryptoStreamDef(typeDef);
				return true;
			}
			catch { return false; }
		}
	}

	public class CryptoStreamDefV2 : CryptoStreamDef
	{
		public Int32 Special { get; private set; }

		public CryptoStreamDefV2(TypeDef cryptoStream)
			: base(cryptoStream)
		{
			this.Initialize();
		}

		private void Initialize()
		{
			// Find/set special
			var special = this.FindSpecial();
			if (!special.HasValue)
				throw new Exception("Unable to find special value of crypt method of CryptoStreamDef");
			else this.Special = special.Value;
		}

		protected Int32? FindSpecial()
		{
			var instrs = this.CryptMethod.Body.Instructions;
			foreach (var instr in instrs)
			{
				if (instr.IsLdcI4())
					return (Int32)instr.Operand;
			}

			return null;
		}

		public override CryptoStreamBase CreateStream(Stream baseStream, Int32 key)
		{
			return new V2.CryptoStreamV2(baseStream, key, this.Special);
		}

		public static Boolean Is(TypeDef typeDef)
		{
			try
			{
				var cryptoStreamDef = new CryptoStreamDefV2(typeDef);
				// Check if the crypt method has a ldc.i4 instruction
				return cryptoStreamDef.CryptMethod.Body.Instructions.FirstOrDefault(
					instr => instr.IsLdcI4()) != null;
			}
			catch { return false; }
		}
	}

	public class CryptoStreamDefModern : CryptoStreamDef
	{
		public Int32 XorKey { get; private set; }

		public CryptoStreamDefModern(TypeDef cryptoStream)
			: base(cryptoStream)
		{
			this.InitializeModern();
		}

		private void InitializeModern()
		{
			var ctor = this.TypeDef.Methods.FirstOrDefault(m =>
				m.IsConstructor
				&& m.Parameters.Count == 3
				&& m.Parameters[1].Type.FullName.Equals(typeof(Stream).FullName)
				&& m.Parameters[2].Type.FullName.Equals(typeof(Int32).FullName));
			if (ctor == null)
				throw new Exception("Unable to find modern crypto stream constructor");

			var instructions = ctor.Body.Instructions;
			for (int i = 0; i < instructions.Count - 1; i++)
			{
				var instr = instructions[i];
				if (instr.IsLdcI4())
				{
					for (int j = i + 1; j < instructions.Count && j <= i + 3; j++)
					{
						if (instructions[j].OpCode.Code == Code.Xor)
						{
							this.XorKey = instr.GetLdcI4Value();
							return;
						}
					}
				}
			}

			throw new Exception("Unable to find modern crypto stream xor key");
		}

		public override CryptoStreamBase CreateStream(Stream baseStream, Int32 key)
		{
			return new V3.CryptoStreamV3(baseStream, key, this.XorKey);
		}

		public new static Boolean Is(TypeDef typeDef)
		{
			try
			{
				var cryptoStreamDef = new CryptoStreamDefModern(typeDef);
				return cryptoStreamDef.CryptMethod.Parameters[2].Type.FullName.Equals(typeof(UInt32).FullName);
			}
			catch { return false; }
		}
	}
}
