namespace crypto_context;

public class Magenta : ISymmetricCipher
{
    private FeistelNetwork network = new FeistelNetwork(new MagentaKeyExpansion(), new MagentaRoundFunction(), 16);

    public int BlockSize => 16;

    public void SetKey(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 16 && key.Length != 24 && key.Length != 32) throw new ArgumentException("magenta key must be 16, 24 or 32 bytes");

        network.SetKey(key);
    }

    public byte[] Encrypt(byte[] block) => SwapHalves(network.Encrypt(block));

    public byte[] Decrypt(byte[] block) => network.Decrypt(SwapHalves(block));

    private static byte[] SwapHalves(byte[] block) => [.. block[8..], .. block[..8]];
}

public class MagentaKeyExpansion : IKeyExpansion
{
    private static readonly int[] ORDER_128 = [0, 0, 1, 1, 0, 0];
    private static readonly int[] ORDER_192 = [0, 1, 2, 2, 1, 0];
    private static readonly int[] ORDER_256 = [0, 1, 2, 3, 3, 2, 1, 0];

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        int[] order = key.Length switch
        {
            16 => ORDER_128,
            24 => ORDER_192,
            _ => ORDER_256,
        };

        byte[][] round_keys = new byte[order.Length][];
        for (int round = 0; round < order.Length; round++)
        {
            round_keys[round] = key[(8 * order[round])..(8 * order[round] + 8)];
        }

        return round_keys;
    }
}

public class MagentaRoundFunction : ICipherTransform
{
    private const int MODULUS = 0x165;

    private static readonly byte[] POWERS = BuildPowers();

    public byte[] Transform(byte[] block, byte[] round_key) => S(C(3, [.. block, .. round_key]))[..8];

    private static byte[] BuildPowers()
    {
        byte[] powers = new byte[256];
        int value = 1;
        for (int i = 0; i < 255; i++)
        {
            powers[i] = (byte)value;
            value <<= 1;
            if (value > 0xFF)
            {
                value ^= MODULUS;
            }
        }
        powers[255] = 0;
        return powers;
    }

    private static byte A(byte x, byte y) => POWERS[x ^ POWERS[y]];

    private static (byte, byte) PE(byte x, byte y) => (A(x, y), A(y, x));

    private static byte[] Pi(byte[] x)
    {
        byte[] result = new byte[16];
        for (int i = 0; i < 8; i++)
        {
            (result[2 * i], result[2 * i + 1]) = PE(x[i], x[i + 8]);
        }
        return result;
    }

    private static byte[] T(byte[] x) => Pi(Pi(Pi(Pi(x))));

    private static byte[] S(byte[] x)
    {
        byte[] result = new byte[16];
        for (int i = 0; i < 8; i++)
        {
            result[i] = x[2 * i];
            result[i + 8] = x[2 * i + 1];
        }
        return result;
    }

    private static byte[] C(int n, byte[] x)
    {
        if (n == 1)
        {
            return T(x);
        }

        byte[] previous = S(C(n - 1, x));
        byte[] mixed = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            mixed[i] = (byte)(x[i] ^ previous[i]);
        }
        return T(mixed);
    }
}
