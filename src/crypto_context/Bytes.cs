namespace crypto_context;

public static class Bytes
{
    public static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] res = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            res[i] = (byte)(a[i] ^ b[i]);
        }
        return res;
    }
}