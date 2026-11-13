namespace crypto_context;

public sealed class Rc5 : ISymmetricCipher
{
    private const decimal E = 2.7182818284590452353602874714m;
    private const decimal Phi = 1.6180339887498948482045868344m;

    private readonly int _w;
    private readonly int _r;
    private readonly ulong _mask;
    private readonly ulong _p;
    private readonly ulong _q;
    private ulong[] _s = [];

    public Rc5(int wordSize = 32, int rounds = 12)
    {
        if (wordSize is not (16 or 32 or 64)) { throw new ArgumentOutOfRangeException(nameof(wordSize), wordSize, "w = 16, 32 или 64"); }

        if (rounds is < 0 or > 255) { throw new ArgumentOutOfRangeException(nameof(rounds), rounds, "r = 0...255"); }

        _w = wordSize;
        _r = rounds;
        _mask = wordSize == 64 ? ulong.MaxValue : (1UL << wordSize) - 1;
        _p = Odd(E - 2);
        _q = Odd(Phi - 1);
    }

    public int BlockSize => _w / 4;

    public void SetKey(byte[] key)
    {
        if (key.Length > 255) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, "b = 0...255 байт"); }

        int u = _w / 8;
        int c = Math.Max(1, (key.Length + u - 1) / u);
        var l = new ulong[c];
        
        for (int i = key.Length - 1; i >= 0; i--)
        {
            l[i / u] = (l[i / u] << 8) | key[i];
        }

        int t = 2 * (_r + 1);
        var s = new ulong[t];
        s[0] = _p;

        for (int i = 1; i < t; i++)
        {
            s[i] = (s[i - 1] + _q) & _mask;            
        }

        ulong a = 0, b = 0;
        for (int k = 0, i = 0, j = 0; k < 3 * Math.Max(t, c); k++, i = (i + 1) % t, j = (j + 1) % c)
        {
            a = s[i] = RotateLeft((s[i] + a + b) & _mask, 3);
            b = l[j] = RotateLeft((l[j] + a + b) & _mask, a + b);
        }

        _s = s;
    }

    public byte[] Encrypt(byte[] block)
    {
        var (a, b) = FromBytes(block);
        a = (a + _s[0]) & _mask;
        b = (b + _s[1]) & _mask;

        for (int i = 1; i <= _r; i++)
        {
            a = (RotateLeft(a ^ b, b) + _s[2 * i]) & _mask;
            b = (RotateLeft(b ^ a, a) + _s[2 * i + 1]) & _mask;
        }

        return ToBytes(a, b);
    }

    public byte[] Decrypt(byte[] block)
    {
        var (a, b) = FromBytes(block);

        for (int i = _r; i >= 1; i--)
        {
            b = RotateRight((b - _s[2 * i + 1]) & _mask, a) ^ a;
            a = RotateRight((a - _s[2 * i]) & _mask, b) ^ b;
        }

        b = (b - _s[1]) & _mask;
        a = (a - _s[0]) & _mask;
        return ToBytes(a, b);
    }

    private ulong Odd(decimal fraction)
    {
        for (int i = 0; i < _w; i++)
        {
            fraction *= 2;
        }

        ulong x = (ulong)decimal.Truncate(fraction);
        return x % 2 == 0 ? x + 1 : x;
    }

    private ulong RotateLeft(ulong x, ulong amount)
    {
        int n = (int)(amount % (ulong)_w);
        return ((x << n) | (x >> (_w - n))) & _mask;
    }

    private ulong RotateRight(ulong x, ulong amount)
    {
        int n = (int)(amount % (ulong)_w);
        return ((x >> n) | (x << (_w - n))) & _mask;
    }

    private (ulong A, ulong B) FromBytes(byte[] block)
    {
        int u = _w / 8;
        ulong a = 0, b = 0;
        for (int i = u - 1; i >= 0; i--)
        {
            a = (a << 8) | block[i];
            b = (b << 8) | block[u + i];
        }
        return (a, b);
    }

    private byte[] ToBytes(ulong a, ulong b)
    {
        int u = _w / 8;
        var block = new byte[2 * u];
        for (int i = 0; i < u; i++)
        {
            block[i] = (byte)(a >> (8 * i));
            block[u + i] = (byte)(b >> (8 * i));
        }
        return block;
    }
}