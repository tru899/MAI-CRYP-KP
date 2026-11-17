namespace crypto_context;

public interface ISymmetricCipher
{
    int BlockSize { get; }

    void SetKey(byte[] key);

    byte[] Encrypt(byte[] block);

    byte[] Decrypt(byte[] block);
}

public interface IKeyExpansion
{
    byte[][] GenerateRoundKeys(byte[] key);
}

public interface ICipherTransform
{
    byte[] Transform(byte[] block, byte[] roundKey);
}
