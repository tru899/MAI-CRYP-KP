namespace crypto_context;

public interface ISymmetricCipher
{
    int BlockSize { get; }

    void SetKey(byte[] key);

    byte[] Encrypt(byte[] block);

    byte[] Decrypt(byte[] block);
}
