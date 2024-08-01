using System.Runtime.InteropServices;
using System.Text;
using ASodium;

static (string publicKey, string secretKey) GeneratePublicAndSecretKey()
{
    var keyPair = SodiumPublicKeyBox.GenerateKeyPair();

    var publicKey =  SodiumHelper.BinaryToHex(keyPair.GetPublicKey());

    var secretKeyIntPtr = keyPair.GetPrivateKey();
    var secretKey = new byte[keyPair.GetPrivateKeyLength()];
    Marshal.Copy(secretKeyIntPtr, secretKey, 0, keyPair.GetPrivateKeyLength());
    
    return (publicKey, SodiumHelper.BinaryToHex(secretKey));
}

static string CalculateSharedSecret(string otherUserPublicKey, string currentUserSecretKey)
{
    var sharedKeyBytes = SodiumPublicKeyBoxPCI.CalculateSharedSecret(SodiumHelper.HexToBinary(otherUserPublicKey), SodiumHelper.HexToBinary(currentUserSecretKey));
    return SodiumHelper.BinaryToHex(sharedKeyBytes);
}

var (otherUserPublicKey, otherUserSecretKey) = GeneratePublicAndSecretKey();
var (currentUserPublicKey, currentUserSecretKey) = GeneratePublicAndSecretKey();
var rawData = "This is a book.";
Console.WriteLine("Plain Message: " + rawData);

var nonce = SodiumPublicKeyBox.GenerateNonce();

var encrypedSharedSecret = CalculateSharedSecret(otherUserPublicKey, currentUserSecretKey);
var encryptedMessageBinary = SodiumPublicKeyBoxPCI.Create(Encoding.UTF8.GetBytes(rawData), nonce, SodiumHelper.HexToBinary(encrypedSharedSecret));
Console.WriteLine("Encrypted Message: " + SodiumHelper.BinaryToHex(encryptedMessageBinary));

var decrypedSharedSecret = CalculateSharedSecret(currentUserPublicKey, otherUserSecretKey);
var decryptedMessageBinary = SodiumPublicKeyBoxPCI.Open(encryptedMessageBinary, nonce, SodiumHelper.HexToBinary(decrypedSharedSecret));
Console.WriteLine("Decrypted Message: " + Encoding.UTF8.GetString(decryptedMessageBinary));