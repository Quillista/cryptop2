using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

class Server
{
    static void Main()
    {
        // Se inicializa el servidor
        IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, 11000);
        Socket listener = new Socket(IPAddress.Any.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

        try
        {
            listener.Bind(localEndPoint);
            listener.Listen(10);
            Console.WriteLine("Esperando conexión...");

            Socket handler = listener.Accept();

            // Protocolo Diffie-Hellman para intercambio de llaves
            var dh = new ECDiffieHellmanCng();
            dh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            dh.HashAlgorithm = CngAlgorithm.Sha256;

            // Clave pública del servidor
            byte[] serverPublicKey = dh.PublicKey.ToByteArray();

            // Recibir la clave pública del cliente
            byte[] clientPublicKey = new byte[1024];
            int clientPublicKeySize = handler.Receive(clientPublicKey);

            // Enviar la clave pública al cliente
            Console.WriteLine("Enviando clave pública al cliente...");
            handler.Send(serverPublicKey);

            // Generar el secreto compartido usando la clave pública del cliente
            byte[] sharedSecret = dh.DeriveKeyMaterial(CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob));

            // Derivar la clave simétrica utilizando SHA-256 como KDF
            byte[] symKey = SHA256.Create().ComputeHash(sharedSecret);
            byte[] nonce = Encoding.ASCII.GetBytes("12345678"); // 8 bytes nonce

            Console.WriteLine("Clave simétrica derivada. Esperando mensajes cifrados...");

            while (true)
            {
                // Recibir mensaje cifrado
                byte[] buffer = new byte[1024];
                int bytesReceived = handler.Receive(buffer);
                byte[] encryptedMessage = new byte[bytesReceived];
                Array.Copy(buffer, encryptedMessage, bytesReceived);

                // Descifrar con Salsa20 usando la clave derivada
                byte[] decryptedMessage = DecryptSalsa20(encryptedMessage, symKey, nonce);

                Console.WriteLine("Mensaje recibido y descifrado: {0}", Encoding.ASCII.GetString(decryptedMessage));

                // Responder al cliente
                byte[] msg = Encoding.ASCII.GetBytes("Mensaje recibido en el servidor.");
                handler.Send(msg);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }

        Console.WriteLine("Servidor cerrado.");

    }


    // Función para descifrar usando Salsa20, usamos la biblioteca BouncyCastle en c#

    public static byte[] DecryptSalsa20(byte[] cipherText, byte[] key, byte[] nonce)
    {
        Salsa20Engine engine = new Salsa20Engine(); // Salsa20
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), nonce);

        engine.Init(false, parameters); // false para descifrar
        byte[] plainText = new byte[cipherText.Length];
        engine.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);

        return plainText;
    }
}
