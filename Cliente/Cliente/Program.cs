using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

class Client
{
    static void Main()
    {
        try
        {
            // Se inicializa el cliente
            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[1];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

            Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            sender.Connect(remoteEP);

            // Protocolo Diffie-Hellman para intercambio de llaves
            var dh = new ECDiffieHellmanCng();
            dh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            dh.HashAlgorithm = CngAlgorithm.Sha256;

            // Clave pública del cliente
            byte[] clientPublicKey = dh.PublicKey.ToByteArray();

            // Enviar la clave pública al servidor
            Console.WriteLine("Enviando clave pública al servidor...");
            sender.Send(clientPublicKey);

            // Recibir la clave pública del servidor
            byte[] serverPublicKey = new byte[1024];
            int serverPublicKeySize = sender.Receive(serverPublicKey);

            // Generar el secreto compartido usando la clave pública del servidor
            byte[] sharedSecret = dh.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));

            // Derivar la clave simétrica utilizando SHA-256 como KDF
            byte[] symKey = SHA256.Create().ComputeHash(sharedSecret);
            byte[] nonce = Encoding.ASCII.GetBytes("12345678"); // 8 bytes nonce

            Console.WriteLine("Conectado al servidor. Se generó la clave simétrica.");

            // Ciclo para cifrar y enviar mensajes
            while (true)
            {
                Console.WriteLine("Por favor, ingrese su mensaje:");
                string message = Console.ReadLine();
                byte[] messageBytes = Encoding.ASCII.GetBytes(message);

                // Cifrar con Salsa20 usando la clave derivada
                byte[] encryptedMessage = EncryptSalsa20(messageBytes, symKey, nonce);

                Console.WriteLine("Enviando mensaje cifrado...");
                sender.Send(encryptedMessage);

                // Recibir respuesta del servidor
                byte[] buffer = new byte[1024];
                int bytesRec = sender.Receive(buffer);
                Console.WriteLine("Respuesta del servidor: {0}", Encoding.ASCII.GetString(buffer, 0, bytesRec));
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }


    }

    //Funcion para cifrar usando Salsa20,usamos la biblioteca BouncyCastle en c#
    public static byte[] EncryptSalsa20(byte[] plainText, byte[] key, byte[] nonce)
    {
        Salsa20Engine engine = new Salsa20Engine(); // Salsa20
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), nonce);

        engine.Init(true, parameters); // true para cifrar
        byte[] cipherText = new byte[plainText.Length];
        engine.ProcessBytes(plainText, 0, plainText.Length, cipherText, 0);

        return cipherText;
    }
}
