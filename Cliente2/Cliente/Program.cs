using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

class Client
{
    static void Main()
    {
        while (true) {
            try
            {
                // Inicializar el cliente
                IPHostEntry host = Dns.GetHostEntry("localhost");
                IPAddress ipAddress = host.AddressList[1];
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
                Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                sender.Connect(remoteEP);

                // Solicitar la clave pública del servidor para ECDH
                Console.WriteLine("Conectado al servidor. Iniciando intercambio de claves ECDH...");

                // Generar par de claves (privada y pública) para ECDH con la curva P-256
                using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
                {
                    ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    ecdh.HashAlgorithm = CngAlgorithm.Sha256;

                    // Obtener la clave pública del cliente
                    byte[] publicKey = ecdh.PublicKey.ToByteArray();

                    // Enviar la clave pública al servidor
                    sender.Send(publicKey);
                    Console.WriteLine("Clave pública enviada al servidor.");

                    // Recibir la clave pública del servidor
                    byte[] serverPublicKey = new byte[72]; // Longitud de la clave pública para P-256
                    int bytesReceived = sender.Receive(serverPublicKey);
                    Console.WriteLine("Clave pública del servidor recibida.");

                    // Generar la clave simétrica compartida
                    using (ECDiffieHellmanPublicKey serverECDHPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(serverPublicKey, CngKeyBlobFormat.EccPublicBlob))
                    {
                        byte[] sharedKey = ecdh.DeriveKeyMaterial(serverECDHPublicKey);

                        // Derivar la clave simétrica (AES-256) usando una KDF
                        byte[] aesKey = new byte[32]; // 256 bits
                        Array.Copy(sharedKey, aesKey, 32); // Tomar los primeros 32 bytes como clave AES

                        // Solicitar el mensaje a cifrar
                        Console.WriteLine("Por favor, ingrese su mensaje:");
                        string mensajerec = Console.ReadLine();
                        byte[] messageBytes = Encoding.ASCII.GetBytes(mensajerec);

                        // Generar un IV (nonce) para AES
                        byte[] nonce = new byte[16]; // 128 bits
                        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                        {
                            rng.GetBytes(nonce);
                        }

                        // Cifrar el mensaje con AES-256 CBC
                        byte[] encryptedMessage = EncryptAes256Cbc(messageBytes, aesKey, nonce);

                        // Enviar el IV y el mensaje cifrado al servidor
                        sender.Send(nonce); // Enviar primero el nonce (IV)
                        sender.Send(encryptedMessage); // Luego enviar el mensaje cifrado
                        Console.WriteLine("Mensaje cifrado enviado al servidor.");

                        // Recibir la respuesta del servidor
                        byte[] buffer = new byte[1024];
                        int bytesRec = sender.Receive(buffer);
                        Console.WriteLine("Respuesta del servidor: {0}", Encoding.ASCII.GetString(buffer, 0, bytesRec));

                        // Finalizar la conexión
                        sender.Shutdown(SocketShutdown.Both);
                        sender.Close();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

    }

    //Funcion para cifrar usando Salsa20,usamos la biblioteca BouncyCastle en c#
    public static byte[] EncryptAes256Cbc(byte[] plainText, byte[] key, byte[] iv)
    {
        // Asegúrate de que la clave y el IV tengan el tamaño adecuado
        if (key.Length != 32) // 256 bits
            throw new ArgumentException("La clave debe tener 256 bits (32 bytes).");
        if (iv.Length != 16) // 128 bits (tamaño del bloque AES)
            throw new ArgumentException("El IV debe tener 128 bits (16 bytes).");

        // Crear el motor AES en modo CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));

        // Inicializar el cifrador para cifrar
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

        // Cifrar el texto plano
        byte[] cipherText = new byte[cipher.GetOutputSize(plainText.Length)];
        int length = cipher.ProcessBytes(plainText, 0, plainText.Length, cipherText, 0);
        cipher.DoFinal(cipherText, length);

        return cipherText;
    }
}
