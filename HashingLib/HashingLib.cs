using HashingLib.Hashers;
using HashingLib.Utils;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HashingLib
{
    /// <summary>
    /// Class with commom methods to use hashers
    /// </summary>
    public static class HashingLib
    {
        /// <summary>
        /// A method for getting a ED2K hash from a specified file path
        /// </summary>
        /// <param name="file">The FileStream to hash</param>
        /// <returns>A string containing the ED2K hash</returns>
        public static string GetED2K(FileStream file)
        {
            byte[] buffer;
            const int CHUNK_SIZE = 9728000;
            long chunkCount = 0;
            List<byte> md4HashedBytes = new List<byte>();

            buffer = new byte[CHUNK_SIZE];
            int bufferLength;
            while ((bufferLength = file.Read(buffer, 0, CHUNK_SIZE)) > 0)
            {
                ++chunkCount;
                byte[] chunkMd4HashedBytes = MD4.GetByteHashFromBytes(buffer.Take(bufferLength).ToArray());
                md4HashedBytes.AddRange(chunkMd4HashedBytes);
                buffer = new byte[CHUNK_SIZE];
            }

            string hash = (chunkCount > 1
        ? MD4.GetHexHashFromBytes(md4HashedBytes.ToArray())
        : MD4.BytesToHex(md4HashedBytes.ToArray(), md4HashedBytes.Count)).ToLower();
            return hash;
        }

        /// <summary>
        /// A method for getting a ED2K hash from a specified file path
        /// </summary>
        /// <param name="filePath">The path for the file to hash</param>
        /// <returns>A string containing the ED2K hash</returns>
        public static string GetED2K(string filePath)
        {
            string hash = String.Empty;

            using (FileStream file = File.OpenRead(filePath))
            {
                byte[] buffer;
                const int CHUNK_SIZE = 9728000;
                double totalChunkCount = 0;
                long chunkCount = 0;
                int bufferLength = 0;
                MD4 md4 = new MD4();
                List<byte> md4HashedBytes = new List<byte>();

                buffer = new byte[CHUNK_SIZE];
                totalChunkCount = Math.Ceiling(file.Length * 1.0 / CHUNK_SIZE);
                while ((bufferLength = file.Read(buffer, 0, CHUNK_SIZE)) > 0)
                {
                    ++chunkCount;
                    byte[] chunkMd4HashedBytes = MD4.GetByteHashFromBytes(buffer.Take(bufferLength).ToArray());
                    md4HashedBytes.AddRange(chunkMd4HashedBytes);
                    buffer = new byte[CHUNK_SIZE];
                }

                hash = (chunkCount > 1
                        ? MD4.GetHexHashFromBytes(md4HashedBytes.ToArray())
                        : MD4.BytesToHex(md4HashedBytes.ToArray(), md4HashedBytes.Count)).ToLower();
            }

            return hash;
        }

        /// <summary>
        /// A method for getting a MD5 hash from a specified file path
        /// </summary>
        /// <param name="file">The FileStream to hash</param>
        /// <returns>A string containing the MD5 hash</returns>
        public static string GetMD5(FileStream file)
        {
            string hash = String.Empty;

            using (HashAlgorithm hasher = MD5.Create())
            {
                byte[] buffer;
                int bytesToRead = 0;
                long totalBytesRead = 0;

                do
                {
                    buffer = new byte[4096];

                    bytesToRead = file.Read(buffer, 0, buffer.Length);

                    totalBytesRead += bytesToRead;

                    hasher.TransformBlock(buffer, 0, bytesToRead, null, 0);
                }
                while (bytesToRead != 0);

                hasher.TransformFinalBlock(buffer, 0, 0);

                hash = HashStringConverter.MD5HashStringBuilder(hasher.Hash);
            }

            return hash;
        }

        /// <summary>
        /// A method for getting a MD5 hash from a specified file path
        /// </summary>
        /// <param name="filePath">The path for the file to hash</param>
        /// <returns>A string containing the MD5 hash</returns>
        public static string GetMD5(string filePath)
        {
            string hash = String.Empty;

            using (FileStream file = File.OpenRead(filePath))
            {
                using HashAlgorithm hasher = MD5.Create();
                byte[] buffer;
                int bytesToRead = 0;
                long totalBytesRead = 0;

                do
                {
                    buffer = new byte[4096];

                    bytesToRead = file.Read(buffer, 0, buffer.Length);

                    totalBytesRead += bytesToRead;

                    hasher.TransformBlock(buffer, 0, bytesToRead, null, 0);
                }
                while (bytesToRead != 0);

                hasher.TransformFinalBlock(buffer, 0, 0);

                hash = HashStringConverter.MD5HashStringBuilder(hasher.Hash);
            }

            return hash;
        }

        /// <summary>
        /// A method for getting a SHA1 hash from a specified file path
        /// </summary>
        /// <param name="file">The FileStream to hash</param>
        /// <returns>A string containing the SHA1 hash</returns>
        public static string GetSHA1(FileStream file)
        {
            string hash = String.Empty;

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                byte[] bHash = sha1.ComputeHash(file);
                StringBuilder sb = new StringBuilder(bHash.Length * 2);

                foreach (byte b in bHash)
                {
                    sb.Append(b.ToString("x2"));
                }

                hash = sb.ToString();
            }

            return hash;
        }

        /// <summary>
        /// A method for getting a SHA1 hash from a specified file path
        /// </summary>
        /// <param name="filePath">The path for the file to hash</param>
        /// <returns>A string containing the SHA1 hash</returns>
        public static string GetSHA1(string filePath)
        {
            string hash = String.Empty;

            using (FileStream file = File.OpenRead(filePath))
            {
                using SHA1Managed sha1 = new SHA1Managed();
                byte[] bHash = sha1.ComputeHash(file);
                StringBuilder sb = new StringBuilder(bHash.Length * 2);

                foreach (byte b in bHash)
                {
                    sb.Append(b.ToString("x2"));
                }

                hash = sb.ToString();
            }

            return hash;
        }

        /// <summary>
        /// A method for getting a TTH hash from a specified file path
        /// </summary>
        /// <param name="file">The FileStream to hash</param>
        /// <returns>A string containing the TTH hash</returns>
        public static string GetTTH(FileStream file)
        {
            TTH_Optimized TTH = new TTH_Optimized();
            string hash = HashStringConverter.ToBase32String(TTH.GetTTH(file.Name)).ToLower();
            return hash;
        }

        /// <summary>
        /// A method for getting a TTH hash from a specified file path
        /// </summary>
        /// <param name="filePath">The path for the file to hash</param>
        /// <returns>A string containing the TTH hash</returns>
        public static string GetTTH(string filePath)
        {
            TTH_Optimized TTH = new TTH_Optimized();
            string hash = HashStringConverter.ToBase32String(TTH.GetTTH(filePath)).ToLower();
            return hash;
        }

        /// <summary>
        /// A method for getting a human-readable file size
        /// </summary>
        /// <param name="size">The file size</param>
        /// <param name="formatting">The formatting to use (E.g.: {0:0.#} {1} will output 15.6 GB)</param>
        /// <returns>The string containing the readable file size</returns>
        public static string GetHumanReadableFileSize(long size, string formatting)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return String.Format(formatting, size, sizes[order]);
        }
    }
}