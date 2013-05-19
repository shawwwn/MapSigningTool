using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;

namespace MapSigningTool
{
    public partial class Form1 : Form
    {
        const string PUBLIC_KEY_FOLDER = "PublicKeys";

        public byte[] maphash;
        public byte[] mapsignature;
        public long signature_pos = -1;

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //MapSignature ms = new MapSignature();
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                button2.Enabled = false;
                textBox2.Text = "";
                textBox1.Text = "";
                maphash = null;
                mapsignature = null;
                try
                {
                    signature_pos = MapSignature.MapGetSignatureInfo(openFileDialog1.FileName, ref maphash, ref mapsignature);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                    return;
                }

                //print the map path
                textBox2.Text = openFileDialog1.FileName;

                //print SHA1 hash
                textBox1.Text = BitConverter.ToString(maphash);
                if (mapsignature != null)  //If map has digital signature
                {
                    //verify
                    for (int i = 0; i < listView1.Items.Count; i++)
                    {
                        byte[] signedhash_raw = MapSignature.VerifyData(mapsignature, PUBLIC_KEY_FOLDER + "\\" + listView1.Items[i].Text + ".pem");  //verify = public key decrypt
                        byte[] signedhash = MapSignature.RemovePadding(signedhash_raw);
                        listView1.Items[i].SubItems["status"].ResetStyle();
                        if (maphash.SequenceEqual(signedhash))
                        {
                            listView1.Items[i].SubItems["status"].BackColor = Color.LawnGreen;
                            listView1.Items[i].SubItems["status"].Text = "Validated";
                        }
                        else { listView1.Items[i].SubItems["status"].Text = "Failed"; }
                    }
                }
                else
                {
                    listView1.Items.Clear();
                    Form1_Load(null, null);
                }
            }
            button2.Enabled = true;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            byte[] raw_signature = MapSignature.AddPadding(maphash);
            if (openFileDialog2.ShowDialog() == DialogResult.OK)
            {
                Application.DoEvents();
                byte[] signature;

                //try to sign
                try
                {
                    signature = MapSignature.SignData(raw_signature, openFileDialog2.FileName);
                }
                catch
                {
                    MessageBox.Show("Please use a 2048bit RSA private key in pem format.", "Invaild Key!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                Application.DoEvents();
                Console.WriteLine("Signature:");
                Console.WriteLine(BitConverter.ToString(signature));

                //add signature to a map
                Application.DoEvents();
                MapSignature.MapAddSignature(textBox2.Text, signature, signature_pos);

                MessageBox.Show("DONE!");
            }
            
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            openFileDialog2.InitialDirectory = Application.StartupPath + @"\PrivateKeys";
            if (!Directory.Exists(PUBLIC_KEY_FOLDER)) { return; }
            foreach (string file in Directory.GetFiles(PUBLIC_KEY_FOLDER))
            {
                if (Path.GetExtension(file) == ".pem")
                {
                    ListViewItem item = new ListViewItem(Path.GetFileNameWithoutExtension(file));
                    item.UseItemStyleForSubItems = false;
                    ListViewItem.ListViewSubItem subitem = new ListViewItem.ListViewSubItem(item, "");
                    subitem.Name = "status";
                    item.SubItems.Add(subitem);
                    listView1.Items.Add(item);
                }
            }
        }
    }
}
