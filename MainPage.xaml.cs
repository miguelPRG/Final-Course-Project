using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using PdfSharpCore.Drawing;
using PdfSharpCore.Pdf;
using Windows.Storage.Pickers;
using Windows.Storage;
using System.Threading.Tasks;

// O modelo de item de Página em Branco está documentado em https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x416

namespace ProjetoA
{
    /// <summary>
    /// Uma página vazia que pode ser usada isoladamente ou navegada dentro de um Quadro.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            string codigoCSharp = Input.Text;
            PdfDocument document = CriarDocumentoPDF(codigoCSharp);

            await SalvarDocumentoPDF(document);
        }

        private PdfDocument CriarDocumentoPDF(string codigoCSharp)
        {
            PdfDocument document = new PdfDocument();

            PdfPage page = document.AddPage();
            XGraphics gfx = XGraphics.FromPdfPage(page);

            XFont font = new XFont("Courier New", 15, XFontStyle.Regular);

            FormatarCodigo(gfx, font, codigoCSharp, page);

            return document;
        }

        private void FormatarCodigo(XGraphics gfx, XFont font, string codigoCSharp, PdfPage page)
        {
            // Substitua diferentes caracteres de quebra de linha por \n para padronização
            codigoCSharp = codigoCSharp.Replace("\r\n", "\n").Replace("\r", "\n");

            string[] linhasCodigo = codigoCSharp.Split(new string[] { "\n" }, StringSplitOptions.None);

            double xPos = 20;
            double yPos = 20;

            foreach (string linha in linhasCodigo)
            {
                gfx.DrawString(linha, font, XBrushes.Black,
                    new XRect(xPos, yPos, page.Width, page.Height),
                    XStringFormats.TopLeft);

                yPos += font.GetHeight();
            }
        }


        private async Task SalvarDocumentoPDF(PdfDocument document)
        {
            FileSavePicker savePicker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = "Relatorio.pdf"
            };
            savePicker.FileTypeChoices.Add("Documento PDF", new string[] { ".pdf" });

            StorageFile file = await savePicker.PickSaveFileAsync();
            if (file != null)
            {
                using (var fileStream = await file.OpenStreamForWriteAsync())
                {
                    document.Save(fileStream);
                }
            }
            else
            {
                Console.WriteLine("Operação cancelada.");
            }
        }

        private void Input_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Tab)
            {
                // Insere múltiplos espaços de texto para a direita
                var textBox = (TextBox)sender;
                int selectionStart = textBox.SelectionStart;

                // Obtém o texto antes e depois da posição do cursor
                string textBeforeCursor = textBox.Text.Substring(0, selectionStart);
                string textAfterCursor = textBox.Text.Substring(selectionStart);

                // Concatena múltiplos espaços ao texto
                textBox.Text = textBeforeCursor + "    " + textAfterCursor;

                // Move o cursor para frente (para a posição após os espaços)
                textBox.SelectionStart = selectionStart + 4;

                // Indica que o evento foi tratado, impedindo que o Tab mude o foco para o próximo elemento
                e.Handled = true;
            }
        }

    }
}
