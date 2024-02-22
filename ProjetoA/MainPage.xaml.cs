using DinkToPdf;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;

namespace ProjetoA
{
    public sealed partial class MainPage : Page
    {
        private double initialBorderWidth = 980;
        //private TextBox inputTextBox;

        public MainPage()
        {
            this.InitializeComponent();
            TextoInserir.Visibility = Visibility.Collapsed;
        }

        private void MostrarConteudo_Click(object sender, RoutedEventArgs e)
        {
            TextoInserir.Visibility = Visibility.Visible;
            Opcoes.Visibility = Visibility.Collapsed;
        }

        private void Retroceder_Click(object sender, RoutedEventArgs e)
        {
            TextoInserir.Visibility = Visibility.Collapsed;
            Opcoes.Visibility = Visibility.Visible;
        }

        private void Input_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Tab)
            {
                // Insira vários espaços à direita
                var textBox = (TextBox)sender;
                int selectionStart = textBox.SelectionStart;

                // Obtenha o texto antes e depois da posição do cursor
                string textBeforeCursor = textBox.Text.Substring(0, selectionStart);
                string textAfterCursor = textBox.Text.Substring(selectionStart);

                // Concatene vários espaços ao texto
                textBox.Text = textBeforeCursor + "    " + textAfterCursor;

                // Mova o cursor para frente (para a posição após os espaços)
                textBox.SelectionStart = selectionStart + 4;

                // Indique que o evento foi manipulado, impedindo que Tab mude o foco para o próximo elemento
                e.Handled = true;
            }
        }

        private async void EscolherFicheiro_Click(object sender, RoutedEventArgs e)
        {
            // Crie um seletor de arquivo para escolher um arquivo C#
            FileOpenPicker filePicker = new FileOpenPicker();
            filePicker.ViewMode = PickerViewMode.Thumbnail;
            filePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            filePicker.FileTypeFilter.Add(".cs");

            // Aguarde a seleção do arquivo
            StorageFile file = await filePicker.PickSingleFileAsync();

            if (file != null)
            {
                // Leia o conteúdo do arquivo C#
                string codigoCSharp = await FileIO.ReadTextAsync(file);

                // Gere o relatório em formato HTML
                string relatorioHTML = CodeAnalyzer.GerarRelatorioHTML(codigoCSharp);

                // Salve o relatório HTML
                StorageFile relatorio = await SaveHtmlRelatorio(relatorioHTML);

                if (relatorio == null)
                {
                    // Lide com o erro de salvamento do relatório
                    // Considere exibir uma mensagem de erro para o usuário
                    Console.WriteLine("Erro ao salvar o relatório!");
                }
            }
        }

        private async void AnalisarCodigo_Click(object sender, RoutedEventArgs e)
        {
            string codigo = Input.Text.Trim();

            // Agora você pode fazer algo com o código
            if (string.IsNullOrEmpty(codigo))
            {
                Console.WriteLine("O TextBox está vazio. Insira código antes de analisar.");
                return;
            }

            // Gere o relatório em formato HTML
            string relatorioHTML = CodeAnalyzer.GerarRelatorioHTML(codigo);

            // Salve o relatório HTML
            StorageFile relatorio = await SaveHtmlRelatorio(relatorioHTML);

            // Converta o HTML para PDF
            if (relatorio == null)
            {
                // Lide com o erro de salvamento de registro
                // Considere exibir uma mensagem de erro para o usuário
                Console.WriteLine("Erro ao salvar o relatório!");
            }

        }

        private TextBox FindTextBox(DependencyObject parent)
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);

                if (child is TextBox textBox)
                {
                    return textBox;
                }

                TextBox childTextBox = FindTextBox(child);
                if (childTextBox != null)
                {
                    return childTextBox;
                }
            }

            return null;
        }

        private async Task ConvertHtmlToPdfAsync(string relatorioHTML, StorageFile file)
        {
            var converter = new BasicConverter(new PdfTools());

            var doc = new HtmlToPdfDocument()
            {
                GlobalSettings = {
            ColorMode = ColorMode.Color,
            Orientation = DinkToPdf.Orientation.Portrait, // Especifique o namespace completo aqui
            PaperSize = PaperKind.A4,
        },
                Objects = {
            new ObjectSettings() {
                PagesCount = true,
                HtmlContent = relatorioHTML,
            }
        }
            };

            byte[] pdfBytes = converter.Convert(doc);

            await FileIO.WriteBytesAsync(file, pdfBytes);
        }


        private async Task<StorageFile> SaveHtmlRelatorio(string relatorioHTML)
        {
            FileSavePicker savePicker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = "Relatorio",
            };

            // Adiciona as escolhas de tipo de arquivo
            savePicker.FileTypeChoices.Add("Documento HTML", new List<string> { ".html" });
            savePicker.FileTypeChoices.Add("Documento PDF", new List<string> { ".pdf" });

            try
            {
                StorageFile file = await savePicker.PickSaveFileAsync();

                if (file != null)
                {
                    string selectedExtension = file.FileType.ToLower();

                    if (selectedExtension.Equals(".html"))
                    {
                        // Salve o conteúdo HTML no arquivo
                        byte[] htmlBytes = Encoding.UTF8.GetBytes(relatorioHTML);

                        await FileIO.WriteBytesAsync(file, htmlBytes);
                    }
                    else if (selectedExtension.Equals(".pdf"))
                    {
                        // Converta o HTML para PDF
                        await ConvertHtmlToPdfAsync(relatorioHTML, file);
                    }

                    return file;
                }
                else
                {
                    // Usuário cancelou a operação de salvamento
                    return null;
                }
            }
            catch (UnauthorizedAccessException ex1)
            {
                // Lidar com exceções de acesso não autorizado
                Console.WriteLine("Erro de acesso não autorizado: " + ex1.Message);
                return null;
            }
            catch (Exception ex2)
            {
                // Lidar com outras exceções de maneira mais específica, se necessário
                Console.WriteLine("Erro desconhecido: " + ex2.Message);
                return null;
            }
        }
    }
}