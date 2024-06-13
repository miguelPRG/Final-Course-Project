using DinkToPdf;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using ProjetoA.Classes;

namespace ProjetoA
{
    public sealed partial class MainPage : Page
    {
        bool isRecordSaved;

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
            if (e.Key == VirtualKey.Tab)
            {
                var textBox = (TextBox)sender;
                int selectionStart = textBox.SelectionStart;

                string textBeforeCursor = textBox.Text.Substring(0, selectionStart);
                string textAfterCursor = textBox.Text.Substring(selectionStart);

                textBox.Text = textBeforeCursor + "    " + textAfterCursor;
                textBox.SelectionStart = selectionStart + 4;

                e.Handled = true;
            }
        }

        private async void EscolherPasta_Click(object sender, RoutedEventArgs e)
        {
            // Seletor de pasta para escolher a pasta a ser analisada
            FolderPicker folderPicker = new FolderPicker
            {
                ViewMode = PickerViewMode.Thumbnail,
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary
            };
            folderPicker.FileTypeFilter.Add("*");

            StorageFolder pasta = await folderPicker.PickSingleFolderAsync();

            if (pasta != null)
            {
                // Obtém todos os arquivos .cs na pasta e subpastas
                List<StorageFile> arquivosCsList = await ObterArquivosCsRecursivamente(pasta);

                if (arquivosCsList.Any())
                {
                    // Seletor de pasta para escolher a pasta onde os relatórios serão salvos
                    FolderPicker saveFolderPicker = new FolderPicker
                    {
                        ViewMode = PickerViewMode.Thumbnail,
                        SuggestedStartLocation = PickerLocationId.DocumentsLibrary
                    };
                    saveFolderPicker.FileTypeFilter.Add("*");

                    StorageFolder saveFolder = await saveFolderPicker.PickSingleFolderAsync();

                    if (saveFolder != null)
                    {
                    SolicitarNomePasta:
                        // Solicita o nome da nova pasta
                        var inputTextBox = new TextBox
                        {
                            AcceptsReturn = false,
                            Height = 32
                        };

                        ContentDialog dialog = new ContentDialog
                        {
                            Content = inputTextBox,
                            Title = "Nome da Nova Pasta",
                            IsSecondaryButtonEnabled = true,
                            PrimaryButtonText = "Salvar",
                            SecondaryButtonText = "Cancelar"
                        };

                        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
                        {
                            string nomeNovaPasta = inputTextBox.Text;

                            if (!string.IsNullOrWhiteSpace(nomeNovaPasta))
                            {
                                // Cria a nova pasta no destino escolhido
                                StorageFolder novaPasta = await saveFolder.CreateFolderAsync(nomeNovaPasta, CreationCollisionOption.GenerateUniqueName);

                                // Processa os arquivos em paralelo
                                var tasks = arquivosCsList.Select(async arquivo =>
                                {
                                    string codigoCSharp = await FileIO.ReadTextAsync(arquivo);
                                    string relatorioHTML = await CodeAnalyzer.GerarRelatorioHTML(codigoCSharp.Trim());
                                    await SalvarRelatorioHTML(novaPasta, relatorioHTML, arquivo.DisplayName);
                                }).ToList();

                                await Task.WhenAll(tasks);
                            }
                            else
                            {
                                // Se o nome da pasta for inválido, volta para solicitar o nome novamente
                                goto SolicitarNomePasta;
                            }
                        }
                    }
                }
                else
                {
                    // Exibe um dialogo informando que não foram encontrados arquivos .cs
                    ContentDialog noFilesDialog = new ContentDialog
                    {
                        Title = "Nenhum arquivo encontrado",
                        Content = "Nenhum arquivo .cs foi encontrado na pasta selecionada.",
                        CloseButtonText = "OK"
                    };

                    await noFilesDialog.ShowAsync();
                }
            }
        }


        private async Task<List<StorageFile>> ObterArquivosCsRecursivamente(StorageFolder pasta)
        {
            List<StorageFile> arquivosCsList = new List<StorageFile>();
            await ObterArquivosCsRecursivamente(pasta, arquivosCsList);
            return arquivosCsList;
        }

        private async Task ObterArquivosCsRecursivamente(StorageFolder pasta, List<StorageFile> arquivosCsList)
        {
            var arquivos = await pasta.GetFilesAsync();
            arquivosCsList.AddRange(arquivos.Where(f => f.FileType == ".cs"));

            var subPastas = await pasta.GetFoldersAsync();
            var tasks = subPastas.Select(subPasta => ObterArquivosCsRecursivamente(subPasta, arquivosCsList)).ToList();
            await Task.WhenAll(tasks);
        }

        private async Task SalvarRelatorioHTML(StorageFolder pasta, string relatorioHTML, string nomeArquivo)
        {
            StorageFile file = await pasta.CreateFileAsync(nomeArquivo + ".html", CreationCollisionOption.ReplaceExisting);
            if (file != null)
            {
                await FileIO.WriteTextAsync(file, relatorioHTML);
                isRecordSaved = true;
            }
            else
            {
                isRecordSaved = false;
            }
        }

        private async void AnalisarCodigo_Click(object sender, RoutedEventArgs e)
        {
            string codigo = Input.Text.Trim();

            if (string.IsNullOrEmpty(codigo))
            {
                Console.WriteLine("O TextBox está vazio. Insira código antes de analisar.");
                return;
            }

            string relatorioHTML = await CodeAnalyzer.GerarRelatorioHTML(codigo);
            await OpenAndSaveHtmlRelatorio(relatorioHTML);

            if (!isRecordSaved)
            {
                Console.WriteLine("Erro ao salvar o relatório!");
            }
        }

        private async Task OpenAndSaveHtmlRelatorio(string relatorioHTML)
        {
            StorageFolder tempFolder = ApplicationData.Current.TemporaryFolder;
            StorageFile tempHtmlFile = await tempFolder.CreateFileAsync("Relatorio.html", CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteTextAsync(tempHtmlFile, relatorioHTML);

            await Launcher.LaunchFileAsync(tempHtmlFile);

            ContentDialog saveDialog = new ContentDialog
            {
                Title = "Salvar Relatório",
                Content = "Deseja salvar o relatório?",
                PrimaryButtonText = "Sim",
                SecondaryButtonText = "Não"
            };

            ContentDialogResult result = await saveDialog.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                FileSavePicker savePicker = new FileSavePicker
                {
                    SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                    SuggestedFileName = "Relatorio",
                };

                savePicker.FileTypeChoices.Add("Documento HTML", new List<string> { ".html" });
                savePicker.FileTypeChoices.Add("Documento PDF", new List<string> { ".pdf" });

                try
                {
                    StorageFile file = await savePicker.PickSaveFileAsync();

                    if (file != null)
                    {
                        await tempHtmlFile.MoveAndReplaceAsync(file);
                        isRecordSaved = true;
                    }
                    else
                    {
                        await tempHtmlFile.DeleteAsync();
                        isRecordSaved = false;
                    }
                }
                catch (UnauthorizedAccessException ex1)
                {
                    Console.WriteLine("Erro de acesso não autorizado: " + ex1.Message);
                    await tempHtmlFile.DeleteAsync();
                    isRecordSaved = false;
                }
                catch (Exception ex2)
                {
                    Console.WriteLine("Erro desconhecido: " + ex2.Message);
                    await tempHtmlFile.DeleteAsync();
                    isRecordSaved = false;
                }
            }
            else
            {
                await tempHtmlFile.DeleteAsync();
                isRecordSaved = false;
            }
        }
    }
}
