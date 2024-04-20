using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ProjetoA.Classes;
using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Net;
using Windows.UI.Xaml.Shapes;
using System.IO;
using Projeto.Classes;
using System.Diagnostics;
using Windows.UI.Xaml.Documents;
using Windows.Globalization.DateTimeFormatting;
using Windows.UI.Xaml;
using System.Threading.Tasks;
using System.Collections;
using Windows.Devices.Power;

namespace ProjetoA
{
    //Hora de testar os outros métodos

    public class CodeAnalyzer
    {
        //Linhas onde forem encontradas informações importantes
        static Dictionary<int, int> linhasImportantes;

        public CodeAnalyzer()
        {
            linhasImportantes = new Dictionary<int, int>();
        }

        public static async Task<string> GerarRelatorioHTML(string code)
        {
            linhasImportantes = new Dictionary<int, int>();
            
            var htmlBuilder = new StringBuilder();
            code = code.Trim();

            // Início do HTML
            htmlBuilder.AppendLine("<!DOCTYPE html>");
            htmlBuilder.AppendLine("<html lang=\"pt\">");
            htmlBuilder.AppendLine("<head><meta charset=\"utf-8\"><title>Análise de Código</title>");
            htmlBuilder.AppendLine("<style>body {\r\n                                font-family: Arial, sans-serif;\r\n                                text-align: center;\r\n                            }\r\n                        \r\n                            h1 {\r\n                                \r\n                                margin-bottom: 20px;\r\n                            }\r\n                        \r\n                            h2 {\r\n                            \r\n                            margin-bottom: 15px;\r\n                            margin-top: 80px; /* Ajuste o valor conforme necessário */\r\n                            }\r\n                        \r\n                            h2#codigo-analisado{\r\n                                text-align: left;\r\n                            }\r\n\r\n                            h3 {\r\n                                \r\n                                margin-bottom: 10px;\r\n                            }\r\n                        \r\n                            a {\r\n                                text-decoration: none;\r\n                                color: #333;\r\n                                cursor: pointer;\r\n                            }\r\n                        \r\n                            a:hover {\r\n                                color: #007bff;\r\n                            }\r\n                        \r\n                            .indice {\r\n                                \r\n                                margin-bottom: 30px;\r\n                                display: block;\r\n                            }\r\n                        \r\n                            ul {\r\n                                list-style: none;\r\n                                padding: 0;\r\n                            }\r\n                        \r\n                            li {\r\n                                margin-bottom: 10px;\r\n                                font-size: 18px;\r\n                            }\r\n                        \r\n                            table {\r\n                                width: 100%;\r\n                                border-collapse: collapse;\r\n                                margin-top: 20px;\r\n                            }\r\n                        \r\n                            /* Estilo para as células da tabela */\r\n                            table td, table th {\r\n                                padding: 10px;\r\n                                border: 1px solid #ddd;\r\n                                text-align: left;\r\n                            }\r\n                        \r\n                            /* Estilo para o cabeçalho da tabela */\r\n                            table th {\r\n                                background-color: #f2f2f2;\r\n                            }\r\n                        \r\n                            /* Estilo para alternância de cores nas linhas */\r\n                            .table tr:nth-child(even) {\r\n                                background-color: #f9f9f9;\r\n                            }\r\n                        \r\n                            .alto {\r\n                                background-color: rgb(238, 93, 93);\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            .medio {\r\n                                background-color: yellow;\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            .baixo {\r\n                                background-color: greenyellow;\r\n                                font-weight: bold;\r\n                            }\r\n\r\n                            .desempenho{\r\n                                background-color: #57e0f8;\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            /* Estilo para o código analisado */\r\n                            .codigo-container {\r\n                                margin-top: 20px;\r\n                                padding: 10px;\r\n                                background-color: #f2f2f2;\r\n                                text-align: justify;\r\n                            }\r\n                        \r\n                            .codigo-container pre {\r\n                                white-space: pre-wrap;\r\n                                font-size: 14px;\r\n                            }\r\n                            \r\n                            span{\r\n                                color: rgb(137, 8, 8);\r\n                            }\r\n\r\n                            .selected{\r\n                                border: 5px solid rgb(167, 224, 9);\r\n                            }\r\n</style>");
            htmlBuilder.AppendLine("<script> function mostrarSecao(id) {\r\n            var secao = document.getElementById(id);\r\n            \r\n            if (secao.style.display == '' || secao.style.display == \"none\") {\r\n                secao.style.display = \"block\";\r\n            } \r\n                    \r\n            else {\r\n                secao.style.display = \"none\";\r\n            }\r\n        }\r\n        \r\n        function modificarPadrao(num,risco){\r\n        var minhaDiv = document.getElementById('linha-numero'+num);\r\n\r\n        if(minhaDiv.classList.length==0){\r\n                \r\n                minhaDiv.style.display = 'inline-block';\r\n\r\n                switch(risco){\r\n                case 0: \r\n                    minhaDiv.classList.add('alto'); \r\n                    break;\r\n                case 1: \r\n                    minhaDiv.classList.add('medio'); break;\r\n                case 2: \r\n                    minhaDiv.classList.add('baixo'); \r\n                    break;\r\n            \r\n                case 3: minhaDiv.classList.add('desempenho')\r\n                }\r\n                \r\n            }\r\n        }\r\n        \r\n        function tirarSelection(num) {\r\n    return function() {\r\n        var minhaDiv = document.getElementById('linha-numero' + num);\r\n        minhaDiv.classList.remove('selected');\r\n        minhaDiv.removeEventListener('click', tirarSelection(num));\r\n    }\r\n}\r\n\r\nfunction selecionar(num) {\r\n    var minhaDiv = document.getElementById('linha-numero' + num);\r\n\r\n    if (!minhaDiv.classList.contains('selected')) {\r\n        minhaDiv.classList.add('selected');\r\n        minhaDiv.onclick= tirarSelection(num)\r\n    }\r\n}\r\n</script>");
            htmlBuilder.AppendLine("</head>");

            // Início do corpo HTML
            htmlBuilder.AppendLine("<body>");
            // Título do relatório
            htmlBuilder.AppendLine("<h1>Relatório de Análise de Código C#</h1>");

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            // Verificar Sintaxe do código
            if (EncontrouErrosSintaxe(htmlBuilder, code))
            {
                stopwatch.Stop();

                htmlBuilder.AppendLine("<h2>Não foi possivel efetuar uma análise profunda do código, pois este apresenta erros de sintaxe!</h2>");
                htmlBuilder.AppendLine($"<p>Tempo Total de Análise: {stopwatch.ElapsedMilliseconds}ms</p>");
                htmlBuilder.Append("</body></html>");
                return htmlBuilder.ToString();
            }

            string[] linhasSeparadas = code.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            var linhas = GuardarEmDicionario(linhasSeparadas);

            htmlBuilder.AppendLine("<h2>Índice</h2>\r\n<div class=\"indice\">\r\n<ul>\r\n    " +
                "<li><a onclick=\"mostrarSecao('analise-vulnerabilidade')\">Análise de Vulnerabilidade</a></li>\r\n    " +
               // "<li><a onclick=\"mostrarSecao('analise-dependencias')\">Análise de Dependências</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('mau-desempenho')\">Identificação de Práticas de Mau Desempenho</a></li>\r\n   " +
               // "<li><a onclick=\"mostrarSecao('analise-excecoes')\">Análise de Exceções</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('repeticao-codigo')\">Análise de Repetição de Código</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('concorrencia')\">Análise de Concorrência</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('complexidade-ciclomatica')\">Complexidade Ciclomática</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('tempo')\">Tempo Total de Análise</a></li>");
            htmlBuilder.AppendLine($"</ul></div>");

            //Este é o método principal que analisa o código inteiro
            StringBuilder analises = await AnalisarCodigo(linhas,code);

            htmlBuilder.Append(analises);
            
            /*
            // Realiza a análise de complexidade ciclomática
            int complexidadeCiclomatica = ComplexidadeCiclomatica.CalcularComplexidadeCiclomatica(code);
            htmlBuilder.AppendLine("<div id=\"complexidade-ciclomatica\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Complexidade Ciclomática: {complexidadeCiclomatica}</h2>");
            htmlBuilder.AppendLine("</div>");

            //Analise de Dependencias
            htmlBuilder.AppendLine("<div id=\"analise-dependencias\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Dependências:</h2>");
            htmlBuilder.Append(AnalizarDependencias(linhas));
            htmlBuilder.AppendLine("</div>");

            // Identificar práticas que afetam o desempenho
            htmlBuilder.AppendLine("<div id=\"mau-desempenho\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Identificação de Práticas de Mau Desempenho:</h2>");
            //IdentificarPraticasDesempenho(htmlBuilder, code);
            htmlBuilder.AppendLine("</div>");

            // Identificar Exceções no código:
            htmlBuilder.AppendLine("<div id=\"analise-excecoes\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Exceções:</h2>");
            AnalisarExcecoes(htmlBuilder, linhas);
            htmlBuilder.AppendLine("</div>");

            //Verificar Repetição de código
            htmlBuilder.AppendLine("<div id=\"repeticao-codigo\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Repetição de código</h2>");
            //VerificarRepeticao(htmlBuilder, linhas);
            htmlBuilder.AppendLine("</div>");

            // Análise de Concorrência
            htmlBuilder.AppendLine("<div id=\"concorrencia\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Concorrência:</h2>");
            //AnalisarConcorrencia(htmlBuilder, code);
            htmlBuilder.AppendLine("</div>");*/


            stopwatch.Stop();

            htmlBuilder.AppendLine("<div id=\"tempo\" style=\"display:none;\">");
            htmlBuilder.AppendLine($"<h2>Tempo Total de Análise:{stopwatch.ElapsedMilliseconds} ms</h2>");
            htmlBuilder.AppendLine("</div>");

            htmlBuilder.AppendLine($"<h2 id=\"codigo-analisado\">Código Analisado:</h2>");
            ExibirCodigo(linhasSeparadas, htmlBuilder);

            //Marca as linhas que estão com alguma vulnerabilidade
            if(linhasImportantes!=null)
            {
                htmlBuilder.AppendLine("<script>");
                modificarBackground(linhasImportantes, htmlBuilder);
                htmlBuilder.AppendLine("</script>");
            }
            
            // Feche as tags HTML
            htmlBuilder.AppendLine("</body></html>");

            return await Task.FromResult(htmlBuilder.ToString());
        }

        static bool EncontrouErrosSintaxe(StringBuilder htmlBuilder, string code)
        {

            SyntaxTree syntaxTree;

            try
            {
                syntaxTree = CSharpSyntaxTree.ParseText(code);
            }
            catch (Exception ex)
            {
                htmlBuilder.AppendLine($"<tr><td>1</td><td>{WebUtility.HtmlEncode(ex.Message)}</td></tr>");
                htmlBuilder.AppendLine("</table>");
                return false;
            }

            var diagnostics = syntaxTree.GetDiagnostics();

            if (diagnostics.Count() != 0)
            {
                return true;
            }

            else
            {
                return false;
            }

        }

        static Dictionary<string, List<int>> GuardarEmDicionario(string[] linhasSeparadas)
        {
            Dictionary<string, List<int>> dicionario = new Dictionary<string, List<int>>();

            int numeroLinha = 1;
            bool isMultiLine = false;

            foreach (string linha in linhasSeparadas)
            {
                string linhaSemComentarios = RemoverComentarios(linha, ref isMultiLine);

                if (!string.IsNullOrWhiteSpace(linhaSemComentarios))
                {
                    if (!dicionario.ContainsKey(linhaSemComentarios))
                    {
                        dicionario[linhaSemComentarios] = new List<int>();
                    }

                    dicionario[linhaSemComentarios].Add(numeroLinha);
                }

                numeroLinha++;
            }

            return dicionario;
        }
        static string RemoverComentarios(string linha, ref bool isMultiline)
        {
            if (string.IsNullOrEmpty(linha))
            {
                return null;
            }

            linha = linha.Trim();
            int fimComentario;

            if (isMultiline)
            {
                fimComentario = linha.IndexOf("*/");

                if (fimComentario != -1)
                {
                    isMultiline = false;
                    linha = linha.Substring(0, fimComentario);
                }

                else
                {
                    return null;
                }
            }

            bool dentroString = false;
            char charAnterior = '\0';

            for (int i = 0; i < linha.Length; i++)
            {
                if (linha[i] == '"' && charAnterior != '\\')
                {
                    dentroString = !dentroString;
                }

                if (!dentroString)
                {
                    int inicioComentario;

                    // Verificar se a linha contém um comentário de uma única linha
                    if (linha[i] == '/' && i + 1 < linha.Length && linha[i + 1] == '/')
                    {
                        linha = linha.Substring(0, i);
                        break;
                    }

                    else if (linha[i] == '/' && i + 1 < linha.Length && linha[i + 1] == '*')
                    {
                        inicioComentario = i;
                        fimComentario = linha.IndexOf("*/", inicioComentario);

                        if (fimComentario != -1)
                        {
                            linha = linha.Remove(inicioComentario, fimComentario - inicioComentario + 2);
                            i = inicioComentario - 1;
                        }
                        else
                        {
                            isMultiline = true;
                            linha = linha.Substring(0, inicioComentario);
                            break;
                        }
                    }
                }

                charAnterior = linha[i];
            }

            return linha;
        }

        static async Task<StringBuilder> AnalisarCodigo(Dictionary<string, List<int>> lines, string code)
        {
            // Inicia as três tarefas em paralelo
            Task<StringBuilder> taskAnalisarVulnerabilidades = AnalisarVulnerabilidades(lines);
            Task<StringBuilder> taskAnalisarDependencias = IdentificarPraticasDesempenho(lines);
            Task<StringBuilder> taskAnalisarRepeticao = AnalisarRepeticao(lines);
            Task<int> taskComplexidadeCiclomatica = ComplexidadeCiclomatica.CalcularComplexidadeCiclomatica(code);

            // Espera até que todas as tarefas estejam concluídas
            await Task.WhenAll(taskAnalisarVulnerabilidades,taskAnalisarDependencias,taskAnalisarRepeticao,taskComplexidadeCiclomatica);

            int complexidadeCiclomatica = taskComplexidadeCiclomatica.Result;

            // Concatena as strings HTML
            StringBuilder resultadoFinal = new StringBuilder();

            // Adiciona o resultado das tarefas de análise de vulnerabilidades e dependências
            resultadoFinal.Append(taskAnalisarVulnerabilidades.Result);
            resultadoFinal.Append(taskAnalisarDependencias.Result);

            // Adiciona a complexidade ciclomática ao resultado
            resultadoFinal.AppendLine($"<div id=\"complexidade-ciclomatica\" style=\"display: none;\">\n");
            resultadoFinal.AppendLine($"<h2>Complexidade Ciclomática: {complexidadeCiclomatica}</h2>\n");
            resultadoFinal.AppendLine($"</div>");

            // Retorna o resultado final
            return  await Task.FromResult(resultadoFinal);
        }
        static async Task<StringBuilder> AnalisarVulnerabilidades(Dictionary<string, List<int>> code)
        {
            StringBuilder htmlBuilder = new StringBuilder();
            htmlBuilder.AppendLine("<div id=\"analise-vulnerabilidade\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Vulnerabilidades:</h2>");

            var vulnerabilidadeVisitor = new VulnerabilidadeVisitor();
            await vulnerabilidadeVisitor.Visit(code);

            if(vulnerabilidadeVisitor.VulnerabilidadesEncontradas.Count()==0)
            {
                htmlBuilder.AppendLine("<h3>Não foi encontrada nenhuma vulnerabilidade de segurança!</h3>");
                htmlBuilder.AppendLine("</div>");
                return await Task.FromResult(htmlBuilder);
            }

            //Ordenamos as vulnerabilidades por tipo
            vulnerabilidadeVisitor.VulnerabilidadesEncontradas.Sort((x,y) => string.Compare(x.Vulnerabilidade.Tipo, y.Vulnerabilidade.Tipo));
            
            string nomeVulnerabilidade = "";

            // Construir tabela HTML
            //htmlBuilder.AppendLine("<table>");
            //htmlBuilder.AppendLine("<tr><th>Nome da Vulnerabilidade</th><th>Código</th><th>Linhas</th><th>Nível de Risco</th></tr>");

            foreach(var vul in vulnerabilidadeVisitor.VulnerabilidadesEncontradas)
            {
                if(vul.Vulnerabilidade.Tipo != nomeVulnerabilidade)//Vulnerabilidade Nova, Tabela Nova
                {

                    htmlBuilder.AppendLine($"<h3>Vulnerabilidades de {vul.Vulnerabilidade.Tipo}</h3>");
                    htmlBuilder.AppendLine("<table>");
                    htmlBuilder.AppendLine($"<tr><th>Código</th><th>Linhas</th><th>Nível de Risco</th></tr>");
                    nomeVulnerabilidade = vul.Vulnerabilidade.Tipo;
                }

                htmlBuilder.AppendLine("<tr>");
                htmlBuilder.AppendLine($"<td>{vul.Vulnerabilidade.Codigo}</td>");
                htmlBuilder.AppendLine($"<td>");


                for (int i = 0; i < vul.Linhas.Count(); i++)
                {
                    htmlBuilder.Append($"<a href=\"#linha-numero{vul.Linhas[i]}\" onclick=selecionar({vul.Linhas[i]})>{vul.Linhas[i]}</a>");

                    linhasImportantes[vul.Linhas[i]] = (int)vul.Vulnerabilidade.Risco;

                    if (i + 1 < vul.Linhas.Count)
                    {
                        htmlBuilder.Append(',');
                    }
                }

                htmlBuilder.Append("</td>");

                switch (vul.Vulnerabilidade.Risco)
                {
                    case NivelRisco.Baixo: htmlBuilder.AppendLine("<td class=\"baixo\">Baixo</td>"); break;
                    case NivelRisco.Medio: htmlBuilder.AppendLine("<td class=\"medio\">Médio</td>"); break;
                    case NivelRisco.Alto: htmlBuilder.AppendLine("<td class=\"alto\">Alto</td>"); break;
                }

                htmlBuilder.AppendLine("</tr>");
            }

            htmlBuilder.AppendLine("</table>");
            htmlBuilder.AppendLine($"<h3>Taxa de Precisão Média de todas as Análises de Vulnerabilidades: {vulnerabilidadeVisitor.getPrecision()}%</h3>");
            htmlBuilder.AppendLine("</div>");

            return await Task.FromResult(htmlBuilder);

        }
        static async Task<StringBuilder> IdentificarPraticasDesempenho(Dictionary<string, List<int>> codeDictionary)
        {
            var result = new StringBuilder();
            result.AppendLine("<div id=\"mau-desempenho\" style=\"display: none;\">");
            result.AppendLine("<h2>Identificação de Práticas de Mau Desempenho:</h2>");

            var htmlBuilder = new StringBuilder();
            htmlBuilder.AppendLine("<table>");
            htmlBuilder.AppendLine("<tr><th>Nome do Padrão de Mau Desempenho</th><th>Linhas do Código</th></tr>");

            var patterns = new Dictionary<string, string>()
            {
                { "Possível iteração desnecessária sobre uma coleção", @"\bforeach\s*\(.*\)" },
                { "Concatenação de strings em loop", @"\b(?:string|StringBuilder)\s*\+\=\s*\""" },
                { "Casting possivelmente desnecessário", @"\b(?:Convert|(?<!\.ToString))\.To[A-Za-z]+\(" },
                { "Possível uso inadequado de StringBuilder", @"\b(?:new\s*System\.Text\.StringBuilder\s*\(\s*\)|StringBuilder\s*=\s*new\s*StringBuilder\s*\(\s*\))" },
                { "Possível bloqueio inadequado de recursos compartilhados", @"\block\s*\(.*\)" },
                { "Iteração sobre coleção sem uso do índice", @"\bfor\s*\(.*\bLength\b.*\)" },
                { "Utilização excessiva de expressões regulares", @"\b(?:Regex|RegexOptions)\." },
                { "Possível uso de métodos ou operações de alto custo dentro de loops", @"\b(?:Array|List|ICollection)\.\w+\(" },
            };

            var tasks = new List<Task<StringBuilder>>();

            foreach (var padrao in patterns)
            {
                tasks.Add(VerificarPadrao(codeDictionary, padrao));
            }

            var results = await Task.WhenAll(tasks);

            bool hasPatterns = false;

            foreach (var resultBuilder in results)
            {
                if (resultBuilder != null && !hasPatterns)
                {
                    hasPatterns = true;
                }

                htmlBuilder.Append(resultBuilder);
            }

            // Aguarda todas as tarefas serem concluídas

            if (!hasPatterns)
            {
                result.AppendLine("<h3>Não foi encontrado nenhum padrão de mau desempenho!</h3>");
            }

            else
            {
                htmlBuilder.AppendLine("</table>"); // Adicionando a tag de fechamento da tabela
                result.Append(htmlBuilder); // Adiciona a tabela completa ao resultado
            }

            result.AppendLine("</div>");

            return result;
        }
        static async Task<StringBuilder> VerificarPadrao(Dictionary<string, List<int>> codeDictionary, KeyValuePair<string, string> pattern)
        {
            var patternName = pattern.Key;
            var patternValue = pattern.Value;

            bool isEmpty = true;

            StringBuilder htmlBuilder = new StringBuilder();
            List<int> lineList = new List<int>();  

            htmlBuilder.AppendLine("<tr>");
            htmlBuilder.AppendLine($"<td>{patternName}</td>");
            htmlBuilder.AppendLine("<td class=\"desempenho\">");

            foreach (var line in codeDictionary)//O(n)
            {
                var code = line.Key;
                var lineValues = line.Value;

                var match = Regex.Match(code, patternValue);

                if (match.Success)
                {
                    if (isEmpty)
                    {
                        isEmpty = false;
                    }

                    foreach(var i in lineValues)
                    {
                        lineList.Add(i);
                    }
                }

            }

            if(!isEmpty)
            {
                lineList.Sort();
                
                for(int i= 0; i<lineList.Count();i++)
                {
                    htmlBuilder.Append($"<a href=\"#linha-numero{lineList[i]}\" onclick=selecionar({lineList[i]})>{lineList[i]}</a>");
                    linhasImportantes[lineList[i]] = 3;

                    if (i + 1 < lineList.Count())
                    {
                        htmlBuilder.Append(',');
                    }
                }

                htmlBuilder.AppendLine("</td></tr>");

                return await Task.FromResult(htmlBuilder);
            }
            else
            {
                return null;
            }
        
        }
        static async Task<StringBuilder> AnalisarRepeticao(Dictionary<string, List<int>> codeDictionary)
        {
            StringBuilder htmlBuilder = new StringBuilder();

            htmlBuilder.AppendLine($"<div id=\"repeticao-codigo\" style=\"display: none;\">\n");
            htmlBuilder.AppendLine($"<h2>Código Repetido</h2>");
            htmlBuilder.AppendLine("<table>");
            htmlBuilder.AppendLine("<tr><th>Codigo</th><th>Linhas</th></tr>");

            foreach(var key in codeDictionary.Keys)
            {
                htmlBuilder.AppendLine("<tr>");
                htmlBuilder.Append($"<td>{key}</td>");
                htmlBuilder.Append($"<td>");

                int count = codeDictionary[key].Count;

                for(int i = 0; i< count;i++)
                {
                    htmlBuilder.Append($"{codeDictionary[key][i]}");

                        if (i + 1 < count)
                        {
                            htmlBuilder.Append($",");
                        }
                }

                htmlBuilder.Append("</td>");
            
            }
        
            htmlBuilder.AppendLine("</div>");

            return await Task.FromResult(htmlBuilder);
        }

        static void ExibirCodigo(string[] linhasDeCodigo, StringBuilder htmlBuilder)
        {
            htmlBuilder.AppendLine("<div class=\"codigo-container\">"); // Adiciona uma div de contêiner

            htmlBuilder.AppendLine("<pre><code class=\"csharp\">");

            // Descobrir quantos dígitos tem o número da última linha para ajustar a formatação
            int numeroLinhas = linhasDeCodigo.Length;

            // Adicionar cada linha com o número da linha à esquerda
            for (int i = 0; i < numeroLinhas; i++)
            {
                // Adicionar a linha de código com o número da linha à esquerda
                htmlBuilder.AppendLine($"<div id=\"linha-numero{i + 1}\"><span>{i + 1}</span> {WebUtility.HtmlEncode(linhasDeCodigo[i])}</div>");

            }

            htmlBuilder.AppendLine("</code></pre>");
            htmlBuilder.AppendLine("</div>"); // Fecha a div de contêiner
        }
        static void modificarBackground(Dictionary<int, int> linhasImportantes, StringBuilder htmlBuilder)
        {
            foreach (var linha in linhasImportantes.Keys)
            {
                htmlBuilder.AppendLine($"modificarPadrao({linha},{linhasImportantes[linha]})");
            }
        }


        private int GetLineNumber(string code, int index)
        {
            return code.Substring(0, index).Split('\n').Length;
        }


        static void AnalisarExcecoes(StringBuilder relatorio, Dictionary<string, List<int>> lines)
        {
            StringBuilder tabelaHtml = new StringBuilder();
            bool tabelaVazia = true;

            // Iniciar a tabela HTML no relatório
            tabelaHtml.AppendLine("<table>");
            tabelaHtml.AppendLine("<tr><th>Nome da Exceção</th><th>Código</th><th>Linhas</th></tr>");

            // Iterar sobre cada código no dicionário
            foreach (var codigo in lines.Keys)
            {
                
                if (codigo.Contains("catch"))
                {
                    string[] partes = codigo.Split('(', ')');
                    string tipoExcecao = partes[1];

                    tabelaHtml.AppendLine("<tr>");
                    tabelaHtml.AppendLine($"<td>{tipoExcecao}</td>");
                    tabelaHtml.AppendLine($"<td>{codigo}</td>");
                    tabelaHtml.AppendLine("<td>");

                    // Iterar sobre cada linha onde a exceção é capturada
                    for (int i = 0; i < lines[codigo].Count(); i++)
                    {
                        tabelaHtml.Append($"<a href=\"#linha-numero{lines[codigo][i]}\">{lines[codigo][i]}</a>");

                        if (i + 1 < lines[codigo].Count())
                        {
                            tabelaHtml.Append(", ");
                        }
                    }

                    tabelaVazia = false;

                    // Fechar a tag 'td' após listar todas as linhas
                    tabelaHtml.AppendLine("</td>");
                    tabelaHtml.AppendLine("</tr>");
                }
            }

            tabelaHtml.AppendLine("</table>");

            if (tabelaVazia)
            {
                relatorio.AppendLine("<h3>Não foi encontrada nenhuma dependência exceção!</h3>");
            }
            else
            {
                relatorio.Append(tabelaHtml.ToString());
            }
        
        }

        static void VerificarRepeticao(StringBuilder htmlBuilder, Dictionary<string, List<int>> lines)
        {
            StringBuilder tabela = new StringBuilder();
            bool tabelaVazia = true;
            
            tabela.AppendLine("<table><tr><th>Código Repetido</th><th>Linhas</th></tr>");

            foreach(var chave in lines.Keys)
            {
                if (lines[chave].Count() > 1)
                {
                    tabela.AppendLine("<tr>");
                    tabela.Append($"<td>{lines[chave]}</td>");
                    for(int i = 0; i < lines[chave].Count();i++)
                    {
                        tabela.Append($"<td>{i}</td>");

                        if (i + 1 > lines[chave].Count())
                        {
                            tabela.Append(',');
                        }

                        tabelaVazia = false;
                    }
                }
            }

            if (tabelaVazia)
            {
                htmlBuilder.AppendLine("<h3>Não foi encontrado código repetido!</h3>");
            }
            
            else
            {
                htmlBuilder.AppendLine(tabela.ToString());
            }
        
        }

        static Dictionary<string, List<int>> VerificarRepeticao(IEnumerable<SyntaxNode> nodes)
    {
        var repetidos = new Dictionary<string, List<int>>();

        foreach (var node in nodes)
        {
            var nome = ObtenerNombre(node);

            if (!repetidos.ContainsKey(nome))
            {
                repetidos[nome] = new List<int>();
            }

            repetidos[nome].Add(node.GetLocation().GetMappedLineSpan().StartLinePosition.Line + 1);
        }

        // Remover entradas que não têm duplicatas
        repetidos = repetidos.Where(entry => entry.Value.Count > 1).ToDictionary(entry => entry.Key, entry => entry.Value);

        return repetidos;
    }

        static bool GerarTabelaHTML(StringBuilder htmlBuilder, string tipo, Dictionary<string, List<int>> repetidosPorLinha)
    {
        if (repetidosPorLinha.Count == 0)
        {
            return false;
        }

        htmlBuilder.AppendLine($"<h3>{tipo}</h3>");
        htmlBuilder.AppendLine("<table>");
        htmlBuilder.AppendLine("<tr><th>Nome</th><th>Linha(s) Encontrada(s)</th></tr>");

        foreach (var entry in repetidosPorLinha)
        {
            var nome = entry.Key;
            var linhas = entry.Value;

            var linkLinhas = linhas.Select(linha => $"<a href=\"#linha-numero{linha}\" onclick=\"destacarLinha({linha})\">{linha}</a>");

            htmlBuilder.AppendLine($"<tr><td>{nome}</td><td>{string.Join(", ", linkLinhas)}</td></tr>");
        }

        htmlBuilder.AppendLine("</table>");

        return true;
    }

        static string ObtenerNombre(SyntaxNode node)
    {
        // Lógica para obtener el nombre según el tipo de nodo
        if (node is MethodDeclarationSyntax methodSyntax)
        {
            return methodSyntax.Identifier.ValueText;
        }
        else if (node is VariableDeclarationSyntax variableSyntax)
        {
            return variableSyntax.Variables.FirstOrDefault()?.Identifier.ValueText;
        }
        else if (node is ClassDeclarationSyntax classSyntax)
        {
            return classSyntax.Identifier.ValueText;
        }

        return string.Empty;
    }

        static void AnalisarConcorrencia(StringBuilder htmlBuilder, string code)
    {
        ConcurrencyAnalyzer concurrencyAnalyzer = new ConcurrencyAnalyzer();
        List<DependencyInfo> dependencies = concurrencyAnalyzer.AnalyzeConcurrencyIssues(code);

        if (dependencies.Count != 0)
        {
            // Adicionar cabeçalhos da tabela
            htmlBuilder.AppendLine("<table><tr><th>Nome da Concorrência</th><th>Linha do Código</th></tr>");

            foreach (var dependency in dependencies)
            {
                // Adicionar uma linha na tabela para cada dependência
                htmlBuilder.AppendLine("<tr>");

                // Coluna 1: Nome da Concorrência
                htmlBuilder.AppendLine($"<td>{dependency.DependencyType}</td>");

                // Coluna 2: Linha do Código
                htmlBuilder.AppendLine($"<td><a href=\"#linha-numero{dependency.LineNumber}\" onclick=\"destacarLinha({dependency.LineNumber})\">{dependency.LineNumber}</a></td>");

                // Fechar a linha na tabela
                htmlBuilder.AppendLine("</tr>");
            }

            // Fechar a tabela HTML
            htmlBuilder.AppendLine("</table>");
        }
        else
        {
            htmlBuilder.AppendLine("<h3>Não foi encontrada nenhuma concorrência.</h3>");
        }
    }
    }
}