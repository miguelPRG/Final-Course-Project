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

namespace ProjetoA
{
    public class CodeAnalyzer
    {
        public static string GerarRelatorioHTML(string code)
        {
            var htmlBuilder = new StringBuilder();
            code = code.Trim();

            string[] codigo = code.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // Início do HTML
            htmlBuilder.AppendLine("<!DOCTYPE html>");
            htmlBuilder.AppendLine("<html lang=\"pt\">");
            htmlBuilder.AppendLine("<head><meta charset=\"utf-8\"><title>Análise de Código</title>");
            htmlBuilder.AppendLine("<style>body {\r\n                                font-family: Arial, sans-serif;\r\n                            }\r\n                        \r\n                            h1 {\r\n                                text-align: center;\r\n                                margin-bottom: 20px;\r\n                            }\r\n                        \r\n                            h2 {\r\n                            text-align: center;\r\n                            margin-bottom: 15px;\r\n                            margin-top: 80px; /* Ajuste o valor conforme necessário */\r\n                            }\r\n                        \r\n                            h3 {\r\n                                text-align: center;\r\n                                margin-bottom: 10px;\r\n                            }\r\n                        \r\n                            a {\r\n                                text-decoration: none;\r\n                                color: #333;\r\n                                cursor: pointer;\r\n                            }\r\n                        \r\n                            a:hover {\r\n                                color: #007bff;\r\n                            }\r\n                        \r\n                            .indice {\r\n                                text-align: center;\r\n                                margin-bottom: 30px;\r\n                                display: block;\r\n                            }\r\n                        \r\n                            ul {\r\n                                list-style: none;\r\n                                padding: 0;\r\n                            }\r\n                        \r\n                            li {\r\n                                margin-bottom: 10px;\r\n                                font-size: 18px;\r\n                            }\r\n                        \r\n                            table {\r\n                                width: 100%;\r\n                                border-collapse: collapse;\r\n                                margin-top: 20px;\r\n                            }\r\n                        \r\n                            /* Estilo para as células da tabela */\r\n                            table td, table th {\r\n                                padding: 10px;\r\n                                border: 1px solid #ddd;\r\n                                text-align: left;\r\n                            }\r\n                        \r\n                            /* Estilo para o cabeçalho da tabela */\r\n                            table th {\r\n                                background-color: #f2f2f2;\r\n                            }\r\n                        \r\n                            /* Estilo para alternância de cores nas linhas */\r\n                            .table tr:nth-child(even) {\r\n                                background-color: #f9f9f9;\r\n                            }\r\n                        \r\n                            #alto {\r\n                                background-color: red;\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            #medio {\r\n                                background-color: yellow;\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            #baixo {\r\n                                background-color: greenyellow;\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            /* Estilo para o código analisado */\r\n                            .codigo-container {\r\n                                margin-top: 20px;\r\n                                padding: 10px;\r\n                                background-color: #f2f2f2;\r\n                            }\r\n                        \r\n                            .codigo-container pre {\r\n                                white-space: pre-wrap;\r\n                                font-size: 14px;\r\n                            }\r\n                            \r\n                            .destacada {\r\n                                background-color: #ffff66; /* ou qualquer outra cor de destaque desejada */\r\n                                display: block;\r\n                            }\r\n\r\n                            span{\r\n                                color: rgb(137, 8, 8);\r\n                            }</style>");
            htmlBuilder.AppendLine("<style type=\"text/css\" id=\"operaUserStyle\"></style>");
            htmlBuilder.AppendLine("<script>\r\n        function mostrarSecao(id) {\r\n            var secao = document.getElementById(id);\r\n            \r\n            if (secao.style.display == '' || secao.style.display == \"none\") {\r\n                secao.style.display = \"block\";\r\n            } \r\n                    \r\n            else {\r\n                secao.style.display = \"none\";\r\n            }\r\n        }\r\n\r\n        function destacarLinha(numeroLinha, nocodigo = false) {\r\n            var linhaClicada = document.getElementById('linha-numero' + numeroLinha);\r\n\r\n            // Remove o event listener antes de verificar a classe 'destacada' e nocodigo\r\n            linhaClicada.removeEventListener('click', clickHandler);\r\n\r\n            // Verifica se a classe 'destacada' está presente e se nocodigo é verdadeiro\r\n            if (linhaClicada.classList.contains('destacada') && nocodigo) {\r\n                // Se estiver presente e nocodigo for verdadeiro, remove a classe e o event listener\r\n                linhaClicada.classList.remove('destacada');\r\n                linhaClicada.style.cursor = null; // Remover o cursor\r\n            } \r\n    \r\n            else if (!nocodigo) {\r\n                // Se não estiver presente e nocodigo for falso, adiciona a classe e o event listener\r\n                linhaClicada.classList.add('destacada');\r\n                linhaClicada.style.cursor = 'pointer'; // Adicionar o cursor\r\n\r\n                // Define o event listener usando a mesma função de callback\r\n                linhaClicada.addEventListener('click', clickHandler);\r\n            }\r\n\r\n    // Função handler para o event listener\r\n    function clickHandler() {\r\n        destacarLinha(numeroLinha, true);\r\n    }\r\n}\r\n    </script>");
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

                htmlBuilder.Append("<h2>Não foi possivel efetuar uma análise profunda do código, pois este apresenta erros de sintaxe!</h2>");
                htmlBuilder.Append($"<p>Tempo Total de Análise: {stopwatch.ElapsedMilliseconds}ms</p>");
                htmlBuilder.Append("</body>");
                return htmlBuilder.ToString();
            }

            //Vamos pegar em todo o código e dividi-lo em linhas, ignorando qualquer comentário que seja encontrado
            List<string> list = new List<string>();

            using (var enumerator = DividirEmLinhas(code).GetEnumerator())
            {
                while (enumerator.MoveNext())
                {
                    list.Add(enumerator.Current);
                }
            }

            htmlBuilder.AppendLine("<h2>Índice</h2>\r\n<div class=\"indice\">\r\n<ul>\r\n    " +
                "<li><a onclick=\"mostrarSecao('analise-vulnerabilidade')\">Análise de Vulnerabilidade</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('complexidade-ciclomatica')\">Complexidade Ciclomática</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('analise-dependencias')\">Análise de Dependências</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('mau-desempenho')\">Identificação de Práticas de Mau Desempenho</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('analise-excecoes')\">Análise de Exceções</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('repeticao-codigo')\">Análise de Repetição de Código</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('concorrencia')\">Análise de Concorrência</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('tempo')\">Tempo Total de Análise</a></li>");
            htmlBuilder.AppendLine($"</div>");

            // Adicione a chamada para o método AnalisarVulnerabilidade
            htmlBuilder.AppendLine("<div id=\"analise-vulnerabilidade\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Vulnerabilidades:</h2>");
            AnalisarVulnerabilidades(list, htmlBuilder);
            htmlBuilder.AppendLine("</div>");
    /*
            // Realiza a análise de complexidade ciclomática
            int complexidadeCiclomatica = ComplexidadeCiclomatica.CalcularComplexidadeCiclomatica(code);
            htmlBuilder.AppendLine("<div id=\"complexidade-ciclomatica\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Complexidade Ciclomática: {complexidadeCiclomatica}</h2>");
            htmlBuilder.AppendLine("</div>");

            //Analise de Dependencias
            htmlBuilder.AppendLine("<div id=\"analise-dependencias\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Dependências:</h2>");
            //AnalizarDependencias(htmlBuilder,code);
            htmlBuilder.AppendLine("</div>");

            // Identificar práticas que afetam o desempenho
            htmlBuilder.AppendLine("<div id=\"mau-desempenho\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Identificação de Práticas de Mau Desempenho:</h2>");
            //IdentificarPraticasDesempenho(htmlBuilder, code);
            htmlBuilder.AppendLine("</div>");

            // Identificar Exceções no código:
            htmlBuilder.AppendLine("<div id=\"analise-excecoes\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Exceções:</h2>");
            AnalisarExcecoes(htmlBuilder, code);
            htmlBuilder.AppendLine("</div>");

            //Verificar Repetição de código
            htmlBuilder.AppendLine("<div id=\"repeticao-codigo\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Repetição de código</h2>");
            VerificarRepeticao(htmlBuilder, code);
            htmlBuilder.AppendLine("</div>");

            // Análise de Concorrência
            htmlBuilder.AppendLine("<div id=\"concorrencia\" style=\"display: none;\">");
            htmlBuilder.AppendLine($"<h2>Análise de Concorrência:</h2>");
            AnalisarConcorrencia(htmlBuilder, code);
            htmlBuilder.AppendLine("</div>");

    */
            stopwatch.Stop();

            htmlBuilder.AppendLine("<div id=\"tempo\" style=\"display:none;\">");
            htmlBuilder.AppendLine($"<h2>Tempo Total de Análise:{stopwatch.ElapsedMilliseconds} ms</h2>");
            htmlBuilder.AppendLine("</div>");

            htmlBuilder.AppendLine($"<h2 id=\"codigo-analisado\">Código Analisado:</h2>");
            ExibirCodigo(codigo, htmlBuilder);

            // Feche as tags HTML
            htmlBuilder.AppendLine("</body></html>");

            return htmlBuilder.ToString();
        }

        static IEnumerable<string> DividirEmLinhas(string code)
        {
            string[] linhas = code.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            bool multiLineComment = false;
            string linha;

            foreach (string l in linhas)
            {
                linha = l.Trim();

                if (multiLineComment)
                {
                    if (linha.Contains("*/"))
                    {
                        multiLineComment = false;
                        int index = linha.IndexOf("*/") + 2;
                        if (index < linha.Length)
                        {
                            yield return linha.Substring(index);
                        }
                    }
                }
                else
                {
                    /*if (string.IsNullOrEmpty(linha))
                    {
                        continue;
                    }*/
                    if (linha.StartsWith("//"))
                    {
                        continue;
                    }
                    else if (linha.Contains("/*"))
                    {
                        multiLineComment = true;
                        int index = linha.IndexOf("/*");
                        if (index > 0)
                        {
                            yield return linha.Substring(0, index);
                        }
                        if (linha.Contains("*/"))
                        {
                            multiLineComment = false;
                            index = linha.IndexOf("*/") + 2;
                            if (index < linha.Length)
                            {
                                yield return linha.Substring(index);
                            }
                        }
                        continue;
                    }

                    yield return linha;
                }
            }
        }

        static void AnalisarVulnerabilidades(List<string> code, StringBuilder htmlBuilder)
        {
            var vulnerabilidadeVisitor = new VulnerabilidadeVisitor();

            // Analisar o código usando o visitor
            vulnerabilidadeVisitor.Visit(code);

            // Construir tabela HTML
            htmlBuilder.AppendLine("<table>");
            htmlBuilder.AppendLine("<tr><th>Tipo</th><th>Linha</th><th>Código</th><th>Nível de Risco</th></tr>");

            foreach (var vulnerabilidade in vulnerabilidadeVisitor.VulnerabilidadesEncontradas)
            {
                htmlBuilder.AppendLine("<tr>");
                htmlBuilder.AppendLine($"<td>{vulnerabilidade.Tipo}</td>");
                htmlBuilder.AppendLine($"<td>{vulnerabilidade.Codigo}</td>");

                int linha = vulnerabilidade.Linha;

                htmlBuilder.AppendLine($"<td> <a href=\"#linha-numero{linha}\" onclick=\"destacarLinha({linha})\">{linha}</a></td>");

                switch (vulnerabilidade.NivelRisco)
                {
                    case NivelRisco.Baixo: htmlBuilder.AppendLine("<td id=\"baixo\">Baixo</td>"); break;
                    case NivelRisco.Medio: htmlBuilder.AppendLine("<td id=\"medio\">Médio</td>"); break;
                    case NivelRisco.Alto: htmlBuilder.AppendLine("<td id=\"alto\">Alto</td>"); break;
                }

                htmlBuilder.AppendLine("</tr>");
            }

            htmlBuilder.AppendLine("</table>");

            htmlBuilder.AppendLine($"<h3>Taxa de Precisão de Análise de Vulnerabilidades: {vulnerabilidadeVisitor.getPrecision()}%</h3>");
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

        static void AnalizarDependencias(StringBuilder htmlBuilder, string code)
        {
            // Expressão regular para encontrar os usings
            Regex usingRegex = new Regex(@"\busing\s+([^\s;]+)\s*;");

            // Dividir o código em linhas
            string[] lines = code.Split('\n');

            htmlBuilder.Append("<table><tr><th>Excerto do Código</th><th>Linha</th></tr>");

            for (int i = 0; i < lines.Length; i++)
            {
                Match match = usingRegex.Match(lines[i]);
                if (match.Success)
                {
                    htmlBuilder.Append($"<tr><td>{lines[i].Trim()}</td><td> <a href=\"#linha-numero{i + 1}\" onclick=\"destacarLinha({i + 1})\">{i + 1}</a></td></tr>");
                }
            }

            htmlBuilder.Append("</table>");
        }

        /*static void IdentificarPraticasDesempenho(StringBuilder htmlBuilder, string code)
        {
            SyntaxTree tree = CSharpSyntaxTree.ParseText(code);
            SyntaxNode root = tree.GetRoot();

            // Verificar loops desnecessariamente complexos
            IEnumerable<SyntaxNode> loopNodes = root.DescendantNodes()
                .Where(node => node.IsKind(SyntaxKind.ForStatement) || node.IsKind(SyntaxKind.WhileStatement));
            AdicionarRelatorio(htmlBuilder, "Loops desnecessariamente complexos identificados", loopNodes, tree);

            // Verificar alocações excessivas de memória
            IEnumerable<SyntaxNode> allocationNodes = root.DescendantNodes()
                .Where(node => node.IsKind(SyntaxKind.ArrayCreationExpression) ||
                                node.IsKind(SyntaxKind.ObjectCreationExpression) ||
                                (node.IsKind(SyntaxKind.GenericName) &&
                                ((GenericNameSyntax)node).TypeArgumentList?.Arguments.Any() == true));
            AdicionarRelatorio(htmlBuilder, "Possíveis alocações excessivas de memória identificadas", allocationNodes, tree);

            // Verificar uso excessivo de boxing e unboxing
            IEnumerable<SyntaxNode> boxingNodes = root.DescendantNodes()
                .Where(node => node.IsKind(SyntaxKind.CastExpression) ||
                                node.IsKind(SyntaxKind.AsExpression));
            AdicionarRelatorio(htmlBuilder, "Uso excessivo de boxing e unboxing identificado", boxingNodes, tree);

            // Verificar falha de otimização em consultas LINQ
            IEnumerable<SyntaxNode> linqQueryNodes = root.DescendantNodes()
                .Where(node => node.IsKind(SyntaxKind.QueryExpression) ||
                                node.IsKind(SyntaxKind.QueryContinuation));
            AdicionarRelatorio(htmlBuilder, "Possíveis falhas de otimização em consultas LINQ identificadas", linqQueryNodes, tree);

            // Verificar StringBuilder para manipulação de strings
            IEnumerable<SyntaxNode> stringBuilderNodes = root.DescendantNodes()
                .Where(node => node.IsKind(SyntaxKind.ObjectCreationExpression) &&
                                ((ObjectCreationExpressionSyntax)node).Type.ToString() == "StringBuilder");
            AdicionarRelatorio(htmlBuilder, "Uso de StringBuilder para manipulação de strings identificado", stringBuilderNodes, tree);

            // Verificar uso incorreto de cache
            IEnumerable<SyntaxNode> cacheUsageNodes = root.DescendantNodes()
        .Where(node => node.IsKind(SyntaxKind.SimpleMemberAccessExpression) &&
                        ((MemberAccessExpressionSyntax)node).Name.Identifier.Text == "Cache");

            AdicionarRelatorio(htmlBuilder, "Uso incorreto de cache identificado", cacheUsageNodes, tree);
        }*/

        /*static void AdicionarRelatorio(StringBuilder relatorio, string mensagem, IEnumerable<SyntaxNode> nodes, SyntaxTree tree)
        {
            if (nodes != null && nodes.Any())
            {
                relatorio.AppendLine($"<h3>{mensagem}</h3>");
                relatorio.AppendLine("<table>");
                relatorio.AppendLine("<tr><th>Código</th><th>Linha</th></tr>");

                StringBuilder tableContent = new StringBuilder();
                
                // Antes do loop foreach
                HashSet<int> linhasIncluidas = new HashSet<int>();

                foreach (SyntaxNode node in nodes)
                {
                    var lineSpan = tree.GetLineSpan(node.Span);
                    int linha = lineSpan.StartLinePosition.Line + 1;

                    if (linhasIncluidas.Contains(linha))
                    {
                        continue; // Pule esta linha se já estiver incluída na tabela
                    }

                    // Use o método GetNodeContentWithoutComments para obter o conteúdo sem comentários
                    string codigoCompleto = GetNodeContentWithoutComments(node);

                    // Definir um limite para o comprimento máximo do código exibido
                    int comprimentoMaximo = 120; // ajusta conforme necessário

                    // Se o código for muito grande, exibe apenas uma parte dele
                    string codigoFormatado = codigoCompleto.Length > comprimentoMaximo
                        ? WebUtility.HtmlEncode(codigoCompleto.Substring(0, comprimentoMaximo) + "...")
                        : WebUtility.HtmlEncode(codigoCompleto);

                    linhasIncluidas.Add(linha);

                    tableContent.AppendLine($"<tr><td>{codigoFormatado}</td><td><a href=\"#linha-numero{linha}\" onclick=\"destacarLinha({linha})\">{linha}</a></td></tr>");
                }

                relatorio.Append(tableContent.ToString());
                relatorio.AppendLine("</table>");
            }
        }*/

        static void AnalisarExcecoes(StringBuilder relatorio, string code)
        {
            SyntaxTree tree = CSharpSyntaxTree.ParseText(code);
            var root = tree.GetRoot();
            var tryCatchStatements = root.DescendantNodes().OfType<TryStatementSyntax>();

            if (!tryCatchStatements.Any())
            {
                relatorio.Append("<h3>Não foi encontrada nenhuma exceção.</h3>");
                return;
            }

            // Adicionar cabeçalhos da tabela
            relatorio.Append("<table><tr><th>Nome da Exceção</th><th>Linha do Código</th></tr>");

            foreach (var tryCatch in tryCatchStatements.SelectMany(tryStatement => tryStatement.Catches))
            {
                var exceptionType = tryCatch.Declaration?.Type;
                int linha = tree.GetLineSpan(tryCatch.Span).StartLinePosition.Line + 1;

                relatorio.Append("<tr>");

                // Nome da Exceção
                relatorio.Append("<td>");
                relatorio.Append(exceptionType?.ToString() ?? "Exceção não especificada");
                relatorio.Append("</td>");

                // Linha do Código
                relatorio.Append($"<td><a href=\"#linha-numero{linha}\" onclick=\"destacarLinha({linha})\">{linha}</a></td>");

                relatorio.Append("</tr>");
            }

            // Fechar a tabela
            relatorio.Append("</table>");
        }

        static void VerificarRepeticao(StringBuilder htmlBuilder, string code)
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(code);
            var root = syntaxTree.GetRoot();

            var metodosRepetidos = VerificarRepeticao(root.DescendantNodes().OfType<MethodDeclarationSyntax>());
            var variaveisRepetidas = VerificarRepeticao(root.DescendantNodes().OfType<VariableDeclarationSyntax>());
            var classesRepetidas = VerificarRepeticao(root.DescendantNodes().OfType<ClassDeclarationSyntax>());

            // Generar tablas HTML

            if (!GerarTabelaHTML(htmlBuilder, "Métodos Repetidos", metodosRepetidos) &&
               !GerarTabelaHTML(htmlBuilder, "Variáveis Repetidas", variaveisRepetidas) &&
               !GerarTabelaHTML(htmlBuilder, "Classes Repetidas", classesRepetidas))
            {
                htmlBuilder.Append("<h3>Não foi encontrado nenhum código repetido!</h3>");
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