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
using System.Reflection;
using System.Collections.Concurrent;

namespace ProjetoA
{
    public class CodeAnalyzer
    {
        //Linhas onde forem encontradas informações importantes
        static ConcurrentDictionary<int, int> linhasImportantes = new ConcurrentDictionary<int, int>();

        public CodeAnalyzer()
        {
            linhasImportantes = new ConcurrentDictionary<int, int>();

        }

        public static async Task<string> GerarRelatorioHTML(string code)
        {
            SyntaxTree tree = CSharpSyntaxTree.ParseText(code);

            var htmlBuilder = new StringBuilder();

            // Início do HTML
            htmlBuilder.AppendLine("<!DOCTYPE html>");
            htmlBuilder.AppendLine("<html lang=\"pt\">");
            htmlBuilder.AppendLine("<head><meta charset=\"utf-8\"><title>Análise de Código</title>");
            htmlBuilder.AppendLine("<style>body {\r\n                                font-family: Arial, sans-serif;\r\n                                text-align: center;\r\n                            }\r\n                        \r\n                            h1 {\r\n                                \r\n                                margin-bottom: 20px;\r\n                            }\r\n                        \r\n                            h2 {\r\n                            \r\n                            margin-bottom: 15px;\r\n                            margin-top: 80px; /* Ajuste o valor conforme necessário */\r\n                            }\r\n                        \r\n                            h2#codigo-analisado{\r\n                                text-align: left;\r\n                            }\r\n\r\n                            h3 {\r\n                                \r\n                                margin-bottom: 10px;\r\n                            }\r\n                        \r\n                            a {\r\n                                text-decoration: none;\r\n                                color: #333;\r\n                                cursor: pointer;\r\n                            }\r\n                        \r\n                            a:hover {\r\n                                color: #007bff;\r\n                            }\r\n                        \r\n                            .indice {\r\n                                \r\n                                margin-bottom: 30px;\r\n                                display: block;\r\n                            }\r\n                        \r\n                            ul {\r\n                                list-style: none;\r\n                                padding: 0;\r\n                            }\r\n                        \r\n                            li {\r\n                                margin-bottom: 10px;\r\n                                font-size: 18px;\r\n                            }\r\n                        \r\n                            table {\r\n                                width: 100%;\r\n                                border-collapse: collapse;\r\n                                margin-top: 20px;\r\n                            }\r\n                        \r\n                            /* Estilo para as células da tabela */\r\n                            table td, table th {\r\n                                padding: 10px;\r\n                                border: 1px solid #ddd;\r\n                                text-align: left;\r\n                            }\r\n                        \r\n                            /* Estilo para o cabeçalho da tabela */\r\n                            table th {\r\n                                background-color: #f2f2f2;\r\n                            }\r\n                        \r\n                            /* Estilo para alternância de cores nas linhas */\r\n                            .table tr:nth-child(even) {\r\n                                background-color: #f9f9f9;\r\n                            }\r\n                        \r\n                            .alto {\r\n                                background-color: rgb(238, 93, 93);\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            .medio {\r\n                                background-color: yellow;\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            .baixo {\r\n                                background-color: greenyellow;\r\n                                font-weight: bold;\r\n                            }\r\n\r\n                            .desempenho{\r\n                                background-color: #57e0f8;\r\n                                font-weight: bold;\r\n                            }\r\n\r\n                            .overloading{\r\n                                background-color:rgb(182, 138, 18);\r\n                                font-weight: bold;\r\n                            }\r\n                        \r\n                            /* Estilo para o código analisado */\r\n                            .codigo-container {\r\n                                margin-top: 20px;\r\n                                padding: 10px;\r\n                                background-color: #f2f2f2;\r\n                                text-align: justify;\r\n                            }\r\n                        \r\n                            .codigo-container pre {\r\n                                white-space: pre-wrap;\r\n                                font-size: 14px;\r\n                            }\r\n                            \r\n                            span{\r\n                                color: rgb(137, 8, 8);\r\n                            }\r\n\r\n                            .selected{\r\n                                border: 5px solid rgb(130, 160, 100);\r\n                            }\r\n</style>");
            htmlBuilder.AppendLine("<script> function mostrarSecao(id) {\r\n            var secao = document.getElementById(id);\r\n            \r\n            if (secao.style.display == '' || secao.style.display == \"none\") {\r\n                secao.style.display = \"block\";\r\n            } \r\n                    \r\n            else {\r\n                secao.style.display = \"none\";\r\n            }\r\n        }\r\n        \r\n        function modificarPadrao(num,risco){\r\n        var minhaDiv = document.getElementById('linha-numero'+num);\r\n\r\n        if(minhaDiv.classList.length==0){\r\n                \r\n                minhaDiv.style.display = 'inline-block';\r\n\r\n                switch(risco){\r\n                case 0: \r\n                    minhaDiv.classList.add('alto'); \r\n                    break;\r\n                case 1: \r\n                    minhaDiv.classList.add('medio'); break;\r\n                    break;\r\n                case 2: \r\n                    minhaDiv.classList.add('baixo'); \r\n                    break;\r\n            \r\n                case 3: \r\n                    minhaDiv.classList.add('desempenho')\r\n                    break;\r\n\r\n                case 4:\r\n                    minhaDiv.classList.add('overloading')\r\n                    break;\r\n                }\r\n                \r\n            }\r\n        }\r\n        \r\n        function tirarSelection(num) {\r\n    return function() {\r\n        var minhaDiv = document.getElementById('linha-numero' + num);\r\n        minhaDiv.classList.remove('selected');\r\n        minhaDiv.removeEventListener('click', tirarSelection(num));\r\n    }\r\n}\r\n\r\nfunction selecionar(num) {\r\n    var minhaDiv = document.getElementById('linha-numero' + num);\r\n\r\n    if (!minhaDiv.classList.contains('selected')) {\r\n        minhaDiv.classList.add('selected');\r\n        minhaDiv.onclick= tirarSelection(num)\r\n    }\r\n}\r\n</script>");
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

            //Processamos o código inserido pelo utilizador como um dicionário e removemos os comentários
            string[] linhasSeparadas = code.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            var linhas = GuardarEmDicionario(linhasSeparadas);

            //Preparamos o Menu de Navegação no Relatório
            htmlBuilder.AppendLine("<h2>Índice</h2>\r\n<div class=\"indice\">\r\n<ul>\r\n    " +
                "<li><a onclick=\"mostrarSecao('analise-vulnerabilidade')\">Análise de Vulnerabilidade</a></li>\r\n    " +
               // "<li><a onclick=\"mostrarSecao('analise-dependencias')\">Análise de Dependências</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('mau-desempenho')\">Identificação de Práticas de Mau Desempenho</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('overloading')\">Análise de OverLoading</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('concorrencia')\">Análise de Concorrência</a></li>\r\n    " +
                "<li><a onclick=\"mostrarSecao('complexidade-ciclomatica')\">Complexidade Ciclomática</a></li>\r\n   " +
                "<li><a onclick=\"mostrarSecao('tempo')\">Tempo Total de Análise</a></li>");
            htmlBuilder.AppendLine($"</ul></div>");

            //Este é o método principal que analisa o código inteiro
            StringBuilder analises = await AnalisarCodigo(linhas,tree);
            stopwatch.Stop();

            htmlBuilder.Append(analises);

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

        static async Task<StringBuilder> AnalisarCodigo(Dictionary<string, List<int>> lines,SyntaxTree tree)
        {
            // Inicia as três tarefas em paralelo
            Task<StringBuilder> taskAnalisarVulnerabilidades = AnalisarVulnerabilidades(lines);
            Task<StringBuilder> taskAnalisarDependencias = IdentificarPraticasDesempenho(lines);
            Task<StringBuilder> taskAnalisarOverloading = AnalisarOverloading(tree);
            Task<int> taskComplexidadeCiclomatica = ComplexidadeCiclomatica.CalcularComplexidadeCiclomatica(tree);

            // Espera até que todas as tarefas estejam concluídas
            await Task.WhenAll(taskAnalisarVulnerabilidades,taskAnalisarDependencias,taskAnalisarOverloading,taskComplexidadeCiclomatica);

            int complexidadeCiclomatica = taskComplexidadeCiclomatica.Result;

            // Concatena as strings HTML
            StringBuilder resultadoFinal = new StringBuilder();

            // Adiciona o resultado das tarefas de análise de vulnerabilidades e dependências
            resultadoFinal.Append(taskAnalisarVulnerabilidades.Result);
            resultadoFinal.Append(taskAnalisarDependencias.Result);
            resultadoFinal.Append(taskAnalisarOverloading.Result);

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

                    if (!linhasImportantes.ContainsKey(vul.Linhas[i]))
                    {
                        linhasImportantes[vul.Linhas[i]] = (int)vul.Vulnerabilidade.Risco;
                    }

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

            var tabela = new StringBuilder();
            tabela.AppendLine("<table>");
            tabela.AppendLine("<tr><th>Nome do Padrão de Mau Desempenho</th><th>Linhas do Código</th></tr>");

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

                tabela.Append(resultBuilder);
            }

            // Aguarda todas as tarefas serem concluídas

            if (!hasPatterns)
            {
                result.AppendLine("<h3>Não foi encontrado nenhum padrão de mau desempenho!</h3>");
            }

            else
            {
                tabela.AppendLine("</table>"); // Adicionando a tag de fechamento da tabela
                result.Append(tabela); // Adiciona a tabela completa ao resultado
            }

            result.AppendLine("</div>");

            return await Task.FromResult(result);
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

                    if (!linhasImportantes.ContainsKey(lineList[i]))
                    {
                        linhasImportantes[lineList[i]] = 3;
                    }

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
        /*static async Task<StringBuilder> AnalisarRepeticao(Dictionary<string, List<int>> codeDictionary)
        {
            StringBuilder tabela = new StringBuilder();
            StringBuilder resultado = new StringBuilder();

            bool isEmpty = true;

            resultado.AppendLine("<div id=\"overloading\" style=\"display: none;\">");
            resultado.AppendLine("<h2>Código Repetido</h2>");
            tabela.AppendLine("<table>");
            tabela.AppendLine("<tr><th>Codigo</th><th>Linhas</th></tr>");

            foreach (var key in codeDictionary.Keys)
            {
                if (key == "{" || key == "}")
                {
                    continue;
                }

                if (codeDictionary[key].Count() > 1)
                {
                    if (isEmpty)
                    {
                        isEmpty = false;
                    }

                    tabela.AppendLine("<tr>");
                    tabela.AppendLine($"<td>{key}</td><td>");

                    for (int i = 0; i < codeDictionary[key].Count(); i++)
                    {
                        tabela.Append($"<a href=\"#linha-numero{codeDictionary[key][i]}\" onclick=selecionar({codeDictionary[key][i]})>{codeDictionary[key][i]}</a>");

                        if (!linhasImportantes.ContainsKey(codeDictionary[key][i]))
                        {
                            linhasImportantes[codeDictionary[key][i]] = 4;
                        }

                        if (i + 1 < codeDictionary[key].Count())
                        {
                            tabela.Append(',');
                        }
                    }

                    tabela.Append("</td>");
                }
            }

            tabela.AppendLine("</table>");

            if(isEmpty)
            {
                resultado.AppendLine("<h3>Não Foi encontrado nenhum código repetido!</h3>");
            }

            else
            {
                resultado.Append(tabela);
            }

            resultado.AppendLine("</div>");

            return await Task.FromResult(resultado);
        }*/
        
        static async Task<StringBuilder> AnalisarOverloading(SyntaxTree tree)
        {
            // Obter a raiz da árvore sintática
            var root = await tree.GetRootAsync().ConfigureAwait(false);

            StringBuilder resultado = new StringBuilder();
            StringBuilder table = new StringBuilder();
            bool isEmpty = true;

            // Métodos Únicos
            Dictionary<string, List<int>> MetodosUnicos = new Dictionary<string, List<int>>();
            // Assinaturas dos métodos
            Dictionary<string, int> Assinaturas = new Dictionary<string, int>();

            // Percorrer todas as invocações de método na árvore sintática
            foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                // Se a invocação é uma chamada de método, não uma chamada de delegado
                if (invocation.Expression is IdentifierNameSyntax identifierName)
                {
                    var methodName = GetMethodSignature(invocation);

                    var invocationLine = invocation.GetLocation().GetMappedLineSpan().StartLinePosition.Line + 1;

                    // Adicionar à lista de invocações por nome do método
                    if (!MetodosUnicos.ContainsKey(methodName))
                    {
                        MetodosUnicos[methodName] = new List<int>();
                    }
                    MetodosUnicos[methodName].Add(invocationLine);

                    // Contar as assinaturas do método
                    if (!Assinaturas.ContainsKey(methodName))
                    {
                        Assinaturas[methodName] = 1;
                    }
                    else
                    {
                        Assinaturas[methodName]++;
                    }

                }
            }

            resultado.AppendLine("<div id=\"overloading\" style=\"display: none;\">");
            resultado.AppendLine("<h2>Overloading</h2>");

            if (Assinaturas.Any(kv => kv.Value > 1))
            {
                isEmpty = false;

                table.AppendLine("<table>");
                table.AppendLine("<tr><th>Method Name</th><th>Invocation Lines</th></tr>");

                foreach (var methodEntry in MetodosUnicos)
                {
                    var methodName = methodEntry.Key;
                    var invocationLines = methodEntry.Value;

                    if (invocationLines.Count <= 1)
                    {
                        continue;
                    }

                    table.AppendLine($"<tr><td>{methodName}</td>");

                    foreach (var line in invocationLines)
                    {
                        table.Append($"<td><a href=\"#linha-numero{line}\" onclick=selecionar({line})>{line}</a></td>");
                    }

                    table.AppendLine("</tr>");
                }

                table.AppendLine("</table>");
                resultado.Append(table);
            }
            else
            {
                resultado.AppendLine("<h3>Não foi detectado Overloading!</h3>");
            }

            resultado.AppendLine("</div>");

            return resultado;
        }
        static string GetMethodSignature(InvocationExpressionSyntax invocation)
        {
            var methodName = (invocation.Expression as IdentifierNameSyntax)?.Identifier.ValueText;

            var returnType = (invocation.Parent as MethodDeclarationSyntax)?.ReturnType.ToString() ?? "void";

            var parameterTypes = string.Join(", ", invocation.ArgumentList.Arguments.Select(arg => arg.Expression.GetType().ToString())); // Usar os tipos dos argumentos como parte da assinatura

            return $"{returnType} {methodName}({parameterTypes})";
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
        static void modificarBackground(ConcurrentDictionary<int, int> linhasImportantes, StringBuilder htmlBuilder)
        {
            foreach (var linha in linhasImportantes.Keys)
            {
                htmlBuilder.AppendLine($"modificarPadrao({linha},{linhasImportantes[linha]})");
            }
        }

    }
}