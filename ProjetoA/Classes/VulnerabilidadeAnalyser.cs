using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using ProjetoA.Classes;
using System.Collections.Concurrent;
using System.Text;
using System.Reflection;
using System.Data.SqlClient;

namespace ProjetoA.Analyzers
{
    internal enum NivelRisco
    {
        Alto,
        Medio,
        Baixo
    }

    internal class Vulnerability
    {
        public string Tipo { get; }
        public string Codigo { get; }
        public List<int> Linhas { get; }
        public NivelRisco Risco { get; }

        public Vulnerability(string type, string code, NivelRisco riskLevel, List<int> linhas)
        {
            Tipo = type;
            Codigo = code;
            Risco = riskLevel;
            Linhas = linhas;
        }
    }

    internal class VulnerabilityAnalyzer
    {
        private readonly object _lock = new object();

        public List<Vulnerability> Vulnerabilidades{ get; } = new List<Vulnerability>();

        public async Task<List<Vulnerability>> Analyze(SyntaxTree tree)
        {
            var vulnerabilities = new List<Vulnerability>();

            var compilation = CSharpCompilation.Create("MyCompilation", new[] { tree }, new[]
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location)
            });

            var model = compilation.GetSemanticModel(tree);
            var root = tree.GetRoot();


            await Task.WhenAll(
                AnalyzeSqlInjection(root, model),
                AnalyzeXss(root, model)
            );

            return vulnerabilities;
        }

        private async Task AnalyzeSqlInjection(SyntaxNode root, SemanticModel model)
        {
            await Task.Run(() =>
            {
                var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
                foreach (var invocation in invocations)
                {
                    var symbolInfo = model.GetSymbolInfo(invocation);
                    if (symbolInfo.Symbol != null)
                    {
                        if (symbolInfo.Symbol.ToString().StartsWith("System.Data.SqlClient.SqlCommand.ExecuteNonQuery"))
                        {
                            var argumentList = invocation.ArgumentList.Arguments;
                            if (argumentList.Count > 0 && argumentList[0].Expression is LiteralExpressionSyntax)
                            {
                                var lineNumber = ((LiteralExpressionSyntax)argumentList[0].Expression).GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                                lock (_lock)
                                {
                                    var existingVulnerability = Vulnerabilidades.FirstOrDefault(v => v.Tipo == "SQL Injection" && v.Codigo == invocation.ToString());
                                    if (existingVulnerability != null)
                                    {
                                        existingVulnerability.Linhas.Add(lineNumber);
                                    }
                                    else
                                    {
                                        // Avaliação do nível de risco
                                        var nivelRisco = AvaliarNivelDeRiscoSQLInjection(invocation.ToString());
                                        Vulnerabilidades.Add(new Vulnerability("SQL Injection", invocation.ToString(), nivelRisco, new List<int> { lineNumber }));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        private NivelRisco AvaliarNivelDeRiscoSQLInjection(string query)
        {
            // Verifica se a consulta contém palavras-chave suspeitas de SQL Injection
            if (query.Contains("DROP") || query.Contains("DELETE") || query.Contains("TRUNCATE") || query.Contains("UPDATE") || query.Contains("ALTER"))
            {
                return NivelRisco.Alto;
            }
            // Verifica se a consulta utiliza parâmetros
            else if (query.Contains("@"))
            {
                return NivelRisco.Medio;
            }
            // Se nenhum critério de alto risco for atendido, retorna nível de risco baixo
            else
            {
                return NivelRisco.Baixo;
            }
        }

        private async Task AnalyzeXss(SyntaxNode root, SemanticModel model)
        {
            await Task.Run(() =>
            {
                var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignments)
                {
                    var symbolInfo = model.GetSymbolInfo(assignment.Left);
                    if (symbolInfo.Symbol != null)
                    {
                        if (symbolInfo.Symbol.ToString().StartsWith("System.Web.UI.WebControls.Literal.Text"))
                        {
                            if (assignment.Right is LiteralExpressionSyntax)
                            {
                                var lineNumber = ((LiteralExpressionSyntax)assignment.Right).GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                                lock (_lock)
                                {
                                    var existingVulnerability = Vulnerabilidades.FirstOrDefault(v => v.Tipo == "XSS" && v.Codigo == assignment.ToString());
                                    if (existingVulnerability != null)
                                    {
                                        existingVulnerability.Linhas.Add(lineNumber);
                                    }
                                    else
                                    {
                                        // Determinando o nível de risco
                                        var nivelRisco = DetermineNivelRisco(assignment.Right.ToString());
                                        Vulnerabilidades.Add(new Vulnerability("XSS", assignment.ToString(), nivelRisco, new List<int> { lineNumber }));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        private NivelRisco DetermineNivelRisco(string codigo)
        {
            // Implemente suas regras de determinação de risco aqui.
            // Este é apenas um exemplo simplificado.
            if (codigo.Contains("<script>"))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("javascript:"))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("http://"))
            {
                return NivelRisco.Medio;
            }
            else
            {
                return NivelRisco.Baixo;
            }
        }

        private async Task AnalyzeXxe(SyntaxNode root, SemanticModel model)
        {
            await Task.Run(() =>
            {
                var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignments)
                {
                    var symbolInfo = model.GetSymbolInfo(assignment.Left);
                    if (symbolInfo.Symbol != null)
                    {
                        if (symbolInfo.Symbol.ToString().StartsWith("System.Xml.XmlDocument"))
                        {
                            if (assignment.Right is ObjectCreationExpressionSyntax)
                            {
                                var lineNumber = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                                lock (_lock)
                                {
                                    var existingVulnerability = Vulnerabilidades.FirstOrDefault(v => v.Tipo == "XXE" && v.Codigo == assignment.ToString());
                                    if (existingVulnerability != null)
                                    {
                                        existingVulnerability.Linhas.Add(lineNumber);
                                    }
                                    else
                                    {
                                        var nivelRisco = DetermineXxeRiskLevel(assignment.Right.ToString());
                                        Vulnerabilidades.Add(new Vulnerability("XXE", assignment.ToString(), nivelRisco, new List<int> { lineNumber }));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        private NivelRisco DetermineXxeRiskLevel(string codigo)
        {
            // Implemente suas regras de determinação de risco aqui.
            // Este é apenas um exemplo simplificado.
            if (codigo.Contains("LoadXml("))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("XmlDocument"))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("Parse("))
            {
                return NivelRisco.Medio;
            }
            else
            {
                return NivelRisco.Baixo;
            }
        }

        private async Task AnalyzeInsecureDeserialization(SyntaxNode root, SemanticModel model)
        {
            await Task.Run(() =>
            {
                var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignments)
                {
                    var symbolInfo = model.GetSymbolInfo(assignment.Left);
                    if (symbolInfo.Symbol != null)
                    {
                        if (symbolInfo.Symbol.ToString().StartsWith("System.Runtime.Serialization.Json.DataContractJsonSerializer") ||
                            symbolInfo.Symbol.ToString().StartsWith("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"))
                        {
                            if (assignment.Right is ObjectCreationExpressionSyntax)
                            {
                                var lineNumber = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                                lock (_lock)
                                {
                                    var existingVulnerability = Vulnerabilidades.FirstOrDefault(v => v.Tipo == "Insecure Deserialization" && v.Codigo == assignment.ToString());
                                    if (existingVulnerability != null)
                                    {
                                        existingVulnerability.Linhas.Add(lineNumber);
                                    }
                                    else
                                    {
                                        // Determinando o nível de risco
                                        var nivelRisco = DetermineInsecureDeserializationNivelRisco(assignment.Right.ToString());
                                        Vulnerabilidades.Add(new Vulnerability("Insecure Deserialization", assignment.ToString(), nivelRisco, new List<int> { lineNumber }));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        private NivelRisco DetermineInsecureDeserializationNivelRisco(string codigo)
        {
            // Implemente suas regras de determinação de risco aqui.
            // Este é apenas um exemplo simplificado.
            if (codigo.Contains("Deserialize"))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("DeserializeObject"))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("FromBase64String"))
            {
                return NivelRisco.Medio;
            }
            else
            {
                return NivelRisco.Baixo;
            }
        }

        private async Task AnalyzeRemoteCodeExecution(SyntaxNode root, SemanticModel model)
        {
            await Task.Run(() =>
            {
                var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignments)
                {
                    var symbolInfo = model.GetSymbolInfo(assignment.Left);
                    if (symbolInfo.Symbol != null)
                    {
                        // Aqui, você precisa adaptar a lógica para identificar atribuições que podem resultar em execução remota de código.
                        // Isso pode incluir chamadas a APIs perigosas, execução de comandos do sistema, entre outros.
                        if (assignment.Right.ToString().Contains("System.Diagnostics.Process.Start(") || assignment.Right.ToString().Contains("exec("))
                        {
                            var lineNumber = ((LiteralExpressionSyntax)assignment.Right).GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                            lock (_lock)
                            {
                                var existingVulnerability = Vulnerabilidades.FirstOrDefault(v => v.Tipo == "Remote Code Execution" && v.Codigo == assignment.ToString());
                                if (existingVulnerability != null)
                                {
                                    existingVulnerability.Linhas.Add(lineNumber);
                                }
                                else
                                {
                                    var nivelRisco = DetermineRemoteCodeExecutionNivelRisco(assignment.Right.ToString());
                                    Vulnerabilidades.Add(new Vulnerability("Remote Code Execution", assignment.ToString(), nivelRisco, new List<int> { lineNumber }));
                                }
                            }
                        }
                    }
                }
            });
        }

        // Método para determinar o nível de risco de execução remota de código
        private NivelRisco DetermineRemoteCodeExecutionNivelRisco(string codigo)
        {
            // Implemente suas regras de determinação de risco aqui.
            // Este é apenas um exemplo simplificado.
            if (codigo.Contains("System.Diagnostics.Process.Start("))
            {
                return NivelRisco.Alto;
            }
            else if (codigo.Contains("exec("))
            {
                return NivelRisco.Medio;
            }
            else
            {
                return NivelRisco.Baixo;
            }
        }

        /*NoSQL injection
        LDAP Injection
        Log injection
        Mail injection
        Template injection (SSTI)*/

    }
}